// services/deploy.js —— MCP 部署/下线管线（2026-09-11 渐进式拆分，自 server.js 原样迁出）
// 职责：tar/镜像/源码三条部署链、幂等清理、端点轮询、重启策略、ingress 收敛、Registry 同步。
// 依赖经 ctx 注入；extractMcpInspect 由 routes/mcp 提供（lazy 回填与部署共用一份实现）。
/**
 * @typedef {Object} DeployCtx 部署服务依赖（由 server.js 装配区注入，Proxy 对账清单见工作日志）
 * @property {import("better-sqlite3").Database} db
 * @property {(s: Object) => Object} parseMeta
 * @property {(id: string, patch: Object) => void} patchMeta
 * @property {Function} execFileHidden  execFile 包装（隐藏窗口/注入 PATH）
 * @property {(ms: number) => Promise<void>} sleep
 * @property {Function} thvListJson  解析 thv list --json
 * @property {Function} envInjectArgs  env 凭据 → thv run 参数（lib/env-secrets）
 * @property {Function} buildSourceImage  源码包 → 本地镜像（lib/source-build）
 * @property {Function} healMcpIngress  建/验固定端口 socat ingress 并回写稳定 endpoint
 * @property {(imageRef: string) => Promise<Object|null>} extractMcpInspect  镜像元数据提取（脱敏）
 * @property {Function} runTrivyScan  源码构建部署后的补扫
 * @property {Function} invalidateMcpRuntimeCaches  部署事件双清 rtCache/toolsCache
 */
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

/** @param {DeployCtx} ctx */
module.exports = function createDeployService(ctx) {
  const {
    db, parseMeta, patchMeta, execFileHidden, MAX_BUFFER, THV_BIN, DOCKER_BIN,
    envInjectArgs, buildSourceImage, thvListJson, sleep, workloadNameFor,
    registryPublish, healMcpIngress, extractMcpInspect, runTrivyScan,
    ensureStableIngress, probeMcpEndpoint,
    invalidateMcpRuntimeCaches,
  } = ctx;

  // tar 制品 → docker load，返回解析出的镜像名（两种输出形态都兼容）
  async function loadTarImage(key) {
    const fp = path.join(ctx.TAR_ROOT, key);
    if (!fs.existsSync(fp)) throw new Error("tar 文件不存在: " + key);
    const out = await execFileHidden(DOCKER_BIN, ["load", "-i", fp], { timeout: 600000, maxBuffer: MAX_BUFFER });
    const txt = (out.stdout || "") + (out.stderr || "");
    const m1 = txt.match(/Loaded image:\s*([^\r\n]+)/i);
    if (m1 && m1[1].trim()) return m1[1].trim();
    const m2 = txt.match(/Loaded image ID:\s*([^\r\n]+)/i);
    if (m2 && m2[1].trim()) {
      const id = m2[1].trim();
      const tag = "mcp-tar/" + key.replace(/[^a-zA-Z0-9._-]/g, "-") + ":loaded";
      await execFileHidden(DOCKER_BIN, ["tag", id, tag], { timeout: 60000, maxBuffer: MAX_BUFFER });
      return tag;
    }
    return null;
  }

  // 部署配置指纹：镜像 + env 注入参数 + 传输形态的稳定哈希。
  // 指纹一致 ⇒ thv start 恢复的旧运行配置与本次期望完全一致，可安全走秒级快启；
  // 注意它锁定的是「配置字符串」——镜像 tag 被原地覆盖同名校验不到（内部镜像约定不可变 tag），
  // 这类场景请删除提交重新走完整链。
  function deployFingerprint(image, meta) {
    const args = envInjectArgs(meta);
    const norm = JSON.stringify({
      image, args,
      transport: meta.transport || "",
      source_type: meta.source_type || "",
    });
    return crypto.createHash("sha256").update(norm).digest("hex").slice(0, 16);
  }

  // 部署一个 MCP：源码构建 / tar 加载 / 镜像直跑三条链，端点轮询 + 收敛 + Registry 同步
  /** @param {string} id @returns {Promise<void>} 失败时写 meta.deploy_error，不抛出到调用方之外 */
  // —— 部署并发锁 ——
  // 同一 submission 的部署/下线/删除互斥：并发时「一个在 docker start、一个在 thv rm」
  // 会产生半死容器组。Node 单进程内存锁即可（全部入口共用同一个 service 实例），
  // 进程重启自动清零。锁被占抛 code=DEPLOY_BUSY，路由层转 409；reconcile 自愈侧
  // 本就有 try/catch，busy 会跳过本轮、下轮重试。
  const deployLocks = new Set();
  async function withDeployLock(id, fn) {
    if (deployLocks.has(id)) {
      const err = new Error("该 MCP 正在部署/下线中，请等待当前操作完成后再试");
      err.code = "DEPLOY_BUSY";
      throw err;
    }
    deployLocks.add(id);
    try {
      return await fn();
    } finally {
      deployLocks.delete(id);
    }
  }

  async function deployMcpInner(id) {
    invalidateMcpRuntimeCaches(id); // 部署双清 tools/rt 两层缓存（routes/mcp 注入）
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
    if (!sub || sub.type !== "mcp") return;
    const meta = parseMeta(sub);
    // 源码包提交：先平台侧构建本地镜像（building 状态），构建产物走与镜像包一致的部署链
    let sourceBuiltImage = null;
    if (meta.source_type === "source") {
      if (!meta.built_image) {
        patchMeta(id, { deploy_status: "building", deploy_error: "" });
        try {
          sourceBuiltImage = await buildSourceImage(sub);
        } catch (e) {
          // 保留消息尾部：docker/pip 的真实报错在构建日志末尾，头部只是无害进度
          patchMeta(id, {
            deploy_status: "failed",
            deploy_error: "源码构建失败: " + String((e && e.message) || e).slice(-700),
          });
          return;
        }
      } else {
        sourceBuiltImage = meta.built_image;
      }
    }
    // 优先用已同步进内网的 internal_ref，确保运行时从内网拉取、不走外网；
    // 未同步（未勾选或同步失败）时回退原 image_ref，保证业务可用。
    // recovery_image：workload 对账恢复时从孤儿容器捕获的、本地实际存在的镜像（最高优先），
    // 避免 thv 状态丢失后的重部署因外网 ref 不可达而失败。
    let image = sourceBuiltImage || meta.recovery_image || meta.internal_ref || meta.image_ref;
    // tar 提交但此前未成功解析出镜像名（如审批时 docker load 失败/未完成）：
    // 重新尝试 docker load，让「重新部署」按钮对 tar 类提交真正重试。
    if (!image && meta.source_type === "tar" && meta.artifact_key) {
      try {
        const loaded = await loadTarImage(meta.artifact_key);
        if (loaded) {
          patchMeta(id, { image_ref: loaded, deploy_status: "loaded", mirror_status: "skipped:tar" });
          image = loaded;
        } else {
          patchMeta(id, {
            deploy_status: "failed",
            deploy_error: "该 tar 不是合法的 docker save 镜像包（docker load 未解析出镜像名）。请重新提交 `docker save 镜像名:tag -o 文件.tar` 导出的镜像，或改用 ghcr.io 镜像地址。",
          });
          return;
        }
      } catch (e) {
        const msg = (e.stderr || e.stdout || e.message || "").toString().slice(0, 600);
        patchMeta(id, {
          deploy_status: "failed",
          deploy_error: "镜像 tar 加载失败：" + msg + "（请确认上传的是 docker save 导出的合法镜像包，而非源码压缩包）",
        });
        return;
      }
    }
    if (!image) {
      patchMeta(id, {
        deploy_status: "failed",
        deploy_error: "该提交没有可部署的镜像：请重新提交并填写 ghcr.io 镜像地址（image_ref），或上传 `docker save` 导出的合法镜像 tar 包。",
      });
      return;
    }
    // 可观测：记录本次部署实际用的镜像与是否命中内网源
    patchMeta(id, { deployed_image: image, deployed_from_internal: Boolean(meta.internal_ref) });
    const workload = meta.workload_name || workloadNameFor(id);
    patchMeta(id, { deploy_status: "deploying", workload_name: workload, deploy_error: "" });
    // 快启路径（2026-09-18 下线语义改造的另一半）：下线只 thv stop 不删容器，容器原地保留（Exited）。
    // 检测「配置指纹一致 + 存在已停止容器」直接 docker start 原地恢复（实测 ~3s），
    // 跳过 rm+run 完整重建，也绕开 thv start 的副作用——它会重新 pull sidecar 镜像
    //（docker.io 不稳时卡死数分钟，这正是「重新部署很久」的根因）。
    // 门禁：① meta.deploy_fp 与当前指纹一致（镜像/env 注入/传输均未变）；
    //      ② source 构建不快启——重建后镜像名字符串不变、指纹感知不到代码变更，必须走完整链。
    const deployFp = deployFingerprint(image, meta);
    let fastStarted = false;
    if (meta.deploy_fp && meta.deploy_fp === deployFp && meta.source_type !== "source") {
      try {
        const entry = (await thvListJson()).find((x) => x.name === workload);
        if (entry && !/running/i.test(String(entry.status || ""))) {
          const { stdout: stoppedNames } = await execFileHidden(
            "docker",
            ["ps", "-a", "--filter", `name=${workload}`, "--filter", "status=exited", "--format", "{{.Names}}"],
            { timeout: 15000, maxBuffer: MAX_BUFFER },
          );
          const names = stoppedNames.split(/\r?\n/).map((s) => s.trim())
            .filter((n) => n && n !== `${workload}-ingress`); // -ingress 是平台 socat，由 ensureStableIngress 重建
          if (names.length) {
            await execFileHidden("docker", ["start", ...names], { timeout: 60000, maxBuffer: MAX_BUFFER });
            fastStarted = true;
          }
        }
      } catch (_) { /* 快启失败退回完整链 */ }
    }
    if (!fastStarted) try {
      // 幂等：先清理同名 workload（避免重部署时 "already exists" 冲突），
      // 不存在或已删时 thv rm 会报错，由 try/catch 吞掉即可。
      try {
        await execFileHidden(THV_BIN, ["rm", workload], { timeout: 30000, maxBuffer: MAX_BUFFER });
      } catch (_) { /* 不存在，忽略 */ }
      const args = ["run", "--name", workload, image];
      // 源码构建的 MCP：自起 HTTP 服务，必须显式 sse 代理模式，否则 thv 按 stdio
      // 包裹会出现 "upstream connect failed"。目标端口不写死 3000——自带 Dockerfile
      // 的工程监听端口由作者决定（曾见 8765，写死 3000 会让代理 502）：
      // 优先读镜像 EXPOSE，EXPOSE 3000 或读不到时回退约定值 3000。
      if (meta.source_type === "source") {
        let targetPort = 3000;
        try {
          const insp = await execFileHidden("docker", ["inspect", "--format", "{{json .Config.ExposedPorts}}", image], { timeout: 15000, maxBuffer: MAX_BUFFER });
          const exposed = JSON.parse(String(insp.stdout || "{}").trim() || "{}");
          const keys = Object.keys(exposed);
          if (keys.length) {
            const hit = keys.find((k) => String(k).split("/")[0] === "3000") || keys[0];
            targetPort = parseInt(String(hit).split("/")[0], 10) || 3000;
          }
        } catch (_) { /* 读不到 EXPOSE 就用约定 3000 */ }
        args.push("--proxy-mode", "sse", "--target-port", String(targetPort));
      } else if (meta.transport === "sse") {
        args.push("--proxy-mode", "sse");
      }
      // .env 私密配置注入：secret 引用形态（值由 ToolHive 启动容器时向加密凭据库请求）
      args.push(...envInjectArgs(meta));
      await execFileHidden(THV_BIN, args, { timeout: 180000, maxBuffer: MAX_BUFFER });
    } catch (e) {
      const msg = (e.stderr || e.stdout || e.message || "").toString().slice(0, 600);
      patchMeta(id, { deploy_status: "failed", deploy_error: msg });
      return;
    }
    if (fastStarted) {
      // 原地恢复就绪轮询：docker start 不会复活 thv 的宿主代理进程，thv 报告的 url 已死，
      // 故不走下方 thv-url 轮询，改走平台自己的固定端口 ingress 链路：
      // 主容器就绪 → ensureStableIngress 重建 socat（若主容器 IP 变了也能纠正）→ 探活。
      let fastEndpoint = null;
      for (let i = 0; i < 60; i++) { // 上限 ~3 分钟，实测秒级
        await sleep(3000);
        try {
          const p = await ensureStableIngress(workload, meta);
          if (p && await probeMcpEndpoint(`http://127.0.0.1:${p}/mcp`)) {
            fastEndpoint = `http://127.0.0.1:${p}/mcp`;
            break;
          }
        } catch (_) { /* 未就绪，继续轮询 */ }
      }
      if (fastEndpoint) {
        patchMeta(id, { deploy_status: "deployed", endpoint: fastEndpoint, deploy_error: "", deploy_fp: deployFp });
        registryPublish(id).catch((e) => console.error("同步 Registry 失败:", e));
        return;
      }
      patchMeta(id, {
        deploy_status: "failed",
        deploy_error: "快启恢复超时：容器已运行但固定端口端点不可达，请重试部署（将自动走完整链）",
      });
      return;
    }
    // 轮询端点（最多 ~10 分钟）。thv runtime 启容器 + health check + 端口 ready
    // 在大镜像/冷启动时可能数分钟，原 60×3s=180s 太短会让 deploying 误判 failed。
    let endpoint = null;
    let lastStatus = "";
    for (let i = 0; i < 200; i++) {
      const list = await thvListJson();
      const entry = list.find((x) => x.name === workload);
      if (entry) {
        lastStatus = entry.status;
        if (entry.url) {
          // thv 报告 url 只代表代理端口已监听，不代表上游容器服务就绪（端口指错时代理会
          // 持续 502，曾把 502 的部署误判成 deployed）。加一次 HTTP 探活：
          // 502/503 视为未就绪继续等；其余任何响应（含 4xx，如 MCP 的 406）都算上游可达。
          try {
            const probe = await fetch(entry.url, { signal: AbortSignal.timeout(3000) });
            if (probe.status !== 502 && probe.status !== 503) { endpoint = entry.url; break; }
          } catch (_) { /* 探测异常（超时/拒连）说明上游未就绪，继续轮询而非误判 deployed */ }
        }
      }
      await sleep(3000);
    }
    if (endpoint) {
      patchMeta(id, { deploy_status: "deployed", endpoint, deploy_error: "", deploy_fp: deployFp });
      // 提取镜像元数据（脱敏后）供详情页「代码」标签展示；失败不影响部署结果
      extractMcpInspect(image).then((insp) => {
        if (insp) patchMeta(id, { mcp_inspect: insp });
      }).catch(() => {});
      // 源码构建的镜像：部署成功后补一次 Trivy 扫描（本地镜像直扫，结果入 meta.trivy 供审计）
      if (meta.source_type === "source" || !meta.artifact_key) {
        runTrivyScan(id);
      }
      // 主容器跟随 Docker 守护进程自动拉起：thv run 无 restart 选项，宿主机/Docker
      // 重启后主容器会全部停止（巡检只能修 ingress 修不了主容器）——部署成功即
      // 对主容器设置 unless-stopped 策略，重启后自动恢复。
      try {
        const { stdout: names } = await execFileHidden("docker", ["ps", "--filter", `name=${workload}`, "--format", "{{.Names}}"], { timeout: 8000, maxBuffer: MAX_BUFFER });
        for (const cname of names.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)) {
          await execFileHidden("docker", ["update", "--restart", "unless-stopped", cname], { timeout: 8000, maxBuffer: MAX_BUFFER }).catch(() => {});
        }
      } catch (_) { /* 策略设置失败不影响部署结果 */ }
      // 统一收敛到平台固定端口 ingress：thv 报告的端点端口随重建漂移，弃作长期地址；
      // healMcpIngress 建/验固定端口 socat ingress 并把稳定 endpoint 回写 meta
      // （用户侧 URL 走 /mcp-proxy 反代收敛，本就不依赖这个端口——它是详情页/诊断用的真值）。
      try { await healMcpIngress(id); } catch (_) { /* 失败则保留 thv endpoint 兜底 */ }
      // 部署成功拿到 endpoint → 同步发布到 Registry Server（使目录可消费）
      registryPublish(id).catch((e) => console.error("同步 Registry 失败:", e));
    } else {
      patchMeta(id, {
        deploy_status: "failed",
        deploy_error: "部署后未获取到端点，最后状态: " + lastStatus,
      });
    }
  }

  // 下线一个 MCP：thv rm 删除容器，清掉 endpoint
  /** @param {string} id 幂等：条目不存在/非 MCP/sidecar 已清均静默返回 */
  async function undeployMcpInner(id, opts = {}) {
    invalidateMcpRuntimeCaches(id); // 停止/部署双清 tools/rt 两层缓存（routes/mcp 注入）
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
    if (!sub || sub.type !== "mcp") return;
    const meta = parseMeta(sub);
    const workload = meta.workload_name || workloadNameFor(id);
    try {
      // 下线（默认）= thv stop：只停运行态，运行配置保留在 ToolHive 状态里，
      //   重上线走 deployMcp 的 docker start 快启路径，秒级恢复、不重拉镜像。
      // 硬删除（opts.hard，删除提交/彻底清理）= thv rm：整组移除容器与运行配置。
      await execFileHidden(THV_BIN, [opts.hard ? "rm" : "stop", workload], { timeout: 30000, maxBuffer: MAX_BUFFER });
    } catch (_) { /* 不存在或已停，忽略 */ }
    if (!opts.hard) {
      // 兜底：快启恢复的 workload 在 thv 状态机里呈 starting，thv stop 可能拒绝执行——
      // 直接 docker stop 所有仍在运行的 thv 容器（平台 socat ingress 由下一行单独停）。
      try {
        const { stdout: runNames } = await execFileHidden(
          "docker", ["ps", "--filter", `name=${workload}`, "--format", "{{.Names}}"],
          { timeout: 15000, maxBuffer: MAX_BUFFER },
        );
        const names = runNames.split(/\r?\n/).map((s) => s.trim())
          .filter((n) => n && n !== `${workload}-ingress`);
        if (names.length) {
          await execFileHidden("docker", ["stop", ...names], { timeout: 60000, maxBuffer: MAX_BUFFER });
        }
      } catch (_) {}
      // 平台自建的固定端口 socat ingress 不归 thv 管，同步停掉（重上线时 ensureStableIngress 会重建）
      try { await execFileHidden("docker", ["stop", `${workload}-ingress`], { timeout: 15000, maxBuffer: MAX_BUFFER }); } catch (_) {}
    }
    patchMeta(id, { deploy_status: "undeployed", endpoint: "", deploy_error: "" });
    // 注：下线只停容器 + 清运行态，Registry 目录条目保留（按设计：仅「删除」才从 Registry 摘除）。
  }

  // 导出层统一包锁：部署/下线路由、删除提交、reconcile 自愈全部互斥
  return {
    deployMcp: (id) => withDeployLock(id, () => deployMcpInner(id)),
    undeployMcp: (id, opts = {}) => withDeployLock(id, () => undeployMcpInner(id, opts)),
  };
};
