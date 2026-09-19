// lib/ingress-heal.js —— 固定端口 ingress 的「健康探测自愈」层（2026-09-19 自 server.js 拆出，渐进式拆分第六步）
// 覆盖：docker port 解析（getIngressPort，自 lib/ingress.js 归位——自愈层是它的原生归属，
//   同时解除 heal→ingress→heal 的工厂装配循环）/ 稳定端口派生（stablePortFor + hashCode）/
//   主容器定位（findMcpMainContainer）/ 幂等确保与重建（ensureStableIngress + rebuildIngress，
//   含同 workload 单飞任务表）/ 自愈回写（healMcpIngress）/ workload 反查（subIdByWorkload）。
// 依赖全部经 ctx 注入：docker 执行（execFileHidden / MAX_BUFFER）、端点探活（probeMcpEndpoint，
//   来自 lib/mcp-client）、数据层（db / parseMeta / patchMeta / workloadNameFor）。
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

module.exports = function createIngressHeal(ctx) {
  const {
    execFileHidden, MAX_BUFFER, probeMcpEndpoint,
    db, parseMeta, patchMeta, workloadNameFor,
  } = ctx;

  async function getIngressPort(workloadName) {
    try {
      const { stdout } = await execFileHidden(
        "docker", ["port", `${workloadName}-ingress`],
        { timeout: 10000, maxBuffer: MAX_BUFFER },
      );
      // docker port 输出每行格式："<container_port>/<proto> -> <host>:<host_port>"
      // 例："31396/tcp -> 127.0.0.1:31396" 或 "13433/tcp -> 0.0.0.0:13433"
      // ToolHive 不同版本/不同环境下 ingress 端口可能动态变化，不能硬编码 13433。
      const lines = stdout.trim().split("\n").filter(Boolean);
      for (const line of lines) {
        const m = line.match(/->\s+(?:127\.0\.0\.1|0\.0\.0\.0|localhost|::1)?:(\d+)/);
        if (m) return m[1];
      }
    } catch (_) {
      /* 无 ingress 或 docker 异常 */
    }
    return null;
  }

  // ---- 兜底：thv 未自动创建 <workload>-ingress 时的自愈 ----
  // 背景：thv 对「纯容器 image run」(尤其无 OCI provenance label 的镜像) 有时不会自动
  // 建 squid ingress 容器 → getIngressPort 拿不到端口 → /mcp-proxy 全 502。
  // 方案：探测到无 ingress 时，自动起一个 socat 反向代理容器（命名 <workload>-ingress，
  // 复刻 thv ingress 结构：连 toolhive-external 提供 host publish + connect 到 workload
  // 的 internal 网络以路由到主容器），把主容器 MCP 端口暴露到 host 固定端口。
  async function findMcpMainContainer(workload) {
    try {
      const { stdout } = await execFileHidden(
        "docker", ["inspect", "--format", "{{json .}}", workload],
        { timeout: 12000, maxBuffer: MAX_BUFFER },
      );
      const info = JSON.parse(stdout);
      const nets = (info.NetworkSettings && info.NetworkSettings.Networks) || {};
      // 主容器所在网络通常是 toolhive-<workload>-internal
      const netName =
        Object.keys(nets).find((n) => n === `toolhive-${workload}-internal`) ||
        Object.keys(nets).find((n) => n.includes("-internal")) ||
        Object.keys(nets)[0];
      const ip = netName ? nets[netName].IPAddress : null;
      // MCP 监听端口。注意容器 env 里的 MCP_PORT / FASTMCP_PORT 是 thv 按 --target-port
      // 回写的"假设值"（写死 3000 时代它会跟着错），不是事实——authoritative 是镜像自己的
      // EXPOSE（作者声明）。容器 Config.ExposedPorts 也会被 thv 追加污染，所以查镜像配置。
      let port = null;
      try {
        const imgRef = (info.Config && info.Config.Image) || workload;
        const imgOut = await execFileHidden("docker", ["inspect", "--format", "{{json .Config.ExposedPorts}}", imgRef], { timeout: 12000, maxBuffer: MAX_BUFFER });
        const imgExposed = JSON.parse(String(imgOut.stdout || "{}").trim() || "{}");
        const keys = Object.keys(imgExposed);
        if (keys.length) {
          // 多端口时优先平台约定的 3000，否则取第一个
          const hit = keys.find((k) => String(k).split("/")[0] === "3000") || keys[0];
          port = Number(String(hit).split("/")[0]) || null;
        }
      } catch (_) { /* 镜像配置读不到再走 env/端口映射回退 */ }
      if (!port) {
        const env = (info.Config && info.Config.Env) || [];
        const pv = env.find((e) => e.startsWith("MCP_PORT=")) ||
                    env.find((e) => e.startsWith("FASTMCP_PORT="));
        if (pv) port = Number(pv.split("=")[1]) || null;
      }
      if (!port) {
        const ex = (info.NetworkSettings && info.NetworkSettings.Ports) || {};
        port = Number(Object.keys(ex)[0] && Object.keys(ex)[0].split("/")[0]) || null;
      }
      return { ip, port, netName };
    } catch (_) {
      return null;
    }
  }

  // 基于 workload 名派生的稳定 host 端口（36000-36999）：同一名永远算出同一端口，
  // 这是「固定端口」层的根基——ingress 重建后端口不变，meta.endpoint 不再漂移。
  function stablePortFor(workload, offset = 0) {
    return 36000 + ((hashCode(workload) + offset) % 1000);
  }

  // 固定端口 ingress（幂等确保）：
  //   1) 现有 ingress 端口 == 固定值且探测通过 → 直接复用（快路径）
  //   2) 现有 ingress 可用但非固定端口（如 thv 的动态 squid）→ rebuild=false 时先用它；
  //      rebuild=true（部署/自愈）时重建为固定端口 socat ingress
  //   3) 坏 ingress（端口在但 502）或无 ingress → 重建；固定端口被占时线性后移重试
  // 返回实际可用的 host 端口；彻底失败时回退现有动态端口（若有）。
  // 同一 workload 的 ingress 重建任务表（单飞）：并发重建会互相 rm 掉对方刚建好的
  // 容器，造成 ingress 反复抖动、接口拖死——同 workload 的重建必须共享一个任务
  const ingressRebuildJobs = new Map();

  async function ensureStableIngress(workload, meta = {}, { rebuild = true } = {}) {
    const fixed = Number(meta && meta.ingress_port) || stablePortFor(workload);
    const cur = await getIngressPort(workload);
    if (cur === String(fixed)) {
      if (await probeMcpEndpoint(`http://127.0.0.1:${fixed}/mcp`)) return fixed;
    } else if (cur && (await probeMcpEndpoint(`http://127.0.0.1:${cur}/mcp`))) {
      if (!rebuild) return Number(cur);
    }
    if (!rebuild) return null;
    let job = ingressRebuildJobs.get(workload);
    if (!job) {
      job = rebuildIngress(workload, cur).finally(() =>
        ingressRebuildJobs.delete(workload),
      );
      ingressRebuildJobs.set(workload, job);
    }
    return job;
  }

  async function rebuildIngress(workload, cur) {
    const ingressName = `${workload}-ingress`;
    const main = await findMcpMainContainer(workload);
    if (!main || !main.ip || !main.port) return cur ? Number(cur) : null;
    // 需要 external 网络作 host publish 通道
    let extNet = "toolhive-external";
    try {
      const { stdout } = await execFileHidden("docker", ["network", "ls", "--format", "{{.Name}}"], { timeout: 8000, maxBuffer: MAX_BUFFER });
      const all = stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (!all.includes(extNet)) {
        const fallback = all.find((n) => n.includes("external"));
        if (fallback) extNet = fallback;
        else return cur ? Number(cur) : null; // 无 external 网络，无法 host publish
      }
    } catch (_) { return cur ? Number(cur) : null; }
    for (let off = 0; off < 5; off++) {
      const hostPort = stablePortFor(workload, off * 37);
      // 清理同名旧容器（无论它是 thv 的动态 squid 还是坏死的 socat）——统一收敛到固定端口
      try { await execFileHidden("docker", ["rm", "-f", ingressName], { timeout: 15000, maxBuffer: MAX_BUFFER }); } catch (_) {} // 容器可能本就不存在，rm 失败不影响后续重建
      try {
        await execFileHidden(
          "docker", ["run", "-d", "--restart", "unless-stopped", "--name", ingressName, "--network", extNet,
            "-p", `127.0.0.1:${hostPort}:${hostPort}`, "alpine/socat",
            `TCP-LISTEN:${hostPort},fork,reuseaddr`, `TCP:${main.ip}:${main.port}`],
          { timeout: 60000, maxBuffer: MAX_BUFFER },
        );
        // 加入 internal 网络使 socat 能路由到主容器
        await execFileHidden("docker", ["network", "connect", main.netName, ingressName], { timeout: 15000, maxBuffer: MAX_BUFFER }).catch(() => {});
      } catch (_) { continue; }
      // 等 socat 就绪后探测确认（docker port 对已退出容器也显示映射，probe 才是真验证）
      await sleep(2000);
      const p = await getIngressPort(workload);
      if (String(p) === String(hostPort) && (await probeMcpEndpoint(`http://127.0.0.1:${hostPort}/mcp`))) {
        return hostPort;
      }
    }
    return cur ? Number(cur) : null;
  }

  function hashCode(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) {
      h = (Math.imul(31, h) + str.charCodeAt(i)) | 0;
    }
    return Math.abs(h);
  }

  // 探测+自愈+回写（「健康探测自愈」层核心）：固定端口 ingress 不可用则重建（端口不变），
  // 并把真实端口/endpoint 回写 meta——保证 DB 里的 endpoint 始终等于实际在听的端口。
  async function healMcpIngress(id) {
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
    if (!sub || sub.type !== "mcp") return null;
    const meta = parseMeta(sub);
    if (meta.deploy_status !== "deployed") return null;
    const workload = meta.workload_name || workloadNameFor(id);
    const p = await ensureStableIngress(workload, meta);
    if (!p) return null;
    const endpoint = `http://127.0.0.1:${p}/mcp`;
    if (endpoint !== meta.endpoint || p !== Number(meta.ingress_port)) {
      patchMeta(id, { endpoint, ingress_port: p, deploy_error: "" });
    }
    return endpoint;
  }

  // 按 workload 名反查 submission id（proxy 转发失败时触发自愈用）
  function subIdByWorkload(workload) {
    if (!workload) return null;
    const row = db
      .prepare("SELECT id FROM submissions WHERE type='mcp' AND meta LIKE ?")
      .get(`%"workload_name":"${workload}"%`);
    return row ? row.id : null;
  }

  return {
    getIngressPort, stablePortFor, findMcpMainContainer,
    ensureStableIngress, rebuildIngress, healMcpIngress, subIdByWorkload,
  };
};
