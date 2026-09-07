// lib/reconcile.js —— workload 三方对账自愈：平台 DB（唯一真相源）↔ Docker 容器 ↔ thv 管理态。
// thv state 文件（本地单点）丢失/容器被清后，一个巡检周期内自动恢复；孤儿容器走反向重建加速。
"use strict";

module.exports = function makeReconcile(ctx) {
  const {
    db, parseMeta, patchMeta, execFileHidden, MAX_BUFFER, THV_BIN, deployMcp, audit,
  } = ctx;

const healFailState = new Map(); // id -> { fails, nextTryAt }
// 自愈退避：连续重建失败的条目拉长巡检间隔，避免对"永远修不好"的条目每 60 秒空转。成功即清零。
const HEAL_BACKOFF_MS = 10 * 60 * 1000; // 连续 3 次失败后，退避到 10 分钟一次

// ---- workload 三方对账：平台 DB（唯一真相源）↔ Docker 容器 ↔ thv 管理态 ----
// 背景：standalone 模式下 thv 的 workload 清单存于用户目录本地 state 文件（单点），
// 机器重启/清理后可能丢失，而容器因 --restart 策略仍存活 → "孤儿 workload"：
// 容器在跑但 thv list 不认识，无法 stop/恢复/按名管理，重启后也无法靠 thv 拉起。
// 对账口径：DB 里 deploy_status='deployed' 的条目，其 workload 必须出现在 thv list；
// 缺失即恢复（每轮巡检执行一次，失败计入 healFailState 退避）：
//   ② 反向重建加速——孤儿主容器还活着 → 直接取它 Config.Image 里的真实镜像
//      （本地已验证存在，免源码重构建/免 tar 重载），记回 meta 后清掉孤儿容器组；
//   容器也没了 → 全量 deployMcp（幂等：源码会重建、tar 会重 load）。
async function thvWorkloadNames() {
  // 注意区分「空列表」与「thv 不可用」：后者必须跳过本轮，否则会把全部条目误判为失联
  try {
    const { stdout } = await execFileHidden(
      THV_BIN, ["list", "--format", "json", "--all"],
      { timeout: 20000, maxBuffer: MAX_BUFFER },
    );
    return new Set((JSON.parse(stdout || "[]") || []).map((x) => x.name));
  } catch (_) {
    return null;
  }
}

async function reconcileMcpWorkloads() {
  const thvNames = await thvWorkloadNames();
  if (!thvNames) return; // thv CLI 不可用（如 Docker 未就绪），本轮放弃，下轮再对账
  const rows = db.prepare("SELECT id, meta FROM submissions WHERE type='mcp'").all();
  for (const r of rows) {
    const meta = parseMeta(r);
    if (meta.deploy_status !== "deployed") continue;
    const workload = meta.workload_name || workloadNameFor(r.id);
    if (thvNames.has(workload)) {
      // thv 有登记，但主容器可能已没了（thv 状态在、容器被清理）——同样是状态与现实失联
      const alive = await dockerContainerRunning(workload).catch(() => false);
      if (alive) continue;
      console.warn("[workload 对账] thv 有登记但主容器缺失，开始恢复:", r.id, workload);
    } else {
      console.warn("[workload 对账] 管理态缺失，开始恢复:", r.id, workload);
    }
    try {
      await recoverOrphanWorkload(r.id, meta, workload, thvNames.has(workload));
      healFailState.delete(r.id);
      console.log("[workload 对账] 恢复完成:", r.id, workload);
    } catch (e) {
      const fails = ((healFailState.get(r.id) || {}).fails || 0) + 1;
      healFailState.set(r.id, { fails, nextTryAt: Date.now() + (fails >= 3 ? HEAL_BACKOFF_MS : 0) });
      console.error("[workload 对账] 恢复失败:", r.id, e.message);
    }
  }
}

// 主容器是否在运行（对账用的轻量探针）
async function dockerContainerRunning(name) {
  const { stdout } = await execFileHidden(
    "docker", ["inspect", "--format", "{{.State.Running}}", name],
    { timeout: 12000, maxBuffer: MAX_BUFFER },
  );
  return String(stdout || "").trim() === "true";
}

async function recoverOrphanWorkload(id, meta, workload, thvHasEntry) {
  // ② 反向重建：孤儿主容器还在 → 捕获它真实运行的镜像，且本地镜像必须仍存在
  let img = null;
  try {
    const r1 = await execFileHidden(
      "docker", ["inspect", "--format", "{{.Config.Image}}", workload],
      { timeout: 12000, maxBuffer: MAX_BUFFER },
    );
    const candidate = String(r1.stdout || "").trim();
    if (candidate) {
      await execFileHidden("docker", ["image", "inspect", candidate], { timeout: 12000, maxBuffer: MAX_BUFFER });
      img = candidate;
    }
  } catch (_) { /* 主容器或镜像不存在 → 走全量重部署 */ }
  if (img) {
    // 真实镜像记回 meta：源码型填 built_image（deployMcp 跳过重新构建）；其他型走 recovery_image
    if (meta.source_type === "source") patchMeta(id, { built_image: img });
    else patchMeta(id, { recovery_image: img });
    // 清掉孤儿容器组（main/ingress/egress/dns），thv run 会原样重建；先删避免重名冲突
    for (const suffix of ["", "-ingress", "-egress", "-dns"]) {
      await execFileHidden("docker", ["rm", "-f", workload + suffix], { timeout: 30000, maxBuffer: MAX_BUFFER }).catch(() => {});
    }
  }
  // thv 侧残留登记（unhealthy/error 旧条目）一并清掉，让 deployMcp 全新登记
  if (thvHasEntry) {
    await execFileHidden(THV_BIN, ["rm", "-f", workload], { timeout: 60000, maxBuffer: MAX_BUFFER }).catch(() => {});
  }
  audit(
    { headers: { "x-actor-email": "system@reconcile" } },
    "workload_recovered", "mcp", id,
    { workload, mode: img ? "orphan-reimage" : "full-redeploy", image: img || "(重新构建/加载)" },
  );
  await deployMcp(id);
}


  return { HEAL_BACKOFF_MS, healFailState, thvWorkloadNames, reconcileMcpWorkloads, recoverOrphanWorkload, dockerContainerRunning };
};
