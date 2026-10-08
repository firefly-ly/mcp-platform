// recoverOrphanWorkload 竞态防护单测（lib/reconcile.js）——
// 2026-10-08 实锤：下线与对账同秒撞车 → 自愈把刚下线的服务全链重部署复活。
// 修复 = 整段包部署锁 + 拿锁后二次确认 deploy_status（人工意图优先）。
"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const makeReconcile = require("../../lib/reconcile");

function makeCtx(opts = {}) {
  const calls = { lock: [], exec: [], audit: [], deployInner: [], patch: [] };
  const ctx = {
    db: {
      prepare(sql) {
        if (sql.includes("type='mcp'")) return { all: () => opts.dbRows || [] };
        return { get: () => (opts.dbGetRow ? opts.dbGetRow() : undefined) };
      },
    },
    parseMeta: (row) => JSON.parse(row.meta),
    patchMeta: (id, patch) => calls.patch.push([id, patch]),
    execFileHidden: async (bin, args) => {
      calls.exec.push([bin, ...args]);
      if (args[0] === "list") return { stdout: opts.thvListOut || "[]" }; // thv list --format json
      if (args[0] === "inspect" && args.includes("{{.Config.Image}}")) {
        if (opts.dockerImage == null) throw new Error("no such container");
        return { stdout: opts.dockerImage + "\n" };
      }
      if (args[0] === "image" && args[1] === "inspect") {
        if (opts.dockerImage == null) throw new Error("no such image");
        return { stdout: "" };
      }
      return { stdout: "" };
    },
    MAX_BUFFER: 1024 * 1024,
    THV_BIN: "thv",
    audit: (_req, action, targetType, id, detail) => calls.audit.push({ action, targetType, id, detail }),
    workloadNameFor: (id) => "mcp-" + id,
    withDeployLock: (id, fn) => {
      calls.lock.push(id);
      if (opts.lockError) throw opts.lockError;
      return fn();
    },
    deployMcpInner: async (id) => { calls.deployInner.push(id); },
  };
  return { ctx, calls };
}

test("recoverOrphanWorkload：整段被 withDeployLock 包裹（锁 id = 提交 id）", async () => {
  const { ctx, calls } = makeCtx({
    dbGetRow: () => ({ meta: JSON.stringify({ deploy_status: "deployed" }) }),
    dockerImage: null, // 容器已消失 → 全量重部署路径
  });
  const svc = makeReconcile(ctx);
  await svc.recoverOrphanWorkload("sub_1", { source_type: "image" }, "mcp-sub_1", false);
  assert.deepEqual(calls.lock, ["sub_1"]);
  assert.deepEqual(calls.deployInner, ["sub_1"]);
  assert.equal(calls.audit[0].action, "workload_recovered");
});

test("锁内二次确认：状态已变 undeployed → 放弃恢复（不重部署、不 rm、审计 skipped）", async () => {
  const { ctx, calls } = makeCtx({
    dbGetRow: () => ({ meta: JSON.stringify({ deploy_status: "undeployed" }) }),
  });
  const svc = makeReconcile(ctx);
  await svc.recoverOrphanWorkload("sub_1", {}, "mcp-sub_1", true);
  assert.deepEqual(calls.deployInner, [], "不得调部署");
  assert.equal(calls.exec.filter((c) => c.includes("rm")).length, 0, "不得删容器");
  const skip = calls.audit.find((a) => a.action === "workload_recover_skipped");
  assert.ok(skip, "必须记 workload_recover_skipped 审计");
  assert.match(skip.detail.reason, /undeployed/);
});

test("锁内二次确认：条目已删除 → 放弃恢复", async () => {
  const { ctx, calls } = makeCtx({ dbGetRow: () => undefined });
  const svc = makeReconcile(ctx);
  await svc.recoverOrphanWorkload("sub_1", {}, "mcp-sub_1", false);
  assert.deepEqual(calls.deployInner, []);
  const skip = calls.audit.find((a) => a.action === "workload_recover_skipped");
  assert.ok(skip);
  assert.match(skip.detail.reason, /已删除/);
});

test("状态仍 deployed → 正常恢复：孤儿镜像捕获 + 四连 rm + 裸版部署（recovery_image 记回）", async () => {
  const { ctx, calls } = makeCtx({
    dbGetRow: () => ({ meta: JSON.stringify({ deploy_status: "deployed" }) }),
    dockerImage: "retail:3.0.0",
  });
  const svc = makeReconcile(ctx);
  await svc.recoverOrphanWorkload("sub_1", { source_type: "tar" }, "mcp-sub_1", true);
  const dockerRm = calls.exec.filter((c) => c[0] === "docker" && c[1] === "rm");
  const thvRm = calls.exec.filter((c) => c[0] === "thv" && c[1] === "rm");
  assert.equal(dockerRm.length, 4, "主容器 + ingress/egress/dns 四连清理");
  assert.equal(thvRm.length, 1, "thv 残留登记清理");
  assert.deepEqual(calls.patch, [["sub_1", { recovery_image: "retail:3.0.0" }]]);
  assert.deepEqual(calls.deployInner, ["sub_1"]);
  assert.equal(calls.audit[0].detail.mode, "orphan-reimage");
});

test("DEPLOY_BUSY：让路不计入失败退避（否则用户操作密集时自愈被越推越远）", async () => {
  const busy = new Error("busy");
  busy.code = "DEPLOY_BUSY";
  const { ctx } = makeCtx({
    dbRows: [{ id: "sub_9", meta: JSON.stringify({ deploy_status: "deployed" }) }],
    lockError: busy,
  });
  const svc = makeReconcile(ctx);
  await svc.reconcileMcpWorkloads();
  assert.equal(svc.healFailState.get("sub_9"), undefined, "busy 不得写入退避表");
});

test("反面对照：普通恢复失败仍计入退避（防误伤回归）", async () => {
  const { ctx } = makeCtx({
    dbRows: [{ id: "sub_9", meta: JSON.stringify({ deploy_status: "deployed" }) }],
    lockError: new Error("docker 炸了"),
  });
  const svc = makeReconcile(ctx);
  await svc.reconcileMcpWorkloads();
  const st = svc.healFailState.get("sub_9");
  assert.ok(st && st.fails === 1, "普通失败必须计入 fails");
});
