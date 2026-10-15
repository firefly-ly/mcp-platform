// routes/mcp/member-tokens.js —— 成员级代理 Token 域（2026-10-15 自 routes/mcp.js 外迁）。
// 覆盖：列表 / 单签 / 批量 / 吊销 / 成员接入配置 / 自助签发 / 可见范围名单合并。
// 名单语义：与可见性模式解耦（mode=all 下名单 = 已自助签发/管理员添加的成员，切模式保留）。
// 名单读取/归一化/签发轮换统一走 lib/member-tokens.js 与 lib/visibility.js。
const { memberTokenAllowed } = require("../../lib/visibility");
const {
  normalizeEmail,
  normalizeEmails,
  readUsers,
  readRawVisibility,
  visibilityWithMember,
  issueOrRotateToken,
} = require("../../lib/member-tokens");

module.exports = function registerMemberTokenRoutes(app, ctx) {
  const {
    db, parseMeta, patchMeta, actorFromReq, audit, canAccessSubmission,
    publicEndpointFor, workloadNameFor,
  } = ctx;

  // ---- 成员级代理 Token 管理（双轨制，仅管理员，仅 MCP）----
  // 成员 token 与包级 token 并行有效：签发/轮换/吊销成员 token 只影响该成员的接入配置。
  // member 必须在条目可见范围 users（按邮箱授权名单）内——D2 决策：groups 授权不参与成员 token。

  // 列表：可见范围 users × 各自签发状态（token 一并返回，管理员可直接复制成员专属配置）。
  // 2026-10-14：任何模式都返回名单（mode=all 的名单 = 已自助签发/管理员添加的成员，
  // 名单在切模式时保留）。名单读取/归一化统一走 lib/member-tokens.js。
  app.get("/submissions/:id/member-tokens", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可查看成员 Token" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const meta = parseMeta(sub);
    const rv = readRawVisibility(meta);
    const rows = db
      .prepare("SELECT member, token, created_at, rotated_at FROM mcp_member_tokens WHERE submission_id=?")
      .all(sub.id);
    const byEmail = {};
    rows.forEach((r) => { byEmail[r.member] = r; });
    const members = readUsers(meta).map((u) => ({
      member: u,
      token: byEmail[u] ? byEmail[u].token : null,
      created_at: byEmail[u] ? byEmail[u].created_at : null,
      rotated_at: byEmail[u] ? byEmail[u].rotated_at : null,
    }));
    res.json({ ok: true, mode: rv.mode, members });
  });

  // 签发 / 轮换（body: {member}）。已签发 → 轮换（旧 token 立即作废）；未签发 → 签发。
  app.post("/submissions/:id/member-tokens", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可签发成员 Token" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const member = normalizeEmail((req.body && req.body.member) || "");
    if (!member) return res.status(400).json({ error: "缺少 member（成员邮箱）" });
    // 管理员签发：名单内直接走 memberTokenAllowed；名单外（mode=all 下给新成员代签）
    // 自动把成员并入 users 再签发（audit 记 visibility_adopt_member）。
    const meta = parseMeta(sub);
    if (!memberTokenAllowed(meta, member)) {
      if (!actor.admin) {
        return res.status(422).json({
          error: "该成员不在条目可见范围（按邮箱授权名单）内，请先在「可见范围」中添加",
        });
      }
      const { visibility, changed } = visibilityWithMember(meta, member);
      patchMeta(sub.id, { visibility, visibility_configured: true });
      if (changed) audit(req, "visibility_adopt_member", "mcp", sub.id, { member });
    }
    const { token, action } = issueOrRotateToken(db, sub.id, member, new Date().toISOString());
    audit(req, action === "rotated" ? "token_rotate" : "token_issue", "mcp", sub.id, { scope: "member", member });
    res.json({ ok: true, id: sub.id, member, token });
  });

  // 批量签发 / 轮换（P1，2026-10-14，body: {members:[邮箱,...]}）：
  // 逐个走与单签完全相同的校验（memberTokenAllowed）与入库逻辑，名单外成员跳过不中断整批。
  // 用途：mode=all / groups 条目收编 restricted+users 后一次性为全员签发（收编动作见下方 merge-users）。
  app.post("/submissions/:id/member-tokens/batch", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可批量签发成员 Token" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const raw = Array.isArray(req.body && req.body.members) ? req.body.members : [];
    // 归一化（与 visibility 名单同规则：小写去空白）+ 去重；上限 500 防误传全通讯录拖垮请求
    const members = normalizeEmails(raw);
    if (!members.length) return res.status(400).json({ error: "缺少 members（成员邮箱数组）" });
    if (members.length > 500) return res.status(400).json({ error: "单批最多 500 个成员" });
    const meta = parseMeta(sub);
    const now = new Date().toISOString();
    const results = members.map((member) => {
      if (!memberTokenAllowed(meta, member)) {
        return { member, ok: false, reason: "not_in_visibility" };
      }
      const { token, action } = issueOrRotateToken(db, sub.id, member, now);
      audit(req, action === "rotated" ? "token_rotate" : "token_issue", "mcp", sub.id, { scope: "member", member });
      return { member, ok: true, action, token };
    });
    const okCount = results.filter((r) => r.ok).length;
    audit(req, "token_batch", "mcp", sub.id, {
      scope: "member-batch", total: members.length, issued_rotated: okCount,
      skipped: members.length - okCount,
    });
    res.json({ ok: true, id: sub.id, total: members.length, issued: okCount, results });
  });

  // 可见范围名单合并（P1，IdP 无关）：把外部来源整理好的成员邮箱合并进 visibility.users。
  // 用途：① mode=all 条目首次合并即自动转为 restricted（首次即完成「收编」）；
  //       ② restricted+groups 条目把组展开后的邮箱并入 users（组员从此可签发成员 token）。
  // 注意：不做 IdP 自动拉取——组成员数据在 Casdoor 且其即将退役，自动同步随 P2/Authentik
  // 一并落地；本接口只接收已整理好的名单（企微通讯录导出 / 管理员手工整理均可）。
  // drop_groups=true 时同时清空 groups（组授权改名单制的收尾动作，防止组员继续共用包级 token 的歧义）。
  app.post("/submissions/:id/visibility/merge-users", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可合并可见范围名单" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    const raw = Array.isArray(req.body && req.body.users) ? req.body.users : [];
    const incoming = normalizeEmails(raw);
    if (!incoming.length) return res.status(400).json({ error: "缺少 users（成员邮箱数组）" });
    if (incoming.length > 5000) return res.status(400).json({ error: "单次最多合并 5000 个邮箱" });
    const meta = parseMeta(sub);
    // 基线名单读原始 visibility（readRawVisibility）——parseVisibility 在 mode=all 时
    // 返回空名单，用它做基线会把保留的名单清掉（2026-10-14 自检整改时修复的潜伏 bug）。
    const rv = readRawVisibility(meta);
    const merged = [...new Set([...rv.users, ...incoming])].sort();
    const added = merged.filter((u) => !rv.users.includes(u)).length;
    const dropGroups = Boolean(req.body && req.body.drop_groups);
    const nextGroups = dropGroups ? [] : rv.groups;
    patchMeta(sub.id, {
      visibility: { mode: "restricted", users: merged, groups: nextGroups },
      visibility_configured: true, // 管理员显式配置过可见范围 → 上架（isOnShelf 语义）
    });
    audit(req, "visibility_merge_users", sub.type, sub.id, {
      before: { mode: rv.mode, users: rv.users.length, groups: rv.groups },
      added, total: merged.length, drop_groups: dropGroups,
    });
    res.json({
      ok: true, id: sub.id, mode: "restricted",
      added, total: merged.length, groups: nextGroups,
    });
  });

  // 自助签发（2026-10-14，D2 修订：groups 在「签发时」参与资格判定，调用层仍凭个人 token）。
  // 登录用户为自己签发/轮换成员 token，资格走 canAccessSubmission 单一入口：
  //   mode=all → 任何登录用户；restricted+users → 名单内；restricted+groups → 组命中；
  //   未上架（visibility_configured=false）仅管理员可见，普通用户天然 403。
  // 签发即把成员并入 visibility.users（名单自增长，audit 留痕）——proxy 双轨校验零改动，
  // memberTokenAllowed（member ∈ users）天然放行；组资格只在签发时验证一次，
  // 调岗后 token 仍有效的问题由 P2（IDM 同步 / token 有效期）兜底。
  app.post("/submissions/:id/my-member-token", (req, res) => {
    const actor = actorFromReq(req);
    const member = String(actor.email || "").toLowerCase().trim();
    if (!member) return res.status(401).json({ error: "未识别到登录身份" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const meta = parseMeta(sub);
    if (!actor.admin && !canAccessSubmission(meta, actor)) {
      audit(req, "token_selfissue_denied", "mcp", sub.id, { member }, "denied");
      return res.status(403).json({ error: "你不在该条目的可见范围内，无法自助签发" });
    }
    const now = new Date().toISOString();
    const { token, action } = issueOrRotateToken(db, sub.id, member, now);
    audit(req, action === "rotated" ? "token_rotate" : "token_issue", "mcp", sub.id, { scope: "member", member, self_service: true });
    // 名单自增长：把签发者并入 users（幂等；mode=all 下名单保留，切回受限即生效）。
    // 合并基准统一走 lib/member-tokens.js（读原始 meta.visibility，勿用 parseVisibility）。
    const { visibility, changed } = visibilityWithMember(meta, member);
    let adopted = false;
    if (changed) {
      patchMeta(sub.id, { visibility, visibility_configured: true });
      audit(req, "visibility_adopt_member", "mcp", sub.id, { member });
      adopted = true;
    }
    // 顺带返回接入配置（等价 member-token-config，省一次往返）
    const fresh = parseMeta(db.prepare("SELECT * FROM submissions WHERE id=?").get(sub.id));
    const endpoint = fresh.endpoint || null;
    res.json({
      ok: true, id: sub.id, member, token, adopted,
      url: endpoint ? publicEndpointFor(fresh.workload_name || workloadNameFor(sub.id), endpoint, req) : null,
      headers: { Authorization: `Bearer ${token}` },
    });
  });

  // 吊销（成员 token 立即作废；该成员接入配置 401，需管理员重新签发）
  app.delete("/submissions/:id/member-tokens/:member", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可吊销成员 Token" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const member = String(req.params.member || "").toLowerCase().trim();
    const info = db
      .prepare("DELETE FROM mcp_member_tokens WHERE submission_id=? AND member=?")
      .run(sub.id, member);
    if (info.changes > 0) {
      audit(req, "token_revoke", "mcp", sub.id, { scope: "member", member });
    }
    res.json({ ok: true, id: sub.id, member, revoked: info.changes > 0 });
  });

  // 成员专属接入配置（仅管理员）：publicEndpointFor + 该成员 token 的 Authorization 头，
  // 供「Token 管理」弹窗一键复制，免去前端自行拼对外地址。
  app.get("/submissions/:id/member-token-config", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可获取成员接入配置" });
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const member = String(req.query.member || "").toLowerCase().trim();
    const row = db
      .prepare("SELECT token FROM mcp_member_tokens WHERE submission_id=? AND member=?")
      .get(sub.id, member);
    if (!row) return res.status(404).json({ error: "该成员尚未签发 Token" });
    const meta = parseMeta(sub);
    const endpoint = meta.endpoint || null;
    if (!endpoint) return res.json({ ok: true, url: null, headers: null });
    return res.json({
      ok: true,
      url: publicEndpointFor(meta.workload_name || workloadNameFor(sub.id), endpoint, req),
      headers: { Authorization: `Bearer ${row.token}` },
    });
  });
};
