// lib/mcp-proxy.js —— MCP 代理处理器（2026-09-19 自 server.js 拆出，渐进式拆分第六步）
// 覆盖：代理目标解析（resolveMcpProxyTarget：submission id / workload 名 / item_ref 三态）/
//   代理处理器主体（mcpProxyHandler：token 门禁 → 解析目标 → 凭证代理 → 管道转发，
//   转发失败触发后台 ingress 自愈）。
// 路由注册留在 server.js（app/proxyApp 归宿主文件）：回环 4000 注册在 express.json() 之前
//   （请求体未被消费，管道转发才拿得到完整 body）；对外 4100 proxyApp 以 forceToken=true 注册。
// 依赖全部经 ctx 注入：数据层（db / parseMeta / workloadNameFor）、门禁与审计
//   （authHeaderCandidates / deniedThrottled / audit）、ingress 链路（getIngressPort /
//   ensureStableIngress / discoverThvEndpoint / subIdByWorkload / healMcpIngress，
//   来自 lib/ingress-heal 与 lib/ingress）。
const http = require("node:http");

module.exports = function createMcpProxy(ctx) {
  const {
    db, parseMeta, workloadNameFor, authHeaderCandidates, deniedThrottled, audit,
    getIngressPort, ensureStableIngress, discoverThvEndpoint, subIdByWorkload, healMcpIngress,
  } = ctx;

  // 用户复制到的 URL 因此永久有效，不随容器重建变化。
  async function resolveMcpProxyTarget(name) {
    let workload = null;
    let meta = {};
    // 1) name 是 submission id —— 换算 workload 名；name 直接是 workload 名也算
    const sub = db
      .prepare("SELECT * FROM submissions WHERE id=? AND type='mcp'")
      .get(name);
    if (sub) {
      meta = parseMeta(sub);
      workload = meta.workload_name || workloadNameFor(sub.id);
    } else if (name && /^mcp-/.test(name)) {
      workload = name;
    }
    if (workload) {
      // 现有 ingress 端口（自愈任务会把它维持在固定端口上）
      const direct = await getIngressPort(workload);
      if (direct) return { host: "127.0.0.1", port: Number(direct), path: "/mcp", workload };
      // 无 ingress → 幂等重建固定端口 socat ingress
      const p = await ensureStableIngress(workload, meta);
      if (p) return { host: "127.0.0.1", port: p, path: "/mcp", workload };
    }
    // 2) name 是 item_ref（LIVE_MCPS 等）—— 经 thv list 按镜像别名动态发现
    const ep = await discoverThvEndpoint(name);
    if (ep) {
      try {
        const u = new URL(ep);
        return { host: u.hostname, port: Number(u.port) || 80, path: u.pathname };
      } catch (_) {
        /* 解析失败继续返回 null */
      }
    }
    return null;
  }

  // 代理处理器主体（4000 回环口与 4100 对外口共用）。
  // opts.forceToken=true（对外口）：无条件校验 token——对外口上 token 是唯一凭证，
  // mode=all 也不例外（回环口维持原语义：仅 restricted 校验）。
  /**
   * MCP 代理处理器：token 门禁 → 解析目标实例 → 管道转发。
   * 安全语义（两个监听口共用此函数，差异仅由 opts.forceToken 表达）：
   *  - 回环 4000：restricted 条目要求 Bearer/X-MCP-Token/?t= 三来源之一命中 meta.mcp_token；
   *  - 对外 4100：forceToken=true，所有条目（含 mode=all）一律强制校验，token 是唯一门禁；
   *  - token 校验先于实例解析——无 token 的 restricted/对外请求在碰 Docker 之前就被 403。
   * @param {import("express").Request} req
   * @param {import("express").Response} res
   * @param {{forceToken?: boolean}} opts
   */
  async function mcpProxyHandler(req, res, opts = {}) {
    if (req.method === "OPTIONS") return res.sendStatus(204);

    const name = req.params.name;
    const sid = subIdByWorkload(name) || (String(name).startsWith("sub_") ? name : null);
    let proxyMeta = null;
    if (sid) {
      const row = db.prepare("SELECT meta FROM submissions WHERE id=?").get(sid);
      if (row) {
        const meta = parseMeta(row);
        proxyMeta = meta;
        const v = meta.visibility;
        const needToken = opts.forceToken || (v && v.mode === "restricted");
        if (needToken) {
          // token 三来源（按优先级）：Authorization: Bearer / X-MCP-Token 头 / 旧 ?t=（兼容已复制配置）
          const auth = String(req.headers["authorization"] || "");
          const headerToken = auth.startsWith("Bearer ")
            ? auth.slice(7).trim()
            : String(req.headers["x-mcp-token"] || "").trim();
          let t = headerToken || null;
          if (!t) {
            try { t = new URL(req.url, "http://x").searchParams.get("t"); } catch (_) {} // URL 解析失败保持 t=null，由后续校验统一 403
          }
          if (!meta.mcp_token || t !== meta.mcp_token) {
            if (deniedThrottled("proxy:" + sid + ":" + (req.socket.remoteAddress || ""))) {
              audit(req, "proxy_denied", "mcp", sid, { workload: meta.workload_name || "", reason: opts.forceToken ? "external without valid token" : "restricted without valid token" }, "denied");
            }
            return res.status(403).json({ error: "forbidden: 该 MCP 仅限授权成员调用（缺少或错误的访问令牌）" });
          }
        }
      } else if (opts.forceToken) {
        // 对外口：查无条目（或非 submission 条目）无法验证凭证 → 一律拒绝
        return res.status(403).json({ error: "forbidden" });
      }
    } else if (opts.forceToken) {
      return res.status(403).json({ error: "forbidden" });
    }

    resolveMcpProxyTarget(req.params.name)
      .then((target) => {
        if (!target) {
          return res.status(502).json({
            error: "MCP 未运行或找不到 ingress 端口",
            name: req.params.name,
          });
        }
        const headers = { ...req.headers };
        delete headers.host;
        delete headers.connection;
        // 平台凭证代理：条目 env 里配了 API Key/Token 时，把调用方的平台凭证
        // （mcp_token）替换为应用自身的鉴权头再转发——调用方无需（也不应）知道应用凭证。
        const appAuth = authHeaderCandidates(proxyMeta || {})[0];
        if (appAuth) {
          delete headers.authorization;
          Object.assign(headers, appAuth);
        }

        const upstream = http.request(
          {
            host: target.host,
            port: target.port,
            path: req.url || target.path,
            method: req.method,
            headers,
          },
          (upRes) => {
            res.writeHead(upRes.statusCode || 502, upRes.headers);
            upRes.pipe(res);
          },
        );
        upstream.on("error", (e) => {
          if (!res.headersSent) {
            res.status(502).json({ error: "转发到 MCP 失败", detail: e.message });
          } else {
            res.end();
          }
          // 转发失败（端口漂移/ingress 坏死）→ 后台自愈：重建固定端口 ingress 并回写 meta。
          // 本次请求不重试（SSE/POST 非幂等），下一次请求即恢复。
          const sid = target && target.workload ? subIdByWorkload(target.workload) : null;
          if (sid) healMcpIngress(sid).catch(() => {});
        });
        req.pipe(upstream);
      })
      .catch((e) => {
        if (!res.headersSent) {
          res.status(500).json({ error: "代理异常", detail: e.message });
        }
      });
  }

  return { resolveMcpProxyTarget, mcpProxyHandler };
};
