// routes/mcp.js —— MCP 路由域（2026-09-11 渐进式拆分第三步，自 server.js 原样迁出）
// 覆盖：列表 / 单条 / 文件预览 / tools(SWR) / call / rotate-token，
//   以及 rtCache（实例运行时缓存）与 toolsCache（tools 清单缓存）两层 SWR。
// 注意：/mcp-proxy 的回环注册（4000，express.json 之前）与对外监听（4100）仍留在 server.js——
//   前者对中间件链顺序敏感（必须在 express.json 之前），后者是安全边界，二者不宜随本模块迁移。
// 依赖经 ctx 注入（全部为 server.js 中的声明式函数或先于此装配的常量）：
const crypto = require("node:crypto");
const http = require("node:http");
const express = require("express");

module.exports = function registerMcpRoutes(app, ctx) {
  const {
    db, parseMeta, patchMeta, actorFromReq, audit, deniedThrottled,
    canAccessSubmission, pickDisplayVersions, isOnShelf, LIVE_MCPS,
    discoverIngressForSubmission, probeMcpEndpoint, discoverThvEndpoint,
    resolveMcpProxyTarget, subIdByWorkload, healMcpIngress,
    mapMcpRow, publicEndpointFor, mcpAuthHeadersFor, getOrCreateMcpToken,
    authHeaderCandidates, mcpCallAuthed, rewriteForWsl2, resolveEndpoint,
    workloadNameFor, servePackageFile, execFileHidden, MAX_BUFFER,
  } = ctx;

  // ---- 实例运行时缓存（SWR）：ingress 端点发现（docker 查询）+ 真实探活 ----
  // /mcp 列表与 /mcp/:id 每次都对每个实例做 docker 查询 + HTTP 探活（各 ~450ms），
  // 目录页 N 轮版本聚合叠加后严重拖慢导航。策略与 toolsCache 一致：
  //   fresh 60s 直接回缓存；stale 回旧值 + 后台单飞刷新；失败负缓存 30s；
  //   deploy/undeploy 主动失效（经本模块返回的 invalidate）。
  const RT_FRESH_MS = 60_000;
  const RT_FAIL_MS = 30_000;
  const rtCache = new Map(); // id -> { endpoint, healthy, ts, failed }
  const rtInflight = new Map(); // id -> Promise（单飞锁）

  // 单飞执行：同 id 并发共享同一次 docker 查询 + 探活，完成后写缓存
  function rtFetchSingleFlight(id, s, opts = {}) {
    let p = rtInflight.get(id);
    if (p) return p;
    p = (async () => {
      try {
        const ep = await discoverIngressForSubmission(s, opts);
        if (!ep) return { endpoint: null, healthy: false, failed: true };
        const healthy = await probeMcpEndpoint(ep);
        return { endpoint: ep, healthy, failed: !healthy };
      } catch (e) {
        return { endpoint: null, healthy: false, failed: true, error: String((e && e.message) || e) };
      }
    })()
      .then((r) => {
        rtCache.set(id, { ...r, ts: Date.now() });
        return r;
      })
      .finally(() => rtInflight.delete(id));
    rtInflight.set(id, p);
    return p;
  }

  // ---- tools 清单缓存（SWR）：详情页每点一次都实时握手太慢（秒级）----
  //   fresh（60s 内）→ 直接回缓存；stale（60s 后）→ 立即回旧值 + 后台单飞刷新；
  //   miss → 现场拉取（并发共享单飞）。失败结果做 30s 负缓存，防对挂掉实例的重试风暴。
  const TOOLS_FRESH_MS = 60_000;
  const TOOLS_FAIL_MS = 30_000;
  const toolsCache = new Map(); // id -> { result, ts, failed }
  const toolsInflight = new Map(); // id -> Promise（单飞锁：同 id 并发共享一次握手）

  // 现场拉取（原 handler 主体抽出）：无实例/失败均优雅降级，8s 超时防挂住
  async function fetchToolsLive(id) {
    let s = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
    let ep = null;
    if (s) {
      ep = await discoverIngressForSubmission(s);
    } else {
      for (const m of LIVE_MCPS) {
        const e = await discoverThvEndpoint(m.item_ref);
        if (e && m.id === id) { ep = e; break; }
      }
    }
    if (!ep) return { tools: [], live: false };
    const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("tools/list 超时")), 8000));
    try {
      const r = await Promise.race([mcpCallAuthed(ep, {}, s ? parseMeta(s) : {}), timeout]);
      const last = (r.events && r.events[r.events.length - 1]) || {};
      const tools = last.result && Array.isArray(last.result.tools) ? last.result.tools : [];
      return {
        live: true,
        tools: tools.map((t) => ({
          name: t.name,
          description: t.description || "",
          // 前端按 schema 生成参数模板（字段名/类型/必填），剥离后模板会退化成 {}
          ...(t.inputSchema ? { inputSchema: t.inputSchema } : {}),
        })),
      };
    } catch (e) {
      return { tools: [], live: false, failed: true, error: String((e && e.message) || e) };
    }
  }

  // 单飞执行：同 id 并发共享同一个进行中的刷新，完成后写缓存
  function toolsFetchSingleFlight(id) {
    let p = toolsInflight.get(id);
    if (p) return p;
    p = fetchToolsLive(id)
      .then((r) => {
        toolsCache.set(id, { result: r, ts: Date.now(), failed: !r.live });
        return r;
      })
      .catch((e) => {
        const r = { tools: [], live: false, failed: true, error: String((e && e.message) || e) };
        toolsCache.set(id, { result: r, ts: Date.now(), failed: true });
        return r;
      })
      .finally(() => toolsInflight.delete(id));
    toolsInflight.set(id, p);
    return p;
  }

  // 已审批 mcp 列表（供 /catalog 浏览页）。多版本场景下每 group 只展示最新已上架的版本。
  app.get("/mcp", async (req, res) => {
    const actor = actorFromReq(req);
    const rows = db.prepare(
      "SELECT * FROM submissions WHERE type='mcp' AND status='approved' ORDER BY created_at DESC"
    ).all();
    // 可见性过滤：restricted 条目仅对被授权的成员/组与管理员可见
    const displayRows = pickDisplayVersions(rows)
      .filter((s) => canAccessSubmission(parseMeta(s), actor));
    const calls = db.prepare(
      "SELECT item_ref, COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' GROUP BY item_ref"
    ).all();
    const callMap = {};
    calls.forEach((c) => { callMap[c.item_ref] = c.c; });
    const favs = db.prepare(
      "SELECT item_ref, COUNT(*) c FROM favorites WHERE item_type='mcp' GROUP BY item_ref"
    ).all();
    const favMap = {};
    favs.forEach((f) => { favMap[f.item_ref] = f.c; });
    for (const m of LIVE_MCPS) {
      const ep = await discoverThvEndpoint(m.item_ref);
      if (ep) m.endpoint = ep;
    }
    // 已部署的 MCP 重新发现一次真实 ingress 端口（meta 里存的是部署瞬间的内部端口，
    // 容器重建后会漂移）。每个项一次 docker port 调用，故并发执行并限制条数，
    // 避免条目多时把列表接口拖慢。
    const deployed = displayRows
      .filter((s) => parseMeta(s).deploy_status === "deployed")
      .slice(0, 30);
    // 实例运行时缓存（SWR）：docker 查询 + 探活不再每次全量重做（原先每项 ~450ms）
    const epMap = new Map();
    const rtMissing = [];
    for (const s of deployed) {
      const c = rtCache.get(s.id);
      if (!c) { rtMissing.push(s); continue; }
      const age = Date.now() - c.ts;
      const ttl = c.failed ? RT_FAIL_MS : RT_FRESH_MS;
      // 过期不阻塞：立即用旧值，后台单飞刷新（失败负缓存过期后暂不采用，等刷新结果）
      if (age > ttl && !rtInflight.has(s.id)) rtFetchSingleFlight(s.id, s, { rebuild: false });
      if (!(c.failed && age > RT_FAIL_MS) && c.endpoint) {
        epMap.set(s.id, { endpoint: c.endpoint, healthy: c.healthy });
      }
    }
    await Promise.all(
      rtMissing.map(async (s) => {
        const r = await rtFetchSingleFlight(s.id, s, { rebuild: false });
        if (!r.failed && r.endpoint) {
          epMap.set(s.id, { endpoint: r.endpoint, healthy: r.healthy });
        }
      }),
    );
    const mcpRows = displayRows.map((s) => {
      const row = mapMcpRow(s, callMap, favMap);
      const found = epMap.get(s.id);
      if (found) row.endpoint = found.endpoint;
      // 供列表卡片「复制配置」使用：走后端代理的固定地址（非 127.0.0.1 直连端口）
      if (row.endpoint) {
        row.healthy = found ? found.healthy : false;
        // 不可达就不给对外地址，否则用户复制过去是 502
        if (row.healthy) {
          row.public_endpoint = publicEndpointFor(
            parseMeta(s).workload_name || workloadNameFor(s.id),
            row.endpoint,
            req,
          );
          row.mcp_headers = mcpAuthHeadersFor(
            parseMeta(s).workload_name || workloadNameFor(s.id),
          );
        }
      }
      return row;
    });

    const liveRows = await Promise.all(
      LIVE_MCPS.map(async (m) => {
        const healthy = m.endpoint ? await probeMcpEndpoint(m.endpoint) : undefined;
        return {
          ...m,
          healthy,
          public_endpoint: healthy
            ? publicEndpointFor(m.item_ref, m.endpoint, req)
            : undefined,
          mcp_headers: healthy ? mcpAuthHeadersFor(m.item_ref) : undefined,
          call_count: callMap[m.id] || 0,
          favorite_count: favMap[m.id] || 0,
          created_at: m.created_at || new Date().toISOString(),
        };
      }),
    );
    res.json([...mcpRows, ...liveRows]);
  });

  // ---- 镜像元数据提取（docker inspect，供详情页「代码」标签展示）----
  // 安全红线：Env 一律不提取不展示（镜像常在 ENV 里内置密钥）；entrypoint/cmd 参数与
  // labels 按敏感模式（password/secret/token/api key/credential/auth 等）脱敏后才返回。
  const INSPECT_SENSITIVE_RE = /(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth(orization)?|cookie|session|cert|key)/i;
  function maskInspectToken(tok) {
    const s = String(tok);
    if (!INSPECT_SENSITIVE_RE.test(s)) return s;
    const eq = s.indexOf("=");
    // key=value 形态保留键名、掩去值；其余整段掩掉
    if (eq > 0 && !/\s/.test(s.slice(0, eq))) return s.slice(0, eq + 1) + "******";
    return "******";
  }
  function maskInspectLabels(map) {
    const out = {};
    for (const [k, v] of Object.entries(map || {})) {
      out[k] = INSPECT_SENSITIVE_RE.test(k) ? "******" : String(v);
    }
    return out;
  }
  async function extractMcpInspect(imageRef) {
    try {
      const { stdout } = await execFileHidden(
        "docker", ["inspect", "--format", "{{json .Config}}", imageRef],
        { timeout: 15000, maxBuffer: MAX_BUFFER },
      );
      const cfg = JSON.parse(String(stdout).trim() || "{}");
      const insp = {};
      if (cfg.Labels && Object.keys(cfg.Labels).length) insp.labels = maskInspectLabels(cfg.Labels);
      if (cfg.ExposedPorts) insp.exposed_ports = Object.keys(cfg.ExposedPorts);
      if (Array.isArray(cfg.Entrypoint) && cfg.Entrypoint.length) insp.entrypoint = cfg.Entrypoint.map(maskInspectToken);
      if (Array.isArray(cfg.Cmd) && cfg.Cmd.length) insp.cmd = cfg.Cmd.map(maskInspectToken);
      if (cfg.WorkingDir) insp.working_dir = cfg.WorkingDir;
      // 注意：绝不携带 cfg.Env
      return Object.keys(insp).length ? insp : null;
    } catch (_) {
      return null;
    }
  }
  // 懒回填：功能上线前已部署成功的记录没有镜像元数据，详情页首次访问时补提取一次
  async function ensureMcpInspect(s) {
    const meta = parseMeta(s);
    if (meta.deploy_status !== "deployed" || meta.mcp_inspect) return {};
    const image = meta.deployed_image || meta.recovery_image || meta.internal_ref || meta.image_ref;
    if (!image) return {};
    const insp = await extractMcpInspect(image);
    if (insp) {
      patchMeta(s.id, { mcp_inspect: insp });
      return { mcp_inspect: insp };
    }
    return {};
  }

  // MCP 源码包 README + 文件树懒回填：功能上线前审批的源码提交没有提取过，
  // 详情页首次访问时补提取一次并落 meta。mcp_readme_inspected 存提取规则版本号，
  // 规则升级后旧记录会自动用新规则重提一次。
  // v3：新增文件树提取（mcp_tree），供「代码」标签页展示 zip 包内文件。
  const MCP_README_INSPECT_VERSION = 3;

  async function ensureMcpReadme(s) {
    const meta = parseMeta(s);
    if (meta.source_type !== "source" || !meta.artifact_key) return {};
    if (meta.mcp_readme_inspected === MCP_README_INSPECT_VERSION) {
      return {
        mcp_readme: meta.mcp_readme || null,
        mcp_readme_name: meta.mcp_readme_name || null,
        mcp_tree: meta.mcp_tree || null,
      };
    }
    const insp = await inspectSkillPackage(meta.artifact_key).catch(() => null);
    const patch = {
      mcp_readme_inspected: MCP_README_INSPECT_VERSION,
      mcp_readme: (insp && insp.readme) || null,
      mcp_readme_name: (insp && insp.readme_name) || null,
      mcp_tree: insp && insp.tree ? insp.tree.slice(0, MCP_TREE_MAX) : null,
      mcp_file_count: insp ? insp.file_count : null,
    };
    patchMeta(s.id, patch);
    return {
      mcp_readme: patch.mcp_readme,
      mcp_readme_name: patch.mcp_readme_name,
      mcp_tree: patch.mcp_tree,
      mcp_file_count: patch.mcp_file_count,
    };
  }

  // 单个 mcp 详情（供 /mcp/[ref] 详情页）
  app.get("/mcp/:id", async (req, res) => {
    const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (s && !canAccessSubmission(parseMeta(s), actorFromReq(req))) {
      return res.status(403).json({ error: "你没有权限查看该 MCP（未获管理员授权）" });
    }
    if (!s) {
      for (const m of LIVE_MCPS) {
        const ep = await discoverThvEndpoint(m.item_ref);
        if (ep) m.endpoint = ep;
      }
      const live = LIVE_MCPS.find((m) => m.id === req.params.id);
      if (live) {
        const calls = db.prepare(
          "SELECT COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' AND item_ref=?"
        ).get(live.id);
        const favs = db.prepare(
          "SELECT COUNT(*) c FROM favorites WHERE item_type='mcp' AND item_ref=?"
        ).get(live.id);
        const healthy = live.endpoint
          ? await probeMcpEndpoint(live.endpoint)
          : undefined;
        return res.json({
          ...live,
          healthy,
          public_endpoint: healthy
            ? publicEndpointFor(live.item_ref, live.endpoint, req)
            : undefined,
          mcp_headers: healthy ? mcpAuthHeadersFor(live.item_ref) : undefined,
          call_count: calls ? calls.c : 0,
          favorite_count: favs ? favs.c : 0,
          created_at: live.created_at || new Date().toISOString(),
        });
      }
      return res.status(404).json({ error: "mcp 不存在" });
    }
    const calls = db.prepare(
      "SELECT COUNT(*) c FROM metric_events WHERE item_type='mcp' AND event='call' AND item_ref=?"
    ).get(s.id);
    const favs = db.prepare(
      "SELECT COUNT(*) c FROM favorites WHERE item_type='mcp' AND item_ref=?"
    ).get(s.id);
    const row = mapMcpRow(s, { [s.id]: calls.c }, { [s.id]: favs.c });
    // 源码包 README（懒回填：历史提交首次访问时补提取一次，之后读 meta）
    Object.assign(row, await ensureMcpReadme(s));
    // 镜像元数据（懒回填：已部署但未提取过的记录首次访问时补一次）
    Object.assign(row, await ensureMcpInspect(s));
    // 部署时 thv list 报告的内部端口可能不可达；详情页返回前重新动态发现 ingress 端口。
    // 实例运行时缓存（SWR）：命中直接用；miss 时 rebuild 默认开启（保留"访问触发自愈"语义）
    let rt = rtCache.get(s.id);
    if (!rt) {
      rt = await rtFetchSingleFlight(s.id, s);
    } else {
      const age = Date.now() - rt.ts;
      const ttl = rt.failed ? RT_FAIL_MS : RT_FRESH_MS;
      if (age > ttl && !rtInflight.has(s.id)) rtFetchSingleFlight(s.id, s);
    }
    if (rt.endpoint) row.endpoint = rt.endpoint;
    // 只有真的跑起来了才给对外地址，否则用户复制过去是个连不通的空壳
    if (row.endpoint) {
      row.healthy = rt.healthy;
      if (row.healthy) {
        row.public_endpoint = publicEndpointFor(
          parseMeta(s).workload_name || workloadNameFor(s.id),
          row.endpoint,
          req,
        );
        row.mcp_headers = mcpAuthHeadersFor(
          parseMeta(s).workload_name || workloadNameFor(s.id),
        );
      }
    }
    res.json(row);
  });

  // 源码包单文件内容预览（servePackageFile 共享实现留在 server.js，经 ctx 注入）
  app.get("/mcp/:id/file", async (req, res) => {
    const s = db.prepare("SELECT * FROM submissions WHERE id=?").get(req.params.id);
    if (!s) return res.status(404).json({ error: "mcp 不存在" });
    if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
      return res.status(403).json({ error: "你没有权限查看该 MCP（未获管理员授权）" });
    }
    await servePackageFile(req, res, s);
  });

  // 真实 MCP 工具清单：按 id 找到运行中实例，调用 tools/list 返回真实能力。
  app.get("/mcp/:id/tools", async (req, res) => {
    const id = req.params.id;
    const cached = toolsCache.get(id);
    if (cached) {
      const age = Date.now() - cached.ts;
      const ttl = cached.failed ? TOOLS_FAIL_MS : TOOLS_FRESH_MS;
      // 过期不阻塞：立即回旧值，后台单飞刷新（已有刷新在跑则不重复发起）
      if (age > ttl && !toolsInflight.has(id)) toolsFetchSingleFlight(id);
      return res.json(
        req.query.debug === "1"
          ? { ...cached.result, debug: { cached: true, ageMs: age } }
          : cached.result,
      );
    }
    const r = await toolsFetchSingleFlight(id);
    return res.json(
      req.query.debug === "1" ? { ...r, debug: { cached: false } } : r,
    );
  });

  // 真实 MCP 调用：初始化连接 -> 列出工具 / 调用工具，返回真实结果。
  // body: { ref?, endpoint?, tool?, args?, actor_id? }
  //   - ref 命中 LIVE_ENDPOINTS 或服务名即 URL 时自动解析端点；
  //   - 也可直接传 endpoint 显式指定；
  //   - 不传 tool 返回 tools/list，传 tool 返回 tools/call 结果。
  app.post("/mcp/call", async (req, res) => {
    const { ref, endpoint, tool, args, actor_id } = req.body || {};
    let ep = null;
    // 1) 对平台已提交的 MCP，优先按 workload 动态发现当前 ingress 端口。
    //    不能信任前端传来的 endpoint，因为 thv list 在部署时报告的是内部端口，浏览器访问不到。
    let s = null;
    if (ref) {
      s = db.prepare("SELECT * FROM submissions WHERE id=? OR payload_ref=?").get(ref, ref);
      if (!s) {
        // ref 是 group_key：回落该组最新已上架版本（激活指针已废弃）
        s = db.prepare(
          "SELECT * FROM submissions WHERE status='approved' AND (meta LIKE ? OR payload_ref=?) ORDER BY created_at DESC"
        ).all(`%"group_key":"${ref}"%`, ref)
         .find((row) => isOnShelf(parseMeta(row)));
      }
    }
    if (s) {
      // 可见性校验：restricted 条目仅对被授权的成员/组与管理员开放调用
      if (!canAccessSubmission(parseMeta(s), actorFromReq(req))) {
        return res.status(403).json({ error: "你没有权限调用该 MCP（未获管理员授权）" });
      }
      ep = rewriteForWsl2(await discoverIngressForSubmission(s));
    }
    // 2) 未命中 submission（如 LIVE_MCPS / Registry Server 条目）按 ref/endpoint 解析
    if (!ep && ref) {
      ep = rewriteForWsl2(await resolveEndpoint(ref, endpoint));
    }
    // 3) 兜底：直接用显式 endpoint
    if (!ep && endpoint) {
      ep = rewriteForWsl2(endpoint);
    }
    if (!ep) return res.status(404).json({ error: "未找到该 MCP 的可调用端点（可能未在平台运行）" });
    if (!(await probeMcpEndpoint(ep))) {
      return res.status(502).json({
        error: "MCP 端点不可达",
        detail: `无法连接到 ${ep}，请确认 ToolHive MCP server 正在运行且端口可访问`,
      });
    }
    try {
      // 平台代调同样自动携带应用自身的 API Key（用户无需也不应知道应用凭证）
      const result = await mcpCallAuthed(ep, { tool, args }, s ? parseMeta(s) : {});
      // 仅在真正执行了某个工具时才记一次调用指标，保持统计语义
      if (tool) {
        db.prepare("INSERT INTO metric_events VALUES(?,?,?,?,?,?)")
          .run("ev_" + Date.now() + "_" + Math.floor(Math.random() * 1000),
            "mcp", ref || ep, "call", actor_id || "", new Date().toISOString());
      }
      res.json({ ok: true, endpoint: ep, ...result });
    } catch (e) {
      res.status(502).json({ error: "调用 MCP 失败", detail: e.message });
    }
  });

  // 轮换代理访问令牌（仅管理员，仅 MCP）：生成新 mcp_token 覆盖旧值。
  // 旧 Token 立即作废——所有已复制到客户端的接入配置会 401，需重新复制配置；
  // 其他 MCP 不受影响（token 本就是 per-MCP 一把）。写审计轨迹备查。
  app.post("/submissions/:id/rotate-token", (req, res) => {
    const actor = actorFromReq(req);
    if (!actor.admin) return res.status(403).json({ error: "仅管理员可轮换 Token" });
    const { id } = req.params;
    const sub = db.prepare("SELECT * FROM submissions WHERE id=?").get(id);
    if (!sub) return res.status(404).json({ error: "submission 不存在" });
    if (sub.type !== "mcp") return res.status(400).json({ error: "只有 MCP 有代理 Token" });
    const token = crypto.randomBytes(16).toString("hex");
    patchMeta(id, { mcp_token: token });
    audit(req, "token_rotate", "mcp", id, {});
    res.json({ ok: true, id });
  });

  // 供 server.js 的 deploy/undeploy 在部署事件时双清两层缓存；
  // extractMcpInspect 供 services/deploy 在部署成功后提取镜像元数据（详情页「代码」标签）
  return {
    invalidate(id) {
      toolsCache.delete(id);
      rtCache.delete(id);
    },
    extractMcpInspect,
  };
};
