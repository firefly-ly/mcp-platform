// lib/mcp-client.js —— MCP 协议客户端（2026-09-18 自 server.js 拆出，渐进式拆分第五步）
// 覆盖：SSE 流解析（parseSSE）/ JSON-RPC POST（mcpPost）/ initialize→initialized→tools
//   三步调用（mcpCall）/ 鉴权候选轮试（mcpCallAuthed）/ 端点探活（probeMcpEndpoint）。
// 纯 fetch 实现、无状态；唯一外部依赖 authHeaderCandidates（lib/env-secrets 提供）经 ctx 注入。
module.exports = function createMcpClient({ authHeaderCandidates }) {
  function r401403(e) {
    return /\b40[13]\b|unauthorized|forbidden/i.test(String((e && e.message) || e));
  }

  // 解析 SSE 流，返回所有 message 事件的 data 数组
  async function parseSSE(body) {
    const reader = body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    const events = [];
    const ingest = (text) => {
      buf += text;
      let idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const chunk = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const dataLine = chunk.split("\n").find((l) => l.startsWith("data:"));
        if (dataLine) {
          try { events.push(JSON.parse(dataLine.slice(5).trim())); } catch (_) {} // SSE data 行为心跳/注释等非 JSON 内容时跳过
        }
      }
    };
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      ingest(decoder.decode(value, { stream: true }));
    }
    // 处理没有结尾 \n\n 的最后一个事件（服务器关流时常见）
    if (buf.trim()) ingest(buf + "\n\n");
    return events;
  }

  async function mcpPost(endpoint, sessionId, body, extraHeaders) {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(extraHeaders || {}),
    };
    if (sessionId) headers["Mcp-Session-Id"] = sessionId;
    const resp = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const sid = resp.headers.get("Mcp-Session-Id") || sessionId;
    const ct = resp.headers.get("content-type") || "";
    let events;
    if (ct.includes("text/event-stream")) {
      events = await parseSSE(resp.body);
    } else {
      try { events = [await resp.json()]; } catch (_) { events = []; }
    }
    return { sid, events, status: resp.status };
  }

  // 真实 MCP 调用：initialize -> initialized -> (tools/list | tools/call)
  async function mcpCall(endpoint, { tool, args, headers } = {}) {
    const init = await mcpPost(endpoint, null, {
      jsonrpc: "2.0", id: 1, method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "platform-backend", version: "1.0" },
      },
    }, headers);
    const payload = init.events[init.events.length - 1] || {};
    if (payload.error) throw new Error("initialize 失败: " + JSON.stringify(payload.error));
    const sid = init.sid;
    await mcpPost(endpoint, sid, { jsonrpc: "2.0", method: "notifications/initialized" }, headers);
    if (!tool) {
      const r = await mcpPost(endpoint, sid, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, headers);
      return { stage: "tools/list", events: r.events, status: r.status };
    }
    const r = await mcpPost(endpoint, sid, {
      jsonrpc: "2.0", id: 3, method: "tools/call",
      params: { name: tool, arguments: args || {} },
    }, headers);
    return { stage: "tools/call", events: r.events, status: r.status };
  }

  // 带鉴权候选的 MCP 调用：条目 env 里配了 API Key/Token 时逐个尝试（按优先级），
  // 全部 401/403 才回落到无鉴权（与旧行为一致）。应用未做鉴权时带凭证调用也无害
  // （大多数实现忽略多余头），所以凭证候选放在前面，减少一轮往返。
  async function mcpCallAuthed(endpoint, opts, meta) {
    const candidates = [{}, ...authHeaderCandidates(meta || {})];
    let last;
    for (let i = 0; i < candidates.length; i++) {
      try {
        const r = await mcpCall(endpoint, { ...opts, headers: candidates[i] });
        const denied = r.status === 401 || r.status === 403;
        if (denied && i < candidates.length - 1) { last = r; continue; }
        return r;
      } catch (e) {
        last = e;
        const denied = r401403(e);
        if (denied && i < candidates.length - 1) continue;
        throw e;
      }
    }
    return last;
  }

  // 调用前探活：MCP endpoint 对 GET 通常 405，但 TCP 通即可；ECONNREFUSED 会抛错。
  async function probeMcpEndpoint(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3000);
    try {
      await fetch(url, { method: "GET", signal: controller.signal });
      return true;
    } catch (_) {
      return false;
    } finally {
      clearTimeout(timer);
    }
  }

  return { probeMcpEndpoint, parseSSE, mcpPost, mcpCall, mcpCallAuthed, r401403 };
};
