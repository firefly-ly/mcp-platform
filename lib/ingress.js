// lib/ingress.js —— ToolHive ingress 端口发现与端点解析（2026-09-18 自 server.js 拆出，渐进式拆分第五步）
// 覆盖：WSL2 端口改写（rewriteForWsl2）/ docker port 解析（getIngressPort）/
//   平台固定端口优先的端点发现（discoverIngressForSubmission）/ thv 镜像别名发现
//   （discoverThvEndpoint）/ 统一入口（resolveEndpoint）。
// 注意：ensureStableIngress / rebuildIngress / healMcpIngress 仍留 server.js——
//   它们耦合 db/patchMeta/audit 与自愈任务表，属「健康探测自愈层」非纯发现逻辑。
const fs = require("node:fs");

module.exports = function createIngress(ctx) {
  const {
    execFileHidden, MAX_BUFFER, parseMeta, workloadNameFor,
    ensureStableIngress, thvListJson, MCP_IMAGE_ALIASES, LIVE_ENDPOINTS,
  } = ctx;

  // 默认【不改写】：当前后端与 ToolHive MCP server 同处 WSL2，Docker 已把容器
  // 端口转发到 WSL2 的 127.0.0.1，直接用即可。若 server 真在 Windows 主机、需跨
  // 网络访问，再设 WSL2_REWRITE=1 启用改写（把 127.0.0.1 换成 Windows 主机 IP）。
  function rewriteForWsl2(url) {
    if (process.env.WSL2_REWRITE !== "1" || process.platform !== "linux") return url;
    try {
      const osrelease = fs.readFileSync("/proc/sys/kernel/osrelease", "utf8");
      if (!/microsoft|wsl/i.test(osrelease)) return url;
      const resolv = fs.readFileSync("/etc/resolv.conf", "utf8");
      const m = resolv.match(/nameserver\s+(\d+\.\d+\.\d+\.\d+)/);
      const winIp = m && m[1];
      if (!winIp || winIp.startsWith("127.")) return url;
      return url.replace(/^(https?:\/\/)(127\.0\.0\.1|localhost)(:|\/)/, `$1${winIp}$3`);
    } catch (_) {
      return url;
    }
  }

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

  // 对平台已提交的 MCP，动态发现当前可达的 ingress 端口（优先平台固定端口）。
  // 背景：ToolHive 部署时 thv list 先报告内部端口（如 127.0.0.1:21784），此时 ingress
  // 容器尚未创建，导致写入 meta.endpoint 的端口浏览器无法访问。详情/调用时重新查一次。
  // ensureStableIngress 幂等：固定端口可用时秒回；坏/缺 ingress 时重建（端口不变）。
  async function discoverIngressForSubmission(sub, opts = {}) {
    if (!sub || sub.type !== "mcp") return null;
    const meta = parseMeta(sub);
    const workload = meta.workload_name || workloadNameFor(sub.id);
    const p = await ensureStableIngress(workload, meta, opts);
    if (p) return `http://127.0.0.1:${p}/mcp`;
    return meta.endpoint || null;
  }

  async function discoverThvEndpoint(ref) {
    if (!ref) return null;
    const alias = MCP_IMAGE_ALIASES[ref] || ref;
    const list = await thvListJson();
    const entry = list.find((x) =>
      x.status === "running" &&
      (x.name === ref || (x.package && x.package.includes(alias)))
    );
    if (!entry) return null;
    // thv list 报告的 url 可能不是实际可访问的 ingress 端口（如 14801 不可达，
    // 而 Docker 实际映射的是 13433），优先用 docker port 取 ingress 容器端口。
    const ingressPort = await getIngressPort(entry.name);
    if (ingressPort) return `http://127.0.0.1:${ingressPort}/mcp`;
    return entry.url || null;
  }

  async function resolveEndpoint(ref, explicit) {
    if (explicit) return explicit;
    if (ref && /^https?:\/\//.test(ref)) return ref;
    // 优先运行时动态发现 ToolHive 实际端口，避免硬编码端口失效
    const discovered = await discoverThvEndpoint(ref);
    if (discovered) return discovered;
    if (ref && LIVE_ENDPOINTS[ref]) return LIVE_ENDPOINTS[ref];
    return null;
  }

  return { rewriteForWsl2, getIngressPort, discoverIngressForSubmission, discoverThvEndpoint, resolveEndpoint };
};
