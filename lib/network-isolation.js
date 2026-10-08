// lib/network-isolation.js —— ToolHive 网络隔离豁免（--isolate-network=false）
// 背景：thv v0.30.1 起 workload 默认罩隔离网络（-ingress/-egress/-dns 三 sidecar），
// 出网仅经 HTTP(S) egress 代理；数据库裸 TCP（如新零售 DWS postgresql://host:8000）
// 无法走 egress，MCP 容器侧 errno 101、tools/list 握手返回空列表。
// 官方解法是按 workload 退出隔离（--isolate-network=false，thv run --help 实锤 v0.42.1 支持）。
// 豁免来源两路（任一命中即退出隔离；默认全部保持隔离——安全默认）：
//   1. 审批授权（两段式）：提交者声明 meta.data_source，admin 审批勾选写 meta.network_exempt=true；
//   2. 运维开关：.env 的 THV_ISOLATE_NETWORK_OFF 填逗号分隔的「提交 id 或 workload 名」。
"use strict";

/** 解析豁免清单字符串 → Set（容错：空串/多余逗号/首尾空白） */
function parseIsolateOffSet(raw) {
  return new Set(
    String(raw || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

/** 判断某次部署是否应退出网络隔离：
 *  meta.network_exempt === true（审批授权）优先；其次 .env 清单命中提交 id 或 meta.workload_name。 */
function isolateNetworkOff(set, id, meta) {
  // 严格布尔判定：脏数据（字符串 "true" 等）不生效，安全默认
  if (meta && meta.network_exempt === true) return true;
  if (!set || !set.size) return false;
  if (id && set.has(id)) return true;
  const wn = meta && meta.workload_name;
  return typeof wn === "string" && wn !== "" && set.has(wn);
}

module.exports = { parseIsolateOffSet, isolateNetworkOff };
