// lib/network-isolation.js —— ToolHive 网络隔离豁免清单（--isolate-network=false）
// 背景：thv v0.30.1 起 workload 默认罩隔离网络（-ingress/-egress/-dns 三 sidecar），
// 出网仅经 HTTP(S) egress 代理；数据库裸 TCP（如新零售 DWS postgresql://host:8000）
// 无法走 egress，MCP 容器侧 errno 101、tools/list 握手返回空列表。
// 官方解法是按 workload 退出隔离（--isolate-network=false，thv run --help 实锤 v0.42.1 支持）。
// 此处做成按条目可控：.env 的 THV_ISOLATE_NETWORK_OFF 填逗号分隔的「提交 id 或 workload 名」，
// 命中者部署时退出隔离；默认（清单为空/未命中）全部保持隔离——安全默认，豁免必须显式声明。
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

/** 判断某次部署是否应退出网络隔离（命中提交 id 或 meta.workload_name 即豁免） */
function isolateNetworkOff(set, id, meta) {
  if (!set || !set.size) return false;
  if (id && set.has(id)) return true;
  const wn = meta && meta.workload_name;
  return typeof wn === "string" && wn !== "" && set.has(wn);
}

module.exports = { parseIsolateOffSet, isolateNetworkOff };
