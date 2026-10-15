// lib/classify-registry.js —— 镜像来源分级信任模型（2026-10-15 自 server.js 外迁，逻辑零改动）。
// 档1 内网直通 / 档2 受信白名单留痕 / 档3 未知来源拦截。
"use strict";

const INTERNAL_REGISTRY = (process.env.INTERNAL_REGISTRY || "localhost:5000").replace(/\/+$/, "");
const TRUSTED_REGISTRIES = (process.env.TRUSTED_REGISTRIES || "ghcr.io/stackloklabs,ghcr.io/stacklok")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const INTERNAL_ONLY = process.env.INTERNAL_ONLY === "1" || process.env.INTERNAL_ONLY === "true";

/** 提取镜像引用的 registry 部分：无域名前缀（如 node:22）视为 docker.io */
function registryOf(ref) {
  const s = String(ref || "").trim();
  const first = s.split("/")[0];
  if (first.includes(".") || first.includes(":") || first === "localhost") return first.toLowerCase();
  return "docker.io";
}

function isInternalRegistry(reg) {
  const internal = INTERNAL_REGISTRY.toLowerCase();
  return reg === internal || reg.startsWith(internal + "/");
}

/**
 * 分级信任模型：档1 内网直通 / 档2 受信白名单留痕 / 档3 未知来源拦截。
 * 关键治理原则：用户提交阶段【不允许】直接填写平台内网仓库地址（INTERNAL_REGISTRY）。
 * 内网仓库只应由平台在审批通过后写入（mirror / build）。默认模式下 tier-1 拒绝提交；
 * INTERNAL_ONLY 严格模式用于纯内网环境，此时只接受已在内网仓库的镜像，由管理员预置。
 */
function classifyRegistry(ref) {
  const reg = registryOf(ref);
  if (!ref) return { tier: 3, registry: reg, allowed: false, message: "缺少镜像引用" };
  if (isInternalRegistry(reg)) {
    if (INTERNAL_ONLY) {
      return { tier: 1, registry: reg, allowed: true, message: "内网镜像源，直接通过" };
    }
    return {
      tier: 1,
      registry: reg,
      allowed: false,
      message: "平台内网仓库地址不接受直接提交；请提供外部镜像源（如 ghcr.io/...），审批通过后由平台同步入内网",
    };
  }
  if (!INTERNAL_ONLY) {
    // 白名单两种粒度：纯域名（ghcr.io）或 域名/命名空间（ghcr.io/stackloklabs）。
    // 命名空间级白名单须按"完整引用前缀"匹配，只比对 registry 域名会漏判。
    const full = String(ref).toLowerCase();
    for (const t of TRUSTED_REGISTRIES) {
      if (reg === t || full.startsWith(t + "/") || reg.endsWith("." + t)) {
        return { tier: 2, registry: reg, allowed: true, message: "受信外部源，审批通过后将同步到内网仓库" };
      }
    }
  }
  return {
    tier: 3,
    registry: reg,
    allowed: false,
    message: INTERNAL_ONLY
      ? "严格模式仅允许内网镜像源 " + INTERNAL_REGISTRY
      : "未知镜像源 " + reg + "：不在受信白名单内，需管理员特批",
  };
}

module.exports = { INTERNAL_REGISTRY, TRUSTED_REGISTRIES, INTERNAL_ONLY, registryOf, isInternalRegistry, classifyRegistry };
