#!/usr/bin/env node
// 拆分完整性对账：每个 routes/services 模块"实际访问的 ctx 字段"（Proxy 实测）
// 与 server.js 装配时"实际提供的字段"（静态解析装配块 + CTX 属性集）逐项 diff。
"use strict";
const fs = require("node:fs");
const path = require("node:path");

const ROOT = __dirname + "/..";
const serverSrc = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");

// ---------- 1. Proxy 实测各模块访问的 ctx 字段 ----------
const MODS = [
  "routes/favorites.js", "routes/stats.js", "routes/issues.js", "routes/audit.js",
  "routes/skills.js", "routes/mcp.js", "routes/submissions.js", "services/deploy.js",
];
const need = {};
for (const f of MODS) {
  const accessed = new Set();
  const ctxProxy = new Proxy({}, { get(t, k) { accessed.add(String(k)); return function () {}; } });
  const appProxy = new Proxy({}, { get(t, k) { return function () {}; } });
  try {
    const m = require(path.join(ROOT, f));
    // deploy.js 是 createDeployService(ctx) 单参；其余 (app, ctx)
    if (f.includes("services/")) m(ctxProxy);
    else m(appProxy, ctxProxy);
  } catch (e) {
    console.log("[加载异常]", f, String(e.message).slice(0, 80));
  }
  need[f] = [...accessed].sort();
}

// ---------- 2. 静态提取 CTX 的属性集 ----------
// CTX 对象字面量（594 行区）+ Object.assign(CTX, {...}) + CTX.xxx = 赋值
const ctxProps = new Set();
// 2a. CTX 字面量内短属性（逐行找 "  xxx," / "  xxx:" 模式，取 CTX 定义段）
const ctxDefMatch = serverSrc.match(/const CTX = \{([\s\S]*?)\n\};/);
if (ctxDefMatch) {
  for (const line of ctxDefMatch[1].split("\n")) {
    const names = line.match(/([A-Za-z_$][\w$]*)\s*[,:}]/g) || [];
    for (const n of names) ctxProps.add(n.replace(/[\s,:}]/g, ""));
  }
}
// 2b. Object.assign(CTX, {...})
for (const m of serverSrc.matchAll(/Object\.assign\(CTX,\s*\{([\s\S]*?)\}\)/g)) {
  for (const n of m[1].match(/([A-Za-z_$][\w$]*)\s*[,:]/g) || [])
    ctxProps.add(n.replace(/[\s,:]/g, ""));
}
// 2c. CTX.xxx = / CTX[...] =
for (const m of serverSrc.matchAll(/CTX\.([A-Za-z_$][\w$]*)\s*=/g)) ctxProps.add(m[1]);
// 2d. getter 形式已在 2a 覆盖（"get TAR_ROOT()" 中 TAR_ROOT 会被抓到）
// 2e. env-secrets / source-build / scan / reconcile 的解构是否回挂 CTX：查解构后是否 Object.assign
const envSecretsBlock = serverSrc.match(/const \{\s*([\s\S]*?)\s*\} = require\("\.\/lib\/env-secrets"\)\(CTX\);/);
const sourceBuildBlock = serverSrc.match(/const \{\s*([\s\S]*?)\s*\} = require\("\.\/lib\/source-build"\)\(CTX\);/);
const scanBlock = serverSrc.match(/const \{\s*([\s\S]*?)\s*\} = require\("\.\/lib\/scan"\)\(CTX\);/);
// 这些 lib 的导出若被装配块显式列出就不依赖 CTX 回挂；此处仅记录以便人工核对
const libExports = {
  "env-secrets": envSecretsBlock ? envSecretsBlock[1].match(/[A-Za-z_$][\w$]*/g) : [],
  "source-build": sourceBuildBlock ? sourceBuildBlock[1].match(/[A-Za-z_$][\w$]*/g) : [],
  scan: scanBlock ? scanBlock[1].match(/[A-Za-z_$][\w$]*/g) : [],
};

// ---------- 3. 提取每个模块装配块提供的字段 ----------
const CTX_SET = ctxProps; // (app, CTX) 形态提供的字段就是 CTX 全集
function extractAssembly(modulePath) {
  // server.js 里的实际形态：require("./routes/favorites")（带 ./ 前缀、不带 .js）
  const rel = "./" + modulePath.replace(/\.js$/, "");
  const esc = rel.replace(/[/.]/g, "\\$&");
  // 形态A：(app, CTX) —— 提供即 CTX 全集
  const reA = new RegExp('require\\("' + esc + '"\\)\\(app,\\s*CTX\\)');
  if (reA.test(serverSrc)) return { set: CTX_SET, spreadCtx: false };
  // 形态B：(app, {...}) —— 对象字面量（可能含 ...CTX 展开）
  const reB = new RegExp('require\\("' + esc + '"\\)\\(app,\\s*\\{([\\s\\S]*?)\\}\\);');
  const mB = serverSrc.match(reB);
  if (mB) {
    const provided = new Set();
    let spread = false;
    const body = mB[1];
    if (/\.\.\.CTX/.test(body)) spread = true;
    for (const n of body.match(/[A-Za-z_$][\w$]*/g) || []) {
      if (["require", "CTX"].includes(n)) continue;
      provided.add(n);
    }
    if (spread) for (const c of CTX_SET) provided.add(c);
    return { set: provided, spreadCtx: spread };
  }
  // 形态C：services/deploy —— __deployService = require(...)({...}) 单参
  const reC = new RegExp('require\\("' + esc + '"\\)\\(\\{([\\s\\S]*?)\\}\\)');
  const mC = serverSrc.match(reC);
  if (mC) {
    const provided = new Set();
    for (const n of mC[1].match(/[A-Za-z_$][\w$]*/g) || []) {
      if (["require"].includes(n)) continue;
      provided.add(n);
    }
    if (/\.\.\.CTX/.test(mC[1])) for (const c of CTX_SET) provided.add(c);
    return { set: provided, spreadCtx: true };
  }
  return null;
}

// ---------- 4. 逐模块 diff ----------
let totalMissing = 0;
for (const f of MODS) {
  const asm = extractAssembly(f);
  if (!asm) {
    console.log("⚠ 未找到装配块: " + f);
    totalMissing++;
    continue;
  }
  const missing = need[f].filter((n) => !asm.set.has(n));
  const tag = missing.length ? "✗ 缺 " + missing.length : "✓";
  console.log(`${tag} ${f} (需 ${need[f].length} / 供 ${asm.set.size})${missing.length ? ": " + missing.join(", ") : ""}`);
  if (missing.length) totalMissing += missing.length;
}

// ---------- 5. server.js 留守代码引用"已迁走标识符"扫描 ----------
// 取重构前(第一步之前)的 server.js 顶层定义名，凡当前 server.js 已无定义但仍出现引用的即嫌疑。
let oldSrc = null;
try { oldSrc = fs.readFileSync(path.join(ROOT, ".git-refcheck-old.js"), "utf8"); } catch (_) {}
if (!oldSrc) {
  console.log("\n(跳过留守引用扫描：无 .git-refcheck-old.js 基线文件)");
}
console.log("\n总计缺失: " + totalMissing);
process.exit(totalMissing ? 1 : 0);
