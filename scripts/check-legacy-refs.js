"use strict";
// 留守引用扫描：对比重构前 server.js 的顶层定义名与当前 server.js。
// 「旧有定义 + 当前 server.js 已无定义 + 但当前 server.js 仍有引用」= 迁移遗漏嫌疑。
// 基线 commit 由命令行传入（渐进式拆分第一步之前的版本）。
"use strict";
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");

const baseCommit = process.argv[2];
if (!baseCommit) {
  console.log("用法: node scripts/check-legacy-refs.js <拆分前基线commit>");
  process.exit(2);
}
function topDefs(src) {
  const names = new Set();
  for (const m of src.matchAll(/^(?:async )?function ([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  for (const m of src.matchAll(/^(?:const|let|var) ([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  return names;
}
const oldSrc = execFileSync("git", ["show", baseCommit + ":server.js"], { encoding: "utf8", maxBuffer: 20e6 });
const curSrc = fs.readFileSync(__dirname + "/../server.js", "utf8");

const oldDefs = topDefs(oldSrc);
const curDefs = topDefs(curSrc);
// 模块/路由文件中的本地定义也算"有归属"
let modSrc = "";
for (const f of fs.readdirSync(__dirname + "/../routes"))
  modSrc += fs.readFileSync(__dirname + "/../routes/" + f, "utf8");
for (const f of fs.readdirSync(__dirname + "/../services"))
  modSrc += fs.readFileSync(__dirname + "/../services/" + f, "utf8");
const modDefs = topDefs(modSrc);

const migrated = [...oldDefs].filter((n) => !curDefs.has(n));
console.log("旧顶层定义:", oldDefs.size, "| 当前 server.js 保留:", curDefs.size, "| 已迁出:", migrated.length);

// 当前 server.js 中仍引用这些迁走名的位置（排除注释行做粗过滤）
let hits = 0;
for (const name of migrated.sort()) {
  const re = new RegExp("(?<![\\w$.'\"])(" + name + ")(?![\\w$])", "g");
  const lines = [];
  curSrc.split("\n").forEach((line, i) => {
    if (/^\s*\/\//.test(line)) return; // 跳过纯注释行
    if (re.test(line)) lines.push(i + 1 + ": " + line.trim().slice(0, 100));
  });
  if (lines.length) {
    // 在 routes/services 模块里有定义 → 引用需要 ctx 注入（对账已覆盖）；否则是真孤儿
    const inMod = modDefs.has(name) || new RegExp("(?<![\\w$.'\"])(" + name + ")(?![\\w$])").test(modSrc);
    console.log((inMod ? "⚠ 模块持有(需注入)" : "✗ 无归属") + " — " + name + " @ server.js 行 " + lines.length);
    lines.slice(0, 3).forEach((l) => console.log("    " + l));
    hits += lines.length;
  }
}
console.log(hits ? "\n发现 " + hits + " 处留守引用嫌疑" : "\n无留守引用 ✓");
