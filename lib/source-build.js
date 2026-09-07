// lib/source-build.js —— 源码包自动构建：识别类型 → 生成 Dockerfile → docker build。
// 构建产物走与镜像包一致的部署链（meta.built_image）。从 server.js 拆出（2026-09-07）。
"use strict";
const fs = require("fs");
const path = require("path");

module.exports = function makeSourceBuild(ctx) {
  const {
    PLATFORM_ROOT, parseMeta, workloadNameFor, objStore, openSkillPackage,
    isPathTraversal, execFileHidden, MAX_BUFFER, patchMeta,
  } = ctx;

// ---- 源码包自动构建：zip/tar.gz 源码 → 识别类型 → 生成 Dockerfile → docker build ----
const SOURCE_MAX_MB = 20;
function detectSourceProject(entries, readText) {
  // 返回 { kind: "node" | "python", dockerfile, startCmd } 或 null
  const names = entries.map((e) => e.toLowerCase());
  const read = async (f) => {
    const entry = entries.find((e) => e.toLowerCase() === f || e.toLowerCase().endsWith("/" + f));
    return entry ? (await readText(entry)) || "" : "";
  };
  if (names.includes("package.json")) return { kind: "node", read };
  if (names.includes("requirements.txt") || names.includes("pyproject.toml")) return { kind: "python", read };
  return null;
}

async function buildSourceImage(sub) {
  const meta = parseMeta(sub);
  const workload = meta.workload_name || workloadNameFor(sub.id);
  const version = String(meta.version || "1.0.0").replace(/[^a-zA-Z0-9._-]/g, "");
  const image = `${workload}:${version || "1.0.0"}`;
  const obj = await objStore.get(meta.artifact_key);
  if (!obj || !obj.buffer) throw new Error("源码包为空");
  const lowerKey = meta.artifact_key.toLowerCase();
  const pkg = await openSkillPackage(obj.buffer, lowerKey);
  if (pkg.error) throw new Error("解包失败: " + pkg.error);

  const buildDir = path.join(PLATFORM_ROOT, "uploads", "build", sub.id);
  fs.rmSync(buildDir, { recursive: true, force: true });
  fs.mkdirSync(buildDir, { recursive: true });
  try {
    for (const entry of pkg.entries.slice(0, 500)) {
      if (isPathTraversal(entry)) continue;
      const buf = await pkg.readEntry(entry);
      if (!buf) continue;
      const dest = path.join(buildDir, entry.replace(/[\\/]/g, "__"));
      if (buf.length < 20 * 1024 * 1024) fs.writeFileSync(dest, buf);
    }
  } finally {
    if (pkg.cleanup) pkg.cleanup();
  }

  // 识别项目类型并生成 Dockerfile
  const files = fs.readdirSync(buildDir);
  let dockerfile;
  const pkgJsonPath = files.find((f) => f === "package.json" || f.endsWith("__package.json"));
  const reqPath = files.find((f) => f.includes("__requirements.txt") || f === "requirements.txt" || f.endsWith("__pyproject.toml"));
  if (pkgJsonPath) {
    let startCmd = "node server.js";
    let installCmd = "npm install --omit=dev";
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(buildDir, pkgJsonPath), "utf8"));
      if (pj.scripts && pj.scripts.start) startCmd = "npm start";
      else if (pj.main) startCmd = `node ${pj.main}`;
    } catch (_) {}
    dockerfile = `FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN ${installCmd}\nENV NODE_ENV=production\nEXPOSE 3000\nCMD ["sh", "-c", "${startCmd}"]\n`;
  } else if (reqPath) {
    let startCmd = "python server.py";
    const candidates = ["server.py", "main.py", "app.py", "run.py"];
    const found = candidates.find((c) => files.some((f) => f === c || f.endsWith("__" + c)));
    if (found) startCmd = `python ${found.split("__").pop()}`;
    const isPyproject = reqPath.includes("__pyproject.toml") || reqPath === "pyproject.toml";
    const installCmd = isPyproject ? "pip install --no-cache-dir ." : "pip install --no-cache-dir -r requirements.txt";
    dockerfile = `FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nRUN ${installCmd}\nENV PYTHONUNBUFFERED=1\nCMD ["sh", "-c", "${startCmd}"]\n`;
  } else {
    throw new Error("无法识别项目类型：源码包中需要包含 package.json（Node）或 requirements.txt / pyproject.toml（Python）");
  }
  fs.writeFileSync(path.join(buildDir, "Dockerfile.generated"), dockerfile);

  // 构建（基础镜像与依赖可能需外网；构建日志留痕供审批查看）
  const t0 = Date.now();
  const bf = path.join(buildDir, "Dockerfile.generated");
  const out = await execFileHidden("docker", ["build", "-f", bf, "-t", image, "."], {
    timeout: 10 * 60 * 1000, maxBuffer: MAX_BUFFER, cwd: buildDir,
  });
  patchMeta(sub.id, {
    built_image: image,
    build_log: (out.stdout || "").slice(-4000),
    build_duration_ms: Date.now() - t0,
    built_at: new Date().toISOString(),
  });
  return image;
}


  return { SOURCE_MAX_MB, detectSourceProject, buildSourceImage };
};
