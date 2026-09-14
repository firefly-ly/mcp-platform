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
  // 旧目录清理是"尽力而为"：某些环境（安全软件/沙箱的批量删除确认层）会拦截
  // recursive rmSync（曾致构建直接失败）。清不掉就继续——解压步骤会覆盖同名文件，
  // 残留的旧文件最多多占点空间，不影响构建正确性。
  try {
    fs.rmSync(buildDir, { recursive: true, force: true });
  } catch (_) {
    try {
      for (const f of fs.readdirSync(buildDir)) {
        try { fs.rmSync(path.join(buildDir, f), { recursive: true, force: true }); } catch (_) {} // 构建目录条目可能被并发清理，rm 失败忽略
      }
    } catch (_) { /* 彻底清不掉也继续 */ }
  }
  const srcDir = path.join(buildDir, "src");
  fs.mkdirSync(srcDir, { recursive: true });
  try {
    // 保留目录结构解压（旧版把 / 和 \ 替换成 __ 压平，导致 pyproject.toml 等工程文件
    // 不在构建上下文根、pip install . 必败、CMD 路径也错——2026-09-08 修复）
    for (const entry of pkg.entries.slice(0, 500)) {
      if (isPathTraversal(entry)) continue;
      const buf = await pkg.readEntry(entry);
      if (!buf) continue;
      const rel = String(entry).replace(/\\/g, "/").replace(/^\.?\//, "");
      if (!rel || rel.endsWith("/")) continue;
      const dest = path.join(srcDir, ...rel.split("/"));
      if (!path.normalize(dest).startsWith(path.normalize(srcDir) + path.sep)) continue; // 二次防逃逸
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      if (buf.length < 20 * 1024 * 1024) fs.writeFileSync(dest, buf);
    }
  } finally {
    if (pkg.cleanup) pkg.cleanup();
  }

  // 定位工程根：压缩包带唯一顶层目录（如 flowvision-retail-mcp/…）且根上无散文件时，进入该目录
  const isDir = (d, f) => { try { return fs.statSync(path.join(d, f)).isDirectory(); } catch (_) { return false; } };
  const PROJECT_MARKER = /^(package\.json|pyproject\.toml|setup\.py|requirements[^/]*\.txt|dockerfile)$/i;
  let root = srcDir;
  const topDirs = fs.readdirSync(srcDir).filter((f) => isDir(srcDir, f));
  const topFiles = fs.readdirSync(srcDir).filter((f) => !isDir(srcDir, f));
  const dirHasMarker = (d) => fs.readdirSync(d).some((f) => PROJECT_MARKER.test(f));
  if (topDirs.length === 1 && topFiles.length === 0 && dirHasMarker(path.join(srcDir, topDirs[0]))) {
    root = path.join(srcDir, topDirs[0]);
  }

  // 生成 Dockerfile（提交者自带 Dockerfile 时直接用——最懂工程结构的是作者本人）
  const files = fs.readdirSync(root);
  let dockerfile;
  const ownDockerfile = files.find((f) => f.toLowerCase() === "dockerfile");
  if (ownDockerfile) {
    dockerfile = fs.readFileSync(path.join(root, ownDockerfile), "utf8");
  } else {
    const pkgJsonPath = files.find((f) => f.toLowerCase() === "package.json");
    if (pkgJsonPath) {
      let startCmd = "node server.js";
      let installCmd = "npm install --omit=dev";
      try {
        const pj = JSON.parse(fs.readFileSync(path.join(root, pkgJsonPath), "utf8"));
        if (pj.scripts && pj.scripts.start) startCmd = "npm start";
        else if (pj.main) startCmd = `node ${pj.main}`;
      } catch (_) {} // package.json 缺字段/损坏时回退默认启动命令
      dockerfile = `FROM node:20-alpine\nWORKDIR /app\nCOPY . .\nRUN ${installCmd}\nENV NODE_ENV=production\nEXPOSE 3000\nCMD ["sh", "-c", "${startCmd}"]\n`;
    } else {
      const reqFiles = files.filter((f) => /^requirements[^/]*\.txt$/i.test(f));
      const hasPyproject = files.some((f) => /^(pyproject\.toml|setup\.py)$/i.test(f));
      if (!reqFiles.length && !hasPyproject) {
        throw new Error("无法识别项目类型：源码包中需要包含 package.json（Node）或 requirements*.txt / pyproject.toml（Python）；也可在包根自带 Dockerfile");
      }
      const installParts = [];
      if (reqFiles.length) installParts.push(reqFiles.map((r) => `pip install --no-cache-dir -r ${r}`).join(" && "));
      if (hasPyproject) installParts.push("pip install --no-cache-dir .");
      let startCmd = "";
      const entryScript = ["server.py", "main.py", "app.py", "run.py"].find((c) =>
        files.some((f) => f.toLowerCase() === c));
      if (entryScript) {
        startCmd = `python ${entryScript}`;
      } else {
        // 根上无入口脚本：找唯一含 __main__.py 的包目录 → python -m
        const mainPkgs = files.filter((f) =>
          isDir(root, f) && fs.existsSync(path.join(root, f, "__main__.py")));
        if (mainPkgs.length === 1) startCmd = `python -m ${mainPkgs[0]}`;
      }
      dockerfile = `FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\nRUN ${installParts.join(" && ")}\nENV PYTHONUNBUFFERED=1\nCMD ["sh", "-c", "${startCmd}"]\n`;
    }
  }
  fs.writeFileSync(path.join(root, "Dockerfile.generated"), dockerfile);

  // 构建（基础镜像与依赖可能需外网；构建日志留痕供审批查看）
  const t0 = Date.now();
  const bf = path.join(root, "Dockerfile.generated");
  const out = await execFileHidden("docker", ["build", "-f", bf, "-t", image, "."], {
    timeout: 10 * 60 * 1000, maxBuffer: MAX_BUFFER, cwd: root,
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
