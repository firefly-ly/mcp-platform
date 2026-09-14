// lib/pkg.js —— 制品包工具（零外部依赖）：tar 助手 + 零依赖 ZIP 读/写 + SKILL.md 校验。
// 从 server.js 拆出（2026-09-07 模块化），依赖经 ctx 注入。
"use strict";
const fs = require("fs");
const path = require("path");
const os = require("os");
const zlib = require("zlib");
const crypto = require("crypto");
const { safeExec } = require("./exec");

module.exports = function makePkg(ctx) {
  const { objStore } = ctx;

// Windows 的 tar.exe（bsdtar）会把含盘符的路径（C:\… / D:\…）误判为远程设备，
// 报 "Cannot connect to C: resolve failed"，导致所有解包操作静默失败。
// 统一规避：把 cwd 设为文件所在目录，只传相对文件名，路径中不再出现盘符。
function tarListFile(filePath) {
  return safeExec("tar", ["-tf", path.basename(filePath)], {
    cwd: path.dirname(filePath),
    maxBuffer: 64 * 1024 * 1024,
  });
}
function tarExtractFile(filePath, entryPath) {
  return safeExec(
    "tar",
    ["-xf", path.basename(filePath), "-O", entryPath],
    { cwd: path.dirname(filePath) },
  );
}


// ---- 零依赖 ZIP 读取（列出/提取）----
// 系统 tar 是 GNU tar，不识别 zip，故 Skill 包校验/详情对 .zip 必须自行解析。
// 解析 EOCD → 遍历中央目录 → 读取本地文件头 → 解压（store / raw-deflate）。
function findEocd(buffer) {
  const sig = 0x06054b50;
  for (let i = buffer.length - 22; i >= 0; i--) {
    if (buffer.readUInt32LE(i) === sig) {
      const commentLen = buffer.readUInt16LE(i + 20);
      if (i + 22 + commentLen === buffer.length) return i;
    }
  }
  return -1;
}
function readZipEntries(buffer) {
  const eocd = findEocd(buffer);
  if (eocd < 0) return null;
  const cdOffset = buffer.readUInt32LE(eocd + 16);
  const cdCount = buffer.readUInt16LE(eocd + 10);
  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (buffer.readUInt32LE(p) !== 0x02014b50) break;
    const method = buffer.readUInt16LE(p + 10);
    const compSize = buffer.readUInt32LE(p + 20);
    const nameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    const localOffset = buffer.readUInt32LE(p + 42);
    const name = buffer.toString("utf8", p + 46, p + 46 + nameLen).replace(/\\/g, "/");
    entries.push({ name, method, compSize, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}
function zipListEntries(buffer) {
  const entries = readZipEntries(buffer);
  if (!entries) return { err: { message: "无法解析 zip（缺少 EOCD 记录）" }, entries: [] };
  return { err: null, entries: entries.map((e) => e.name) };
}
function zipExtractEntry(buffer, entryName) {
  const entries = readZipEntries(buffer);
  if (!entries) return { err: { message: "无法解析 zip（缺少 EOCD 记录）" }, data: null };
  const target = entries.find(
    (e) => e.name === entryName || e.name.endsWith("/" + entryName),
  );
  if (!target) return { err: { message: "zip 内未找到 " + entryName }, data: null };
  let lp = target.localOffset;
  if (buffer.readUInt32LE(lp) !== 0x04034b50) {
    lp = buffer.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04]), 0); // 兜底扫描
    if (lp < 0) return { err: { message: "无法定位 zip 本地文件头" }, data: null };
  }
  const nameLen = buffer.readUInt16LE(lp + 26);
  const extraLen = buffer.readUInt16LE(lp + 28);
  const dataStart = lp + 30 + nameLen + extraLen;
  const comp = buffer.subarray(dataStart, dataStart + target.compSize);
  try {
    if (target.method === 0) return { err: null, data: Buffer.from(comp) };
    if (target.method === 8) {
      let raw;
      try { raw = zlib.inflateRawSync(comp); }
      catch (_) { raw = zlib.inflateSync(comp); }
      return { err: null, data: raw };
    }
    return { err: { message: "不支持的 zip 压缩方式 method=" + target.method }, data: null };
  } catch (e) {
    return { err: { message: "zip 解压失败: " + (e && e.message) }, data: null };
  }
}
// 统一打开 Skill 包（zip 或 tar），返回条目列表 + 提取函数，对两种格式一视同仁。
async function openSkillPackage(buffer, lowerKey) {
  const isZip = lowerKey.endsWith(".zip");
  if (isZip) {
    const list = zipListEntries(buffer);
    if (list.err) return { error: "包内列表读取失败: " + list.err.message };
    return {
      entries: list.entries,
      readEntry: async (name) => {
        const ex = zipExtractEntry(buffer, name);
        return ex.err ? null : ex.data;
      },
      cleanup: () => {},
    };
  }
  const tmp = path.join(os.tmpdir(), `skill-open-${Date.now()}-${crypto.randomBytes(4).toString("hex")}.pkg`);
  try { fs.writeFileSync(tmp, buffer); } catch (e) { return { error: "包写入临时文件失败: " + (e && e.message) }; }
  const list = await tarListFile(tmp);
  if (list.err) { try { fs.unlinkSync(tmp); } catch (_) {} return { error: "包内列表读取失败: " + (list.stderr || list.err.message) }; } // 临时文件可能已不存在，清理失败无副作用
  return {
    entries: list.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
    readEntry: async (name) => {
      const ex = await tarExtractFile(tmp, name);
      return ex.err ? null : Buffer.from(ex.stdout, "utf8");
    },
    // 调用方读取完所有条目后再 cleanup，避免 finally 提前删掉临时文件导致提取失败。
    cleanup: () => { try { fs.unlinkSync(tmp); } catch (_) {} }, // cleanup 幂等：重复调用或文件缺失均忽略
  };
}

// ---- 零依赖 ZIP 打包 ----
// WorkBuddy 导入技能要求 .zip，但用户可上传 .tar/.tar.gz/.tgz。依赖里没有 zip 库，
// 故用内置 zlib 自建最小 zip 写入器（deflate，压缩后更大则自动退回 Store）。
const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c;
  }
  return t;
})();
function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}
// entries: [{ name: "相对路径/用/分隔", data: Buffer }]
function buildZip(entries) {
  const body = [];
  const central = [];
  let offset = 0;
  const now = new Date();
  const dosTime = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xffff;
  const dosDate = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xffff;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, "utf8");
    const raw = e.data;
    const comp = zlib.deflateRawSync(raw, { level: 9 });
    const useDeflate = comp.length < raw.length;
    const payload = useDeflate ? comp : raw;
    const crc = crc32(raw);
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0);
    lfh.writeUInt16LE(20, 4);
    lfh.writeUInt16LE(0, 6);
    lfh.writeUInt16LE(useDeflate ? 8 : 0, 8);
    lfh.writeUInt16LE(dosTime, 10);
    lfh.writeUInt16LE(dosDate, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(payload.length, 18);
    lfh.writeUInt32LE(raw.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);
    body.push(lfh, nameBuf, payload);
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0);
    cdh.writeUInt16LE(20, 4);
    cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0, 8);
    cdh.writeUInt16LE(useDeflate ? 8 : 0, 10);
    cdh.writeUInt16LE(dosTime, 12);
    cdh.writeUInt16LE(dosDate, 14);
    cdh.writeUInt32LE(crc, 16);
    cdh.writeUInt32LE(payload.length, 20);
    cdh.writeUInt32LE(raw.length, 24);
    cdh.writeUInt16LE(nameBuf.length, 28);
    cdh.writeUInt16LE(0, 30);
    cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34);
    cdh.writeUInt16LE(0, 36);
    cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(offset, 42);
    central.push(cdh, nameBuf);
    offset += 30 + nameBuf.length + payload.length;
  }
  const cdBuf = Buffer.concat(central);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...body, cdBuf, eocd]);
}
// 把非 zip 制品（.tar / .tar.gz / .tgz）解包后重新打包成 zip。
async function convertArtifactToZip(buffer) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "skill-zip-"));
  try {
    const src = path.join(dir, "src.pkg");
    fs.writeFileSync(src, buffer);
    const outDir = path.join(dir, "out");
    fs.mkdirSync(outDir, { recursive: true });
    // cwd + 相对名，规避 Windows tar 盘符问题（见 tarListFile 注释）
    const ex = await safeExec(
      "tar", ["-xf", path.basename(src), "-C", "out"], { cwd: dir },
    );
    if (ex.err) throw new Error("解包失败: " + (ex.stderr || ex.err.message));
    const entries = [];
    (function walk(d, prefix) {
      for (const f of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, f.name);
        const rel = prefix ? prefix + "/" + f.name : f.name;
        if (f.isDirectory()) walk(full, rel);
        else entries.push({ name: rel, data: fs.readFileSync(full) });
      }
    })(outDir, "");
    if (!entries.length) throw new Error("包内无文件");
    return buildZip(entries);
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {} // 临时目录清理失败不影响主流程（OS 兜底回收）
  }
}
// 拒绝绝对路径或含 .. 的条目（防 zip 路径穿越攻击）
function isPathTraversal(p) {
  if (!p) return true;
  if (path.isAbsolute(p)) return true;
  const norm = path.normalize(p);
  if (norm.split(/[\\/]/).includes("..")) return true;
  return false;
}
// 解包 Skill 包：列条目 → 找 README → 读 README 内容 → 返回文件树与计数。
// 失败（不支持格式/空包）一律返回 null，不阻断审批主流程。
async function inspectSkillPackage(artifactKey) {
  let obj;
  try { obj = await objStore.get(artifactKey); } catch (_) { return null; }
  if (!obj || !obj.buffer) return null;
  const lowerKey = String(artifactKey).toLowerCase();
  const pkg = await openSkillPackage(obj.buffer, lowerKey);
  if (pkg.error) return null;
  try {
    const MAX_TREE = 200000;
    const entries = pkg.entries;
    const tree = [];
    let readmeCand = null; // { name, prio }
    let fileCount = 0;
    for (const e of entries) {
      if (isPathTraversal(e)) continue;
      if (e.endsWith("/")) continue; // 目录条目跳过，文件树仅列文件
      fileCount++;
      const base = path.basename(e).toLowerCase();
      // README 识别放宽到 readme* 变体（如 README_MCP.md），按命名规范度取优先级最高者
      if (base.startsWith("readme")) {
        const prio =
          /^readme\.md$/.test(base) ? 0 :
          /^readme\.txt$/.test(base) ? 1 :
          /^readme(\.[a-z0-9]+)*$/.test(base) ? 2 : 3;
        if (!readmeCand || prio < readmeCand.prio) readmeCand = { name: e, prio };
      }
      if (tree.length < MAX_TREE) tree.push(e);
    }
    let readme = null, readmeName = null;
    if (readmeCand) {
      const rb = await pkg.readEntry(readmeCand.name);
      if (rb) {
        readme = rb.toString("utf8").slice(0, 65536); // 限制 64KB，避免巨大 README 撑爆响应
        readmeName = readmeCand.name;
      }
    }
    return { readme, readme_name: readmeName, tree, file_count: fileCount };
  } catch (_) {
    return null;
  } finally {
    if (pkg.cleanup) pkg.cleanup();
  }
}

// 解析 Markdown 文件顶部的 YAML front matter（简易实现，满足 name/description 即可）。
function parseYamlFrontMatter(text) {
  const trimmed = text.trim();
  if (!trimmed.startsWith("---")) return null;
  const end = trimmed.indexOf("---", 3);
  if (end === -1) return null;
  const yamlBlock = trimmed.slice(3, end).trim();
  const result = {};
  for (const line of yamlBlock.split(/\r?\n/)) {
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    let value = line.slice(idx + 1).trim();
    value = value.replace(/^["']|["']$/g, "");
    if (key) result[key] = value;
  }
  return result;
}

// Skill 包合规校验：必须包含 SKILL.md，且 SKILL.md 顶部 YAML front matter 包含 name 与 description。
// 返回 { valid, name, description, error }。zip / tar 均支持。
async function validateSkillPackage(artifactKey) {
  let obj;
  try { obj = await objStore.get(artifactKey); } catch (e) { return { valid: false, error: "无法读取制品: " + (e && e.message) }; }
  if (!obj || !obj.buffer) return { valid: false, error: "制品为空" };
  const lowerKey = artifactKey.toLowerCase();
  if (
    !lowerKey.endsWith(".zip") &&
    !lowerKey.endsWith(".tar") &&
    !lowerKey.endsWith(".tar.gz") &&
    !lowerKey.endsWith(".tgz")
  ) {
    return { valid: false, error: "不支持的 skill 包格式（仅 .zip / .tar.gz / .tgz / .tar）" };
  }
  const pkg = await openSkillPackage(obj.buffer, lowerKey);
  if (pkg.error) return { valid: false, error: pkg.error };
  try {
    const skillMdEntry = pkg.entries.find((e) => {
      if (isPathTraversal(e)) return false;
      const parts = e.split(/[\\/]/).filter(Boolean);
      return parts.length > 0 && parts[parts.length - 1].toLowerCase() === "skill.md";
    });
    if (!skillMdEntry) return { valid: false, error: "包内缺少 SKILL.md 文件" };
    const buf = await pkg.readEntry(skillMdEntry);
    if (!buf) return { valid: false, error: "无法提取 SKILL.md" };
    const fm = parseYamlFrontMatter(buf.toString("utf8"));
    if (!fm) return { valid: false, error: "SKILL.md 缺少 YAML front matter（示例：---\\nname: xxx\\ndescription: xxx\\n---）" };
    const name = String(fm.name || "").trim();
    const description = String(fm.description || "").trim();
    if (!name) return { valid: false, error: "SKILL.md YAML front matter 缺少 name" };
    if (!description) return { valid: false, error: "SKILL.md YAML front matter 缺少 description" };
    return { valid: true, name, description, error: "" };
  } finally {
    if (pkg.cleanup) pkg.cleanup();
  }
}



  return {
    tarListFile, tarExtractFile, openSkillPackage, isPathTraversal,
    buildZip, convertArtifactToZip, inspectSkillPackage,
    parseYamlFrontMatter, validateSkillPackage,
  };
};
