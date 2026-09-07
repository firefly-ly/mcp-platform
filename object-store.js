"use strict";
// 内部制品库抽象层：Skill 静态制品的"本体"存放处。
// 默认 fs 后端（本机验证），可经 OBJECT_STORE=minio 切到内网 MinIO（S3 协议）。
// 平台后端只存"钥匙"(artifact_key) + sha256，字节本体在专用存储，不在 SQLite。
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const STORE_TYPE = (process.env.OBJECT_STORE || "fs").toLowerCase();

// fs 后端根目录：复用既有 uploads/ 路径，旧数据不迁移即可访问
const FS_ROOT = process.env.OBJECT_STORE_FS_ROOT
  ? path.resolve(process.env.OBJECT_STORE_FS_ROOT)
  : path.join(__dirname, "uploads");
fs.mkdirSync(FS_ROOT, { recursive: true });

// MinIO 连接配置（落地内网时启用）
const MINIO = {
  endPoint: (process.env.MINIO_ENDPOINT || "localhost").replace(/^https?:\/\//, ""),
  port: parseInt(process.env.MINIO_PORT || "9000", 10),
  useSSL: (process.env.MINIO_USE_SSL || "false") === "true",
  accessKey: process.env.MINIO_ACCESS_KEY || "minioadmin",
  secretKey: process.env.MINIO_SECRET_KEY || "minioadmin",
  bucket: process.env.MINIO_BUCKET || "platform-artifacts",
};

function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}
function safe(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, "_");
}

/* ---------- fs 后端 ---------- */
async function fsPut(key, buf) {
  const fp = path.join(FS_ROOT, key);
  fs.mkdirSync(path.dirname(fp), { recursive: true });
  fs.writeFileSync(fp, buf);
  return { key, sha256: sha256(buf), size: buf.length };
}
async function fsGet(key) {
  const fp = path.join(FS_ROOT, key);
  if (!fs.existsSync(fp)) return null;
  const buf = fs.readFileSync(fp);
  return { buffer: buf, size: buf.length, sha256: sha256(buf) };
}
async function fsExists(key) {
  return fs.existsSync(path.join(FS_ROOT, key));
}
async function fsDelete(key) {
  const fp = path.join(FS_ROOT, key);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
}

/* ---------- minio 后端（lazy require，未安装不影响 fs 后端） ---------- */
let _mc = null;
function mc() {
  if (_mc) return _mc;
  let Minio;
  try {
    Minio = require("minio");
  } catch (e) {
    throw new Error(
      "OBJECT_STORE=minio 但未安装 minio SDK，请 `npm install minio` 或改回 OBJECT_STORE=fs"
    );
  }
  _mc = new Minio.Client({
    endPoint: MINIO.endPoint,
    port: MINIO.port,
    useSSL: MINIO.useSSL,
    accessKey: MINIO.accessKey,
    secretKey: MINIO.secretKey,
  });
  return _mc;
}
async function ensureBucket() {
  const c = mc();
  if (!(await c.bucketExists(MINIO.bucket))) await c.makeBucket(MINIO.bucket);
}
async function minioPut(key, buf) {
  await ensureBucket();
  const h = sha256(buf);
  await mc().putObject(MINIO.bucket, key, buf, buf.length, { sha256: h });
  return { key, sha256: h, size: buf.length };
}
async function minioGet(key) {
  const c = mc();
  const stat = await c.statObject(MINIO.bucket, key);
  const stream = await c.getObject(MINIO.bucket, key);
  const chunks = [];
  for await (const ch of stream) chunks.push(ch);
  const buf = Buffer.concat(chunks);
  return {
    buffer: buf,
    size: stat.size,
    sha256: (stat.metaData && stat.metaData.sha256) || "",
  };
}
async function minioExists(key) {
  try {
    await mc().statObject(MINIO.bucket, key);
    return true;
  } catch (e) {
    return false;
  }
}
async function minioDelete(key) {
  await mc().removeObject(MINIO.bucket, key);
}

const impl =
  STORE_TYPE === "minio"
    ? { put: minioPut, get: minioGet, exists: minioExists, del: minioDelete }
    : { put: fsPut, get: fsGet, exists: fsExists, del: fsDelete };

// 生成唯一、可追溯的存储 key：<group>/<version>/<时间戳>_<文件名>
function makeKey(groupKey, version, filename) {
  return `${safe(groupKey)}/${safe(version)}/${Date.now()}_${safe(filename)}`;
}

module.exports = {
  STORE_TYPE,
  put: (k, b) => impl.put(k, b),
  get: (k) => impl.get(k),
  exists: (k) => impl.exists(k),
  del: (k) => impl.del(k),
  makeKey,
  sha256,
};
