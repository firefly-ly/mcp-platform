"use strict";
// 测试脚本共享的 DB 路径解析——必须与 server.js 的 DB_PATH 逻辑完全一致：
// Linux 上后端用 $HOME/.local/share/platform-backend/platform.db（WSL2 时代为避开
// DrvFS 文件锁的设计），Windows 上用项目根的 platform.db。否则测试插入的临时数据
// 与后端实际读取的库是两个文件，产生"测试写入了但后端看不见"的假阳性。
const path = require("node:path");

const DB_FILE =
  process.env.DB_PATH ||
  (process.platform === "linux"
    ? path.join(process.env.HOME || "/tmp", ".local/share/platform-backend/platform.db")
    : path.join(__dirname, "..", "platform.db"));

module.exports = { DB_FILE };
