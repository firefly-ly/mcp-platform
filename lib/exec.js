// lib/exec.js —— 子进程统一出口：docker/thv/trivy/tar 等控制台程序一律经此调用。
// windowsHide:true 根治 Windows 上每次 spawn 闪 cmd 窗口的问题（2026-09-06 引入）。
// 2026-10-09 补丁：thv 调用统一注入 DOCKER_CONFIG（平台内置空凭据配置）。
//   根因（当日进程树实锤）：thv run/rm 对镜像 registry 做凭据解析时，读全局
//   ~/.docker/config.json 的 credsStore=desktop → spawn docker-credential-desktop.exe，
//   而 ToolHive v0.42 的 Go 代码 spawn 助手未加隐藏窗口标志 → 新控制台被 Windows
//   Terminal（系统默认终端）承载 → 每次部署/恢复弹 2 个 Terminal 窗口（一闪而过）。
//   docker CLI 新版已自行修复窗口问题且依赖用户的 desktop-linux context，故不注入。
//   逃生口：PLATFORM_THV_ALLOW_CREDSTORE=1 恢复全局凭据行为（私有 registry 鉴权场景）。
"use strict";
const { execFile } = require("child_process");
const util = require("util");
const fs = require("fs");
const path = require("path");
const execFileP = util.promisify(execFile);
const MAX_BUFFER = 64 * 1024 * 1024;

const EMPTY_DOCKER_CONFIG_DIR = path.join(__dirname, "..", "tools", "docker-config");
function hasEmptyDockerConfig() {
  try {
    return fs.existsSync(path.join(EMPTY_DOCKER_CONFIG_DIR, "config.json"));
  } catch (_) {
    return false;
  }
}
function isThv(cmd) {
  return /(^|[\\/])thv(\.exe)?$/i.test(String(cmd || ""));
}
// 只补 DOCKER_CONFIG，其余环境变量全量继承（child_process 的 env 选项是整表替换，不能只给一项）
function injectThvEnv(o) {
  if (process.env.PLATFORM_THV_ALLOW_CREDSTORE === "1") return;
  if (!hasEmptyDockerConfig()) return;
  const env = { ...(o.env || process.env) };
  if (!env.DOCKER_CONFIG) env.DOCKER_CONFIG = EMPTY_DOCKER_CONFIG_DIR;
  o.env = env;
}
function execFileHidden(cmd, args, opts = {}) {
  const o = { windowsHide: true, ...opts };
  if (isThv(cmd)) injectThvEnv(o);
  return execFileP(cmd, args, o);
}
function safeExec(cmd, args, opts) {
  return new Promise((resolve) => {
    const o = { windowsHide: true, ...(opts || {}) };
    if (isThv(cmd)) injectThvEnv(o);
    execFile(cmd, args, o, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout || "", stderr: stderr || "" });
    });
  });
}
module.exports = { execFileHidden, safeExec, MAX_BUFFER };
