// lib/exec.js —— 子进程统一出口：docker/thv/trivy/tar 等控制台程序一律经此调用。
// windowsHide:true 根治 Windows 上每次 spawn 闪 cmd 窗口的问题（2026-09-06 引入）。
"use strict";
const { execFile } = require("child_process");
const util = require("util");
const execFileP = util.promisify(execFile);
const MAX_BUFFER = 64 * 1024 * 1024;
function execFileHidden(cmd, args, opts = {}) {
  return execFileP(cmd, args, { windowsHide: true, ...opts });
}
function safeExec(cmd, args, opts) {
  return new Promise((resolve) => {
    execFile(cmd, args, { windowsHide: true, ...(opts || {}) }, (err, stdout, stderr) => {
      resolve({ err, stdout: stdout || "", stderr: stderr || "" });
    });
  });
}
module.exports = { execFileHidden, safeExec, MAX_BUFFER };
