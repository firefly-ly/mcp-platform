# 重构①：routes/mcp.js 成员 token 域外迁 routes/mcp/member-tokens.js（临时脚本，用后即删）
import io

SRC = "routes/mcp.js"
DST = "routes/mcp/member-tokens.js"

lines = io.open(SRC, encoding="utf-8").read().split("\n")
# 域范围：497 行（段注释）~ 699 行（member-token-config 路由结束），1-indexed
start, end = 497, 699
block = "\n".join(lines[start - 1 : end])
assert "成员级代理 Token 管理" in block, "起始锚点不对"
assert "member-token-config" in block, "结束锚点不对"

new_module = (
    "// routes/mcp/member-tokens.js —— 成员级代理 Token 域（2026-10-15 自 routes/mcp.js 外迁）。\n"
    "// 覆盖：列表 / 单签 / 批量 / 吊销 / 成员接入配置 / 自助签发 / 可见范围名单合并。\n"
    "// 名单语义：与可见性模式解耦（mode=all 下名单 = 已自助签发/管理员添加的成员，切模式保留）。\n"
    "// 名单读取/归一化/签发轮换统一走 lib/member-tokens.js 与 lib/visibility.js。\n"
    'const { memberTokenAllowed } = require("../../lib/visibility");\n'
    'const {\n'
    '  normalizeEmail,\n'
    '  normalizeEmails,\n'
    '  readUsers,\n'
    '  readRawVisibility,\n'
    '  visibilityWithMember,\n'
    '  issueOrRotateToken,\n'
    '} = require("../../lib/member-tokens");\n'
    "\n"
    "module.exports = function registerMemberTokenRoutes(app, ctx) {\n"
    "  const {\n"
    "    db, parseMeta, patchMeta, actorFromReq, audit, canAccessSubmission,\n"
    "    publicEndpointFor, workloadNameFor,\n"
    "  } = ctx;\n"
    "\n"
    + block.strip("\n") +
    "\n};\n"
)
import os
os.makedirs("routes/mcp", exist_ok=True)
io.open(DST, "w", encoding="utf-8", newline="\n").write(new_module)
print("created", DST, "lines:", new_module.count("\n") + 1)

# 从 mcp.js 移除域块，替换为挂载调用
remaining = lines[: start - 1] + [
    "  // ---- 成员级代理 Token 域：外迁 routes/mcp/member-tokens.js（2026-10-15 拆分，挂载点与路径不变）----",
    '  require("./mcp/member-tokens").registerMemberTokenRoutes(app, ctx);',
    "",
] + lines[end:]
io.open(SRC, "w", encoding="utf-8", newline="\n").write("\n".join(remaining))
print("trimmed", SRC, "lines:", len(remaining))
