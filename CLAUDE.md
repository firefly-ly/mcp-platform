# CLAUDE.md — platform-backend（企业 MCP+Skill 平台后端）

本文件是给 AI 编程助手（Claude Code / CodeBuddy / WorkBuddy 等）的项目上下文说明。修改代码前请先读完本文件。

## 项目定位

企业级 MCP+Skill 集中管理平台的**后端服务**。基于 ToolHive（thv runtime + registry）二次开发，负责 MCP/Skill 的全生命周期管理：提交 → 安全扫描 → 审批上架 → 部署 → 代理调用。单一维护者、多人按权限调用。

## 技术栈

- **运行时**: Node.js（CommonJS），单进程 Express
- **数据库**: better-sqlite3（`platform.db`，WAL 模式），无 ORM，手写 SQL
- **外部依赖**: ToolHive CLI（`thv`，经 `THV_BIN` 指定）、Docker（容器部署形态）、可选 MinIO（对象存储）
- **端口**: 默认 4000（`PORT` 可覆盖）；Registry 5000、前端 3000 同机运行

## 常用命令

```bash
npm start              # 启动服务（node server.js）
npm run lint           # ESLint（no-undef 为硬错误，必须 0 error）
npm run check:split    # 拆分对账（校验 server.js 拆分后内容零丢失）
npm run test:smoke     # 冒烟测试：20 项全接口断言，需后端运行中
npm run test:security  # 安全自测
node scripts/check-legacy-refs.js <拆分前基线commit>  # 留守引用检查（需要参数）
```

CI（`.github/workflows/ci.yml`）：node --check 全量语法 → 拆分对账 → ESLint → 空库启动(4001) → `scripts/ci-seed.js` 种子数据 → 冒烟 20 断言。

## 代码结构

```
server.js (1708 行)  # 入口 + 编排：CTX 上下文组装、中间件、启动迁移、SSE、代理重写
routes/              # 路由模块，工厂模式 require("./routes/x")(app, CTX)
  mcp.js (482)       #   MCP 生命周期：部署/卸载/README懒回填/树形目录/调用代理
  submissions.js(679)#   提交流：源码包/env 私密配置/审批/制品上传（含 ws 进度）
  skills.js (198)    #   Skill 注册与管理
  favorites/stats/issues/audit  # 收藏 / 统计聚合 / 反馈治理 / 审计查询
lib/                 # 领域逻辑（不依赖 express）
  scan.js            #   Trivy 扫描 + 提示注入检测（INJ-xxx 规则，含零宽字符）
  pkg.js             #   tar 包解析/校验/临时文件（幂等清理）
  source-build.js    #   源码构建（package.json 缺字段回退默认启动命令）
  env-secrets.js     #   .env → ToolHive 加密凭据库（平台不落明文）
  reconcile.js       #   部署状态对账（workloadNameFor 等）
services/deploy.js   # 部署服务
object-store.js      # 制品存储：OBJECT_STORE=fs|minio 二选一
scripts/             # 护航脚本（冒烟/安全/对账/CI 种子）
```

**CTX 模式**：`server.js` 组装一个大上下文对象（db、parseMeta、THV_BIN、audit、deployMcp…），传给各路由工厂。**给 routes/mcp.js 等新增可调用函数时，必须在 server.js 装配点同步补传**——ESLint no-undef 会抓漏传（历史上漏过 inspectSkillPackage/MCP_TREE_MAX/workloadNameFor 三个）。

## 关键机制（AI 容易踩错的点）

1. **内部信任链**：前端 server actions 调本服务必须带 `x-internal-proxy` 头（值取 `INTERNAL_PROXY_TOKEN`，默认 `thv-internal-proxy`，P0-2 身份门）。MCP server 本身不做鉴权——信任收口在本服务。
2. **DB 迁移**：启动时 ALTER TABLE 加列，全部 catch 空处理（幂等），**每处空 catch 必须带行内注释说明理由**——这是硬约定。
3. **Windows 环境**：服务跑在 Windows 宿主机，`WSL2_REWRITE` 做 localhost→WSL IP 改写；exec 子进程注意 GBK/UTF-8 编码问题。
4. **env 私密配置**：`.env` 内容只进 ToolHive 加密凭据库，代码与日志严禁落明文。
5. **Cedar 规划中**：call-time authorization（JWT claims 注入 + default deny + forbid 优先），验签与决策收口在本服务 :4000；未来 principal 分两类——人（department 组树）与 agent（agentRole 组树，机器 JWT `typ=agent`）。

## 工作约定

- **提交信息**: Conventional Commits（feat/fix/refactor/docs/style/perf/test/build/ci/chore/revert）
- **顺序纪律**: 先验证（lint + smoke + 对账）再 commit；绝不提交未验证的代码
- **不要** `git add -A`（会把 tmp-*.js 之外的临时文件带进库）；`.gitignore` 已含 `tmp-*.js`、`_t_*.js`、日志与 db 文件
- **git 二进制**: 用系统 Git `C:\Program Files\Git\cmd\git.exe`（便携版 Git 在 D 盘有 ref 丢失 bug）
- **推送**: 直连 GitHub 优先（会话代理环境变量可能失效），失败时清空代理重试
- **验证基准**: 任何改动后 `npm run lint` 0 error + `npm run test:smoke` 20/20 + `npm run check:split` 0 缺失
