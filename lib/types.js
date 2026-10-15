// lib/types.js —— 平台核心数据结构契约仓库（JSDoc typedef 集中定义）。
// 用法：其他文件在 JSDoc 里用 `import("./types").SubmissionMeta` 引用，
// 配合文件头 `// @ts-check` 即可获得编译期检查（VS Code / tsc --checkJs 均生效）。
// 本文件只含类型与常量说明，无运行时逻辑。
"use strict";

/**
 * 可见范围配置（submissions.meta.visibility 的规范形态）。
 * 名单语义（2026-10-14 定型）：与可见性模式解耦——
 *   mode=all 时 users 是"已自助签发/管理员添加的成员台账"（不参与准入）；
 *   mode=restricted 时 users 是准入名单；groups 仅 restricted 下参与可见性判定。
 * @typedef {Object} Visibility
 * @property {"all"|"restricted"} mode
 * @property {string[]} users 小写邮箱名单（归一化：小写去空白，排序去重）
 * @property {string[]} groups 小写组名单
 */

/**
 * 条目 meta（submissions.meta JSON 解析后的核心结构）。字段随功能演进增加，此处列高频契约字段。
 * @typedef {Object} SubmissionMeta
 * @property {Visibility} [visibility] 可见范围配置
 * @property {boolean} [visibility_configured] 管理员是否显式配置过可见范围（false=未上架）
 * @property {string} [workload_name] ToolHive workload 名（mcp-subXXX）
 * @property {string} [endpoint] 部署成功回填的调用端点
 * @property {string} [deploy_status] unborn|building|loaded|deploying|deployed|undeployed|failed
 * @property {string} [deploy_error] 最近一次部署失败原因
 * @property {string} [deploy_fp] 部署配置指纹（快启路径判定用）
 * @property {string} [mcp_token] 包级代理访问令牌（管理员/应急）
 * @property {string} [name] 条目名
 * @property {string} [owner] 条目 owner
 * @property {string} [payload_ref] 制品引用（ref/文件名）
 * @property {string} [image_ref] ghcr 镜像地址（镜像直跑链）
 * @property {string} [source_type] 提交来源类型（tar/image/source）
 * @property {string} [artifact_key] 制品存储 key
 * @property {string} [transport] 传输协议（sse/http）
 */

/**
 * submissions 表行。
 * @typedef {Object} SubmissionRow
 * @property {string} id 提交 id（sub_XXX / seed_XXX）
 * @property {string} user_id 提交者
 * @property {"mcp"|"skill"} type 类型
 * @property {string} status pending|approved|rejected|removed
 * @property {string} scan_status 安全扫描状态
 * @property {string} created_at
 * @property {string} meta JSON 字符串（parseMeta 解析为 SubmissionMeta）
 */

/**
 * 请求方身份（由可信 Next Server 端写入的 x-actor-* 头解析而来）。
 * @typedef {Object} Actor
 * @property {string} email 小写邮箱；匿名调用为 ""
 * @property {string[]} groups 小写分组列表
 * @property {boolean} admin 仅当 x-actor-admin === "1" 时为 true
 */

/**
 * mcp_member_tokens 表行。
 * @typedef {Object} MemberTokenRow
 * @property {string} submission_id 条目 id
 * @property {string} member 成员邮箱（小写）
 * @property {string} token 访问令牌（hex 32）
 * @property {string|null} created_at 首签时间
 * @property {string|null} rotated_at 最近轮换时间
 */

/**
 * 签发/轮换结果。
 * @typedef {Object} IssueRotateResult
 * @property {string} token 新令牌
 * @property {"issued"|"rotated"} action 本次动作
 */

/**
 * 名单合并结果（visibilityWithMember / resolveVisibilitySave 共用形态）。
 * @typedef {Object} VisibilitySaveResult
 * @property {Visibility} visibility
 * @property {boolean} changed|adoptMembers 是否发生并入
 */

module.exports = {};
