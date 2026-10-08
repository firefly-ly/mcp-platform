// commitlint.config.mjs —— 提交信息规范（Conventional Commits）
// 格式：<type>(<scope>?): <subject>，如 feat(ci): xxx / fix: yyy
// type 枚举：feat fix refactor docs style perf test build ci chore revert
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [2, "always", [
      "feat", "fix", "refactor", "docs", "style", "perf",
      "test", "build", "ci", "chore", "revert",
    ]],
    "subject-max-length": [2, "always", 100],
  },
};
