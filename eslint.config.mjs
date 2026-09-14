// eslint.config.mjs —— platform-backend（Node CommonJS）扁平配置
// 原则：护航而非拦路——no-undef 是硬错误（拆分迁移遗漏的教训），风格类默认 warn。
import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [
      "node_modules/**", "uploads/**", "tools/**", "backups/**", "logs/**",
      "object-store/**", "scripts/tmp-*", "*.corrupt/**",
    ],
  },
  js.configs.recommended,
  {
    files: ["**/*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "commonjs",
      globals: { ...globals.node },
    },
    rules: {
      "no-unused-vars": ["warn", { args: "none", caughtErrors: "none" }],
      "no-undef": "error",
      "no-constant-condition": "warn",
      "no-empty": ["warn", { allowEmptyCatch: true }],
    },
  },
  {
    files: ["**/*.mjs"],
    languageOptions: { ecmaVersion: 2023, sourceType: "module" },
  },
];
