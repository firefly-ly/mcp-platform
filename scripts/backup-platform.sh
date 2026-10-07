#!/usr/bin/env bash
# ============================================================================
# MCP 平台每日备份脚本（cron 执行，也可手动运行）
#
# 备份对象：
#   1. auth PG 实例      —— 容器 toolhive-auth-db（Better Auth + Casdoor 数据）
#   2. registry PG 实例  —— 容器 toolhive-registry-postgres（目录数据）
#   3. platform-backend  —— SQLite（~/.local/share/platform-backend/platform.db，
#                           含提交元数据与上传制品；WAL 模式）
#   4. 配置文件          —— 前端/后端 .env、casdoor conf（若存在，含敏感信息，勿外传）
#
# 产物：~/mcp-platform/backups/ 下 *.sql.gz / *.db / configs_*.tar.gz
# 保留 KEEP_DAYS 天，自动清理过期文件。
# 日志：~/mcp-platform/backups/backup.log
#
# 当天去重：同一自然日已成功备份过则跳过（支持 crontab 每日一次 +
# @reboot 开机补跑组合——服务器 17:30~次日 8:30 停机，cron 定时点
# 若撞上停机，开机补跑兜底）。强制重跑：SKIP_DEDUP=1 bash 本脚本。
#
# 推荐 crontab（服务器开机窗口 8:30~17:30）：
#   30 12 * * *  <脚本绝对路径>          # 每日 12:30 常规备份
#   @reboot sleep 300 && <脚本绝对路径>  # 开机 5 分钟后补跑（当天已备则跳过）
#
# 恢复方法：
#   PG：    docker exec -i <pg容器> psql -U <superuser> -d postgres < xxx.sql.gz 的解压结果
#   SQLite：sudo systemctl stop mcp-backend → 用备份 .db 替换
#           ~/.local/share/platform-backend/platform.db（同时删掉现存 -wal/-shm）→ 重启
# ============================================================================
set -uo pipefail

BASE="$HOME/mcp-platform"
OUT="$BASE/backups"
KEEP_DAYS=14
LOG="$OUT/backup.log"
TS=$(date +%F_%H%M)
TODAY=$(date +%F)
mkdir -p "$OUT"

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

# ---- 0. 当天去重（已成功备份过则跳过；SKIP_DEDUP=1 强制执行）----
if [ "${SKIP_DEDUP:-0}" != "1" ] && ls "$OUT"/auth-pg_"$TODAY"_*.sql.gz >/dev/null 2>&1; then
  log "SKIP: $TODAY 已有备份（去重生效），如需强制重跑：SKIP_DEDUP=1 $0"
  exit 0
fi

# ---- 1. auth PG（官方镜像对容器内本地 socket 信任，超管 = POSTGRES_USER，默认 auth）----
AUTH_PG_USER="${AUTH_PG_USER:-auth}"
docker exec toolhive-auth-db pg_dumpall -U "$AUTH_PG_USER" 2>>"$LOG" \
  | gzip > "$OUT/auth-pg_$TS.sql.gz" \
  && log "auth-pg OK ($(du -h "$OUT/auth-pg_$TS.sql.gz" | cut -f1))" || log "auth-pg FAIL"

# ---- 2. registry PG（compose 里 POSTGRES_USER=registry 即该实例超管）----
REGISTRY_PG_USER="${REGISTRY_PG_USER:-registry}"
docker exec toolhive-registry-postgres pg_dumpall -U "$REGISTRY_PG_USER" 2>>"$LOG" \
  | gzip > "$OUT/registry-pg_$TS.sql.gz" \
  && log "registry-pg OK ($(du -h "$OUT/registry-pg_$TS.sql.gz" | cut -f1))" || log "registry-pg FAIL"

# ---- 1b. 产物完整性哨兵：SQL 备份 < 1KB 视为可疑（空库导出也有 gzip 头尾）----
for f in "$OUT/auth-pg_$TS.sql.gz" "$OUT/registry-pg_$TS.sql.gz"; do
  if [ -f "$f" ] && [ "$(stat -c%s "$f")" -lt 1024 ]; then
    log "WARN: $(basename "$f") 小于 1KB，疑似导出失败（超管用户名不对？），请人工核查"
  fi
done

# ---- 3. platform-backend SQLite（WAL 模式：优先 sqlite3 在线备份，免停服且一致）----
DB="$HOME/.local/share/platform-backend/platform.db"
if [ -f "$DB" ]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB" ".backup '$OUT/platform-db_$TS.db'" >>"$LOG" 2>&1 \
      && log "platform-db OK (sqlite3 online backup)" || log "platform-db FAIL (sqlite3)"
  else
    # 无 sqlite3 CLI：db/-wal/-shm 三件一起拷，恢复时同样三件一起放回
    cp "$DB" "$OUT/platform-db_$TS.db" 2>>"$LOG" \
      && { [ -f "$DB-wal" ] && cp "$DB-wal" "$OUT/platform-db_$TS.db-wal"; } 2>>"$LOG" \
      && { [ -f "$DB-shm" ] && cp "$DB-shm" "$OUT/platform-db_$TS.db-shm"; } 2>>"$LOG" \
      && log "platform-db OK (file copy, WAL included)" || log "platform-db FAIL (copy)"
  fi
else
  log "platform-db SKIP: $DB 不存在"
fi

# ---- 4. 配置文件（含密钥，注意备份目录权限）----
# 路径动态取：前端 .env.local 跟着 mcp-frontend 的 WorkingDirectory，
# 后端 .env 跟着 mcp-backend 的 WorkingDirectory（即本脚本部署目录的权威值）。
CFG_DIR="$OUT/configs_$TS"
mkdir -p "$CFG_DIR"
FRONT_ENV="$(systemctl show mcp-frontend -p WorkingDirectory --value 2>/dev/null)/.env.local"
BACK_ENV="$(systemctl show mcp-backend -p WorkingDirectory --value 2>/dev/null)/.env"
cp -f "$FRONT_ENV" "$CFG_DIR/" 2>>"$LOG" || log "WARN: 前端 .env.local 未备到 ($FRONT_ENV)"
cp -f "$BACK_ENV" "$CFG_DIR/" 2>>"$LOG" || log "WARN: 后端 .env 未备到 ($BACK_ENV)"
# Casdoor 目录属主非 dp-user 且服务在退役中，不再纳入备份；若要恢复：
# sudo find ... -exec cp（需给 cron 配免密 sudo，不值得）
tar czf "$OUT/configs_$TS.tar.gz" -C "$OUT" "configs_$TS" 2>>"$LOG" \
  && rm -rf "$CFG_DIR" && log "configs OK" || log "configs FAIL"
chmod -R go-rwx "$OUT" 2>>"$LOG"   # 备份含敏感数据，仅属主可读

# ---- 5. 清理过期备份 ----
find "$OUT" -maxdepth 1 \( -name "*.sql.gz" -o -name "*.db*" -o -name "configs_*.tar.gz" \) \
  -mtime +"$KEEP_DAYS" -delete 2>>"$LOG"
log "=== backup finished ($TS) ==="
