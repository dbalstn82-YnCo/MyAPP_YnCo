#!/usr/bin/env bash
# LogTriage 서버 제거 — 앱·서비스·nginx 설정 제거. 데이터(DB·업로드·보고서)는 --purge 를 줄 때만 삭제.
# 사용: sudo bash uninstall.sh [--purge]
set -uo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/logtriage}"
PURGE=0; [ "${1:-}" = "--purge" ] && PURGE=1
systemctl disable --now logtriage-server logtriage-cleanup.timer 2>/dev/null
rm -f /etc/systemd/system/logtriage-server.service /etc/systemd/system/logtriage-cleanup.service /etc/systemd/system/logtriage-cleanup.timer; systemctl daemon-reload
rm -f /etc/nginx/conf.d/logtriage.conf /etc/nginx/sites-enabled/logtriage /etc/nginx/sites-available/logtriage
nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null
rm -f /usr/local/bin/logtriage /usr/local/bin/logtriage-server
if [ "$PURGE" = 1 ]; then
  DB_URL=$(grep -E '^LOGTRIAGE_DB=' /etc/logtriage/server.env 2>/dev/null | cut -d= -f2- || true)
  if [[ "$DB_URL" == postgresql://* ]]; then
    sudo -u postgres psql -qc "DROP DATABASE IF EXISTS logtriage;" 2>/dev/null
    sudo -u postgres psql -qc "DROP ROLE IF EXISTS logtriage;" 2>/dev/null
  fi
  rm -rf "$INSTALL_DIR" /etc/logtriage
  userdel logtriage 2>/dev/null
  echo "[제거 완료] 앱·설정·데이터 모두 삭제 (nginx/PostgreSQL 패키지 자체는 유지)"
else
  rm -rf "$INSTALL_DIR/logtriage" "$INSTALL_DIR/venv" "$INSTALL_DIR/tools"
  echo "[제거 완료] 앱 제거. 데이터는 유지: $INSTALL_DIR/{data,uploads,reports,rules-local}, /etc/logtriage, DB — 모두 지우려면 --purge"
fi
