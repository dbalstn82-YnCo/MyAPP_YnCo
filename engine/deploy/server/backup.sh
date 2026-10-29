#!/usr/bin/env bash
# LogTriage 서버 백업 — 분석 이력 DB(SQLite 또는 PostgreSQL 덤프) · data/ 의 계정 · 감시 · 자산 · 자동화 · 게시판 DB · conf/(서버 키 포함) · 사이트 룰 · 보고서 · (선택) server.env
# 사용: sudo bash /opt/logtriage/backup.sh [보관폴더=/opt/logtriage/backup] [--with-env]   (cron 예: 0 2 * * * root bash /opt/logtriage/backup.sh)
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/logtriage}"
DEST="$INSTALL_DIR/backup"; WITH_ENV=0
for a in "$@"; do case "$a" in --with-env) WITH_ENV=1;; *) DEST="$a";; esac; done
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$DEST"
ENV=/etc/logtriage/server.env
DB_URL=$(grep -E '^LOGTRIAGE_DB=' "$ENV" 2>/dev/null | cut -d= -f2- || true)
WORK=$(mktemp -d)
if [[ "$DB_URL" == postgresql://* ]]; then
  # postgresql://user:pw@host:port/db → pg_dump (비밀번호는 URL 로 전달)
  pg_dump --no-owner --format=custom --dbname="$DB_URL" -f "$WORK/logtriage.pgdump"
else
  DBF="${DB_URL#sqlite:///}"; [ -f "$DBF" ] || DBF="$INSTALL_DIR/data/logtriage.db"
  if [ -f "$DBF" ]; then
    "$INSTALL_DIR/venv/bin/python" - "$DBF" "$WORK/logtriage.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1]); dst = sqlite3.connect(sys.argv[2]); src.backup(dst); dst.close(); src.close()
PY
  fi
fi
# server.env(DB 비밀번호 포함)는 기본 제외 — --with-env 를 줄 때만 포함(백업 파일 보관 경로 권한 주의)
[ "$WITH_ENV" = 1 ] && cp "$ENV" "$WORK/server.env" 2>/dev/null || true
# 22차(10-27): 계정 DB(data/auth) · 감시 · 자산 · 자동화 · 게시판 DB 와 서버 키(conf/secret.key)도 담는다.
# 전에는 분석 이력 DB 하나만 담아, 이 백업으로 복원하면 계정이 사라지거나(계정 DB 없음) 로그인이 되지 않았다(키 없음 — 비밀번호 3중 저장의 첫 단계 키).
# SQLite 는 쓰는 중에도 일관되게 backup API 로 뜬다(앱 [예약 백업]과 같은 방식). 업로드 원본(uploads/)은 담지 않는다(개인정보 · 보존 14일).
if [ -d "$INSTALL_DIR/data" ]; then
  "$INSTALL_DIR/venv/bin/python" - "$INSTALL_DIR/data" "$WORK/data" <<'PY'
import os, shutil, sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
for root, dirs, files in os.walk(src):
    for n in files:
        if n.endswith(("-wal", "-shm", "-journal", ".lock")):
            continue
        a = os.path.join(root, n)
        b = os.path.join(dst, os.path.relpath(a, src))
        os.makedirs(os.path.dirname(b), exist_ok=True)
        with open(a, "rb") as f:
            head = f.read(16)
        if head.startswith(b"SQLite format 3"):
            s = sqlite3.connect(a); d = sqlite3.connect(b); s.backup(d); d.close(); s.close()
        else:
            shutil.copy2(a, b)
PY
fi
[ -d "$INSTALL_DIR/conf" ] && cp -a "$INSTALL_DIR/conf" "$WORK/conf"   # secret.key · auth.json · hub.json · tls.json(인증서 경로) — 백업 파일은 600
[ -d "$INSTALL_DIR/rules-local" ] && cp -r "$INSTALL_DIR/rules-local" "$WORK/"
[ -d "$INSTALL_DIR/reports" ] && cp -r "$INSTALL_DIR/reports" "$WORK/"
OUT="$DEST/logtriage-backup-$STAMP.tar.gz"
tar -czf "$OUT" -C "$WORK" .
chmod 600 "$OUT"
rm -rf "$WORK"
# 30일 지난 백업 정리
find "$DEST" -name 'logtriage-backup-*.tar.gz' -mtime +30 -delete 2>/dev/null || true
echo "[백업 완료] $OUT ($(du -h "$OUT" | cut -f1))"
echo "복원: 설치매뉴얼.md '9. 백업·복원' 참조 (data/ 전체 + conf/secret.key 를 함께 되돌림 — 키 없이 계정 DB 만 옮기면 로그인 불가 / PostgreSQL: pg_restore --dbname=<URL> logtriage.pgdump)"
