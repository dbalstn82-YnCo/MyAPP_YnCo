#!/usr/bin/env bash
# LogTriage 정식 설치 점검 — 읽기만 합니다(아무것도 고치지 않음). RHEL 실서버 검증 매뉴얼의 '설치 결과 점검' 장.
# 사용:  sudo bash /opt/logtriage/check_install.sh            (종료 0 = 실패 없음, 1 = 실패 있음)
#        결과를 남기려면:  sudo bash /opt/logtriage/check_install.sh | tee ~/logtriage-check.txt
# 비밀 값(비밀번호 · 앞단 비밀 · 1회용 코드 · 토큰)과 서버 주소는 찍지 않습니다 — 결과를 그대로 회신해도 됩니다.
set -u
INSTALL_DIR="${INSTALL_DIR:-/opt/logtriage}"
[ "$(id -u)" -eq 0 ] || { echo "root 로 실행하십시오: sudo bash $0"; exit 2; }
[ -x "$INSTALL_DIR/venv/bin/python" ] || { echo "정식 설치가 없습니다($INSTALL_DIR/venv/bin/python) — 먼저 install.sh 로 설치하십시오"; exit 2; }
cd "$INSTALL_DIR/venv/lt-import" && exec "$INSTALL_DIR/venv/bin/python" -E -s -m logtriage.install_check --install-dir "$INSTALL_DIR" "$@"
