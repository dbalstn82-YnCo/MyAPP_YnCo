#!/usr/bin/env bash
# 폐쇄망 반입용 OS 패키지 수집 — 폐쇄망 서버와 **같은 배포판·버전**의 인터넷 연결 Linux 에서 실행.
# 결과: deploy/server/pkgs/<os_id><major>/ 에 nginx·postgresql·python3 와 의존 패키지(rpm/deb) 저장 → make_offline_bundle.sh 가 tar 에 포함.
# 사용: bash fetch_os_packages.sh [--no-postgres]
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. /etc/os-release
OS_ID="${ID}"; OS_VER="${VERSION_ID%%.*}"
OUT="$HERE/pkgs/${OS_ID}${OS_VER}"
mkdir -p "$OUT"; rm -f "$OUT"/*.rpm "$OUT"/*.deb 2>/dev/null || true
WANT_PG=1; [ "${1:-}" = "--no-postgres" ] && WANT_PG=0
case "$OS_ID" in
  rhel|rocky|almalinux|centos|ol)
    PY="python3 python3-pip"; [ "$OS_VER" -lt 9 ] && PY="python3.11 python3.11-pip"
    PKGS="$PY nginx tar gzip openssl policycoreutils-python-utils"
    [ "$WANT_PG" = 1 ] && PKGS="$PKGS postgresql-server postgresql"
    # 의존성 포함 다운로드(이미 설치된 것도 포함하도록 --resolve --alldeps)
    dnf download --resolve --alldeps --destdir "$OUT" $PKGS
    ;;
  ubuntu|debian)
    PKGS="python3 python3-venv python3-pip nginx tar gzip openssl"
    [ "$WANT_PG" = 1 ] && PKGS="$PKGS postgresql postgresql-contrib"
    apt-get update -qq
    # apt-rdepends 없이: 설치 시뮬레이션으로 필요한 패키지 목록 산출 후 다운로드
    LIST=$(apt-get install --reinstall --print-uris -y $PKGS 2>/dev/null | grep -oP "^'\K[^']+" || true)
    if [ -n "$LIST" ]; then (cd "$OUT" && echo "$LIST" | xargs -n1 -P4 wget -q); fi
    # 이미 설치돼 --print-uris 에 안 나온 것도 받아 둔다(재설치 대비)
    (cd "$OUT" && apt-get download $PKGS 2>/dev/null || true)
    ;;
  *) echo "지원하지 않는 OS: $OS_ID"; exit 1;;
esac
echo "[완료] $OUT: $(ls "$OUT" | wc -l)개 패키지 ($(du -sh "$OUT" | cut -f1))"
echo "다음: bash $HERE/make_offline_bundle.sh  → tar.gz 를 폐쇄망 서버로 반입"
