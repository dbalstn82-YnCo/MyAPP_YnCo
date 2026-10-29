#!/usr/bin/env bash
# 인터넷망에서 실행 — 폐쇄망 Linux 서버 반입용 오프라인 설치 번들 생성
# 결과: <engine 상위 폴더>/logtriage-server-<날짜>.tar.gz
#   포함: 소스(logtriage/ rules/ errorcodes/ manuals/ tools/ report-template/ deploy/server/)
#         + Linux x86_64 wheel(PyYAML, lxml, psycopg2-binary, python 3.9~3.13)
#         + (있으면) deploy/server/pkgs/<os>/ 의 OS 패키지(fetch_os_packages.sh 로 같은 OS 에서 미리 수집)
# Windows(Git Bash)에서 실행해도 Linux 용 wheel 을 받도록 --platform 을 지정한다.
set -euo pipefail
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
STAMP="$(date +%Y.%m.%d)"
WHEELS="$SRC_DIR/deploy/server/wheels"
mkdir -p "$WHEELS"
rm -f "$WHEELS"/*.whl "$WHEELS"/*.tar.gz 2>/dev/null || true
for PY in 39 310 311 312 313; do
  for PKG in PyYAML lxml psycopg2-binary; do
    pip download "$PKG" --only-binary :all: --no-deps --platform manylinux2014_x86_64 --python-version "$PY" -d "$WHEELS" >/dev/null 2>&1 \
      || pip download "$PKG" --only-binary :all: --no-deps --platform manylinux_2_17_x86_64 --python-version "$PY" -d "$WHEELS" >/dev/null 2>&1 || true
  done
done
echo "[wheels] $(ls "$WHEELS" | wc -l)개:"; ls "$WHEELS"
[ -d "$SRC_DIR/deploy/server/pkgs" ] && echo "[pkgs] $(find "$SRC_DIR/deploy/server/pkgs" -type f | wc -l)개 OS 패키지 포함" || echo "[pkgs] 없음 — 폐쇄망 서버에 nginx/postgresql/python3 가 없다면 같은 OS 인터넷 PC 에서 fetch_os_packages.sh 실행 후 재생성"
# 사내 양식(HWP·layout) 반출 차단
# 허용: 공식 서식 form_status.hwpx / form_postmortem.hwpx (기관명·인명 없음). 그 외 HWP·master*·layout* 은 반출 금지
if find "$SRC_DIR/report-template" -path '*/custom' -prune -o \( -iname '*.hwp*' ! -name 'form_status.hwpx' ! -name 'form_postmortem.hwpx' \) -print -o -iname 'layout*.json' -print 2>/dev/null | grep -q .; then
  echo "[중단] report-template 에 허용되지 않은 HWP/layout 파일이 있습니다 — 기관명 포함 양식은 반출 금지"; exit 1
fi
for f in form_status.hwpx form_postmortem.hwpx; do
  if [ -f "$SRC_DIR/report-template/$f" ] && unzip -p "$SRC_DIR/report-template/$f" Contents/section0.xml | grep -Eq '기관명[[:space:]]*[:：][[:space:]]*[^[:space:]<)]'; then
    echo "[중단] 서식에 기관명이 채워져 있습니다: $f"; exit 1
  fi
done
OUT="$SRC_DIR/../logtriage-server-$STAMP.tar.gz"
tar -czf "$OUT" -C "$SRC_DIR/.." \
    --exclude='engine/deploy/local/build' --exclude='engine/deploy/local/dist' --exclude='engine/incidents' --exclude='engine/incidents.json' \
    --exclude='engine/uploads' --exclude='engine/reports' --exclude='engine/collect' --exclude='engine/samples' --exclude='engine/data' \
    --exclude='engine/.claude' --exclude='engine/report-template/report_profile.json' --exclude='engine/report-template/custom' --exclude='__pycache__' --exclude='*.pyc' engine
echo "[완료] $OUT ($(du -h "$OUT" | cut -f1)) — 폐쇄망 반입 후: tar xzf → sudo bash engine/deploy/server/install.sh"
