#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  LogTriage 서버형 — 오픈소스 스택(nginx + Python 앱서버 + PostgreSQL/SQLite) 즉시 설치
#  OS 만 설치된 Linux(RHEL/Rocky/AlmaLinux/CentOS Stream 8·9, Ubuntu 20.04~24.04, Debian 11~12)에서 실행
#
#  사용:  sudo bash install.sh [옵션]
#    --db postgres|sqlite    저장소 선택 (기본: postgres 가 설치 가능하면 postgres, 아니면 sqlite)
#    --tls                   nginx 에 자체 서명 인증서(443) 구성 + 80→443 리다이렉트
#    (공용 비밀번호는 명령행으로 받지 않습니다 — 무작위로 만들어 /etc/logtriage/server.env 에만 적습니다)
#    --port <n>              앱(WAS) 포트(기본 8088, nginx 가 80/443 으로 대행)
#    --allow-dir <경로>      서버 로컬 로그 디렉터리(반복 가능, 기본 /var/log)
#    --offline               인터넷 없이 pkgs/<os>/ 와 wheels/ 만으로 설치(폐쇄망) — 번들에 pkgs 가 있으면 자동
#    --no-nginx              nginx 생략(앱을 0.0.0.0 에 직접 노출)
#    --no-firewall           방화벽(firewalld/ufw) 포트 개방 생략
#    --journal-access        서비스 계정에 adm/systemd-journal 그룹 부여(서버 전체 로그 읽기 — 필요할 때만)
#  환경변수: INSTALL_DIR(/opt/logtriage) SVC_USER(logtriage)
#  로그: /var/log/logtriage-install.log
# ══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/logtriage}"
SVC_USER="${SVC_USER:-logtriage}"
SRC_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
DB_CHOICE=""; TLS=0; PASSWORD=""; APP_PORT=8088; PORT_SET=0; ALLOW_DIRS=(); OFFLINE=0; USE_NGINX=1; FIREWALL=1; JOURNAL=0; SKIP_PKGS=0
LOG=/var/log/logtriage-install.log

while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB_CHOICE="$2"; shift 2;;
    --tls) TLS=1; shift;;
    --password|--password=*)   # 명령행은 ps · /proc/<PID>/cmdline · 셸 기록으로 누구나 본다(RHEL 검증 매뉴얼 작성 중, GPT 177)
      echo "비밀번호를 명령행 인자로 받지 않습니다 — --password 를 빼고 다시 실행하십시오."
      echo "  설치는 무작위 공용 비밀번호를 /etc/logtriage/server.env(root · 서비스 그룹만 읽기)에만 적습니다."
      echo "  바꾸려면 설치 뒤:  sudo vi /etc/logtriage/server.env  (LOGTRIAGE_PASSWORD=…)  →  sudo systemctl restart logtriage-server"
      exit 1;;
    --port) APP_PORT="$2"; PORT_SET=1; shift 2;;
    --allow-dir) ALLOW_DIRS+=("$2"); shift 2;;
    --offline) OFFLINE=1; shift;;
    --skip-pkgs) SKIP_PKGS=1; shift;;   # OS 패키지(rpm/deb) 단계 생략 — python·nginx·postgres 가 이미 있거나 동봉 Python 사용
    --no-nginx) USE_NGINX=0; shift;;
    --no-firewall) FIREWALL=0; shift;;
    --journal-access) JOURNAL=1; shift;;
    -h|--help) sed -n 2,20p "$0"; exit 0;;
    *) echo "알 수 없는 옵션: $1"; exit 1;;
  esac
done
ALLOW_SET=${#ALLOW_DIRS[@]}   # 0 이면 다시 설치할 때 예전 server.env 의 값을 이어 쓴다(23차)
[ ${#ALLOW_DIRS[@]} -eq 0 ] && ALLOW_DIRS=(/var/log)
[ "$(id -u)" -eq 0 ] || { echo "root 권한이 필요합니다: sudo bash install.sh"; exit 1; }
# 설치 기록은 root 만 읽는다(GPT 177) — 전에는 0644 에 공용 비밀번호까지 찍혀 서버의 모든 계정이 읽었다.
# 링크 · 일반 파일이 아닌 것이면 그 대상에 쓰게 되므로 멈춘다. 예전 기록이 있으면 권한부터 줄이고 비밀번호 교체를 알린다.
if [ -L "$LOG" ] || { [ -e "$LOG" ] && [ ! -f "$LOG" ]; }; then
  echo "$LOG 가 일반 파일이 아닙니다(링크 등) — 확인 후 지우고 다시 실행하십시오"; exit 1
fi
OLDLOG_PW=0; [ -f "$LOG" ] && grep -q '비밀번호 : ' "$LOG" 2>/dev/null && OLDLOG_PW=1
( umask 077; : >> "$LOG" ); chown root:root "$LOG"; chmod 600 "$LOG"
exec > >(tee -a "$LOG") 2>&1
[ "$OLDLOG_PW" = 1 ] && echo "  ! 예전 설치 기록($LOG)에 공용 비밀번호가 적혀 있었습니다 — 권한은 지금 0600 으로 줄였습니다. 그 기록을 다른 계정이 읽었을 수 있으니 server.env 의 LOGTRIAGE_PASSWORD 를 바꾸십시오."
echo "══ LogTriage 서버 설치 시작 $(date '+%F %T') ══  src=$SRC_DIR  dest=$INSTALL_DIR"

# ── 0. OS 판별 ────────────────────────────────────────────────────────────────
. /etc/os-release
OS_ID="${ID:-unknown}"; OS_VER="${VERSION_ID%%.*}"
case "$OS_ID" in
  rhel|rocky|almalinux|centos|ol) FAM=rhel; PKG=dnf; command -v dnf >/dev/null || PKG=yum;;
  ubuntu|debian) FAM=deb; PKG=apt-get;;
  *) echo "지원하지 않는 OS: $OS_ID (RHEL 계열 또는 Debian/Ubuntu 필요)"; exit 1;;
esac
PKGDIR="$HERE/pkgs/${OS_ID}${OS_VER}"
[ -d "$PKGDIR" ] && OFFLINE=1
echo "[OS] $PRETTY_NAME → 계열=$FAM 패키지=$PKG 오프라인=$OFFLINE ${OFFLINE:+pkgs=$PKGDIR}"

# ── 1. OS 패키지 (WEB=nginx, DBMS=postgresql, python3) ───────────────────────
pkg_install() {  # $@ = 패키지명
  if [ "$OFFLINE" = 1 ]; then
    # 이미 갖춰진 서버(python·nginx·postgres 설치됨)면 오프라인 패키지 설치를 건너뛴다 — 버전 충돌(Failed dependencies) 방지
    local have=1
    command -v "$PYBIN" >/dev/null 2>&1 || have=0
    [ "$USE_NGINX" = 1 ] && { command -v nginx >/dev/null 2>&1 || have=0; }
    [ "$WANT_PG" = 1 ] && { command -v initdb >/dev/null 2>&1 || command -v postgresql-setup >/dev/null 2>&1 || command -v pg_ctlcluster >/dev/null 2>&1 || ls /usr/pgsql-*/bin/initdb >/dev/null 2>&1 || have=0; }
    if [ "$have" = 1 ]; then echo "  필요한 OS 패키지가 이미 설치되어 있어 pkgs/ 설치를 건너뜁니다"; return 0; fi
    if [ "$FAM" = rhel ]; then
      ls "$PKGDIR"/*.rpm >/dev/null 2>&1 || { echo "오프라인 패키지 없음: $PKGDIR/*.rpm — fetch_os_packages.sh 로 준비"; return 1; }
      # 이미 설치된 이름의 패키지(예: postgresql 15.6)는 rpm 을 건너뛴다 — 다른 빌드로 덮어쓰면 'Failed dependencies' 충돌
      local todo=() f n
      for f in "$PKGDIR"/*.rpm; do
        n=$(rpm -qp --nosignature --queryformat '%{NAME}' "$f" 2>/dev/null) || continue
        if rpm -q "$n" >/dev/null 2>&1; then echo "  - $n 이미 설치됨 → 건너뜀"; continue; fi
        todo+=("$f")
      done
      if [ ${#todo[@]} -eq 0 ]; then echo "  pkgs/ 의 패키지가 모두 설치되어 있어 건너뜁니다"; return 0; fi
      echo "  설치 대상 rpm ${#todo[@]}개"
      $PKG install -y --disablerepo='*' --nogpgcheck --skip-broken "${todo[@]}" \
        || rpm -ivh --nosignature "${todo[@]}" \
        || { echo "  ! 오프라인 rpm 설치에서 일부 실패 — 이미 설치된 구성요소로 계속 진행합니다(아래 python/nginx/postgres 여부 확인)"; }
    else
      ls "$PKGDIR"/*.deb >/dev/null 2>&1 || { echo "오프라인 패키지 없음: $PKGDIR/*.deb — fetch_os_packages.sh 로 준비"; return 1; }
      DEBIAN_FRONTEND=noninteractive dpkg -i "$PKGDIR"/*.deb || DEBIAN_FRONTEND=noninteractive apt-get -f install -y --no-download
    fi
  else
    if [ "$FAM" = rhel ]; then $PKG install -y "$@"; else
      DEBIAN_FRONTEND=noninteractive apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; fi
  fi
}
echo "[1/8] OS 패키지 설치"
if [ "$FAM" = rhel ]; then
  PY_PKGS="python3.11 python3.11-pip"; PYBIN=python3.11
  [ "$OS_VER" -ge 9 ] 2>/dev/null && { PY_PKGS="python3 python3-pip"; PYBIN=python3; }
  BASE_PKGS="$PY_PKGS tar gzip openssl policycoreutils-python-utils"
  [ "$USE_NGINX" = 1 ] && BASE_PKGS="$BASE_PKGS nginx"
  PG_PKGS="postgresql-server postgresql"
else
  PYBIN=python3
  BASE_PKGS="python3 python3-venv python3-pip tar gzip openssl"
  [ "$USE_NGINX" = 1 ] && BASE_PKGS="$BASE_PKGS nginx"
  PG_PKGS="postgresql postgresql-contrib"
fi
# 저장소 결정: 명시 없으면 postgres 시도, 실패 시 sqlite
WANT_PG=0
if [ -z "$DB_CHOICE" ] || [ "$DB_CHOICE" = postgres ]; then WANT_PG=1; fi
if [ "$SKIP_PKGS" = 1 ]; then
  echo "  --skip-pkgs: OS 패키지 설치 단계를 건너뜁니다(이미 설치된 python/nginx/postgres 또는 동봉 Python 사용)"
elif [ "$OFFLINE" = 1 ]; then
  pkg_install   # 디렉터리의 모든 패키지 설치(nginx·postgresql·python 포함)
else
  pkg_install $BASE_PKGS
  if [ "$WANT_PG" = 1 ]; then pkg_install $PG_PKGS || { echo "  ! PostgreSQL 설치 실패 → SQLite 로 진행"; WANT_PG=0; }; fi
fi
# >>> 파이썬 고르기 (23차, RHEL 검증 매뉴얼 작성 중 발견)
# 엔진은 3.10 이상이고 동봉 wheel 은 3.11(cp311)용이 빠짐없이 있다(cffi 는 cp311 뿐). 그래서 3.11 을 먼저 쓴다.
# 전에는 RHEL 9 에서 시스템 python3(3.9)를 고른 뒤 '3.10 이상 필요' 로 멈췄다 — 동봉 Python 은 run.sh 를 먼저 돌려
# 풀어 둔 경우에만 쓰였다. 이제 서버 묶음의 python-3.11-linux-x86_64.tar.gz 를 설치 폴더에 직접 푼다.
pyok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; }
PICK=""
for cand in python3.11 "$INSTALL_DIR/python/bin/python3.11" "$SRC_DIR/../python/bin/python3.11"; do
  if command -v "$cand" >/dev/null 2>&1 && pyok "$cand"; then PICK="$cand"; break; fi
done
if [ -z "$PICK" ]; then
  for TGZ in "$SRC_DIR/../python-3.11-linux-x86_64.tar.gz" "$SRC_DIR/python-3.11-linux-x86_64.tar.gz"; do
    [ -f "$TGZ" ] || continue
    echo "  python3.11 없음 → 동봉 Python 3.11 을 $INSTALL_DIR/python 에 풉니다"
    mkdir -p "$INSTALL_DIR"; rm -rf "$INSTALL_DIR/python"
    tar xzf "$TGZ" -C "$INSTALL_DIR" || { echo "  ! 동봉 Python 압축 해제 실패 — 디스크 여유 · noexec 마운트 확인"; exit 1; }
    pyok "$INSTALL_DIR/python/bin/python3.11" && PICK="$INSTALL_DIR/python/bin/python3.11"
    break
  done
fi
if [ -z "$PICK" ]; then   # 동봉본이 없으면 3.10 이상인 시스템 파이썬(이때 wheel 은 그 판에 맞는 것이 있어야 함)
  for cand in python3.12 python3.13 python3.10 python3; do
    if command -v "$cand" >/dev/null 2>&1 && pyok "$cand"; then PICK="$cand"; break; fi
  done
fi
[ -n "$PICK" ] || { echo "python 3.10 이상을 찾지 못했습니다 — 서버 묶음(logtriage-server-1.0.0.zip)을 통째로 풀어 그 안의 install.sh 로 설치하면 동봉 Python 3.11 을 씁니다"; exit 1; }
PYBIN="$PICK"
# <<< 파이썬 고르기
PYV=$("$PYBIN" -c 'import sys;print("%d.%d"%sys.version_info[:2])')
"$PYBIN" -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' || { echo "python $PYV — 3.10 이상 필요"; exit 1; }
echo "  python=$PYBIN($PYV) nginx=$(command -v nginx >/dev/null && echo yes || echo no) postgres=$(command -v postgres >/dev/null 2>&1 || ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1 || ls /usr/pgsql-*/bin/postgres >/dev/null 2>&1 && echo yes || echo no)"
if [ "$WANT_PG" = 1 ] && ! { command -v initdb >/dev/null 2>&1 || command -v postgresql-setup >/dev/null 2>&1 || command -v pg_ctlcluster >/dev/null 2>&1; }; then
  echo "  ! PostgreSQL 실행 파일 없음 → SQLite 로 진행"; WANT_PG=0
fi
[ "$DB_CHOICE" = sqlite ] && WANT_PG=0

# ── 2. 앱 파일 ────────────────────────────────────────────────────────────────
echo "[2/8] 앱 설치: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
for d in logtriage rules errorcodes manuals tools report-template samples; do
  [ -d "$SRC_DIR/$d" ] && { rm -rf "$INSTALL_DIR/$d"; cp -r "$SRC_DIR/$d" "$INSTALL_DIR/"; }
done
mkdir -p "$INSTALL_DIR/rules-local" "$INSTALL_DIR/incidents" "$INSTALL_DIR/uploads" "$INSTALL_DIR/reports" "$INSTALL_DIR/data" "$INSTALL_DIR/backup"
cp "$SRC_DIR/deploy/local/사용법.txt" "$INSTALL_DIR/" 2>/dev/null || true
cp "$HERE/설치매뉴얼.md" "$HERE/README.md" "$HERE/backup.sh" "$HERE/uninstall.sh" "$HERE/check_install.sh" "$INSTALL_DIR/" 2>/dev/null || true
find "$INSTALL_DIR" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

echo "[3/8] 파이썬 가상환경 + 의존성(PyYAML, lxml$( [ "$WANT_PG" = 1 ] && echo ', psycopg2-binary'))"
[ -x "$INSTALL_DIR/venv/bin/python" ] || "$PYBIN" -m venv "$INSTALL_DIR/venv"
PIP="$INSTALL_DIR/venv/bin/pip"
PYDEPS="PyYAML lxml cryptography"; [ "$WANT_PG" = 1 ] && PYDEPS="$PYDEPS psycopg2-binary"   # lxml = HWPX 보고서 서식 처리, cryptography = 검증된 암호 구현(없으면 자체 구현으로 동작하나 권장하지 않음)
# wheel 폴더 탐색: deploy/server/wheels → 패키지 최상위 wheels(구동 테스트 zip) → engine/../wheels
WHEELS=""
for cand in "$HERE/wheels" "$SRC_DIR/../wheels" "$SRC_DIR/wheels" "$(dirname "$SRC_DIR")/wheels"; do
  if [ -d "$cand" ] && ls "$cand"/*.whl >/dev/null 2>&1; then WHEELS="$cand"; break; fi
done
if [ -n "$WHEELS" ]; then
  echo "  wheel 폴더: $WHEELS (오프라인 설치)"
  "$PIP" install -q --no-index --find-links "$WHEELS" $PYDEPS || { echo "  ! wheels 에서 설치 실패 — 파이썬 $PYV 용 wheel(cp${PYV/./}) 이 $WHEELS 에 있는지 확인"; ls "$WHEELS" | sed 's/^/     /'; exit 1; }
else
  [ "$OFFLINE" = 1 ] && { echo "  ! 오프라인인데 wheels 폴더가 없습니다 (번들의 deploy/server/wheels 또는 패키지 최상위 wheels)"; exit 1; }
  echo "  wheel 폴더 없음 → PyPI 에서 설치 시도(인터넷 필요, 10초 제한)"
  "$PIP" install -q --timeout 10 --retries 1 $PYDEPS || { echo "  ! PyPI 접속 실패 — 폐쇄망이면 wheel 이 포함된 번들(make_offline_bundle.sh 산출물)로 다시 설치하십시오"; exit 1; }
fi
"$INSTALL_DIR/venv/bin/python" -c "import yaml, lxml.etree" || { echo "  ! 파이썬 의존성 확인 실패(PyYAML/lxml)"; exit 1; }

# ── 3. 서비스 계정 ────────────────────────────────────────────────────────────
echo "[4/8] 서비스 계정·권한 ($SVC_USER)"
id -u "$SVC_USER" >/dev/null 2>&1 || useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null || useradd --system --home "$INSTALL_DIR" --shell /sbin/nologin "$SVC_USER"
chown -R "$SVC_USER":"$SVC_USER" "$INSTALL_DIR"
# 12차(GPT 93차): 코드·합성 견본은 서비스 계정이 고칠 수 없게 root 소유·읽기 전용 — 패치(apply_patch.sh)와 같은 규칙.
# 견본 폴더를 서비스 계정이 쓸 수 있으면 '견본으로 30초 체험' 경로를 링크로 바꿔치기할 여지가 생긴다(분석은 지문 확인한 바이트만 쓰지만 이중으로 막는다)
# 23차: 동봉 Python(python/)도 — venv 가 이 인터프리터 · 표준 라이브러리를 쓰고, root 도 점검 도구로 이것을 돌린다
for d in logtriage tools samples python; do
  [ -d "$INSTALL_DIR/$d" ] && { chown -R root:root "$INSTALL_DIR/$d"; chmod -R a+rX,go-w "$INSTALL_DIR/$d"; }
done
# 23차: root 가 sudo 로 돌리는 관리 스크립트도 root 소유 — 서비스 계정 소유면 서비스가 뚫렸을 때 그 파일을 고쳐 두고
# 관리자의 다음 sudo 실행을 기다릴 수 있다(권한 상승 통로). sticky 설치 폴더라 root 소유 파일은 이름 바꾸기 · 지우기도 못 한다
for f in backup.sh uninstall.sh check_install.sh 설치매뉴얼.md README.md 사용법.txt; do
  [ -f "$INSTALL_DIR/$f" ] || continue
  chown root:root "$INSTALL_DIR/$f"; case "$f" in *.sh) chmod 755 "$INSTALL_DIR/$f";; *) chmod 644 "$INSTALL_DIR/$f";; esac
done
# GPT 94차 P0(조건부): 설치 폴더 자체가 서비스 계정 소유면 그 계정이 root 소유 하위 폴더(코드·견본)를 이름 바꿔 통째로 갈아 끼울 수 있다.
# 설치 폴더는 root:서비스그룹 + sticky(1770) — 서비스는 자기 파일(지식 세대 기록·룰팩 교체 폴더·자료)은 만들고 바꾸지만,
# root 소유 항목(logtriage·tools·samples)은 이름 바꾸기·지우기를 못 한다
chown root:"$SVC_USER" "$INSTALL_DIR"
chmod 1770 "$INSTALL_DIR"
# GPT 95차 P0: sticky 라도 서비스는 설치 폴더에 새 파일을 만들 수 있다 — 그 폴더가 import 경로(작업 폴더)면 yaml.py 같은 가짜 모듈이
# 진짜보다 먼저 잡힌다. 작업 폴더는 root 소유 import 전용 폴더(venv/lt-import: logtriage 링크 하나뿐), venv 도 root 소유
# (전에는 venv 를 만든 뒤 설치 폴더 전체를 서비스 계정 소유로 바꿔 site-packages 까지 서비스가 고칠 수 있었다)
mkdir -p "$INSTALL_DIR/venv/lt-import"
ln -sfn "$INSTALL_DIR/logtriage" "$INSTALL_DIR/venv/lt-import/logtriage"
chown -R root:root "$INSTALL_DIR/venv"; chmod -R go-w "$INSTALL_DIR/venv"
# 바이트코드는 root 가 미리 만든다(서비스 계정은 __pycache__ 를 못 쓰므로 — 쓰면 그 자체가 가로채기 통로)
"$INSTALL_DIR/venv/bin/python" -E -s -m compileall -q "$INSTALL_DIR/logtriage" >/dev/null 2>&1 || true
# GPT 96차: 실제로 서비스 계정·서비스와 같은 실행 방식으로 import 경로를 띄워 본다 — 서비스가 쓸 수 있는 경로(sys.path 의 폴더·
# .pth 가 더한 폴더 포함)나 logtriage 패키지 파일이 하나라도 있으면 설치를 멈춘다
IMPORT_CHECK='import sys, os
bad = [p for p in (q or os.getcwd() for q in sys.path) if os.path.isdir(p) and os.access(p, os.W_OK)]
import logtriage
pk = os.path.dirname(os.path.realpath(logtriage.__file__))
for r, ds, fs in os.walk(pk):
    for n in ds + fs:
        q = os.path.join(r, n)
        if os.access(q, os.W_OK):
            bad.append(q)
print("  import 경로 점검(서비스 계정): 서비스가 쓸 수 있는 곳", len(bad))
for b in bad[:10]:
    print("    ", b)
sys.exit(1 if bad else 0)'
( cd "$INSTALL_DIR/venv/lt-import" && runuser -u "$SVC_USER" -- "$INSTALL_DIR/venv/bin/python" -E -s -c "$IMPORT_CHECK" ) \
  || { echo "  ! 서비스 계정이 고칠 수 있는 import 경로가 있습니다 — 위 목록의 소유·권한을 root·go-w 로 바로잡은 뒤 다시 설치하십시오"; exit 1; }
# 인프라 감시(ICMP): systemd 보안 옵션(NoNewPrivileges·CapabilityBoundingSet=) 아래에서는 ping 이 file capability 를 얻지 못하므로
# 서비스 그룹에 ICMP Echo datagram 소켓을 허용한다(범위를 서비스 GID 하나로 한정). TCP 검사는 이 설정과 무관.
if command -v sysctl >/dev/null 2>&1 && [ -d /etc/sysctl.d ]; then
  SVC_GID="$(id -g "$SVC_USER" 2>/dev/null || true)"
  if [ -n "$SVC_GID" ]; then
    printf 'net.ipv4.ping_group_range = %s %s\n' "$SVC_GID" "$SVC_GID" > /etc/sysctl.d/90-logtriage-ping.conf
    sysctl -q --system >/dev/null 2>&1 || sysctl -q -w "net.ipv4.ping_group_range=$SVC_GID $SVC_GID" || true
    echo "  ICMP 감시: net.ipv4.ping_group_range=$(sysctl -n net.ipv4.ping_group_range 2>/dev/null)  (/etc/sysctl.d/90-logtriage-ping.conf)"
  fi
fi
# 서버 로컬 로그 읽기: 기본은 --allow-dir 화이트리스트 + 파일별 ACL(설치매뉴얼 3.1). 전체 로그 그룹은 --journal-access 때만.
if [ "$JOURNAL" = 1 ]; then
  for g in adm systemd-journal; do getent group $g >/dev/null && usermod -aG $g "$SVC_USER" || true; done
  echo "  (--journal-access) $SVC_USER 에 adm/systemd-journal 그룹 부여"
fi

# ── 4. DBMS ───────────────────────────────────────────────────────────────────
mkdir -p /etc/logtriage; chmod 750 /etc/logtriage
DB_URL="sqlite:///$INSTALL_DIR/data/logtriage.db"
if [ "$WANT_PG" = 1 ]; then
  echo "[5/8] PostgreSQL 초기화·기동·DB/계정 생성"
  PGPASS="$(openssl rand -hex 12)"
  if [ "$FAM" = rhel ]; then
    PGDATA_DIR=/var/lib/pgsql/data
    [ -f "$PGDATA_DIR/PG_VERSION" ] || postgresql-setup --initdb >/dev/null
    systemctl enable --now postgresql
  else
    # Debian/Ubuntu: 패키지가 postgresql-common 방식으로 cluster(main)를 만든다. 없으면 생성.
    if command -v pg_lsclusters >/dev/null 2>&1 && ! pg_lsclusters -h 2>/dev/null | grep -q .; then
      PGV=$(ls /usr/lib/postgresql | sort -V | tail -1); pg_createcluster "$PGV" main >/dev/null
    fi
    systemctl enable --now postgresql
  fi
  # 잠시 대기 후 접속 확인(5432 LISTEN)
  for i in 1 2 3 4 5 6 7 8 9 10; do sudo -u postgres psql -qtAc 'select 1' >/dev/null 2>&1 && break; sleep 1; done
  sudo -u postgres psql -qtAc 'select 1' >/dev/null 2>&1 || { echo "  ! PostgreSQL 접속 실패 — systemctl status postgresql / pg_lsclusters 확인"; exit 1; }
  # 비밀번호 저장·인증은 SCRAM-SHA-256 (PG10+). 역할 생성 전에 적용
  sudo -u postgres psql -qc "ALTER SYSTEM SET password_encryption = 'scram-sha-256';" >/dev/null
  sudo -u postgres psql -qc "SELECT pg_reload_conf();" >/dev/null
  sed "s/__PASSWORD__/$PGPASS/g" "$HERE/postgres/init.sql" | sudo -u postgres psql -v ON_ERROR_STOP=1 -q -f - >/dev/null
  # pg_hba: logtriage 역할만 127.0.0.1 에서 scram 로그인 허용(기본 ident/peer 규칙보다 앞에 삽입)
  HBA=$(sudo -u postgres psql -qtAc 'show hba_file' | tr -d ' ')
  if [ -n "$HBA" ] && ! grep -qE '^host\s+logtriage\s+logtriage\s' "$HBA"; then
    cp "$HBA" "$HBA.bak.$(date +%Y%m%d%H%M%S)"
    LN=$(grep -nE '^(local|host|hostssl|hostnossl)\s' "$HBA" | head -1 | cut -d: -f1)
    RULE="host    logtriage       logtriage       127.0.0.1/32            scram-sha-256"
    if [ -n "$LN" ]; then sed -i "${LN}i $RULE" "$HBA"; else echo "$RULE" >> "$HBA"; fi
    sudo -u postgres psql -qc "SELECT pg_reload_conf();" >/dev/null
  fi
  DB_URL="postgresql://logtriage:$PGPASS@127.0.0.1:5432/logtriage"
  # 실제 로그인 검증(앱과 같은 방식) — 실패 시 중단
  "$INSTALL_DIR/venv/bin/python" -c "import psycopg2,sys; psycopg2.connect(sys.argv[1]).close()" "$DB_URL"     || { echo "  ! logtriage 계정으로 PostgreSQL 로그인 실패 — $HBA 의 127.0.0.1 규칙 확인"; exit 1; }
  echo "  DB=logtriage 계정=logtriage (비밀번호는 /etc/logtriage/server.env 에만 기록)"
else
  echo "[5/8] 저장소: SQLite ($INSTALL_DIR/data/logtriage.db)"
fi

# ── 5. 앱 설정 + systemd ─────────────────────────────────────────────────────
echo "[6/8] 앱 설정(/etc/logtriage/server.env) + systemd(logtriage-server)"
[ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-12)"
ALLOW_ARG=""; for d in "${ALLOW_DIRS[@]}"; do ALLOW_ARG="$ALLOW_ARG --allow-dir $d"; done
APP_HOST=127.0.0.1; [ "$USE_NGINX" = 1 ] || APP_HOST=0.0.0.0
if [ -f /etc/logtriage/server.env ]; then
  # 권한을 지켜서 복사한다. 그냥 cp 하면 umask 를 따라 0644 가 되는데, 이 파일에는
  # **비밀번호가 들어 있다**(GPT 20차에 걸려 드러났다).
  install -m 600 -o root -g root /etc/logtriage/server.env           "/etc/logtriage/server.env.bak.$(date +%Y%m%d%H%M%S)"
  # 기존 비밀번호 유지, DB/포트/허용경로만 갱신
  OLDPW=$(grep -E '^LOGTRIAGE_PASSWORD=' /etc/logtriage/server.env | cut -d= -f2- || true)
  [ -n "$OLDPW" ] && [ "$OLDPW" != "change-me" ] && PASSWORD="$OLDPW"
  OLDDB=$(grep -E '^LOGTRIAGE_DB=' /etc/logtriage/server.env | cut -d= -f2- || true)
  [ -n "$OLDDB" ] && [ "$WANT_PG" = 0 ] && DB_URL="$OLDDB"
  OLDPS=$(grep -E '^LOGTRIAGE_PROXY_SECRET=' /etc/logtriage/server.env | cut -d= -f2- || true)
  # 23차: 다시 설치(패치 뒤 앞단 비밀 넣기 등)할 때 --port · --allow-dir 를 안 주면 예전 값을 그대로 — 전에는 8088 · /var/log 로 되돌아갔다
  OLDPORT=$(grep -E '^LOGTRIAGE_PORT=' /etc/logtriage/server.env | cut -d= -f2- || true)
  [ "$PORT_SET" = 0 ] && [ -n "$OLDPORT" ] && case "$OLDPORT" in *[!0-9]*) ;; *) APP_PORT="$OLDPORT";; esac
  OLDALLOW=$(grep -E '^LOGTRIAGE_ALLOW=' /etc/logtriage/server.env | cut -d= -f2- || true)
  [ "$ALLOW_SET" = 0 ] && [ -n "$OLDALLOW" ] && ALLOW_ARG="$OLDALLOW"
fi
# nginx ↔ 앱 비밀(GPT 177): 앱은 이 값을 실어 온 루프백 요청의 X-Real-IP 만 접속자 주소로 믿는다. 다시 설치해도 그대로 쓴다
PROXY_SECRET="${OLDPS:-}"; [ "${#PROXY_SECRET}" -ge 32 ] || PROXY_SECRET="$(openssl rand -hex 32)"
( umask 077; cat > /etc/logtriage/server.env <<EOF
# LogTriage 서버형 환경설정 — install.sh 가 $(date '+%F %T') 에 생성
LOGTRIAGE_HOST=$APP_HOST
LOGTRIAGE_PORT=$APP_PORT
LOGTRIAGE_PASSWORD=$PASSWORD
LOGTRIAGE_DB=$DB_URL
LOGTRIAGE_ALLOW=$ALLOW_ARG
# nginx 가 X-LogTriage-Proxy 머리글로 같은 값을 보낸다(/etc/nginx/conf.d/logtriage.conf, root 만 읽기). 바꾸면 두 곳을 함께
LOGTRIAGE_PROXY_SECRET=$PROXY_SECRET
# 업로드 원본(개인정보 포함 가능) 보존 일수 — logtriage-cleanup.timer 가 매일 삭제
LOGTRIAGE_UPLOAD_KEEP_DAYS=${LOGTRIAGE_UPLOAD_KEEP_DAYS:-14}
EOF
)
chmod 640 /etc/logtriage/server.env; chown root:"$SVC_USER" /etc/logtriage/server.env
cat > /usr/local/bin/logtriage <<EOF
#!/usr/bin/env bash
cd "$INSTALL_DIR/venv/lt-import" && exec "$INSTALL_DIR/venv/bin/python" -E -s -m logtriage "\$@"
EOF
cat > /usr/local/bin/logtriage-server <<EOF
#!/usr/bin/env bash
set -a; [ -f /etc/logtriage/server.env ] && . /etc/logtriage/server.env; set +a
cd "$INSTALL_DIR/venv/lt-import" && exec "$INSTALL_DIR/venv/bin/python" -E -s -m logtriage.server --base "$INSTALL_DIR" "\$@"
EOF
chmod +x /usr/local/bin/logtriage /usr/local/bin/logtriage-server
sed "s#/opt/logtriage#$INSTALL_DIR#g; s#User=logtriage#User=$SVC_USER#; s#Group=logtriage#Group=$SVC_USER#" \
    "$HERE/logtriage-server.service" > /etc/systemd/system/logtriage-server.service
sed "s#/opt/logtriage#$INSTALL_DIR#g; s#User=logtriage#User=$SVC_USER#" "$HERE/logtriage-cleanup.service" > /etc/systemd/system/logtriage-cleanup.service
cp "$HERE/logtriage-cleanup.timer" /etc/systemd/system/logtriage-cleanup.timer
systemctl daemon-reload
systemctl enable logtriage-server >/dev/null 2>&1 || true
systemctl enable --now logtriage-cleanup.timer >/dev/null 2>&1 || true
systemctl restart logtriage-server
sleep 2
if ! systemctl is-active --quiet logtriage-server; then
  echo "  ! 앱 서비스 기동 실패 — journalctl -u logtriage-server -n 50"; journalctl -u logtriage-server -n 30 --no-pager || true; exit 1
fi

# ── 6. nginx ─────────────────────────────────────────────────────────────────
if [ "$USE_NGINX" = 1 ]; then
  echo "[7/8] nginx 리버스 프록시 구성"
  # >>> HTTPS 유지 (23차, GPT 180): 다시 설치할 때 --tls 를 빠뜨려도 이미 켠 HTTPS 를 평문으로 내리지 않는다
  if [ "$TLS" = 0 ] && [ -f /etc/logtriage/tls/server.crt ]; then
    for c in /etc/nginx/conf.d/logtriage.conf /etc/nginx/sites-available/logtriage; do
      if [ -f "$c" ] && grep -qE '^[[:space:]]*listen[[:space:]]+443[[:space:]]+ssl' "$c"; then
        TLS=1; echo "  기존 설치가 HTTPS(--tls)라 그대로 유지합니다 — 내리려면 $c 와 /etc/logtriage/tls 를 직접 정리한 뒤 다시 설치"; break
      fi
    done
  fi
  # <<< HTTPS 유지
  CONF="$(mktemp)"; sed "s#127.0.0.1:8088#127.0.0.1:$APP_PORT#; s#__PROXY_SECRET__#$PROXY_SECRET#g" "$HERE/nginx/logtriage.conf" > "$CONF"
  if [ "$TLS" = 1 ]; then
    mkdir -p /etc/logtriage/tls
    if [ ! -f /etc/logtriage/tls/server.crt ]; then
      openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=$(hostname -f 2>/dev/null || hostname)/O=LogTriage" \
        -keyout /etc/logtriage/tls/server.key -out /etc/logtriage/tls/server.crt >/dev/null 2>&1
      chmod 600 /etc/logtriage/tls/server.key
    fi
    # TLS 블록 주석 해제 + 80 → 443 리다이렉트
    sed -i '/__TLS_BLOCK_BEGIN__/,/__TLS_BLOCK_END__/s/^# \{0,1\}//' "$CONF"
    # 구분자는 | — 찾는 글에 # 이 들어 있어 # 로 쓰면 sed 가 'unknown option to s' 로 멈췄다(--tls 설치가 nginx 단계에서 중단, 23차 모의 실행에서 발견)
    sed -i 's|^\s*# __TLS_REDIRECT__.*|    return 301 https://$host$request_uri;|' "$CONF"
  fi
  if [ "$FAM" = rhel ]; then
    install -m 600 -o root -g root "$CONF" /etc/nginx/conf.d/logtriage.conf   # 앞단 비밀이 들어 있다 — root 만(nginx 주 프로세스가 root 로 읽음)
    # 기본 server 블록(80)이 있으면 충돌 방지: default_server 비활성화
    [ -f /etc/nginx/nginx.conf ] && sed -i 's/^\(\s*listen\s\+80\s\+default_server;\)/#\1/; s/^\(\s*listen\s\+\[::\]:80\s\+default_server;\)/#\1/' /etc/nginx/nginx.conf
    # SELinux: nginx → 127.0.0.1:앱포트 연결 허용
    command -v setsebool >/dev/null && setsebool -P httpd_can_network_connect 1 2>/dev/null || true
  else
    install -m 600 -o root -g root "$CONF" /etc/nginx/sites-available/logtriage
    ln -sf /etc/nginx/sites-available/logtriage /etc/nginx/sites-enabled/logtriage
    rm -f /etc/nginx/sites-enabled/default
  fi
  rm -f "$CONF"
  nginx -t
  systemctl enable --now nginx >/dev/null 2>&1; systemctl reload nginx || systemctl restart nginx
fi

# ── 7. 방화벽 ────────────────────────────────────────────────────────────────
if [ "$FIREWALL" = 1 ]; then
  echo "[8/8] 방화벽 포트 개방"
  if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
    if [ "$USE_NGINX" = 1 ]; then firewall-cmd -q --permanent --add-service=http; [ "$TLS" = 1 ] && firewall-cmd -q --permanent --add-service=https
    else firewall-cmd -q --permanent --add-port=${APP_PORT}/tcp; fi
    firewall-cmd -q --reload
  elif command -v ufw >/dev/null 2>&1 && ufw status | grep -q active; then
    if [ "$USE_NGINX" = 1 ]; then ufw allow 80/tcp >/dev/null; [ "$TLS" = 1 ] && ufw allow 443/tcp >/dev/null
    else ufw allow ${APP_PORT}/tcp >/dev/null; fi
  else
    echo "  (활성 방화벽 없음 — 건너뜀)"
  fi
else
  echo "[8/8] 방화벽 설정 생략(--no-firewall)"
fi

# ── 완료 ─────────────────────────────────────────────────────────────────────
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
HC=$(curl -s -m 5 "http://127.0.0.1:$APP_PORT/healthz" 2>/dev/null || "$INSTALL_DIR/venv/bin/python" -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:$APP_PORT/healthz',timeout=5).read().decode())" 2>/dev/null || echo "(healthz 확인 실패)")
echo
echo "══ 설치 완료 ══════════════════════════════════════════════════════════"
if [ "$USE_NGINX" = 1 ]; then
  [ "$TLS" = 1 ] && echo "  웹 UI : https://${IP:-<서버IP>}/   (자체 서명 인증서 — 브라우저 경고 후 진행)" || echo "  웹 UI : http://${IP:-<서버IP>}/"
else
  echo "  웹 UI : http://${IP:-<서버IP>}:$APP_PORT/"
fi
if [ -f "$INSTALL_DIR/conf/setup-code.txt" ]; then
  echo "  첫 관리자: 1회용 코드로 만듭니다 — sudo cat $INSTALL_DIR/conf/setup-code.txt  →  브라우저에서 /setup?t=<코드>"
  echo "             (이 코드를 아는 사람이 첫 관리자가 됩니다. 만들면 파일이 지워지고 /setup 은 닫힙니다)"
fi
echo "  비밀번호 : 화면 · 설치 기록에 적지 않습니다 — /etc/logtriage/server.env 의 LOGTRIAGE_PASSWORD(root · 서비스 그룹만 읽기)"
echo "  저장소   : $( [ "$WANT_PG" = 1 ] && echo "PostgreSQL logtriage@127.0.0.1" || echo "SQLite $INSTALL_DIR/data/logtriage.db")"
echo "  헬스체크 : $HC"
echo "  서비스   : systemctl status logtriage-server $( [ "$USE_NGINX" = 1 ] && echo nginx) $( [ "$WANT_PG" = 1 ] && echo postgresql)"
echo "  로그     : journalctl -u logtriage-server -f   /var/log/nginx/logtriage_*.log"
echo "  CLI      : logtriage <로그파일> --product tomcat"
echo "  보존정책 : 업로드 원본 $(grep -E '^LOGTRIAGE_UPLOAD_KEEP_DAYS' /etc/logtriage/server.env | cut -d= -f2)일 후 자동 삭제(logtriage-cleanup.timer) · 백업은 backup.sh(server.env 제외)"
echo "  매뉴얼   : $INSTALL_DIR/설치매뉴얼.md"
echo "  점검     : sudo bash $INSTALL_DIR/check_install.sh   (읽기만 — 권한 · 서비스 · nginx · SELinux · 평문 접속 · 위조 반례)"
echo "═══════════════════════════════════════════════════════════════════════"
