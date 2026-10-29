#!/usr/bin/env bash
# LogTriage Linux 서버 기동 — OS 패키지·root 권한 없이 실행 (동봉한 독립 실행형 Python 사용)
# 사용:  bash run.sh [포트] [바인드주소]
#          포트       기본 8088
#          바인드주소 기본 0.0.0.0(망에 열림). local 또는 127.0.0.1 이면 이 PC 안에서만.
#
#        비밀번호는 **인자로 받지 않습니다.** 리눅스에서 명령행은 누구나 볼 수 있습니다
#        (/proc/<PID>/cmdline · ps -ef · 셸 기록). 로그인이 필요한데 걸려 있지 않으면
#        이 스크립트가 그 자리에서 **가려서** 물어보고 표준 입력으로 넘깁니다.
#        무인 기동(cron·systemd)은 LOGTRIAGE_PASSWORD_FILE=<0600 파일> 로 주십시오.
#        권장은 계정 로그인입니다:  python3 -m logtriage.authmode --base <경로>/data local
#        bash stop.sh                          (중지)
#        이미 설치된 서버를 이 판으로 갱신하려면 **패치 묶음**을 쓰십시오(자료는 그대로):
#          unzip -o logtriage-patch-1.0.0.zip && bash logtriage-patch/apply_patch.sh <기존 설치경로>
# 요구:  Linux x86_64, glibc 2.17 이상(CentOS 7 / RHEL·Rocky 8·9 / Ubuntu 18.04 이상), bash·tar·gzip
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-8088}"
ARG2="${2:-}"
BIND="${3:-}"
# 둘째 자리는 예전에 비밀번호였다. 그대로 두면 모르고 계속 그렇게 쓴다 — 거절하고 말한다.
case "$ARG2" in
  ""|local|localhost|0.0.0.0|127.0.0.1|::|::1) [ -z "$BIND" ] && BIND="$ARG2" ;;
  *) echo
     echo "  ! 비밀번호를 명령행 인자로 받지 않습니다 — 리눅스에서 명령행은 누구나 볼 수 있습니다"
     echo "    (/proc/<PID>/cmdline · ps -ef · 셸 기록). 그대로 띄우면 서버가 떠 있는 내내 보입니다."
     echo
     echo "    다음 중 하나로 다시 실행하십시오."
     echo "      1) 계정 로그인(권장) :  \$PY -m logtriage.authmode --base \$HERE/data local"
     echo "                              그 뒤  bash run.sh $PORT"
     echo "      2) 이 자리에서 입력  :  bash run.sh $PORT          (필요하면 가려서 물어봅니다)"
     echo "      3) 무인 기동         :  LOGTRIAGE_PASSWORD_FILE=/etc/logtriage/pw bash run.sh $PORT"
     echo "                              (그 파일은 chmod 600)"
     echo
     exit 1 ;;
esac
BIND="${BIND:-0.0.0.0}"
case "$BIND" in local|localhost) BIND="127.0.0.1";; esac
PASSWORD=""
PY="$HERE/python/bin/python3"
fail(){ echo; echo "  ! $*"; exit 1; }
case "$PORT" in ''|*[!0-9]*) fail "포트는 숫자여야 합니다: $PORT   (예: bash run.sh 8088)";; esac
for c in tar gzip; do command -v "$c" >/dev/null 2>&1 || fail "$c 명령이 없습니다 — OS 패키지로 설치하십시오"; done
[ -w "$HERE" ] || fail "$HERE 에 쓰기 권한이 없습니다 — 소유자를 현재 계정으로 바꾸거나(chown -R \$USER \"$HERE\") 홈 디렉터리에 푸십시오"

echo "[1/4] 독립 실행형 Python 준비"
if [ -x "$PY" ] && ! "$PY" -V >/dev/null 2>&1; then
  echo "  이전에 풀린 python/ 폴더가 손상되어 다시 풉니다"; rm -rf "$HERE/python"
fi
if [ ! -x "$PY" ]; then
  [ -f "$HERE/python-3.11-linux-x86_64.tar.gz" ] || fail "python-3.11-linux-x86_64.tar.gz 가 없습니다 — zip 을 다시 풀어 주십시오 (분할본이면 cat *.00* > zip 으로 먼저 합친 뒤 sha256sum 확인)"
  gzip -t "$HERE/python-3.11-linux-x86_64.tar.gz" 2>/dev/null || fail "python-3.11-linux-x86_64.tar.gz 가 손상되었습니다 — sha256sum -c SHA256SUMS 로 확인 후 zip 을 다시 반입하십시오"
  tar xzf "$HERE/python-3.11-linux-x86_64.tar.gz" -C "$HERE" || fail "Python 압축 해제 실패 — 디스크 여유(400MB)를 확인하십시오"
fi
[ -x "$PY" ] || chmod +x "$HERE/python/bin/"* 2>/dev/null || true
[ -e "$PY" ] || fail "압축을 풀었지만 $PY 가 없습니다 — tar tzf python-3.11-linux-x86_64.tar.gz | head 로 구조 확인"
"$PY" -c 'import sys; print("  python", sys.version.split()[0], "(" + sys.executable + ")")' || {
  echo "  ! 동봉 Python 실행 실패 — x86_64 Linux(glibc 2.17+)가 아니거나 현재 폴더가 noexec 로 마운트된 경우입니다."
  echo "    확인: uname -m (x86_64 이어야 함) · ldd --version | head -1 · findmnt -T \"$HERE\" -o TARGET,OPTIONS (noexec 여부)"
  echo "    noexec 라면 다른 경로(예: /opt 또는 홈 디렉터리)에 풀어 다시 실행하십시오."; exit 1; }

echo "[2/4] 파이썬 패키지(PyYAML, lxml, cryptography) — 동봉 wheel 로 오프라인 설치"
# wheel 은 **두 곳**에서 찾는다. 서버 묶음은 최상위 wheels/ 에 두지만, 패치(apply_patch.sh)는
# 그 폴더를 갱신하지 않고 engine/deploy/server/wheels 만 갱신한다. 한 곳만 보면 패치로
# 들어온 wheel 이 영영 쓰이지 않는다(현장 기동 기록, 2026-10-06).
WHL=(--no-index --find-links "$HERE/wheels")
[ -d "$HERE/engine/deploy/server/wheels" ] && WHL+=(--find-links "$HERE/engine/deploy/server/wheels")
if ! "$PY" -c 'import yaml, lxml.etree' 2>/dev/null; then
  "$PY" -m pip --version >/dev/null 2>&1 || "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
  "$PY" -m pip install -q "${WHL[@]}" PyYAML lxml || fail "wheel 설치 실패 — ls $HERE/wheels 에 cp311 wheel(PyYAML·lxml)이 있는지 확인"
fi
# 검증된 암호 구현 — **위 if 바깥에서, 기동할 때마다** 본다.
#
# 전에는 이 설치가 위 if(PyYAML·lxml 이 **없을 때**) 안에 들어 있었다. 그래서 첫 기동에
# 단 한 번만 시도했고, 그때 실패하면(cffi 가 묶음에 없었다) **다시는 시도하지 않았다** —
# 두 번째 기동부터는 PyYAML 이 이미 있으니 통째로 건너뛰고 경고도 없이 "자체(순수 파이썬)"
# 만 찍었다. wheel 을 채워 넣어도 한 번 돌린 서버는 영영 못 받는 구조였다(현장 기동 기록,
# 2026-10-06). 실패하면 왜 실패했는지 보여 준다 — 조용히 넘기지 않는다.
if ! "$PY" -c 'import cryptography' 2>/dev/null; then
  "$PY" -m pip --version >/dev/null 2>&1 || "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
  CRYERR="$("$PY" -m pip install -q "${WHL[@]}" cryptography 2>&1)" || {
    echo "  ! cryptography 를 동봉 wheel 로 설치하지 못했습니다 — 자체 구현(순수 파이썬)으로 동작합니다."
    echo "    wheels/ 에 cp311 용 cryptography·cffi·pycparser wheel 이 있어야 합니다."
    printf '%s\n' "$CRYERR" | tail -3 | sed 's/^/      /'
  }
fi
"$PY" -c 'import yaml, lxml.etree; print("  ok")' || fail "PyYAML/lxml 확인 실패"
"$PY" -c 'import cryptography; print("  암호 구현: cryptography", cryptography.__version__)' 2>/dev/null || echo "  암호 구현: 자체(순수 파이썬)"

echo "[3/4] 데이터 폴더 준비 ($HERE/data)"
mkdir -p "$HERE/data" "$HERE/data/reports" "$HERE/data/uploads" "$HERE/data/incidents" "$HERE/logs" || fail "data 폴더를 만들 수 없습니다(권한)"
for d in rules rules-local errorcodes manuals report-template; do
  if [ ! -d "$HERE/data/$d" ]; then
    [ -d "$HERE/engine/$d" ] || fail "$HERE/engine/$d 가 없습니다 — zip 손상. sha256sum -c SHA256SUMS 확인"
    cp -r "$HERE/engine/$d" "$HERE/data/$d" || fail "data/$d 복사 실패"
  fi
done
[ -f "$HERE/engine/logtriage/server.py" ] || fail "$HERE/engine/logtriage 가 없습니다 — zip 을 다시 풀고(unzip -o) 'ls $HERE/engine/logtriage/server.py' 를 확인하십시오"
# 소스가 이 Python 에서 import 되는지 먼저 확인(기동 실패 원인을 바로 보여 준다)
( cd "$HERE/engine" && PYTHONIOENCODING=utf-8 "$PY" -c 'import logtriage.server, logtriage.nms, logtriage.inventory, logtriage.resource_inventory; print("  소스 확인 ok")' ) \
  || fail "소스 import 실패(위 오류 참조) — 패키지가 손상되었거나 Python 버전이 맞지 않습니다"

echo "[4/4] 서버 기동 (포트 $PORT)"
if command -v flock >/dev/null 2>&1; then   # GPT 100차 P1-03: run.sh 두 개·run.sh 와 stop.sh 가 동시에 돌면 pid 파일을 덮어쓴다 — 줄 세움
  exec 9>"$HERE/.ctl.lock"
  flock -n 9 || fail "다른 run.sh·stop.sh 가 실행 중입니다 — 끝난 뒤 다시 실행하십시오"
  export LT_CTL_LOCKED=1                    # 이 셸이 부르는 stop.sh 는 자물쇠를 다시 잡지 않는다
fi
if [ -f "$HERE/server.pid" ]; then
  OLD="$(cat "$HERE/server.pid" 2>/dev/null || true)"
  if [ -n "$OLD" ] && kill -0 "$OLD" 2>/dev/null && tr '\0' ' ' < "/proc/$OLD/cmdline" 2>/dev/null | grep -q "logtriage.server"; then
    echo "  이미 실행 중(pid $OLD) — 먼저 bash stop.sh"; exit 1
  fi
  rm -f "$HERE/server.pid"   # 이전 실행의 잔여 pid 파일(죽었거나 다른 프로세스)
fi
# 포트 점유 확인 (정식 설치 systemd 서비스·이전 실행 잔여 프로세스·다른 서비스). ss/netstat 없으면 Python 소켓으로 확인
BUSY=""
if command -v ss >/dev/null 2>&1; then BUSY="$(ss -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | head -n 3 || true)"
elif command -v netstat >/dev/null 2>&1; then BUSY="$(netstat -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | head -n 3 || true)"
else BUSY="$("$PY" -c "import socket,sys
s=socket.socket(); s.settimeout(1)
try: s.connect(('127.0.0.1',$PORT)); print('port $PORT: 이미 응답하는 프로세스가 있음(ss/netstat 없음)')
except Exception: pass" 2>/dev/null || true)"; fi
if [ -n "$BUSY" ] && bash "$HERE/stop.sh" --mine-only --port "$PORT" >/dev/null 2>&1; then
  # 포트를 **실제로 쥔** 것이 이 폴더·이 사용자의 서버(pid 파일 없이 남은 고아 — 옛 run.sh 결함)면 치우고 다시 본다.
  # 같은 폴더라도 다른 포트에서 도는 서버·다른 사용자 서버는 건드리지 않는다(GPT 100차 P0-01·03)
  echo "  이 폴더의 잔여 서버 프로세스가 포트 $PORT 를 쥐고 있어 정리합니다:"
  bash "$HERE/stop.sh" --port "$PORT" 2>&1 | sed 's/^/     /'
  sleep 1
  if command -v ss >/dev/null 2>&1; then BUSY="$(ss -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | head -n 3 || true)"
  elif command -v netstat >/dev/null 2>&1; then BUSY="$(netstat -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | head -n 3 || true)"; fi
fi
if [ -n "$BUSY" ]; then
  echo "  ! 포트 $PORT 를 다른 프로세스가 쓰고 있습니다:"; echo "$BUSY" | sed 's/^/     /'
  if systemctl is-active --quiet logtriage-server 2>/dev/null; then
    echo "    → 정식 설치 서비스(systemd logtriage-server)가 이 포트를 쓰는 중입니다. 두 가지 중 하나를 선택하십시오:"
    echo "      (a) 정식 설치를 이 판으로 갱신:  sudo bash $HERE/engine/deploy/server/install.sh --port $PORT --skip-pkgs"
    echo "      (b) 이 구동 테스트 서버를 다른 포트로:  bash run.sh $((PORT+1))"
  else
    echo "    → 그 프로세스를 종료(kill <pid>)하거나  bash run.sh <다른 포트>  로 실행하십시오. (이 서버의 잔여 프로세스면 bash stop.sh)"
  fi
  exit 1
fi
# ── 띄우기 전에 막힐 조합인지 **서버에게 묻는다** ─────────────────────────────
# 전에는 이 스크립트가 규칙을 자기 나름대로 다시 구현했다. 같은 규칙이 두 곳에 있으면
# 갈라진다 — 이 제품에서 이미 여러 번 겪었다. 판정은 서버가 한다.
case "$BIND" in 127.0.0.1|::1|localhost) LOOPBACK=1;; *) LOOPBACK=0;; esac
PWFILE="${LOGTRIAGE_PASSWORD_FILE:-}"
PWARGS=()
[ -n "$PWFILE" ] && PWARGS=(--password-file "$PWFILE")
# 22차(GPT 167): 로그인 없는 서버형은 '이 PC 안에서만'이라고 밝힌 기동만 — 루프백 바인드일 때만 붙인다
[ "$LOOPBACK" = 1 ] && PWARGS+=(--local-only)
CHECKERR="$HERE/.check-start.err"
CHECK_RC=0
# 한 번만 묻는다. 표준 출력은 판정(JSON) 한 줄, 표준 오류는 사람에게 하는 말이다.
CHECK="$( cd "$HERE/engine" && PYTHONIOENCODING=utf-8 "$PY" -m logtriage.server --check-start \
    --host "$BIND" --base "$HERE/data" "${PWARGS[@]+"${PWARGS[@]}"}" 2>"$CHECKERR" )" || CHECK_RC=$?
AUTHMODE="$(printf '%s' "$CHECK" | "$PY" -c 'import json,sys
try: print(json.load(sys.stdin).get("mode",""))
except Exception: print("")' 2>/dev/null || true)"
if [ "$CHECK_RC" != 0 ]; then
  # 까닭과 되는 길은 서버가 적는다 — 여기서 다시 적지 않는다(두 곳에 두면 갈라진다).
  [ -s "$CHECKERR" ] && cat "$CHECKERR"
  if [ -t 0 ]; then
    echo
    echo "  지금 이 자리에서 단일 비밀번호를 걸 수도 있습니다(화면에 보이지 않게 입력)."
    echo "  계정 로그인을 쓰시려면 그냥 Enter 를 누르고 아래 명령을 먼저 실행하십시오:"
    echo "    $PY -m logtriage.authmode --base $HERE/data local"
    printf "  접속 비밀번호(안 쓰려면 Enter): "
    read -rs PASSWORD; echo
  fi
  if [ -z "$PASSWORD" ]; then
    echo "  띄우지 않았습니다."
    rm -f "$CHECKERR"
    exit 1
  fi
fi
rm -f "$CHECKERR"
ARGS=(-m logtriage.server --host "$BIND" --port "$PORT" --base "$HERE/data" --allow-dir "$HERE/logs")
[ "$LOOPBACK" = 1 ] && ARGS+=(--local-only)   # 22차: 판정 때와 같은 조건으로
if [ -n "$PASSWORD" ]; then
  ARGS+=(--password-stdin)            # 인자에 적지 않는다 — 표준 입력으로 넘긴다
elif [ -n "$PWFILE" ]; then
  ARGS+=(--password-file "$PWFILE")
fi
# 2026-10-22 현장: 전에는 ( cd … && nohup python … & echo $! ) 로 띄웠다 — $! 가 python 이 아니라 그것을 낳은 **하위 셸**이었다.
# 그래서 ① '포트를 쥔 것은 새 프로세스가 아님(옛 서버)' 이 거짓으로 뜨고 ② 그 하위 셸만 죽여 python 이 고아로 포트를 쥔 채 남고
# ③ stop.sh 도 pid 파일의 하위 셸만 죽였다. python 을 이 셸의 직접 백그라운드 작업으로 띄워 $! 가 python 이 되게 한다.
# GPT 104차 P0: 기동 기록(server.log)에는 첫 관리자 1회용 코드가 찍힌다 — 기본 umask(0644)면 같은 서버의 다른 계정이 읽어
# 관리자 자리를 먼저 차지할 수 있다. 기록 파일은 이 계정만 읽게(0600) 만든 뒤 쓴다(이미 있던 파일도 권한을 좁힌다).
( umask 077; : >> "$HERE/server.log" ); chmod 600 "$HERE/server.log" 2>/dev/null || true
cd "$HERE/engine"
if [ -n "$PASSWORD" ]; then
  printf '%s\n' "$PASSWORD" | PYTHONIOENCODING=utf-8 nohup "$PY" "${ARGS[@]}" > "$HERE/server.log" 2>&1 9>&- &
else
  PYTHONIOENCODING=utf-8 nohup "$PY" "${ARGS[@]}" < /dev/null > "$HERE/server.log" 2>&1 9>&- &
fi                                   # 9>&- : 기동·중지 자물쇠(.ctl.lock)를 서버에 물려주지 않는다(물려주면 서버가 도는 내내 stop.sh 가 못 든다)
echo $! > "$HERE/server.pid"
cd "$HERE"
PASSWORD=""   # 셸 변수에서도 지운다
_P="$(cat "$HERE/server.pid")"   # 혹시 셸이 한 겹 끼었으면(셸 구현 차이) 그 아래 python 을 pid 로 삼는다
if ! tr '\0' ' ' < "/proc/$_P/cmdline" 2>/dev/null | grep -q "logtriage\.server"; then
  _C="$(pgrep -P "$_P" -f 'logtriage\.server' 2>/dev/null | head -n 1 || true)"
  [ -n "$_C" ] && echo "$_C" > "$HERE/server.pid"
fi
HC=""
for i in $(seq 1 20); do
  sleep 1
  HC="$("$PY" -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:$PORT/healthz',timeout=3).read().decode())" 2>/dev/null || true)"
  [ -n "$HC" ] && break
  kill -0 "$(cat "$HERE/server.pid")" 2>/dev/null || break
done
if [ -z "$HC" ]; then
  echo "  ! 기동 확인 실패 — server.log 마지막 줄:"; tail -n 25 "$HERE/server.log" | sed 's/^/     /'; rm -f "$HERE/server.pid"; exit 1
fi
# ── 응답한 것이 **내가 띄운 그 프로세스**인가 ────────────────────────────────
# 현장에는 옛 프로세스가 같은 포트에 떠 있었다. 그러면 새 서버가 못 떠도 옛 서버가 200 을
# 돌려주어 '성공' 이 된다. HTTP 200 하나로 판정하지 않는다.
NEWPID="$(cat "$HERE/server.pid" 2>/dev/null || true)"
BAD=0
if [ -z "$NEWPID" ] || ! kill -0 "$NEWPID" 2>/dev/null; then
  echo "  ! 새 프로세스가 살아 있지 않습니다 — 응답한 것은 **다른 서버**입니다"; BAD=1
else
  CWD="$(readlink -f "/proc/$NEWPID/cwd" 2>/dev/null || true)"
  WANTCWD="$(readlink -f "$HERE/engine" 2>/dev/null || echo "$HERE/engine")"
  if [ -n "$CWD" ] && [ "$CWD" != "$WANTCWD" ]; then
    echo "  ! 떠 있는 프로세스의 코드 경로가 다릅니다: $CWD (기대 $WANTCWD)"; BAD=1
  fi
  OWN=""
  if command -v ss >/dev/null 2>&1; then OWN="$(ss -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | grep -c "pid=$NEWPID," || true)"
  elif command -v netstat >/dev/null 2>&1; then OWN="$(netstat -ltnp 2>/dev/null | grep -E "[:.]$PORT[[:space:]]" | grep -c "^.*[[:space:]]$NEWPID/" || true)"
  fi
  if [ -n "$OWN" ] && [ "$OWN" = "0" ]; then
    echo "  ! 포트 $PORT 를 쥔 것은 새 프로세스(pid $NEWPID)가 아닙니다 — 옛 서버가 응답하고 있습니다"; BAD=1
  fi
fi
# 판 지문 대조 — 이 폴더의 엔진과 같은 판이 응답했는가
# 2026-10-22 현장: 패치가 엔진은 바꿨는데 VERSION.txt 가 옛 값으로 남아, 새로 뜬 서버를 '판이 다르다'며 내렸다.
# 기준은 따로 노는 안내 파일(VERSION.txt)이 아니라 **이 폴더 엔진에 찍힌 판 지문**(engine/logtriage/_build_id.json)이다.
# VERSION.txt 가 그와 다르면 알리고 기준 값으로 고쳐 둔다(사람이 보는 안내가 낡지 않게).
WANT_ID="$("$PY" -c 'import json,sys
try: print(json.load(open(sys.argv[1],encoding="utf-8")).get("id",""))
except Exception: print("")' "$HERE/engine/logtriage/_build_id.json" 2>/dev/null || true)"
VER_ID=""
[ -f "$HERE/VERSION.txt" ] && VER_ID="$(sed -n 's/^Build:[[:space:]]*//p' "$HERE/VERSION.txt" | head -1 | tr -d '[:space:]')"
[ -z "$WANT_ID" ] && WANT_ID="$VER_ID"
if [ -n "$VER_ID" ] && [ -n "$WANT_ID" ] && [ "$VER_ID" != "$WANT_ID" ]; then
  echo "  (알림) VERSION.txt 의 판 지문($VER_ID)이 이 폴더 엔진($WANT_ID)과 달라 엔진 기준으로 고쳤습니다(패치 때 안내 파일이 덮이지 않았음)"
  sed -i "s/^Build:[[:space:]]*$VER_ID/Build: $WANT_ID/" "$HERE/VERSION.txt" 2>/dev/null || true
fi
GOT_ID="$(printf '%s' "$HC" | "$PY" -c 'import json,sys
try: print(json.load(sys.stdin).get("build_id",""))
except Exception: print("")' 2>/dev/null || true)"
if [ -n "$WANT_ID" ] && [ "$GOT_ID" != "$WANT_ID" ]; then
  echo "  ! 응답한 서버의 판 지문이 다릅니다: ${GOT_ID:-(없음)} (이 폴더 엔진 $WANT_ID)"; BAD=1
fi
if [ "$BAD" != 0 ]; then
  # **우리가 띄운 것은 우리가 치운다.** 전에는 여기서 그냥 빠져나가, 방금 띄운 프로세스가
  # 남아 같은 자료 폴더의 자물쇠를 쥐고 있었다. 그러면 운영자가 포트를 바꿔 다시 띄울 때
  # '자동화가 사용 중' 으로 죽는다 — 원인은 보이지 않는다(현장 기동 기록, 2026-10-02).
  if [ -n "${NEWPID:-}" ] && kill -0 "$NEWPID" 2>/dev/null; then
    echo "    (방금 띄운 프로세스 pid $NEWPID 는 치웁니다 — 자료 폴더 자물쇠를 남기지 않기 위해서입니다)"
    kill "$NEWPID" 2>/dev/null || true   # 이제 pid 파일은 python 자신 — 하위 셸이 아니다
    for _i in $(seq 1 15); do kill -0 "$NEWPID" 2>/dev/null || break; sleep 1; done
    if kill -0 "$NEWPID" 2>/dev/null && tr '\0' ' ' < "/proc/$NEWPID/cmdline" 2>/dev/null | grep -q "logtriage\.server"; then
      kill -9 "$NEWPID" 2>/dev/null || true
    fi
  fi
  rm -f "$HERE/server.pid"
  echo "    확인:  ss -ltnp | grep -E ':$PORT'   ·   ps -eo pid,user,args | grep '[l]ogtriage.server'"
  echo "    옛 프로세스를 먼저 멈추십시오(bash stop.sh 또는 kill <pid>) — 그러지 않으면 브라우저는 옛 코드를 봅니다."
  exit 1
fi
# ── 브라우저가 옛 화면을 들고 있지 못하게 되어 있는가 ───────────────────────
# 서버 프로세스가 새것이어도, 화면이 캐시에 남으면 사람은 여전히 옛 코드를 본다.
# 내주는 화면을 직접 받아 **저장 금지 지시와 판 지문**이 붙어 있는지 본다.
#
# 두 가지를 조심한다.
#  ① 리다이렉트를 **따라가지 않는다.** 첫 기동(관리자 계정이 아직 없을 때)에는 /login 이
#     /setup 으로 넘기고, 1회용 코드가 없으니 /setup 은 403 이다. 따라가면 그 403 을 받고
#     "지시가 없다" 고 잘못 판정한다. 머리글은 **넘기는 그 응답**에 이미 들어 있다.
#  ② 이 점검으로 **기동을 막지 않는다.** 옛 코드가 돌고 있는 경우는 바로 위의 판 지문
#     대조가 이미 잡고 멈춘다. 여기서 또 멈추면, 점검이 틀렸을 때 **멀쩡한 서버를 거절하는**
#     새 고장만 생긴다(실제로 그렇게 됐다 — 첫 기동이 거절됐다). 알리고 지나간다.
SCR="$("$PY" - "$PORT" <<'PY' 2>/dev/null || true
import sys, urllib.error, urllib.request


class NoFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None                     # 넘기는 응답 자체를 본다


try:
    try:
        r = urllib.request.build_opener(NoFollow).open(
            "http://127.0.0.1:%s/login" % sys.argv[1], timeout=5)
    except urllib.error.HTTPError as e:
        r = e                           # 3xx·4xx 도 응답이다 — 머리글을 그대로 읽는다
    h = r.headers
    cc = "no-store" in (h.get("Cache-Control") or "").lower()
    html = (h.get("Content-Type") or "").startswith("text/html")
    body = r.read(4096).decode("utf-8", "replace") if html else ""
    # 화면을 실제로 받은 경우에만 박힌 지문을 본다. 넘기는 응답은 본문이 비어 있다.
    meta = ('meta name="lt-build"' in body) if body.strip() else "skip"
    print("%s|%s|%s" % (cc, h.get("X-LogTriage-Build") or "", meta))
except Exception:
    print("?||?")                       # 못 봤다 — '없다' 와 구분한다
PY
)"
S_CC="${SCR%%|*}"; S_REST="${SCR#*|}"; S_ID="${S_REST%%|*}"; S_META="${S_REST#*|}"
if [ "$S_CC" = "False" ] || [ "$S_META" = "False" ]; then
  echo "  ! 화면에 '저장 금지' 지시나 판 지문이 붙지 않았습니다 — 패치가 덜 들어간 판일 수 있습니다."
  echo "    (저장금지=$S_CC 지문심기=$S_META) 이 상태로는 브라우저가 옛 화면을 계속 보여 줄 수 있습니다."
  echo "    기동은 계속합니다. 판 지문이 위 VERSION.txt 와 같다면 서버 자체는 이 판입니다."
elif [ "$S_CC" = "?" ]; then
  echo "  · 화면 쪽 캐시 설정은 확인하지 못했습니다(기동에는 영향 없습니다)."
fi
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo
echo "========================================================"
if [ "$LOOPBACK" = 1 ]; then
  echo " LogTriage 기동 완료  →  http://127.0.0.1:$PORT   (이 PC 안에서만)"
else
  echo " LogTriage 기동 완료  →  http://${IP:-<서버IP>}:$PORT   (같은 PC: http://127.0.0.1:$PORT)"
fi
echo "   healthz: $HC"
echo "   ↑ build_id 가 VERSION.txt 의 Build 와 같으면 이 판이 돌고 있는 것입니다."
# 2026-10-22 마스터: "기동 시 1회용 코드가 안 나온다 — 또 파일을 찾아야 하는 건 아니다" — 계정이 아직 없으면 코드와 바로 열 주소를 여기 보여 준다.
# 서버는 기동할 때 이 파일을 새 코드로 다시 쓰고(0600), 첫 관리자를 만들면 지운다 — 파일이 있으면 지금 코드가 유효하다.
SETUP_F="$HERE/data/conf/setup-code.txt"
for _i in 1 2 3; do [ -f "$SETUP_F" ] && break; sleep 1; done
if [ -f "$SETUP_F" ]; then
  SCODE="$(sed -n 's/^코드[[:space:]]*:[[:space:]]*//p' "$SETUP_F" | head -n 1 | tr -d '[:space:]')"
  if [ -n "$SCODE" ]; then
    if [ "$LOOPBACK" = 1 ]; then SHOST="127.0.0.1"; else SHOST="${IP:-<서버IP>}"; fi
    echo
    echo " ┌─ 첫 관리자 계정 만들기 — 아직 계정이 없습니다 ──────────────────────"
    echo " │  1회용 코드 : $SCODE"
    echo " │  바로 열기  : http://$SHOST:$PORT/setup?t=$SCODE"
    echo " │  위 주소를 열면 코드가 들어간 채로 [관리자 계정 만들기] 가 뜹니다 — 관리자 아이디(회사 이메일)와"
    echo " │  비밀번호를 직접 정하십시오. 만들면 이 코드는 사라집니다. 서버를 다시 띄우면 새 코드가 나옵니다."
    echo " │  이 코드를 아는 사람이 첫 관리자가 됩니다 — 화면을 남에게 보이거나 메신저로 보내지 마십시오."
    echo " └───────────────────────────────────────────────────────────────"
  fi
fi
echo
echo " [브라우저 쪽 확인]  화면은 저장되지 않게 내보냅니다(캐시 금지) — 새로 열면 늘 새 코드입니다."
echo "   이미 열어 둔 창은 그대로 살아 있으므로, 바뀐 것을 스스로 알리고 사람이 누르면 바뀝니다:"
echo "     · 최대 1분 안에 화면 아래에 '서버가 새 판으로 바뀌었습니다' 띠 + [새로 불러오기]"
SHOW_ID="${S_ID:-${WANT_ID:-}}"
echo "     · 직접 확인하려면 화면 오른쪽 위 [내 정보] → '화면 판' 이 ${SHOW_ID:-위 build_id} 와 같아야 합니다"
echo "   (저절로 다시 읽지는 않습니다 — 분석 도중인 입력을 말없이 날리지 않기 위해서입니다.)"
# ── 이 판으로 **처음** 올린 경우에만: 한 번은 사람 손이 필요하다 ──────────────
# 저장을 금지하는 지시는 **앞으로** 저장하지 말라는 뜻이고, 브라우저에 **이미 들어 있던
# 것을 지우지는 않는다.** 게다가 이 판 이전 화면에는 판 지문도, 비교하는 코드도 없다.
# 그러니 '화면이 스스로 알린다' 는 이 판 **이후의** 업그레이드에만 해당한다.
# 첫 전환은 한 번, 사람이 강제로 새로 받아야 끝난다.
MARK="$HERE/.browser-refresh-done"
if [ ! -f "$MARK" ]; then
  echo
  echo " [처음 올리신 경우 — 한 번만 필요합니다]"
  echo "   이 판 이전에 열어 둔 화면에는 판을 비교하는 기능이 **아직 없습니다.** 저장 금지"
  echo "   지시는 앞으로 저장하지 말라는 뜻일 뿐, 이미 받아 둔 화면을 지우지는 않습니다."
  echo "   접속하는 분들께 한 번만 이렇게 안내해 주십시오:"
  echo "     · 브라우저 탭을 모두 닫고 다시 열기,  또는"
  echo "     · 화면에서 Ctrl+Shift+R (맥은 Cmd+Shift+R) 로 강제 새로 받기"
  echo "   이 판 이후의 업그레이드부터는 화면이 스스로 알립니다 — 이 안내는 다시 안 뜹니다."
  : > "$MARK" 2>/dev/null || true
fi
echo
echo " [앞단에 프록시·로드밸런서가 있다면]  위 확인은 이 서버에서 본 것입니다. 프록시가"
echo "   화면을 스스로 보관하면 서버가 아무리 금지해도 사용자는 옛 화면을 봅니다."
echo "   **사용자 PC 에서** 한 번 대조해 주십시오(지문이 위 build_id 와 같아야 합니다):"
echo "     curl -sI http://<사용자가 쓰는 주소>/login | grep -i -e x-logtriage-build -e cache-control"
echo "   상태/중지: cat server.log · bash stop.sh   |  로그 파일을 서버에서 직접 분석하려면 $HERE/logs 에 복사"
if [ "$AUTHMODE" != "local" ] && [ "$AUTHMODE" != "portal" ] && [ "$LOOPBACK" = 0 ]; then
  echo "   로그인: 단일 비밀번호"
elif [ "$AUTHMODE" = "local" ] || [ "$AUTHMODE" = "portal" ]; then
  echo "   로그인: 계정($AUTHMODE)"
  if [ "$AUTHMODE" = "local" ]; then
    echo "     · 계정이 없으면 처음 접속에서 [관리자 계정 만들기] 가 뜹니다 — 1회용 코드와 바로 열 주소는 위 상자에 있습니다"
    echo "     · 그 뒤 사람들은 로그인 화면 [계정 만들기] 로 직접 가입하고, 관리자가 [계정 · 가입] 에서 승인합니다"
  fi
else
  echo "   로그인 없음 — 이 PC 안에서만 열려 있습니다($BIND). 망에 열려면 비밀번호나 계정 로그인이 필요합니다."
  echo "   ! 이 PC 전용 포트에 nginx 같은 프록시를 연결하지 마십시오. 프록시를 쓰려면 계정 로그인을 켜십시오."
fi
echo "   방화벽이 켜져 있으면 포트 $PORT 인바운드 허용 필요 (예: firewall-cmd --add-port=$PORT/tcp)"
echo "   메뉴: 대시보드·로그분석·분석 리포트·로그 검색·분석 이력·코드 조회·보고서 양식·룰팩 업데이트·인프라 감시(/nms)·자원 관리(/resources)"
echo "========================================================"
