#!/usr/bin/env bash
# LogTriage 구동 테스트 서버 중지 — 이 폴더(engine)에서 **이 사용자가** 실행한 logtriage.server 를 끈다(pid 파일 + 남은 고아 프로세스).
# 정식 설치(systemd logtriage-server)·다른 폴더의 서버·다른 사용자의 프로세스는 건드리지 않는다.
#   bash stop.sh                   끄기(정상 종료를 30초 기다리고, 그래도 남으면 다시 확인한 뒤 강제 종료)
#   bash stop.sh --port 8088       그 포트를 **실제로 쥔** 이 폴더의 서버만 끈다(run.sh 가 포트 정리에 씀)
#   bash stop.sh --mine-only [--port N]   끄지 않고, 해당하는 서버가 있으면 종료 코드 0
# 2026-10-22 현장: 옛 run.sh 의 pid 파일에는 python 이 아니라 하위 셸 pid 가 적혀 있었다 — 그것만 죽여 python 이 고아로 남았다.
#   그래서 pid 파일만 믿지 않고, 실행 경로(cwd)가 이 폴더 engine 이고 실행 사용자가 나인 logtriage.server 를 찾는다(경로는 링크를 풀어 비교).
# GPT 100차: 같은 폴더 다른 포트의 정상 서버를 포트 정리로 끄지 않게 --port 는 포트 소유 pid 까지 대조, 다른 사용자(root 포함)의 서버 제외,
#   강제 종료 직전 다시 확인(pid 재사용), run.sh·stop.sh 동시 실행은 flock 으로 줄 세움.
HERE="$(cd "$(dirname "$0")" && pwd -P)"
WANT="$(readlink -f "$HERE/engine" 2>/dev/null || echo "$HERE/engine")"
ME="$(id -u)"
MODE="stop"; PORT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mine-only) MODE="check"; shift ;;
    --port) PORT="${2:-}"; shift 2 ;;
    *) echo "알 수 없는 인자: $1"; exit 2 ;;
  esac
done
if [ -z "${LT_CTL_LOCKED:-}" ] && command -v flock >/dev/null 2>&1; then
  exec 9>"$HERE/.ctl.lock"
  flock -w 30 9 || { echo "다른 run.sh·stop.sh 가 실행 중입니다 — 끝난 뒤 다시 실행하십시오"; exit 1; }
fi
mine() {
  [ -d "/proc/$1" ] || return 1
  [ "$(stat -c %u "/proc/$1" 2>/dev/null)" = "$ME" ] || return 1
  [ "$(readlink -f "/proc/$1/cwd" 2>/dev/null)" = "$WANT" ] || return 1
  tr '\0' ' ' < "/proc/$1/cmdline" 2>/dev/null | grep -q "logtriage\.server"
}
holders() {   # 포트를 LISTEN 으로 쥔 pid 들(ss 없으면 빈 값 — 그때는 포트 기준 정리를 하지 않는다)
  command -v ss >/dev/null 2>&1 || return 0
  ss -ltnpH "sport = :$PORT" 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u
}
PIDS=""
add() { case " $PIDS " in *" $1 "*) ;; *) PIDS="$PIDS $1";; esac; }
SKIP=""
if [ -n "$PORT" ]; then
  for P in $(holders); do mine "$P" && add "$P"; done
else
  if [ -f "$HERE/server.pid" ]; then
    P="$(cat "$HERE/server.pid" 2>/dev/null || true)"
    case "$P" in
      ''|*[!0-9]*) ;;
      *) mine "$P" && add "$P"
         for C in $(pgrep -P "$P" 2>/dev/null || true); do mine "$C" && add "$C"; done ;;
    esac
  fi
  for P in $(pgrep -f "logtriage\.server" 2>/dev/null || true); do
    if mine "$P"; then add "$P"; else SKIP="$SKIP $P"; fi
  done
fi
PIDS="${PIDS# }"
if [ "$MODE" = "check" ]; then
  [ -n "$PIDS" ]; exit $?
fi
for P in $SKIP; do
  echo "건너뜀: pid $P (실행 경로 $(readlink -f "/proc/$P/cwd" 2>/dev/null || echo '확인 불가 — 다른 사용자') — 이 폴더·이 사용자의 서버가 아님. 정식 설치는 systemctl restart logtriage-server)"
done
if [ -z "$PIDS" ]; then
  echo "실행 중인 구동 테스트 서버가 없습니다${PORT:+ (포트 $PORT)}"
  [ -z "$PORT" ] && rm -f "$HERE/server.pid"
  exit 0
fi
kill $PIDS 2>/dev/null || true          # 서버는 SIGTERM 을 받으면 스스로 정리하고 끝난다
LEFT="$PIDS"
for _i in $(seq 1 30); do
  LEFT=""
  for P in $PIDS; do mine "$P" && LEFT="$LEFT $P"; done
  [ -z "$LEFT" ] && break
  sleep 1
done
if [ -n "$LEFT" ]; then
  FORCE=""
  for P in $LEFT; do mine "$P" && FORCE="$FORCE $P"; done   # 강제 종료 직전 다시 확인(그사이 끝나고 pid 가 재사용됐으면 건드리지 않음)
  if [ -n "$FORCE" ]; then
    echo "30초 안에 끝나지 않아 강제 종료:$FORCE"
    kill -9 $FORCE 2>/dev/null || true
  fi
fi
echo "중지: pid $PIDS"
if [ -z "$PORT" ] || ! { [ -f "$HERE/server.pid" ] && mine "$(cat "$HERE/server.pid" 2>/dev/null)"; }; then
  rm -f "$HERE/server.pid"
fi
