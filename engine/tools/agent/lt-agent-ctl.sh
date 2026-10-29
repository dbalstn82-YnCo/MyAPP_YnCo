#!/bin/sh
# LogTriage 자원 사용률 에이전트 — 설치형(압축 해제 후 실행) 제어 스크립트. root 불필요, POSIX sh(dash/ksh/bash) 로 동작.
#
#   sh lt-agent-ctl.sh start [서버주소] [토큰] [간격초] [디스크]   백그라운드 시작(처음 한 번은 주소·토큰을 주면 agent.conf 에 저장)
#   sh lt-agent-ctl.sh stop | restart | status | log | test        중지 / 재시작 / 상태 / 최근 로그 / 서버 연결·전송 시험
#   sh lt-agent-ctl.sh enable-boot | disable-boot                  재부팅 후 자동 시작(사용자 crontab @reboot) 등록 / 해제
#   sh lt-agent-ctl.sh setup 서버주소 토큰 [간격초] [디스크]        agent.conf 만 작성
#
# 압축을 푼 폴더 안에서만 동작한다(설정 agent.conf · 로그 lt-agent.log · pid 파일 agent.pid 모두 같은 폴더). 다른 곳에 아무것도 쓰지 않는다.
# 수집기 선택(자동): python3 → lt-agent.py, Linux+bash → lt-agent.sh, 그 외 Unix → lt-agent-posix.sh(vmstat·df 표준 명령).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
CONF="$HERE/agent.conf"; PIDF="$HERE/agent.pid"; LOG="$HERE/lt-agent.log"
CMD="${1:-status}"; [ $# -gt 0 ] && shift

say() { printf '%s\n' "$*"; }
die() { say "! $*" >&2; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }

fix_crlf() {   # Windows 에서 압축한 경우 CR 제거(같은 폴더의 .sh/.py/.conf 만)
  for f in "$HERE"/*.sh "$HERE"/*.py "$CONF"; do
    [ -f "$f" ] || continue
    if grep -q "$(printf '\r')" "$f" 2>/dev/null; then tr -d '\r' < "$f" > "$f.tmp" && cat "$f.tmp" > "$f" && rm -f "$f.tmp"; fi
  done
  chmod 700 "$HERE"/*.sh 2>/dev/null; chmod 600 "$CONF" 2>/dev/null
}

write_conf() {   # setup/start 인자 → agent.conf
  [ -n "${1:-}" ] && [ -n "${2:-}" ] || die "사용: sh lt-agent-ctl.sh setup http://<LogTriage서버>:8088 <토큰> [간격초=30] [디스크=all]"
  case "$1" in http://*|https://*) ;; *) die "서버 주소는 http:// 또는 https:// 로 시작해야 합니다: $1";; esac
  case "$1" in *[!A-Za-z0-9.:/_%\[\]-]*) die "서버 주소에 허용되지 않는 문자가 있습니다";; esac
  case "$2" in *[!A-Za-z0-9_-]*) die "토큰 형식이 올바르지 않습니다";; esac
  case "$1" in *[!A-Za-z0-9.:/_%\[\]-]*) die "서버 주소에 허용되지 않는 문자가 있습니다";; esac
  case "$2" in *[!A-Za-z0-9_-]*) die "토큰 형식이 올바르지 않습니다";; esac
  {
    say "# LogTriage 에이전트 설정 — 이 파일은 토큰이 들어 있으므로 권한 600 을 유지하십시오"
    say "URL=$(say "$1" | sed 's#/*$##')"
    say "TOKEN=$2"
    say "INTERVAL=${3:-30}"
    say "DISK=${4:-all}"
    say "# COLLECTOR=python|bash|posix   (비우면 자동 선택)"
    say "# PROCS=1   (0 이면 계정별 프로세스 현황을 보내지 않음)"
  } > "$CONF" && chmod 600 "$CONF" && say "설정 저장: $CONF"
}

conf_get() { sed -n "s/^$1=//p" "$CONF" 2>/dev/null | head -n 1 | tr -d '\r'; }
load_conf() {   # source 하지 않고 허용 키만 읽는다(설정 파일 내용이 셸 코드로 실행되지 않게)
  [ -f "$CONF" ] || die "설정이 없습니다. 먼저:  sh lt-agent-ctl.sh start http://<LogTriage서버>:8088 <토큰>"
  URL=$(conf_get URL); TOKEN=$(conf_get TOKEN); INTERVAL=$(conf_get INTERVAL); DISK=$(conf_get DISK); COLLECTOR=$(conf_get COLLECTOR); PROCS=$(conf_get PROCS)
  case "$PROCS" in 0|no|off) PROCS=0;; *) PROCS=1;; esac
  [ -n "$URL" ] && [ -n "$TOKEN" ] || die "agent.conf 에 URL·TOKEN 이 필요합니다"
  case "$URL" in http://*|https://*) ;; *) die "URL 은 http:// 또는 https:// 로 시작해야 합니다";; esac
  case "$URL" in *[!A-Za-z0-9.:/_%\[\]-]*) die "URL 에 허용되지 않는 문자가 있습니다: $URL";; esac
  case "$TOKEN" in *[!A-Za-z0-9_-]*) die "TOKEN 형식이 올바르지 않습니다";; esac
  case "$INTERVAL" in ''|*[!0-9]*) INTERVAL=30;; esac; [ "$INTERVAL" -lt 5 ] && INTERVAL=5
  [ -n "$DISK" ] || DISK=all
  case "$COLLECTOR" in ''|python|bash|posix) ;; *) die "COLLECTOR 값은 python|bash|posix";; esac
}

find_python() {   # 진짜 Python 3 만(Windows 스토어 스텁·python2 제외)
  for p in ${LT_PY:-} python3 python; do
    [ -n "$p" ] || continue
    has "$p" || continue
    v=$("$p" -c 'import sys; print(sys.version_info[0])' 2>/dev/null) || continue
    [ "$v" = "3" ] && { say "$p"; return 0; }
  done
  return 1
}

pick() {   # 수집기 결정 → RUN(명령 배열 대신 문자열)·WHAT
  OS=$(uname -s 2>/dev/null || say unknown)
  PY=$(find_python || true)
  want="${COLLECTOR:-}"
  if [ -z "$want" ]; then
    if [ -n "$PY" ]; then want=python; elif [ "$OS" = Linux ] && has bash; then want=bash; else want=posix; fi
  fi
  case "$want" in
    python) [ -n "$PY" ] || die "python3 이 없습니다(COLLECTOR=python)"; [ -f "$HERE/lt-agent.py" ] || die "lt-agent.py 없음"
            WHAT="Python 3 ($PY)"; RUN_BIN="$PY"; RUN_SCRIPT="$HERE/lt-agent.py";;
    bash)   has bash || die "bash 가 없습니다(COLLECTOR=bash)"; [ "$OS" = Linux ] || say "주의: lt-agent.sh 는 Linux(/proc) 전용입니다"
            WHAT="bash (lt-agent.sh)"; RUN_BIN=bash; RUN_SCRIPT="$HERE/lt-agent.sh";;
    posix)  [ -f "$HERE/lt-agent-posix.sh" ] || die "lt-agent-posix.sh 없음"; has curl || has wget || die "curl 또는 wget 이 필요합니다(python3 도 없음)"
            WHAT="POSIX sh (vmstat·df)"; RUN_BIN=sh; RUN_SCRIPT="$HERE/lt-agent-posix.sh";;
    *) die "COLLECTOR 값은 python|bash|posix";;
  esac
}

is_agent_pid() {   # pid 가 살아 있고(가능하면) 정말 우리 수집기인지(ps 로 명령행 확인 — PID 재사용 시 남의 프로세스를 죽이지 않게)
  kill -0 "$1" 2>/dev/null || return 1
  args=$(ps -o args= -p "$1" 2>/dev/null) || return 0   # ps 가 없거나 -o 미지원이면 kill -0 결과만 사용
  [ -z "$args" ] && return 0
  case "$args" in *lt-agent*) return 0;; *) return 1;; esac
}
alive() { [ -f "$PIDF" ] && p=$(cat "$PIDF" 2>/dev/null) && [ -n "$p" ] && is_agent_pid "$p"; }

rotate_log() {   # 5MB 넘으면 .1 로 한 번만 보관
  [ -f "$LOG" ] || return 0
  sz=$(wc -c < "$LOG" 2>/dev/null | tr -d ' '); [ "${sz:-0}" -gt 5242880 ] && mv -f "$LOG" "$LOG.1"
  return 0
}

LOCK="$HERE/.start.lock"
lock_start() {   # 동시 start 방지(원자적 mkdir). 60초 넘은 잠금은 죽은 것으로 보고 제거
  if ! mkdir "$LOCK" 2>/dev/null; then
    age=$(( $(date +%s) - $(stat -c %Y "$LOCK" 2>/dev/null || stat -f %m "$LOCK" 2>/dev/null || date +%s) ))
    [ "$age" -gt 60 ] && rmdir "$LOCK" 2>/dev/null && mkdir "$LOCK" 2>/dev/null || die "다른 start 가 진행 중입니다(잠시 후 다시 시도: $LOCK)"
  fi
  trap 'rmdir "$LOCK" 2>/dev/null' EXIT INT TERM
}
do_start() {
  fix_crlf
  if [ -n "${1:-}" ]; then write_conf "$@"; fi
  load_conf; pick; lock_start
  if alive; then say "이미 실행 중 (pid $(cat "$PIDF"))"; return 0; fi
  rotate_log
  say "$(date '+%F %T') [ctl] start: $WHAT  url=$URL interval=${INTERVAL}s disk=$DISK user=$(id -un 2>/dev/null)" >> "$LOG"
  # 토큰은 명령행(ps 노출)이 아니라 환경변수로 넘기고 인자는 '-' (수집기가 LT_AGENT_TOKEN 을 읽음). cron 의 C 로케일에서도 한글 로그 안전.
  LT_AGENT_TOKEN="$TOKEN" LT_PROCS="$PROCS" LC_ALL=C LANG=C PYTHONIOENCODING=utf-8 PYTHONUNBUFFERED=1 nohup "$RUN_BIN" "$RUN_SCRIPT" "$URL" "-" "$INTERVAL" "$DISK" >> "$LOG" 2>&1 &
  say $! > "$PIDF"
  sleep 2
  if alive; then
    say "시작됨: $WHAT · pid $(cat "$PIDF") · 첫 전송은 ${INTERVAL}초 뒤"
    say "로그: $LOG   (마지막에 {\"ok\": true 가 보이면 정상)"
    say "LogTriage [모니터링]에 이 서버 IP 가 '자원 사용률 수집: 에이전트'로 등록돼 있어야 저장됩니다."
  else
    rm -f "$PIDF"; say "! 시작 실패 — 로그 마지막 줄:"; tail -n 5 "$LOG" 2>/dev/null; exit 1
  fi
}

do_stop() {
  if alive; then p=$(cat "$PIDF"); kill "$p" 2>/dev/null; sleep 1; kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null
    rm -f "$PIDF"; say "$(date '+%F %T') [ctl] stop pid $p" >> "$LOG"; say "중지됨 (pid $p)"
  else rm -f "$PIDF"; say "실행 중이 아닙니다"; fi
}

do_status() {
  fix_crlf
  if alive; then say "실행 중: pid $(cat "$PIDF")"; else say "중지 상태"; fi
  if [ -f "$CONF" ]; then load_conf; say "서버: $URL · 간격 ${INTERVAL}s · 디스크 $DISK · 프로세스 $([ "$PROCS" = 1 ] && say 수집 || say 안함)"; fi
  if [ -f "$LOG" ]; then
    ok=$(grep -n '"ok": *true' "$LOG" 2>/dev/null | tail -n 1 | cut -c1-80)
    [ -n "$ok" ] && say "마지막 정상 전송: $(say "$ok" | sed 's/^[0-9]*://' | cut -c1-19)" || say "정상 전송 기록 없음(등록 여부·토큰·방화벽 확인)"
    say "--- 최근 로그 ---"; tail -n 5 "$LOG"
  fi
}

do_test() {
  fix_crlf; load_conf; pick
  say "1) 서버 연결: $URL/healthz"
  if has curl; then R=$(curl -s -m 5 "$URL/healthz" 2>&1)
  elif has wget; then R=$(wget -q -O - --timeout=5 "$URL/healthz" 2>&1)
  elif [ -n "$PY" ]; then R=$("$PY" -c "import urllib.request,sys;print(urllib.request.urlopen(sys.argv[1],timeout=5).read().decode())" "$URL/healthz" 2>&1)
  else R="(curl·wget·python 없음)"; fi
  case "$R" in *'"ok": true'*|*'"ok":true'*) say "   OK";; *) say "   실패: $R"; say "   주소·포트(기본 8088)·방화벽(이 서버 → LogTriage 서버 TCP) 확인"; exit 1;; esac
  if [ -n "$PY" ] && [ -f "$HERE/lt-agent.py" ]; then
    say "2) 1회 전송 시험(수집기: Python)"
    LT_AGENT_TOKEN="$TOKEN" LT_PROCS="$PROCS" PYTHONIOENCODING=utf-8 "$PY" "$HERE/lt-agent.py" "$URL" "-" 2 "$DISK" --once || { say "   ! 전송 실패 — 위 메시지 확인(토큰 불일치=401, 미등록 IP=404)"; exit 1; }
    say "   OK — 등록된 IP 라면 [모니터링] 화면에 곧 값이 보입니다."
  else
    say "2) 수집기: $WHAT — start 후 로그로 확인하십시오"
  fi
}

cron_line() {   # 설치 경로를 작은따옴표로 인용하고 crontab 특수문자 % 는 \% 로. marker 에 경로를 넣어 다른 설치본의 줄은 건드리지 않는다
  q=$(printf '%s' "$HERE" | sed "s/'/'\\\\''/g; s/%/\\\\%/g")
  printf "@reboot sh '%s/lt-agent-ctl.sh' start >/dev/null 2>&1 # lt-agent:%s" "$q" "$q"
}
do_enable_boot() {
  has crontab || die "crontab 명령이 없습니다 — 관리자에게 root 설치(lt-agent-install.sh) 또는 로그인 스크립트 등록을 요청하십시오"
  case "$HERE" in *"'"*) die "설치 경로에 작은따옴표가 있어 crontab 등록을 지원하지 않습니다";; esac
  line=$(cron_line)
  cur=$(crontab -l 2>/dev/null | grep -F -x -v "$line" || true)
  printf '%s\n%s\n' "$cur" "$line" | sed '/^$/d' | crontab - || die "crontab 등록 실패(이 계정에 cron 사용 권한이 없을 수 있음: /etc/cron.allow 확인)"
  say "등록됨(사용자 crontab @reboot): $line"
}
do_disable_boot() {
  has crontab || die "crontab 명령이 없습니다"
  line=$(cron_line)
  crontab -l 2>/dev/null | grep -F -x -v "$line" | crontab - 2>/dev/null; say "자동 시작 해제"
}

case "$CMD" in
  start) do_start "$@";;
  stop) do_stop;;
  restart) do_stop; do_start;;
  status) do_status;;
  log) tail -n "${1:-30}" "$LOG" 2>/dev/null || say "로그 없음";;
  test) do_test;;
  setup) fix_crlf; write_conf "$@";;
  enable-boot) do_enable_boot;;
  disable-boot) do_disable_boot;;
  *) sed -n '2,9p' "$0"; exit 2;;
esac
