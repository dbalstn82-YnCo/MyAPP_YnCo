#!/bin/sh
# LogTriage 자원 사용률 에이전트 — 간편 설치(19차). [모니터링] 감시 항목 [편집] → [설치 명령 만들기] 가 주는 한 줄로 실행한다.
#
#   printf %s <등록코드> | sh lt-setup.sh <LogTriage주소> -   설치(root 면 시스템 서비스, 아니면 이 계정 사용자 설치)
#   sh lt-setup.sh <LogTriage주소>                   등록 코드를 물어봄(코드는 명령 인자로 주지 않는 것이 좋다 — ps 에 보임)
#   sh lt-setup.sh --status                         상태
#   sh lt-setup.sh --remove                         제거
#
# 보안
#   · 등록 코드는 30분 · 1회용이고 이 감시 항목(이 서버)에만 쓸 수 있다. 쓰고 나면 셸 기록에 남아도 쓸모가 없다.
#   · 수집 토큰은 등록 코드와 바꾸어 받아 설정 파일(권한 600)에만 쓴다 — 화면·명령줄(ps)·셸 기록에 나오지 않는다.
#   · 내려받는 수집기 파일은 아래에 박힌 SHA-256 과 같아야 설치한다(이 파일 자체는 화면이 보여 준 SHA-256 으로 먼저 확인했다).
#   · root 설치는 전용 계정(lt-agent)으로 도는 systemd 서비스 — 쓰기 금지(ProtectSystem=strict)·권한 상승 금지(NoNewPrivileges).
set -u
umask 077
FILES="lt-agent-ctl.sh lt-agent.sh lt-agent-posix.sh lt-agent.py lt_procs.py"
SUMS="lt-agent-ctl.sh=@@SHA:lt-agent-ctl.sh@@ lt-agent.sh=@@SHA:lt-agent.sh@@ lt-agent-posix.sh=@@SHA:lt-agent-posix.sh@@ lt-agent.py=@@SHA:lt-agent.py@@ lt_procs.py=@@SHA:lt_procs.py@@"

say() { printf '%s\n' "$*"; }
die() { say "! $*" >&2; exit 1; }
has() { command -v "$1" >/dev/null 2>&1; }
is_root() { [ "$(id -u 2>/dev/null)" = "0" ]; }
find_python() { for p in python3 python; do has "$p" || continue; v=$("$p" -c 'import sys; print(sys.version_info[0])' 2>/dev/null) || continue; [ "$v" = 3 ] && { say "$p"; return 0; }; done; return 1; }
PY=$(find_python || true)

if is_root; then DEST=/opt/lt-agent; ETC=/etc/lt-agent; else DEST="${HOME:-/tmp}/lt-agent"; ETC="$DEST"; fi
UNIT=/etc/systemd/system/lt-agent.service
use_systemd() { is_root && has systemctl && [ -d /run/systemd/system ]; }

sha_of() {   # 표준 도구 순서대로(sha256sum → shasum → openssl → python3)
  if has sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif has shasum; then shasum -a 256 "$1" | awk '{print $1}'
  elif has openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  elif [ -n "$PY" ]; then "$PY" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
  else say ""; fi
}
want_sum() { for kv in $SUMS; do [ "${kv%%=*}" = "$1" ] && { say "${kv#*=}"; return 0; }; done; return 1; }
fetch() {    # fetch <주소> <저장 파일>
  if has curl; then curl -fsS -m 30 -o "$2" "$1"
  elif has wget; then wget -q -T 30 -O "$2" "$1"
  elif [ -n "$PY" ]; then "$PY" -c 'import sys,urllib.request;open(sys.argv[2],"wb").write(urllib.request.urlopen(sys.argv[1],timeout=30).read())' "$1" "$2"
  else die "curl·wget·python3 중 하나가 필요합니다"; fi
}
post_json() {   # post_json <주소> <본문 파일> → 응답 본문(표준 출력). 본문(등록 코드)은 명령줄이 아니라 파일로 보낸다
  if has curl; then curl -sS -m 30 -X POST -H 'Content-Type: application/json' -H 'Expect:' --data-binary "@$2" "$1"
  elif has wget; then wget -q -O - -T 30 --header='Content-Type: application/json' --post-file="$2" "$1"
  elif [ -n "$PY" ]; then "$PY" -c 'import sys,urllib.request,urllib.error
r=urllib.request.Request(sys.argv[1],data=open(sys.argv[2],"rb").read(),headers={"Content-Type":"application/json"})
try: print(urllib.request.urlopen(r,timeout=30).read().decode())
except urllib.error.HTTPError as e: print(e.read().decode())' "$1" "$2"
  else die "curl·wget·python3 중 하나가 필요합니다"; fi
}
jget() { say "$1" | sed -n "s/.*\"$2\": *\"\\([^\"]*\\)\".*/\\1/p" | head -n 1; }
jnum() { say "$1" | sed -n "s/.*\"$2\": *\\([0-9][0-9]*\\).*/\\1/p" | head -n 1; }

collector() {   # 수집기 고르기 → RUN_BIN RUN_SCRIPT WHAT (ctl 과 같은 순서: python3 → Linux bash → POSIX sh)
  if [ -n "$PY" ]; then RUN_BIN=$(command -v "$PY"); RUN_SCRIPT="$DEST/lt-agent.py"; WHAT="Python 3"
  elif [ "$(uname -s 2>/dev/null)" = Linux ] && has bash; then RUN_BIN=$(command -v bash); RUN_SCRIPT="$DEST/lt-agent.sh"; WHAT="bash"
  else RUN_BIN=$(command -v sh); RUN_SCRIPT="$DEST/lt-agent-posix.sh"; WHAT="POSIX sh"; fi
}

do_status() {
  if use_systemd && [ -f "$UNIT" ]; then systemctl --no-pager status lt-agent 2>/dev/null | head -n 12; journalctl -u lt-agent -n 5 --no-pager 2>/dev/null
  elif [ -f "$DEST/lt-agent-ctl.sh" ]; then sh "$DEST/lt-agent-ctl.sh" status
  else say "설치되어 있지 않습니다($DEST)"; fi
}
do_remove() {
  if use_systemd && [ -f "$UNIT" ]; then systemctl disable --now lt-agent 2>/dev/null; rm -f "$UNIT"; systemctl daemon-reload; fi
  [ -f "$DEST/lt-agent-ctl.sh" ] && { sh "$DEST/lt-agent-ctl.sh" stop >/dev/null 2>&1; sh "$DEST/lt-agent-ctl.sh" disable-boot >/dev/null 2>&1; }
  case "$DEST" in */lt-agent) rm -rf "$DEST";; esac
  is_root && rm -rf /etc/lt-agent
  if is_root && [ -f /var/lib/lt-agent.created ]; then userdel lt-agent 2>/dev/null; rm -f /var/lib/lt-agent.created; fi   # 우리가 만든 계정만 지운다
  say "제거했습니다($DEST). LogTriage 화면에서 이 서버의 토큰도 [폐기]하십시오."
}

case "${1:-}" in
  --status) do_status; exit 0;;
  --remove) do_remove; exit 0;;
  ''|-h|--help) sed -n '2,13p' "$0"; exit 0;;
esac

URL=$(say "${1:-}" | sed 's#/*$##'); CODE="${2:-}"
if [ "$CODE" = "-" ] || [ -z "$CODE" ]; then   # 화면 명령: printf %s <코드> | sudo sh lt-setup.sh <주소> -  (코드가 ps 에 보이지 않게)
  [ -t 0 ] && printf '등록 코드: ' >&2
  IFS= read -r CODE || true
fi
CODE=$(say "$CODE" | tr -d ' \r' | tr 'a-z' 'A-Z')
case "$URL" in http://*|https://*) ;; *) die "LogTriage 주소는 http:// 또는 https:// 로 시작해야 합니다";; esac
case "$URL" in *[!A-Za-z0-9.:/_%\[\]-]*) die "주소에 허용되지 않는 문자가 있습니다";; esac
case "$CODE" in LT-????-????-????) ;; *) die "등록 코드 형식이 아닙니다(LT-XXXX-XXXX-XXXX) — 화면의 명령을 그대로 붙여 넣으십시오";; esac
case "$CODE" in *[!A-Z0-9-]*) die "등록 코드 형식이 아닙니다";; esac
case "$URL" in http://*) say "참고: http 로 연결합니다 — 사내망 밖을 지나면 LogTriage 를 https 로 운영하십시오(토큰이 오가는 구간).";; esac

say "1) LogTriage 연결 확인: $URL"
TMP=$(mktemp -d 2>/dev/null) || { TMP="${TMPDIR:-/tmp}/lt-setup.$$"; mkdir -m 700 "$TMP" || die "임시 폴더를 만들 수 없습니다"; }
trap 'rm -rf "$TMP"' EXIT INT TERM
fetch "$URL/healthz" "$TMP/h" 2>/dev/null && grep -q '"ok"' "$TMP/h" || die "LogTriage 에 닿지 못했습니다 — 주소·포트, 방화벽(이 서버 → LogTriage TCP) 확인"

say "2) 수집기 파일 내려받기 · 무결성 확인(SHA-256)"
for f in $FILES; do
  fetch "$URL/agent/files/$f" "$TMP/$f" || die "$f 내려받기 실패"
  got=$(sha_of "$TMP/$f"); want=$(want_sum "$f") || die "$f 의 기준값이 없습니다"
  [ -n "$got" ] || die "SHA-256 을 계산할 도구가 없습니다(sha256sum·shasum·openssl·python3)"
  [ "$got" = "$want" ] || die "$f 가 기준값과 다릅니다 — 중간에서 바뀌었을 수 있어 설치하지 않습니다(기준 $want / 받은 것 $got)"
done
say "   5개 파일 확인"

say "3) 등록 코드로 이 서버 전용 토큰 받기"
HN=$(hostname 2>/dev/null || uname -n)
case "$HN" in *[!A-Za-z0-9._-]*) HN=$(say "$HN" | tr -cd 'A-Za-z0-9._-');; esac
printf '{"code":"%s","hostname":"%s"}' "$CODE" "$HN" > "$TMP/req"
R=$(post_json "$URL/agent/enroll" "$TMP/req" 2>&1) || true
TOKEN=$(jget "$R" token)
if [ -z "$TOKEN" ]; then
  err=$(jget "$R" error); die "토큰을 받지 못했습니다: ${err:-$R}"
fi
case "$TOKEN" in *[!A-Za-z0-9_-]*) die "받은 토큰 형식이 올바르지 않습니다";; esac
NAME=$(jget "$R" name); INTERVAL=$(jnum "$R" interval); [ -n "$INTERVAL" ] || INTERVAL=30
say "   감시 항목 '$NAME' 전용 토큰을 받았습니다(화면에 보이지 않음)"

say "4) 설치: $DEST"
mkdir -p "$DEST" "$ETC" || die "$DEST 를 만들 수 없습니다"
for f in $FILES; do cp "$TMP/$f" "$DEST/$f"; done
chmod 755 "$DEST"; chmod 644 "$DEST"/*.py; chmod 755 "$DEST"/*.sh
collector
if use_systemd; then
  if ! id lt-agent >/dev/null 2>&1; then
    if has useradd; then useradd -r -M -d "$DEST" -s /sbin/nologin lt-agent 2>/dev/null || useradd -r -M -d "$DEST" -s /bin/false lt-agent 2>/dev/null
    elif has adduser; then adduser -S -D -H -h "$DEST" lt-agent 2>/dev/null; fi
    id lt-agent >/dev/null 2>&1 && { mkdir -p /var/lib; : > /var/lib/lt-agent.created; }
  fi
  RUNAS=lt-agent; id lt-agent >/dev/null 2>&1 || { RUNAS=root; say "   주의: 전용 계정을 만들지 못해 root 로 실행합니다"; }
  chmod 700 "$ETC"
  { say "# LogTriage 에이전트 — 토큰이 들어 있습니다(root 만 읽기). systemd 가 읽어 환경변수로만 넘깁니다"; say "LT_AGENT_TOKEN=$TOKEN"; } > "$ETC/agent.env"
  chmod 600 "$ETC/agent.env"
  [ -f "$UNIT" ] && systemctl stop lt-agent 2>/dev/null   # 예전 설치(토큰이 명령줄에 있던 서비스)를 바꾼다
  UURL=$(say "$URL" | sed 's/%/%%/g')   # systemd 단위 파일에서 % 는 지정자 — 두 번 써서 글자로
  cat > "$UNIT" <<EOF
[Unit]
Description=LogTriage resource usage agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUNAS
EnvironmentFile=$ETC/agent.env
Environment=LC_ALL=C LANG=C PYTHONIOENCODING=utf-8 PYTHONUNBUFFERED=1
ExecStart=$RUN_BIN $RUN_SCRIPT $UURL - $INTERVAL all
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$UNIT"
  systemctl daemon-reload && systemctl enable --now lt-agent >/dev/null 2>&1
  sleep 2
  systemctl is-active --quiet lt-agent || { journalctl -u lt-agent -n 20 --no-pager 2>/dev/null; die "서비스 시작 실패"; }
  say "   시스템 서비스로 시작했습니다(lt-agent · 계정 $RUNAS · 수집기 $WHAT · ${INTERVAL}초마다)"
  say "   상태: sh $0 --status   ·   로그: journalctl -u lt-agent -f   ·   제거: sh $0 --remove"
else
  { say "# LogTriage 에이전트 설정 — 토큰이 들어 있으므로 권한 600 을 유지하십시오"; say "URL=$URL"; say "TOKEN=$TOKEN"
    say "INTERVAL=$INTERVAL"; say "DISK=all"; say "PROCS=1"; } > "$DEST/agent.conf"
  chmod 600 "$DEST/agent.conf"; chmod 700 "$DEST"
  if [ "${LT_SETUP_NO_START:-0}" = 1 ]; then say "   설정만 저장했습니다(시작하지 않음 — LT_SETUP_NO_START=1)"; exit 0; fi
  sh "$DEST/lt-agent-ctl.sh" start || die "시작 실패 — sh $DEST/lt-agent-ctl.sh log 로 확인하십시오"
  sh "$DEST/lt-agent-ctl.sh" enable-boot >/dev/null 2>&1 && say "   재부팅 후 자동 시작 등록(사용자 crontab)"
  say "   사용자 설치로 시작했습니다(root 가 아님 · 수집기 $WHAT). 상태: sh $DEST/lt-agent-ctl.sh status"
fi
say "5) 끝 — LogTriage [설치 명령] 창에 '첫 보고 받음'이 뜨면 정상입니다(${INTERVAL}초 안팎)."
