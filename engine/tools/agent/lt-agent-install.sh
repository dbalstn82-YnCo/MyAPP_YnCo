#!/usr/bin/env bash
# LogTriage 자원 사용률 에이전트 설치(Linux, root) — lt-agent.sh 를 /opt/lt-agent 에 복사하고 systemd 서비스로 등록·시작한다.
# 사용:  read -rs T; printf '%s\n' "$T" | sudo bash lt-agent-install.sh http://<LogTriage서버>:8088 - [간격초=30] [디스크=all]; unset T
#        토큰 자리에 '-' 를 쓰면 표준 입력 한 줄로 받는다(명령행 · 셸 기록에 남지 않음). 토큰을 직접 적어도 되지만 설치하는 동안 ps 에 보인다.
#        (lt-agent.sh 가 이 파일과 같은 폴더에 있어야 함)
# 23차(RHEL 검증 매뉴얼 작성 중): 서비스 실행 줄에 토큰을 넣지 않는다 — /etc/lt-agent/agent.env(root 만)를 systemd 가 읽어
#        환경변수로만 넘긴다(전에는 ExecStart 인자라 ps · systemctl show 로 같은 서버의 누구나 토큰을 봤다). 간편 설치(lt-agent-setup.sh)와 같은 방식
# 확인:  systemctl status lt-agent   /   tail -f /var/log/lt-agent.log
# 제거:  sudo bash lt-agent-install.sh --remove
set -u
if [ "${1:-}" = "--remove" ]; then
  systemctl disable --now lt-agent 2>/dev/null; rm -f /etc/systemd/system/lt-agent.service; systemctl daemon-reload
  rm -rf /opt/lt-agent /etc/lt-agent; echo "제거 완료 (로그 /var/log/lt-agent.log 는 남겨 둠)"; exit 0
fi
URL="${1:?LogTriage 서버 주소 필요 (예: http://10.0.0.5:8088)}"; TOKEN="${2:?토큰 필요 ([모니터링] 등록 화면의 에이전트 토큰)}"
INTERVAL="${3:-30}"; DISK="${4:-all}"
if [ "$TOKEN" = "-" ]; then IFS= read -r TOKEN || true; fi
case "$TOKEN" in ''|*[!A-Za-z0-9_-]*) echo "! 토큰 형식이 올바르지 않습니다(영문 · 숫자 · - · _ 만)"; exit 1;; esac
case "$INTERVAL" in ''|*[!0-9]*) echo "! 간격은 초 단위 숫자입니다: $INTERVAL"; exit 1;; esac
HERE="$(cd "$(dirname "$0")" && pwd)"
[ "$(id -u)" -eq 0 ] || { echo "! root 로 실행하십시오: sudo bash $0 ..."; exit 1; }
[ -f "$HERE/lt-agent.sh" ] || { echo "! $HERE/lt-agent.sh 가 없습니다 — lt-agent.sh 를 같은 폴더에 두십시오"; exit 1; }
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { echo "! curl 또는 wget 이 필요합니다"; exit 1; }
# 1) 연결 확인 — 서버 응답(healthz)이 오는지
if command -v curl >/dev/null 2>&1; then R=$(curl -s -m 5 "$URL/healthz" 2>&1); else R=$(wget -q -O - --timeout=5 "$URL/healthz" 2>&1); fi
case "$R" in *'"ok": true'*|*'"ok":true'*) echo "서버 연결 OK: $URL";; *) echo "! 서버 응답 없음: $URL  ($R)"; echo "  주소·포트, 방화벽(대상 서버 → LogTriage 서버 TCP 포트) 확인"; exit 1;; esac
# 2) 설치
mkdir -p /opt/lt-agent && cp "$HERE/lt-agent.sh" /opt/lt-agent/lt-agent.sh && chmod 700 /opt/lt-agent && chmod 700 /opt/lt-agent/lt-agent.sh
sed -i 's/\r$//' /opt/lt-agent/lt-agent.sh
mkdir -p /etc/lt-agent && chmod 700 /etc/lt-agent
( umask 077; printf '# LogTriage 에이전트 — 토큰이 들어 있습니다(root 만 읽기). systemd 가 읽어 환경변수로만 넘깁니다\nLT_AGENT_TOKEN=%s\n' "$TOKEN" > /etc/lt-agent/agent.env )
chmod 600 /etc/lt-agent/agent.env
UURL=$(printf '%s' "$URL" | sed 's/%/%%/g')   # systemd 단위 파일에서 % 는 지정자 — 두 번 써서 글자로
systemctl stop lt-agent 2>/dev/null || true    # 예전 설치(토큰이 실행 줄에 있던 서비스)를 바꾼다
cat > /etc/systemd/system/lt-agent.service <<EOF
[Unit]
Description=LogTriage resource usage agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/lt-agent/agent.env
ExecStart=/bin/bash /opt/lt-agent/lt-agent.sh $UURL - $INTERVAL $DISK
Restart=always
RestartSec=10
StandardOutput=append:/var/log/lt-agent.log
StandardError=append:/var/log/lt-agent.log

[Install]
WantedBy=multi-user.target
EOF
chmod 644 /etc/systemd/system/lt-agent.service   # 토큰은 여기 없다(agent.env)
systemctl daemon-reload && systemctl enable --now lt-agent && sleep 1
systemctl is-active --quiet lt-agent && echo "서비스 시작 OK (lt-agent)" || { echo "! 서비스 시작 실패"; journalctl -u lt-agent -n 20 --no-pager; exit 1; }
# 2026-10-22 현장: healthz(GET)는 통과했는데 실제 전송(POST)은 '[HTTP 000]' 으로 실패했다 — 설치 때 **실제 전송을 한 번** 해 본다.
# 값은 비워 보내 기록을 남기지 않는 시험이 아니라, 진짜 보고 한 건이다(받으면 화면에 바로 나타난다).
TB="{\"hostname\":\"$(hostname)\",\"cpu\":0,\"mem\":0,\"disk\":0,\"os\":\"linux\"}"
if command -v curl >/dev/null 2>&1; then
  TR=$(printf 'header = "X-Agent-Token: %s"\n' "$TOKEN" | curl -K - -sS -m 10 -w ' [HTTP %{http_code}]' -X POST -H 'Expect:' -H "Content-Type: application/json" --data "$TB" "$URL/api/nms/metrics" 2>&1 | tr '\n' ' ')
else
  WR=$(mktemp); ( umask 077; printf 'header = X-Agent-Token: %s\n' "$TOKEN" > "$WR" )   # wget 은 권한 600 임시 설정 파일로(명령행에 두지 않음)
  TR=$(WGETRC="$WR" wget -nv -O - --timeout=10 --tries=1 --header="Content-Type: application/json" --post-data="$TB" "$URL/api/nms/metrics" 2>&1 | tr '\n' ' ')
  rm -f "$WR"
fi
case "$TR" in
  *'"ok": true'*|*'"ok":true'*) echo "전송 시험 OK — LogTriage 가 이 서버의 보고를 받았습니다";;
  *'HTTP 000'*|'') echo "! 전송 시험 실패 — 서버에 닿지 못했습니다: ${TR:-응답 없음}"
                   echo "  연결 확인(GET)은 됐는데 전송(POST)만 안 되면 중간 방화벽·보안 장비(IPS·WAF)가 POST 를 막는 경우가 많습니다."
                   echo "  자세히: curl -v -m 10 -X POST -H 'Content-Type: application/json' --data '{}' $URL/api/nms/metrics";;
  *'HTTP 401'*) echo "! 전송 시험 실패 — 토큰이 맞지 않거나 폐기·만료됐습니다: $TR";;
  *'HTTP 403'*|*'HTTP 404'*) echo "! 전송 시험 실패 — LogTriage 에 이 서버가 '에이전트'로 등록돼 있지 않거나 주소·이름이 다릅니다: $TR"
                   echo "  LogTriage [모니터링] 노란 띠에 '보낸 곳·호스트명·고치는 법'이 나옵니다(이 서버 hostname: $(hostname))";;
  *) echo "! 전송 시험 결과: $TR";;
esac
# 같은 로그에 쓰는 에이전트가 또 돌고 있으면(예전 수동 실행·옛 설치) 줄이 섞이고 보고가 겹친다 — 알려 준다(끄지는 않는다)
OTHER=$(pgrep -af 'lt-agent(\.sh|-posix\.sh|\.py)' 2>/dev/null | grep -v '/opt/lt-agent/lt-agent.sh' | grep -v pgrep || true)
if [ -n "$OTHER" ]; then
  echo "! 이 서비스 말고도 에이전트가 돌고 있습니다(보고가 겹치고 로그가 섞입니다) — 확인 뒤 끄십시오:"
  printf '%s\n' "$OTHER" | sed 's/^/    /'
  echo "  끄기: kill <위 번호>   (설치형 ctl 로 띄웠다면: sh lt-agent-ctl.sh stop)"
fi
echo "첫 전송은 ${INTERVAL}초 뒤 — 확인: tail -f /var/log/lt-agent.log  (마지막에 {\"ok\": true, ...} 가 보이면 정상)"
echo "LogTriage [모니터링]에 이 서버 IP 가 '자원 사용률 수집: 에이전트'로 등록돼 있어야 저장됩니다."
