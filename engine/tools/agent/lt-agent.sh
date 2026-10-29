#!/usr/bin/env bash
# LogTriage 자원 사용률 에이전트(Linux) — 이 서버의 CPU/메모리/디스크 사용률을 LogTriage 서버에 주기적으로 보낸다(표준 명령만 사용).
# 사용: bash lt-agent.sh http://<LogTriage서버>:8088 <토큰> [간격초=30] [디스크=all]   (all: 모든 로컬 볼륨, 또는 특정 경로). 계정별 프로세스도 보냄(LT_PROCS=0 이면 생략)
#   백그라운드: nohup bash lt-agent.sh http://10.0.0.5:8088 abcd1234 30 all > /var/log/lt-agent.log 2>&1 &
#   systemd 예: /etc/systemd/system/lt-agent.service → ExecStart=/bin/bash /opt/lt-agent/lt-agent.sh http://10.0.0.5:8088 <토큰> 30 all
# LogTriage [모니터링]에 이 서버의 IP 를 '자원 사용률 수집: 에이전트'로 등록해 두어야 저장된다.
set -u
export LC_ALL=C LANG=C   # 숫자·명령 출력 형식 고정
URL="${1:?LogTriage 서버 주소 필요}"; TOKEN="${2:?토큰 필요}"; INTERVAL="${3:-30}"; DISK="${4:-all}"
[ "$TOKEN" = "-" ] && TOKEN="${LT_AGENT_TOKEN:?토큰 인자가 '-' 이면 LT_AGENT_TOKEN 환경변수 필요}"   # 설치형 ctl: 명령행 노출 방지
HOST="$(hostname)"
read -r _ u n s i w q sq st _ < /proc/stat; PB=$((u+n+s+i+w+${q:-0}+${sq:-0}+${st:-0})); PI=$((i+w))
netsum(){ awk -F: 'NR>2 && $1!~/lo/ {split($2,v," "); rx+=v[1]; tx+=v[9]} END{print rx+0, tx+0}' /proc/net/dev; }
read -r PRX PTX < <(netsum); PT=$(date +%s)
procs_json() {   # 계정별 프로세스 집계 + 상위 20개 — ps -eo uid,user,pid,pcpu,rss,comm(표준 옵션; rss/uid 미지원 OS 는 대체). uid 로 묶어 user 열 8자 잘림에도 계정이 섞이지 않게. 이름만 수집(명령행 인자 없음).
  [ "${LT_PROCS:-1}" = "0" ] && return 0
  PS=$(ps -eo uid=,user=,pid=,pcpu=,rss=,comm= 2>/dev/null) || PS=$(ps -eo user=,pid=,pcpu=,rss=,comm= 2>/dev/null | awk '{print $1, $1, $2, $3, $4, $5}') || PS=$(ps -eo user=,pid=,pcpu=,comm= 2>/dev/null | awk '{print $1, $1, $2, $3, 0, $4}')
  [ -n "$PS" ] || return 0
  printf '%s\n' "$PS" | awk '
    function jq(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/[\001-\037]/," ",s); return s }
    NF>=6 && $3 ~ /^[0-9]+$/ { k=$1; if(!(k in uname)) uname[k]=$2; c=$4+0; m=$5/1024; n=$6; for(i=7;i<=NF;i++) n=n" "$i; if(length(n)>48) n=substr(n,1,48)
      cnt[k]++; cpu[k]+=c; mem[k]+=m; tot++; if($2!="?" && $2!="N/A") known++
      lc[tot]=c; lm[tot]=m; line[tot]=sprintf("{\"pid\":%d,\"user\":\"%s\",\"name\":\"%s\",\"cpu\":%.1f,\"mem_mb\":%.1f}", $3, jq($2), jq(n), c, m) }
    END { printf "{\"total\":%d,\"known\":%d,\"failed\":0,\"users\":[", tot, known; k=0
      for(u in cnt) { order[++k]=u }
      for(i=1;i<=k;i++) for(j=i+1;j<=k;j++) if(cnt[order[j]]>cnt[order[i]]) { t=order[i]; order[i]=order[j]; order[j]=t }
      lim=(k>40)?40:k
      for(i=1;i<=lim;i++){ u=order[i]; printf "%s{\"user\":\"%s\",\"count\":%d,\"cpu\":%.1f,\"mem_mb\":%.1f}", (i>1?",":""), jq(uname[u]), cnt[u], cpu[u], mem[u] }
      if(k>lim){ rc=0; rcpu=0; rm=0; for(i=lim+1;i<=k;i++){ u=order[i]; rc+=cnt[u]; rcpu+=cpu[u]; rm+=mem[u] } printf ",{\"user\":\"(기타 %d계정)\",\"count\":%d,\"cpu\":%.1f,\"mem_mb\":%.1f}", k-lim, rc, rcpu, rm }
      printf "],\"top\":["; shown=0
      for(s=1;s<=tot && shown<20;s++){ best=0; for(i=1;i<=tot;i++) if(!(i in used) && (best==0 || lc[i]>lc[best] || (lc[i]==lc[best] && lm[i]>lm[best]))) best=i; if(best==0) break; used[best]=1; printf "%s%s", (shown?",":""), line[best]; shown++ }
      printf "]}" }'
}

while true; do
  sleep "$INTERVAL"
  read -r _ u n s i w q sq st _ < /proc/stat; T=$((u+n+s+i+w+${q:-0}+${sq:-0}+${st:-0})); I=$((i+w))
  DT=$((T-PB)); DI=$((I-PI)); PB=$T; PI=$I
  CPU=$(awk -v dt="$DT" -v di="$DI" 'BEGIN{ if(dt>0) printf "%.1f", 100*(dt-di)/dt; else print "0" }')
  MEM=$(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{ if(t>0) printf "%.1f", 100*(t-a)/t; else print "0" }' /proc/meminfo)
  if [ "$DISK" = "all" ]; then   # 서버와 같은 규칙: /proc/mounts 의 /dev 장치·실제 파일시스템, 같은 장치는 첫 마운트만, 산식은 df 와 동일(used/(used+avail))
    DISKS=""; DSK=0; n=0; SEEN=" "
    while read -r dev mp fst _; do
      case "$dev" in /dev/*) ;; *) continue;; esac
      case "$fst" in tmpfs|devtmpfs|squashfs|overlay|proc|sysfs|cgroup|cgroup2|devpts|efivarfs|autofs|mqueue|debugfs|tracefs|securityfs|pstore|bpf|configfs|fusectl|hugetlbfs|binfmt_misc|ramfs|rpc_pipefs|nsfs|selinuxfs|iso9660|fuse.*) continue;; esac
      case "$mp" in /snap/*|/var/lib/docker/*|/run/*|/sys/*|/proc/*|/dev/*) continue;; esac
      case "$SEEN" in *" $dev "*) continue;; esac; SEEN="$SEEN$dev "
      mp=$(printf '%b' "$mp")   # \040(공백) 등 이스케이프 해제
      LINE=$(df -Pk "$mp" 2>/dev/null | awk 'NR==2{print $2, $3, $4}'); [ -z "$LINE" ] && continue
      T=${LINE%% *}; R=${LINE#* }; U=${R%% *}; A=${R#* }; [ $((U+A)) -le 0 ] && continue
      P=$(awk -v u="$U" -v a="$A" 'BEGIN{printf "%.1f", 100*u/(u+a)}')
      [ $n -gt 0 ] && DISKS="$DISKS,"
      DISKS="$DISKS{\"path\":\"$mp\",\"pct\":$P,\"used_gb\":$(awk -v u="$U" 'BEGIN{printf "%.1f", u/1048576}'),\"total_gb\":$(awk -v t="$T" 'BEGIN{printf "%.1f", t/1048576}')}"
      n=$((n+1)); DSK=$(awk -v p="$P" -v m="$DSK" 'BEGIN{print (p>m)?p:m}')
      [ $n -ge 32 ] && break
    done < /proc/mounts
  else
    DISKS=$(df -Pk "$DISK" 2>/dev/null | awk -v p="$DISK" 'NR==2{printf "{\"path\":\"%s\",\"pct\":%.1f,\"used_gb\":%.1f,\"total_gb\":%.1f}", p, ($3+$4>0)?100*$3/($3+$4):0, $3/1048576, $2/1048576}')
    DSK=$(df -Pk "$DISK" 2>/dev/null | awk 'NR==2{printf "%.1f", ($3+$4>0)?100*$3/($3+$4):0}')
  fi
  LOAD=$(cut -d' ' -f1 /proc/loadavg)
  read -r RX TX < <(netsum); NT=$(date +%s); DTS=$((NT-PT)); [ "$DTS" -le 0 ] && DTS=1
  RXS=$(( (RX-PRX)/DTS )); TXS=$(( (TX-PTX)/DTS )); PRX=$RX; PTX=$TX; PT=$NT; [ "$RXS" -lt 0 ] && RXS=0; [ "$TXS" -lt 0 ] && TXS=0
  PJ=$(procs_json); [ -n "$PJ" ] && PJ=",\"procs\":$PJ"
  BODY="{\"hostname\":\"$HOST\",\"cpu\":$CPU,\"mem\":$MEM,\"disk\":${DSK:-0},\"load1\":$LOAD,\"rx\":$RXS,\"tx\":$TXS,\"os\":\"linux\",\"disk_path\":\"$DISK\",\"disks\":[${DISKS}]$PJ}"
  # 10-22 현장 3차: 작은 보고(설치 시험)는 닿는데 큰 보고(프로세스 목록 포함, 수 KB)만 '[HTTP 000]' — curl 은 1KB 넘는 POST 에
  # 'Expect: 100-continue' 를 붙이고, 중간 보안 장비가 이를 처리하지 못하면 응답 없이 끊긴다. 그 머리글을 빼고(-H 'Expect:'),
  # 그래도 닿지 못하면 프로세스 정보를 뺀 작은 보고로 한 번 더 보내 CPU·메모리·디스크는 들어오게 한다.
  send() {
    if command -v curl >/dev/null 2>&1; then
      # 19차: 토큰을 명령줄에 두지 않는다(같은 서버의 다른 계정이 ps 로 볼 수 있음) — curl 은 표준 입력 설정(-K -)으로 받는다
      printf 'header = "X-Agent-Token: %s"\n' "$TOKEN" | curl -K - -sS -m 10 -w ' [HTTP %{http_code}]' -X POST -H 'Expect:' -H "Content-Type: application/json" --data "$1" "$URL/api/nms/metrics" 2>&1 | tr '\n' ' '
    else
      WR=$(mktemp 2>/dev/null) || WR="${TMPDIR:-/tmp}/lt-agent.$$.$(date +%s).wgetrc"   # wget 은 권한 600 임시 설정 파일로
      ( umask 077; printf 'header = X-Agent-Token: %s\n' "$TOKEN" > "$WR" )
      WGETRC="$WR" wget -nv -O - --timeout=10 --tries=1 --header="Content-Type: application/json" --post-data="$1" "$URL/api/nms/metrics" 2>&1 | tr '\n' ' '
      rm -f "$WR"
    fi
  }
  R=$(send "$BODY")
  if [ -n "$PJ" ] && case "$R" in *'[HTTP 000]'*|'') true;; *) false;; esac; then
    SMALL=$(printf '%s' "$BODY" | sed 's/,"procs":{.*}}$/}/')
    R2=$(send "$SMALL")
    case "$R2" in *'"ok"'*) R="$R2 (프로세스 정보를 빼고 보냄 — 큰 보고가 중간에서 끊깁니다: 보안 장비·MTU 확인)";; esac
  fi
  case "$R" in *'[HTTP 000]'*|'') R="${R:-응답 없음} — 서버에 닿지 못했습니다(주소·포트·방화벽·보안 장비 확인: curl -v -m 10 $URL/healthz)";; esac
  echo "$(date '+%F %T') cpu=$CPU mem=$MEM disk=$DSK load=$LOAD rx=${RXS}B/s tx=${TXS}B/s -> ${R:-전송 실패}"
done
