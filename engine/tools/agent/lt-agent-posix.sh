#!/bin/sh
# LogTriage 자원 사용률 에이전트 — POSIX sh 판(python3·bash 가 없는 AIX/Solaris/HP-UX/FreeBSD 등 Unix 용, 표준 명령 vmstat·df·uptime 만 사용).
# 사용: sh lt-agent-posix.sh http://<LogTriage서버>:8088 <토큰> [간격초=30] [디스크=all]     (보통은 lt-agent-ctl.sh 가 자동 선택해 실행)
# 한계: 네트워크 트래픽은 보내지 않음(null). 메모리는 Linux(/proc/meminfo)·Solaris(kstat)·AIX(svmon)·FreeBSD(sysctl)에서만 시도, HP-UX 등은 null.
#       AIX(svmon inuse)·Solaris(physmem-freemem) 값은 파일 캐시를 포함해 Linux 의 MemAvailable 기준보다 높게 나온다(임계치 해석 주의).
set -u
export LC_ALL=C LANG=C   # vmstat·df·awk 출력 형식 고정
URL=$(printf '%s' "${1:?LogTriage 서버 주소 필요}" | sed 's#/*$##'); TOKEN="${2:?토큰 필요}"; INTERVAL="${3:-30}"; DISK="${4:-all}"
[ "$TOKEN" = "-" ] && TOKEN="${LT_AGENT_TOKEN:?토큰 인자가 '-' 이면 LT_AGENT_TOKEN 환경변수 필요}"   # 설치형 ctl: 명령행 노출 방지
HOST=$(hostname 2>/dev/null || uname -n); OS=$(uname -s 2>/dev/null | tr 'A-Z' 'a-z')
command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || { echo "! curl 또는 wget 이 필요합니다"; exit 1; }
jstr() { printf '%s' "$1" | tr -d '\r\n' | tr '\t' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g'; }   # JSON 문자열: 역슬래시·따옴표 이스케이프, 제어문자 제거

cpu_pct() {   # vmstat 헤더에서 'id'(idle) 열 위치를 찾아 마지막 표본을 읽는다(Linux·AIX·Solaris·FreeBSD 공통)
  command -v vmstat >/dev/null 2>&1 || { echo null; return; }
  vmstat 1 2 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "id") c = i; n = split($0, a, " "); if (c && a[1] ~ /^[0-9]/) last = a[c] }
                                END { if (c && last != "") printf "%.1f", 100 - last; else print "null" }'
}
mem_pct() {
  if [ -r /proc/meminfo ]; then
    awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}/MemFree/{f=$2}/^Buffers/{b=$2}/^Cached/{c=$2}END{ if(!a) a=f+b+c; if(t>0) printf "%.1f", 100*(t-a)/t; else print "null" }' /proc/meminfo
  elif [ "$OS" = sunos ] && command -v kstat >/dev/null 2>&1; then
    kstat -p unix:0:system_pages:physmem unix:0:system_pages:freemem 2>/dev/null | awk '/physmem/{t=$2}/freemem/{f=$2}END{ if(t>0) printf "%.1f", 100*(t-f)/t; else print "null" }'
  elif [ "$OS" = aix ] && command -v svmon >/dev/null 2>&1; then
    svmon -G 2>/dev/null | awk '/^memory/{ if($2>0) printf "%.1f", 100*$3/$2; else print "null"; exit }'
  elif [ "$OS" = freebsd ] && command -v sysctl >/dev/null 2>&1; then
    t=$(sysctl -n hw.physmem 2>/dev/null); f=$(sysctl -n vm.stats.vm.v_free_count 2>/dev/null); p=$(sysctl -n hw.pagesize 2>/dev/null)
    awk -v t="${t:-0}" -v f="${f:-0}" -v p="${p:-4096}" 'BEGIN{ if(t>0) printf "%.1f", 100*(t-f*p)/t; else print "null" }'
  else echo null; fi
}
load1() { uptime 2>/dev/null | sed -n 's/.*load average[s]*: *\([0-9.]*\).*/\1/p' | head -n 1; }

disks_json() {   # df -Pk 전체에서 실제 파일시스템만(가상·특수 마운트 제외), 같은 장치는 첫 마운트만, 최대 32개 — 산식 used/(used+avail)=df %
  n=0; SEEN=" "
  if [ "$DISK" != all ]; then LIST=$(df -Pk "$DISK" 2>/dev/null); else LIST=$(df -Pk 2>/dev/null); fi
  # 장치명·마운트 경로에 공백이 있어도 되게: 숫자 3개 + % 열의 위치를 찾아 앞은 장치, 뒤는 마운트 경로(탭 구분으로 출력)
  printf '%s\n' "$LIST" | awk 'NR>1 { for (i = 2; i + 3 <= NF; i++) if ($i ~ /^[0-9]+$/ && $(i+1) ~ /^[0-9]+$/ && $(i+2) ~ /^[0-9]+$/ && $(i+3) ~ /%$/) {
        dev = $1; for (k = 2; k < i; k++) dev = dev " " $k; mp = $(i+4); for (k = i + 5; k <= NF; k++) mp = mp " " $k
        printf "%s\t%s\t%s\t%s\t%s\n", dev, $i, $(i+1), $(i+2), mp; break } }' |
  while IFS="$(printf '\t')" read -r dev tot used avail mp; do
    [ -n "$mp" ] || continue
    case "$dev" in tmpfs|devtmpfs|devfs|proc|procfs|swap|fdescfs|mfs|ctfs|objfs|sharefs|fd|none|overlay|shm|/proc*|-hosts|auto_home|map*) continue;; esac
    case "$dev" in *:/*|//*) continue;; esac   # NFS(host:/path)·CIFS(//host/share) 등 원격 파일시스템 제외(로컬 볼륨만)
    case "$mp" in /proc|/proc/*|/sys|/sys/*|/dev|/dev/*|/run|/run/*|/snap/*|/var/lib/docker/*|/system/*|/platform/*) continue;; esac
    case "$SEEN" in *" $dev "*) continue;; esac; SEEN="$SEEN$dev "
    P=$(awk -v u="$used" -v a="$avail" 'BEGIN{ if (u + a > 0) printf "%.1f", 100*u/(u+a) }')   # 셸 정수 폭(32비트) 의존 없이 awk 로 계산
    [ -n "$P" ] || continue
    [ $n -gt 0 ] && printf ','
    printf '{"path":"%s","pct":%s,"used_gb":%s,"total_gb":%s}' "$(jstr "$mp")" "$P" "$(awk -v u="$used" 'BEGIN{printf "%.1f", u/1048576}')" "$(awk -v t="$tot" 'BEGIN{printf "%.1f", t/1048576}')"
    n=$((n + 1)); [ $n -ge 32 ] && break
  done
}
disk_max() { printf '%s' "$1" | tr '{' '\n' | sed -n 's/.*"pct":\([0-9.]*\).*/\1/p' | sort -n | tail -n 1; }

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

while :; do
  sleep "$INTERVAL"
  CPU=$(cpu_pct); MEM=$(mem_pct); L=$(load1); DJ=$(disks_json); DM=$(disk_max "$DJ")
  PJ=$(procs_json); [ -n "$PJ" ] && PJ=",\"procs\":$PJ"
  BODY="{\"hostname\":\"$(jstr "$HOST")\",\"cpu\":${CPU:-null},\"mem\":${MEM:-null},\"disk\":${DM:-null},\"load1\":${L:-null},\"rx\":null,\"tx\":null,\"os\":\"$OS\",\"disk_path\":\"$(jstr "$DISK")\",\"disks\":[$DJ]$PJ}"
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
  echo "$(date '+%Y-%m-%d %H:%M:%S') cpu=${CPU:-null} mem=${MEM:-null} disk=${DM:-null} load=${L:-null} -> ${R:-전송 실패}"
done
