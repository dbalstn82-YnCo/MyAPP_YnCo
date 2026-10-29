# -*- coding: utf-8 -*-
"""Linux 서버 최종 설치판 zip 생성 — 구동 테스트 전체 패키지(동봉 Python+엔진+wheels+run/stop) + upgrade.sh + 문서 + 룰팩 + SHA256SUMS
   결과: 반출/LogTriage-Linux-Install-2026.09.14.zip  (루트 폴더 LogTriage-Linux-2026.09.14/, 항목명은 모두 ASCII)"""
import hashlib, time, zipfile
from pathlib import Path
OUT = Path(r"C:\Users\dbals\Desktop\로그수집기\반출"); DATE = __import__("os").environ.get("LT_DATE") or __import__("time").strftime("%Y.%m.%d")
SRC = OUT / f"logtriage-linux-test-{DATE}.zip"; ROOT = f"LogTriage-Linux-{DATE}"
DST = OUT / f"LogTriage-Linux-Install-{DATE}.zip"
README = f"""LogTriage — Linux 서버 설치판 (최종 통합 {DATE})
=====================================================
장애 로그 1차 대응 분석기 · 서버형. 지금까지의 설치·패치 내용(전 계층 룰 376·코드 1,252, 제품별 적용 버전 카탈로그,
매뉴얼 기준 수행 절차 80건, 인과 타임라인 요점·구간 로그 검색, 보고서 HWPX·사용자 서식, 인프라 감시(NMS)·자원 관리,
install.sh --skip-pkgs·ICMP 권한 설정, 정식 설치 동시 갱신, 서버 자원 사용률(CPU·메모리·디스크·트래픽) 실시간 그래프·에이전트, 자원 관리 개편(엑셀 문서 기준·병합 셀·큰 화면·엑셀 재다운로드·문서 편집: 셀 수정·행/열 추가·삭제·되돌리기), GPT 교차 검증 반영)이 모두 들어 있는 완전판입니다.
이 판에서 더해진 것: ① 전사 배포 — 통합 로그인·권한(운영/조회/관리)·사이트별 자산 조회 권한, 본사 중앙 수집(conf/hub.json)
                     ② 예약·자동화 개편 — 상시 상태 점검과 정기 보고(HTML·PDF·HWPX), 저장 경로 설정, 화면에서 바로 내려받기
                     ③ 회사 이메일 계정 로그인 — @solideos.com 전용 ID, 비밀번호 3중 저장(페퍼·scrypt·암호화), 첫 로그인 강제 변경,
                        (주)솔리데오 CI 색 로그인 화면. 계정 발급은 python3 -m logtriage.accounts --base <설치경로> add --email ○○@solideos.com
                        서버 키 conf/secret.key 는 DB 와 함께 백업하고 백업 묶음과는 분리 보관(유실 시 전체 비밀번호 초기화).
이 zip 하나로 새 서버에 처음 설치할 수 있고, 이미 설치된 서버는 upgrade.sh 로 갱신할 수 있습니다.

■ 지금 돌고 있는 서버를 이 판으로 바꾸려면 (재설치)
  zip 을 푸신 폴더에서 아래 한 줄이면 됩니다. 자료(분석 이력·계정·게시판·보고서)는 그대로 두고 코드만 새로 깝니다.
      bash reinstall.sh /home/yms/log_svr 8088
  경로를 적지 않으면 이 서버에서 돌고 있는 LogTriage 와 systemd 설치를 스스로 찾아 모두 바꿉니다.
  하는 일: ① 대상 찾기  ② 자료 백업(tar.gz)  ③ 코드 새로 설치  ④ 재기동  ⑤ 빌드 확인
  끝에 'OK  포트 8088 — 빌드 <이 판>' 가 보이면 반영된 것입니다.

■ 어느 판이 돌고 있는지만 확인하려면
      bash verify.sh              (열린 포트를 찾아 모두 확인)
      bash verify.sh 8088 8090    (포트 지정)
  브라우저로 확인하려면 주소창에  http://<서버IP>:<포트>/healthz  를 여십시오.
  게시판 화면 오른쪽 위에도 같은 빌드 값이 표시됩니다.

■ 구성
  reinstall.sh / verify.sh             재설치 / 돌고 있는 판 확인
  run.sh / stop.sh / upgrade.sh        기동·중지 / 이미 설치된 서버를 이 판으로 갱신(bash upgrade.sh <기존 log_svr> <포트>)
  python-3.11-linux-x86_64.tar.gz      동봉 독립 실행형 Python(x86_64, glibc 2.17+) — OS 패키지 불필요
  engine/                              앱 소스(logtriage/)·룰·코드·매뉴얼·공식 서식·도구·tests/·deploy/server(install.sh, nginx, systemd, wheels)
  wheels/                              PyYAML·lxml·psycopg2 wheel(cp311) — run.sh 가 오프라인 설치
  docs/                                설치운영매뉴얼 INSTALL-OPERATION-MANUAL(md·docx), Linux 설치·적용 매뉴얼 LINUX-INSTALL-MANUAL(md)
  rulepack/rulepack-{DATE}.rpk         룰·코드·매뉴얼 지식베이스(engine/ 에 같은 내용이 이미 있음). rulepack-signing.pub(공개키)·지문은 별도 매체
  SHA256SUMS                           무결성 확인: sha256sum -c SHA256SUMS

■ 요구 사항
  Linux x86_64(RHEL/Rocky/Alma 8·9, Ubuntu 20.04+, Debian 11+), bash·tar·gzip·unzip, 디스크 약 500MB, 메모리 2GB 이상.
  인터넷 불필요. ICMP 감시를 쓰려면 ping(iputils).

■ 0. 분할 전송본(.001~.004)을 받았다면 먼저 합치기
  cat LogTriage-Linux-Install-{DATE}.zip.00* > LogTriage-Linux-Install-{DATE}.zip
  sha256sum LogTriage-Linux-Install-{DATE}.zip        # 전달받은 SHA256 값과 같아야 함. 다르면 조각을 다시 받으십시오
  unzip -t LogTriage-Linux-Install-{DATE}.zip | tail -1  # "No errors detected" 확인

■ A. 처음 설치 — 구동 테스트(3분, root 불필요)
  cd /home/yms
  unzip -o LogTriage-Linux-Install-{DATE}.zip
  mv LogTriage-Linux-{DATE} log_svr && cd log_svr
  sha256sum -c SHA256SUMS | grep -v 'OK$' ; true      # 아무것도 안 나오면 정상
  bash run.sh 8088 [비밀번호]                          # → http://<서버IP>:8088
  중지: bash stop.sh   로그: server.log   데이터: data/  (분석 이력·업로드·보고서·NMS·자원)

■ B. 정식 설치 — systemd + nginx + PostgreSQL(root)
  sudo bash /home/yms/log_svr/engine/deploy/server/install.sh --port 8088 --allow-dir /var/log
  (Failed dependencies 로 멈추면  --skip-pkgs  추가. 재실행 안전. 상세: docs/INSTALL-OPERATION-MANUAL 4장)

■ C. 이미 설치된 서버 갱신(이전 판 → 이 판) — 한 줄
  cd /home/yms && unzip -o LogTriage-Linux-Install-{DATE}.zip && bash LogTriage-Linux-{DATE}/upgrade.sh /home/yms/log_svr 8088 [비밀번호]
  → 기존 log_svr 의 engine/·run.sh·stop.sh 를 이 판으로 교체(사이트 룰·등록 서식·기본 정보 보존), data/ 의 룰·코드·매뉴얼 갱신,
    정식 설치(systemd /opt/logtriage)가 있으면 그쪽도 갱신·재시작(실패 시 자동 롤백), 구동 테스트 서버 재기동.
  ※ 분석 이력·업로드·보고서·등록 서식·보고서 기본 정보·NMS·자원 DB 는 data/(정식: /opt/logtriage) 에 있어 그대로 남습니다.

■ D. 설치 후 점검
  1) 화면 우상단 룰 376 · 코드 1,252, 빨간 '환경 점검' 배너 없음
  2) [로그분석] 파일 업로드 → [즉시 분석 시작] → [분석 리포트] ③ 조치 방안의 '수행 절차', 인과 타임라인 요점, 추이 막대 → 구간 로그 검색
  3) [보고서 기본 정보] 저장 → [장애 보고서 생성] → HWPX
  4) 왼쪽 메뉴 [인프라 감시] → 서버 자신의 IP·포트(TCP) 등록, 자원 사용률 수집='이 LogTriage 서버 자체' → 30초 내 '정상' + CPU/MEM/DISK 게이지, [추이] 그래프
     원격 서버는 engine/tools/agent/lt-agent.sh 를 그 서버에서 실행(토큰·명령은 등록 창에 표시) / [자원 관리] → 아무 엑셀이나 업로드 → [열기]에서 병합 셀·행 순서 확인 → [현재 표 엑셀]
  5) 정식 설치: systemctl is-active logtriage-server nginx, ss -lntp | grep ':8088'(127.0.0.1), journalctl -u logtriage-server -n 50

■ 기동이 안 될 때 — run.sh 가 단계별([1/4]~[4/4])로 원인을 출력합니다. 그 출력과 server.log 를 함께 보내 주십시오.
  - "bash\\r: command not found" 또는 "$'\\r': command not found": 스크립트가 Windows 줄바꿈으로 바뀐 것 → sed -i 's/\\r$//' run.sh stop.sh upgrade.sh
  - "포트 8088 를 다른 프로세스가 쓰고 있습니다": 정식 설치 서비스(systemd)가 그 포트를 쓰는 경우가 대부분 → run.sh 안내대로
    (a) bash upgrade.sh 또는 sudo bash engine/deploy/server/install.sh --port 8088 --skip-pkgs 로 정식 설치를 이 판으로 갱신, (b) 다른 포트 bash run.sh 8089
  - "동봉 Python 실행 실패": uname -m 이 x86_64 인지, ldd --version 이 2.17 이상인지, 풀어 둔 경로가 noexec 마운트인지(mount | grep noexec) 확인
  - "소스 import 실패": zip 손상 → sha256sum -c SHA256SUMS 로 깨진 파일 확인 후 다시 반입
  - "wheel 설치 실패": ls wheels/ 에 cp311 wheel 3개(PyYAML·lxml·psycopg2)가 있는지 확인
  - 접속은 되는데 /nms, /resources 가 not found: 접속 포트의 서버가 이전 소스 → ps -ef | grep logtriage.server 로 경로 확인 후 C 절차
  - ICMP '수집 오류': ping 설치 또는 /etc/sysctl.d/90-logtriage-ping.conf(install.sh 가 기록) 확인, TCP 검사로 대체

■ 보안
  비밀번호 없이 띄운 서버는 같은 네트워크 누구나 접속합니다. 룰팩 공개키 지문은 zip 과 다른 경로로 확인하고, 서명 개인키는 서버에 저장하지 마십시오.
  engine/logtriage/resource-template.xlsx(자원정보 양식)·등록 서식·보고서 기본 정보·자원 DB 는 외부 반출 금지입니다.
"""
__import__("sys").path.insert(0, str(Path(__file__).resolve().parent))
import _buildstamp as _bs
BUILD_ID = _bs.build_id(OUT.parent / "engine")   # 빌드 표시는 엔진에서 직접 읽는다 — 손으로 고치다 어긋나지 않도록
VERIFY_SH = '#!/usr/bin/env bash\n# 지금 돌고 있는 LogTriage 서버가 어느 판인지 알려 준다.\n#   bash verify.sh              — 열려 있는 포트를 찾아 모두 확인\n#   bash verify.sh 8088 8090    — 포트를 직접 지정\nWANT="@@LOGTRIAGE_BUILD@@"\necho "LogTriage 판 확인 — 이 설치판의 빌드: $WANT"\necho\n\nports_from_args="$*"\nPORTS="$ports_from_args"\nif [ -z "$PORTS" ]; then\n  PORTS="8088"\n  if [ -f /etc/logtriage/server.env ]; then\n    SP="$(sed -n \'s/^LOGTRIAGE_PORT=//p\' /etc/logtriage/server.env | tr -dc \'0-9\')"\n    [ -n "$SP" ] && PORTS="$PORTS $SP"\n  fi\n  # 실제로 열려 있는 포트도 함께 본다\n  if command -v ss >/dev/null 2>&1; then\n    FOUND="$(ss -ltnp 2>/dev/null | grep -i python | grep -oE \':[0-9]+\' | tr -d \':\' | sort -un | tr \'\\n\' \' \')"\n  elif command -v netstat >/dev/null 2>&1; then\n    FOUND="$(netstat -ltnp 2>/dev/null | grep -i python | grep -oE \':[0-9]+\' | tr -d \':\' | sort -un | tr \'\\n\' \' \')"\n  else\n    FOUND=""\n  fi\n  PORTS="$PORTS $FOUND"\nfi\nPORTS="$(printf \'%s\\n\' $PORTS | sort -un | tr \'\\n\' \' \')"\n\nBAD=0; SEEN=0\nfor p in $PORTS; do\n  body="$(curl -fsS --max-time 5 "http://127.0.0.1:${p}/healthz" 2>/dev/null || true)"\n  [ -z "$body" ] && continue\n  SEEN=$((SEEN+1))\n  got="$(printf \'%s\' "$body" | python3 -c \'import json,sys\ntry: print(json.load(sys.stdin).get("build",""))\nexcept Exception: print("")\' 2>/dev/null || true)"\n  src="$(ps -eo pid,args 2>/dev/null | grep -m1 "[l]ogtriage.server" | sed -n \'s/.*PYTHONPATH=\\([^ ]*\\).*/\\1/p\')"\n  if [ "$got" = "$WANT" ]; then\n    echo "  OK  포트 $p — 빌드 $got"\n  elif [ -z "$got" ]; then\n    echo "  !!  포트 $p — 빌드 표시 없음 (이번 판 이전 소스입니다)"; BAD=1\n  else\n    echo "  !!  포트 $p — 빌드 $got (기대 $WANT)"; BAD=1\n  fi\ndone\n\nif [ "$SEEN" = 0 ]; then\n  echo "  응답하는 LogTriage 서버를 찾지 못했습니다."\n  echo "  열려 있는 포트:  ss -ltnp | grep -i python"\n  exit 1\nfi\necho\nif [ "$BAD" = 0 ]; then\n  echo "모두 이번 판입니다."\nelse\n  echo "예전 판이 돌고 있는 포트가 있습니다 — 그 서버를 띄운 경로를 확인하십시오:"\n  echo "   ps -ef | grep [l]ogtriage.server"\n  echo "   그 경로를 대상으로:  bash reinstall.sh <그 경로에 맞는 log_svr 폴더> <포트>"\n  exit 2\nfi\n'
REINSTALL_SH = '#!/usr/bin/env bash\n# LogTriage 재설치 — 이 설치판으로 코드를 통째로 새로 깔고, 자료(분석 이력·계정·게시판·보고서)는 그대로 둔다.\n#\n#   bash reinstall.sh [log_svr 경로] [포트] [비밀번호]\n#     예) bash reinstall.sh /home/yms/log_svr 8088\n#     경로를 적지 않으면 돌고 있는 서버와 systemd 설치를 스스로 찾는다.\n#\n# 하는 일\n#   [1] 지금 돌고 있는 LogTriage 를 모두 찾는다(구동 테스트·systemd·그 밖의 프로세스)\n#   [2] 자료를 통째로 백업한다(conf·data·reports·uploads → tar.gz)\n#   [3] 코드(engine/logtriage 등)를 지우고 이 판으로 새로 깐다 — 자료는 건드리지 않는다\n#   [4] 다시 띄운다\n#   [5] 각 포트에 직접 접속해 이번 판이 맞는지 확인하고 결과를 보여 준다\nset -uo pipefail\nHERE="$(cd "$(dirname "$0")" && pwd)"\nWANT="@@LOGTRIAGE_BUILD@@"\nTARGET="${1:-}"; PORT="${2:-8088}"; PW="${3:-}"\n[ -f "$HERE/engine/logtriage/server.py" ] || { echo "! $HERE/engine 이 없습니다 — zip 을 푼 폴더에서 실행하십시오"; exit 1; }\necho "============================================================"\necho " LogTriage 재설치   설치판 빌드: $WANT"\necho "============================================================"\n\n# ── [1] 대상 찾기 ───────────────────────────────────────────────\necho\necho "[1/5] 대상 찾기"\nCANDS=""\nif [ -n "$TARGET" ]; then\n  TARGET="$(cd "$TARGET" 2>/dev/null && pwd || echo "$TARGET")"\n  CANDS="$TARGET"\nfi\nfor g in /home/*/log_svr /opt/log_svr /srv/log_svr; do\n  [ -d "$g/engine/logtriage" ] && CANDS="$CANDS $g"\ndone\n# 돌고 있는 프로세스에서 소스 경로를 뽑는다\nRUNNING="$(ps -eo args 2>/dev/null | grep "[l]ogtriage.server" || true)"\nif [ -n "$RUNNING" ]; then\n  echo "  돌고 있는 서버:"\n  printf \'%s\\n\' "$RUNNING" | sed \'s/^/    /\'\nfi\nINST="${INSTALL_DIR:-/opt/logtriage}"\nHAS_SVC=0\nif [ -f /etc/systemd/system/logtriage-server.service ] && [ -d "$INST/logtriage" ]; then\n  HAS_SVC=1\n  echo "  systemd 정식 설치: $INST"\nfi\nCANDS="$(printf \'%s\\n\' $CANDS | awk \'NF\' | sort -u | tr \'\\n\' \' \')"\n[ -n "$CANDS" ] && echo "  구동 테스트 폴더: $CANDS"\nif [ -z "$CANDS" ] && [ "$HAS_SVC" = 0 ]; then\n  echo "  ! 기존 설치를 찾지 못했습니다. 새로 설치하려면:  bash run.sh $PORT"\n  exit 1\nfi\n\n# ── [2] 백업 ───────────────────────────────────────────────────\necho\necho "[2/5] 자료 백업"\nSTAMP="$(date +%Y%m%d-%H%M%S)"\nbackup_one() {\n  local dir="$1" name="$2" out\n  out="$(dirname "$dir")/logtriage-backup-${name}-${STAMP}.tar.gz"\n  local items=""\n  for d in conf data reports uploads rules-local; do [ -e "$dir/$d" ] && items="$items $d"; done\n  [ -e "$dir/engine/rules-local" ] && items="$items engine/rules-local"\n  [ -e "$dir/engine/report-template/custom" ] && items="$items engine/report-template/custom"\n  if [ -z "$items" ]; then echo "  (백업할 자료 없음: $dir)"; return 0; fi\n  if tar czf "$out" -C "$dir" $items 2>/dev/null; then\n    echo "  $dir → $out  ($(du -h "$out" 2>/dev/null | cut -f1))"\n  else\n    echo "  ! 백업 실패: $dir — 계속할지 결정하십시오"; return 1\n  fi\n}\nFAILED_BAK=0\nfor d in $CANDS; do backup_one "$d" "$(basename "$d")" || FAILED_BAK=1; done\nif [ "$HAS_SVC" = 1 ]; then\n  SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"\n  $SUDO tar czf "/var/tmp/logtriage-backup-opt-${STAMP}.tar.gz" -C "$INST" conf data reports uploads rules-local 2>/dev/null \\\n    && echo "  $INST → /var/tmp/logtriage-backup-opt-${STAMP}.tar.gz" \\\n    || echo "  (정식 설치 자료 백업 생략 — 해당 폴더 없음)"\nfi\nif [ "$FAILED_BAK" != 0 ]; then\n  echo "  ! 백업에 실패한 대상이 있습니다. 중단합니다(자료를 먼저 지키십시오)."\n  exit 1\nfi\n\n# ── [3] 코드 교체 ───────────────────────────────────────────────\necho\necho "[3/5] 코드 새로 설치 (자료는 그대로)"\nreplace_tree() {   # $1=대상 폴더(engine 이 들어갈 곳)\n  local dst="$1" t\n  mkdir -p "$dst"\n  for t in logtriage rules errorcodes manuals tools deploy tests; do\n    rm -rf "$dst/$t"; cp -r "$HERE/engine/$t" "$dst/$t"\n  done\n  mkdir -p "$dst/report-template"\n  cp -f "$HERE/engine/report-template/"*.hwpx "$HERE/engine/report-template/"*.yaml \\\n        "$HERE/engine/report-template/"style_profile.json "$dst/report-template/" 2>/dev/null || true\n}\nfor d in $CANDS; do\n  echo "  $d"\n  [ -f "$d/stop.sh" ] && bash "$d/stop.sh" >/dev/null 2>&1 || true\n  # 사이트 룰·사용자 서식·보고서 기본 정보는 남긴다\n  SAVE="$(mktemp -d)"\n  [ -d "$d/engine/rules-local" ] && cp -r "$d/engine/rules-local" "$SAVE/rules-local"\n  [ -d "$d/engine/report-template/custom" ] && cp -r "$d/engine/report-template/custom" "$SAVE/custom"\n  [ -f "$d/engine/report-template/report_profile.json" ] && cp -f "$d/engine/report-template/report_profile.json" "$SAVE/report_profile.json"\n  replace_tree "$d/engine"\n  [ -d "$SAVE/rules-local" ] && { rm -rf "$d/engine/rules-local"; cp -r "$SAVE/rules-local" "$d/engine/rules-local"; }\n  [ -d "$SAVE/custom" ] && cp -r "$SAVE/custom" "$d/engine/report-template/custom"\n  [ -f "$SAVE/report_profile.json" ] && cp -f "$SAVE/report_profile.json" "$d/engine/report-template/report_profile.json"\n  rm -rf "$SAVE"\n  [ -d "$d/engine/rules-local" ] && echo "    사이트 룰 보존: $(ls "$d/engine/rules-local" | wc -l) 개"\n  [ -d "$d/engine/report-template/custom" ] && echo "    등록 서식 보존: $(ls "$d/engine/report-template/custom" | wc -l) 개"\n  cp -f "$HERE/run.sh" "$HERE/stop.sh" "$d/" 2>/dev/null || true\n  [ -f "$HERE/upgrade.sh" ] && cp -f "$HERE/upgrade.sh" "$d/" 2>/dev/null || true\n  [ -f "$HERE/verify.sh" ] && cp -f "$HERE/verify.sh" "$d/" 2>/dev/null || true\n  mkdir -p "$d/wheels"; cp -f "$HERE"/wheels/*.whl "$d/wheels/" 2>/dev/null || true\n  [ -f "$d/python-3.11-linux-x86_64.tar.gz" ] || cp -f "$HERE/python-3.11-linux-x86_64.tar.gz" "$d/" 2>/dev/null || true\n  if [ -d "$d/data" ]; then\n    for k in rules errorcodes manuals; do rm -rf "$d/data/$k"; cp -r "$HERE/engine/$k" "$d/data/$k"; done\n  fi\ndone\nif [ "$HAS_SVC" = 1 ]; then\n  echo "  $INST (systemd)"\n  SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"\n  SVC_USER="$(grep -E \'^User=\' /etc/systemd/system/logtriage-server.service | cut -d= -f2)"; SVC_USER="${SVC_USER:-logtriage}"\n  for k in logtriage rules errorcodes manuals tools; do $SUDO rm -rf "$INST/$k"; $SUDO cp -r "$HERE/engine/$k" "$INST/$k"; done\n  $SUDO mkdir -p "$INST/report-template"\n  $SUDO cp -f "$HERE/engine/report-template/"*.hwpx "$HERE/engine/report-template/"*.yaml \\\n              "$HERE/engine/report-template/"style_profile.json "$INST/report-template/" 2>/dev/null || true\n  $SUDO chown -R root:root "$INST/logtriage" "$INST/tools"; $SUDO chmod -R a+rX "$INST/logtriage" "$INST/tools"\n  $SUDO chown -R "$SVC_USER:$SVC_USER" "$INST/rules" "$INST/errorcodes" "$INST/manuals" "$INST/report-template" 2>/dev/null || true\n  command -v restorecon >/dev/null 2>&1 && $SUDO restorecon -RF "$INST" 2>/dev/null || true\nfi\n\n# ── [4] 기동 ───────────────────────────────────────────────────\necho\necho "[4/5] 다시 띄우기"\nif [ "$HAS_SVC" = 1 ]; then\n  SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"\n  $SUDO systemctl daemon-reload\n  if $SUDO systemctl restart logtriage-server; then\n    sleep 3\n    echo "  systemd logtriage-server: $($SUDO systemctl is-active logtriage-server)"\n  else\n    echo "  ! 서비스 재시작 실패 — journalctl -u logtriage-server -n 50"\n  fi\nfi\nfor d in $CANDS; do\n  [ -f "$d/run.sh" ] || continue\n  ( cd "$d" && bash run.sh "$PORT" $PW >/dev/null 2>&1 ) && echo "  $d: 기동 요청" || echo "  ! $d: run.sh 기동 실패 (server.log 확인)"\ndone\nsleep 3\n\n# ── [5] 확인 ───────────────────────────────────────────────────\necho\necho "[5/5] 확인"\nif [ -f "$HERE/verify.sh" ]; then\n  bash "$HERE/verify.sh" "$PORT"\n  RC=$?\nelse\n  RC=0\nfi\necho\necho "백업 파일은 위 [2/5] 에 적힌 경로에 있습니다. 문제가 없으면 지우셔도 됩니다."\nexit $RC\n'
VERIFY_SH = _bs.inject(VERIFY_SH, BUILD_ID, "verify.sh")
REINSTALL_SH = _bs.inject(REINSTALL_SH, BUILD_ID, "reinstall.sh")
CRLF = b"\r\n"; LF = b"\n"
sums = []
def add(z, arcname, data, mode=0o644):
    zi = zipfile.ZipInfo(arcname, time.localtime()[:6]); zi.create_system = 3
    zi.compress_type = zipfile.ZIP_STORED if arcname.endswith((".gz", ".whl", ".docx", ".rpk")) else zipfile.ZIP_DEFLATED
    zi.external_attr = mode << 16; z.writestr(zi, data)
    sums.append((hashlib.sha256(data).hexdigest(), arcname[len(ROOT) + 1:]))
with zipfile.ZipFile(SRC) as zin, zipfile.ZipFile(DST, "w") as zout:
    for zi in zin.infolist():
        rel = zi.filename.split("/", 1)[1] if "/" in zi.filename else zi.filename
        if not rel or rel.startswith("README"): continue
        data = zin.read(zi.filename)
        if rel.endswith(".sh"): data = data.replace(CRLF, LF)
        add(zout, f"{ROOT}/{rel}", data, 0o755 if rel.endswith(".sh") else 0o644)
    add(zout, f"{ROOT}/README-INSTALL.txt", README.encode("utf-8"))
    add(zout, f"{ROOT}/upgrade.sh", (OUT / "_upgrade.sh").read_bytes().replace(CRLF, LF), 0o755)
    add(zout, f"{ROOT}/reinstall.sh", REINSTALL_SH.encode("utf-8"), 0o755)
    add(zout, f"{ROOT}/verify.sh", VERIFY_SH.encode("utf-8"), 0o755)
    for src, dst in ((f"LogTriage-설치운영매뉴얼-{DATE}.md", f"INSTALL-OPERATION-MANUAL-{DATE}.md"),
                     (f"LogTriage-설치운영매뉴얼-{DATE}.docx", f"INSTALL-OPERATION-MANUAL-{DATE}.docx"),
                     (f"Linux-설치-적용-매뉴얼-{DATE}.md", f"LINUX-INSTALL-MANUAL-{DATE}.md")):
        add(zout, f"{ROOT}/docs/{dst}", (OUT / src).read_bytes())
    add(zout, f"{ROOT}/rulepack/rulepack-{DATE}.rpk", (OUT / f"rulepack-{DATE}.rpk").read_bytes())
    add(zout, f"{ROOT}/rulepack/README.txt", "룰팩은 공개키 서명(Ed25519)만 받습니다(2026-10-15). 화면 [룰팩 업데이트] 에서 .rpk + rulepack-signing.pub 선택, 처음 한 번 인터넷망 화면의 지문 32자리 입력. 옛 rulepack.key(HMAC) 룰팩은 받지 않음.\n".encode("utf-8"))
    zout.writestr(f"{ROOT}/SHA256SUMS", "".join(f"{h}  {n}\n" for h, n in sums))
print(DST.name, DST.stat().st_size // 1024 // 1024, "MB", len(sums), "files")
with zipfile.ZipFile(DST) as z:
    names = z.namelist()
    for k in ("run.sh", "stop.sh", "upgrade.sh", "python-3.11-linux-x86_64.tar.gz", "engine/logtriage/server.py", "engine/logtriage/nms.py",
              "engine/logtriage/gui/nms.html", "engine/logtriage/_vendor/defusedxml/__init__.py", "engine/deploy/server/install.sh",
              "engine/tests/test_nms.py", "README-INSTALL.txt", f"docs/INSTALL-OPERATION-MANUAL-{DATE}.docx", f"rulepack/rulepack-{DATE}.rpk", "SHA256SUMS"):
        assert f"{ROOT}/{k}" in names, k
    bad = [x for x in names if x.lower().endswith((".hwp", ".hwpx")) and not x.endswith(("form_status.hwpx", "form_postmortem.hwpx"))]
    assert not bad, bad
    assert not any("custom/" in x or "report_profile.json" in x for x in names)
    assert all(x.isascii() for x in names if "/engine/" not in x), [x for x in names if not x.isascii() and "/engine/" not in x]
    for s in ("run.sh", "stop.sh", "upgrade.sh", "reinstall.sh", "verify.sh", "engine/deploy/server/install.sh"):
        assert CRLF not in z.read(f"{ROOT}/{s}"), s
        assert (z.getinfo(f"{ROOT}/{s}").external_attr >> 16) & 0o111, s
    assert b"upgrade.sh" in z.read(f"{ROOT}/run.sh") and b"systemctl is-active" in z.read(f"{ROOT}/run.sh"), "run.sh 신판 아님"
    _bs.audit_zip(DST, BUILD_ID)
    print("verify ok — ASCII names, LF scripts, exec bits; hwpx:", [x.split("/")[-1] for x in names if x.endswith(".hwpx")])
