# LogTriage 설치·운영 매뉴얼

**장애 로그 1차 대응 분석기 — 서버형(Linux) 통합판 2026-09-22**

| 항목 | 내용 |
|---|---|
| 대상 | 사내망 Linux 서버에 LogTriage 를 설치·패치·운영하는 담당자, 화면을 사용하는 1차 대응 담당자 |
| 배포 파일 | `LogTriage-Linux-Install-2026.09.22.zip`(설치 전체판: 동봉 Python+엔진+문서+룰팩) · `logtriage-linux-patch-2026.09.22-py311.zip`(패치) · `rulepack-2026.09.22.rpk` + `rulepack.key`(별도 매체) |
| 이 판에 포함된 기능 | 전 계층(OS·WEB·WAS·DB·상용SW) 룰 376·에러코드 1,252 + 제품별 적용 버전 카탈로그, 매뉴얼 기준 수행 절차(1차/2차/3차) 80건, 인과 타임라인 요점·추이 그래프 구간 로그 검색, 보고서(HWPX 2종·사용자 서식), 인프라 감시(NMS)·자원 관리, install.sh `--skip-pkgs`, apply_patch.sh 정식 설치 동시 갱신 |
| 2026-09-21 추가 | 전사 배포(통합 로그인·권한·사이트별 자산 조회 권한·본사 중앙 수집), 예약·자동화 개편(경로 설정·HTML/PDF/HWP 보고서·화면에서 내려받기), 회사 이메일 계정 로그인(@solideos.com 전용 ID·비밀번호 3중 저장·첫 로그인 강제 변경)과 (주)솔리데오 CI 로그인 화면 |

---

## 1. 구성과 동작 원리

```
[담당자 PC 브라우저] ──HTTP(S)──▶ [nginx :80/:443]* ──▶ [logtriage-server :8088 (Python 3.10+, systemd 또는 run.sh)]
                                                            ├ 로그 업로드 → uploads/          ├ 분석 엔진: rules · errorcodes · manuals(룰팩으로 갱신)
                                                            ├ 분석 이력·이벤트 → SQLite | PostgreSQL
                                                            ├ 보고서(HWPX·HTML) → reports/     ├ 인프라 감시 → data/nms/nms.sqlite3
                                                            └ 자원 관리 → data/inventory/resources.sqlite3
* nginx 는 정식 설치(install.sh)에서만 사용. 구동 테스트(run.sh)는 앱이 직접 포트를 연다.
```

두 가지 설치 방식이 있으며 같은 소스를 씁니다.

| 방식 | 언제 | 실행 | 소스·데이터 위치 |
|---|---|---|---|
| **구동 테스트(run.sh)** | root 없이 바로 확인, 소규모 운영 | `bash run.sh <포트> [비밀번호]` / `bash stop.sh` | `log_svr/engine`, `log_svr/data` |
| **정식 설치(install.sh)** | systemd 자동 기동, nginx·TLS, PostgreSQL | `sudo bash engine/deploy/server/install.sh` | `/opt/logtriage`, 설정 `/etc/logtriage/server.env` |

> 두 방식을 한 서버에 같이 두면 **포트가 겹치지 않게** 하십시오(정식 설치 앱 포트는 `server.env` 의 `LOGTRIAGE_PORT`). 2026-09-14 패치부터 `apply_patch.sh` 가 두 곳을 함께 갱신합니다.

---

## 2. 사전 요구사항

| 항목 | 최소 | 비고 |
|---|---|---|
| OS | RHEL/Rocky/Alma 8·9, Ubuntu 20.04 이상, Debian 11 이상 (x86_64, glibc 2.17+) | 구동 테스트는 동봉 Python 3.11 사용 → OS 패키지 불필요 |
| CPU/메모리 | 2 vCPU / 4 GB (권장 4 vCPU / 8 GB) | 600MB 로그 분석 시 피크 약 150MB, 동시 3건 |
| 디스크 | 10 GB (권장 50 GB) | uploads·reports·DB 가 쌓임 |
| Python | 3.10 이상 (정식 설치가 시스템 python3 없으면 동봉본 사용) | 3.11 권장 |
| 포트 | 앱 8088(내부), nginx 80/443(정식) | 방화벽 인바운드 허용 필요 |
| ICMP 감시 | `ping`(iputils) | 없으면 TCP 검사만 가능 |

---

## 3. 처음 설치 — 구동 테스트 (root 불필요, 3분)

```bash
mkdir -p /home/yms && cd /home/yms
unzip -o LogTriage-Linux-Install-2026.09.14.zip && mv LogTriage-Linux-2026.09.14 log_svr && cd log_svr
bash run.sh 8088                  # 비밀번호 없이(내부망 확인용)
bash run.sh 8088 'S3cret!pass'    # 비밀번호 지정(다른 PC 에서 접속할 때 권장)
```
- 출력 마지막의 `LogTriage 기동 완료 → http://<IP>:8088` 와 `healthz: {"ok": true, …}` 를 확인합니다.
- 방화벽: `sudo firewall-cmd --add-port=8088/tcp --permanent && sudo firewall-cmd --reload` (Ubuntu: `sudo ufw allow 8088/tcp`).
- 중지 `bash stop.sh`, 로그 `cat server.log`, 서버 로컬 로그를 화면에서 직접 고르려면 `log_svr/logs` 에 복사.

---

## 4. 정식 설치 — systemd + nginx + PostgreSQL (root)

```bash
tar xzf logtriage-server-2026.09.14.tar.gz -C /tmp/lt        # 또는 log_svr/engine 을 그대로 사용
sudo bash /tmp/lt/engine/deploy/server/install.sh --port 8088 --allow-dir /var/log --allow-dir /app/logs
```
| 옵션 | 의미 | 기본 |
|---|---|---|
| `--port <n>` | 앱 내부 포트 | 8088 |
| `--db postgres` / `--db sqlite` | 저장소 | PostgreSQL 가능하면 PostgreSQL |
| `--tls` | 자체 서명 인증서로 443, 80→443 리다이렉트 | 80 만 |
| (`--password` 없음) | 명령행 비밀번호는 거절(ps · 셸 기록 노출) | 무작위 12자 → `/etc/logtriage/server.env` 에만 |
| `--allow-dir <경로>` | 화면에서 바로 고를 수 있는 서버 로그 디렉터리(반복) | /var/log |
| `--skip-pkgs` | OS 패키지(rpm/deb) 단계 생략 — python·nginx·postgres 가 이미 있거나 동봉 Python 사용 | 자동 |
| `--offline` | 인터넷 미사용(pkgs/ 있으면 자동) | 자동 |
| `--no-nginx` / `--no-firewall` / `--journal-access` | nginx 없이 0.0.0.0 노출 / 방화벽 개방 생략 / 서비스 계정에 로그 그룹 부여 | |

설치 순서: OS 판별 → (필요 시) 패키지 설치 → `/opt/logtriage` 복사 → venv + PyYAML·lxml(+psycopg2, 동봉 wheel) → 계정 `logtriage` → DB 준비 → `/etc/logtriage/server.env` → systemd `logtriage-server` 등록·기동 → nginx → 방화벽 → healthz. 로그: `/var/log/logtriage-install.log`.
재실행은 안전합니다(비밀번호·DB URL·데이터 유지, 앱·venv·nginx 설정만 갱신).

**`Failed dependencies: postgresql…`** 가 보이면 pkgs 의 rpm 이 이미 설치된 버전과 달라 건너뛴 것이며, `[2/8]`~`[8/8]` 이 이어지면 정상입니다. 멈추면 `--skip-pkgs` 로 재실행하십시오.

---

## 5. 패치 적용

```bash
cd /home/yms && rm -rf logtriage-linux-patch && unzip -o logtriage-linux-patch-2026.09.14-py311.zip
bash logtriage-linux-patch/apply_patch.sh /home/yms/log_svr 8088      # 비밀번호는 인자로 받지 않음
```
apply_patch.sh 가 하는 일:
1. `log_svr/engine` 의 logtriage·rules·rules-local·errorcodes·manuals·tools·deploy 교체, 공식 서식 갱신(사용자 등록 서식·보고서 기본 정보 보존)
2. `log_svr/data` 의 rules·errorcodes·manuals 갱신(분석 이력·업로드·보고서 유지)
3. **정식 설치(systemd `logtriage-server`, `/opt/logtriage`)가 있으면** 그쪽 소스·룰도 갱신 — 교체 전 `/opt/logtriage/.patch-bak-<시각>` 백업 → 코드(logtriage·tools)는 root, 지식 파일(rules·errorcodes·manuals·report-template)·data 는 서비스 계정 소유로 정리 → `restorecon` → `systemctl daemon-reload` → 재시작 → `is-active` 확인, 실패 시 백업으로 자동 롤백
4. `stop.sh` → `run.sh <포트>` 재기동(정식 설치 서비스 프로세스는 건드리지 않음)

룰·코드·매뉴얼(수행 절차 카탈로그 포함)만 갱신할 때는 패치 대신 **룰팩**: 화면 [룰팩 업데이트] → `rulepack-2026.09.14.rpk` + `rulepack.key`. 화면·API 변경(예: 인프라 감시)은 룰팩으로 반영되지 않습니다.

적용 확인:
```bash
curl -s http://127.0.0.1:8088/healthz                 # {"ok": true, ...}
curl -s http://127.0.0.1:8088/api/nms/status | head -c 120   # 로그인 없는 서버: JSON(targets…) = 새 소스
ps -ef | grep -v grep | grep logtriage.server         # 어느 경로의 소스가 도는지
```

---

## 6. 설정 (`/etc/logtriage/server.env`, 정식 설치)

```ini
LOGTRIAGE_HOST=127.0.0.1            # nginx 뒤 루프백. nginx 없이 쓰면 0.0.0.0
LOGTRIAGE_PORT=8088
LOGTRIAGE_PASSWORD=...              # 비우면 인증 없음(권장하지 않음)
LOGTRIAGE_DB=postgresql://logtriage:<pw>@127.0.0.1:5432/logtriage   # 또는 sqlite:////opt/logtriage/data/logtriage.db
LOGTRIAGE_ALLOW=--allow-dir /var/log --allow-dir /app/logs
LOGTRIAGE_UPLOAD_KEEP_DAYS=14       # 업로드 원본 보존 일수(logtriage-cleanup.timer)
LOGTRIAGE_MAX_ACTIVE=3              # 동시 분석·업로드 상한
```
변경 후 `sudo systemctl restart logtriage-server`. 권한 `root:logtriage 640`.
서버 로컬 로그를 화면에서 고르려면 서비스 계정이 읽을 수 있어야 합니다: `setfacl -R -m u:logtriage:rX /app/jeus/logs`.

---

## 7. 일상 운영

### 7.1 기동·중지·상태
| 구동 테스트 | 정식 설치 |
|---|---|
| `bash run.sh 8088 [pw]` / `bash stop.sh` / `cat server.log` | `systemctl status|restart logtriage-server nginx postgresql` / `journalctl -u logtriage-server -f` |

### 7.2 디렉터리·보존
| 데이터 | 구동 테스트 | 정식 설치 | 보존·정리 |
|---|---|---|---|
| 업로드 로그 원본(개인정보 가능) | `log_svr/data/uploads` | `/opt/logtriage/uploads` | 정식: 타이머가 `LOGTRIAGE_UPLOAD_KEEP_DAYS` 초과분 매일 삭제. 테스트: `find … -mtime +14 -delete` |
| 분석 이력·이벤트 | `data/data/logtriage.db` | DB | 이력 500건·이벤트 50건 자동 정리 |
| 보고서 | `data/reports` | `/opt/logtriage/reports` | 수동 정리, 반출 전 검토 |
| 인프라 감시 | `data/nms/nms.sqlite3` | `/opt/logtriage/data/nms/nms.sqlite3` | 측정 원본 7일·종료 장애 90일 자동 정리 |
| 자원 관리 | `data/inventory/resources.sqlite3` | `/opt/logtriage/data/inventory/resources.sqlite3` | 삭제 없음(업로드 이력 30건 표시) |
| 사이트 룰 | `engine/rules-local` | `/opt/logtriage/rules-local` | 백업 대상 |
| 등록 서식·보고서 기본 정보 | `data/report-template/custom`, `report_profile.json` | 동일 | 반출 금지(기관명 포함) |

### 7.3 백업·복원
```bash
sudo bash /opt/logtriage/backup.sh            # DB + rules-local + reports → /opt/logtriage/backup (30일)
sudo bash /opt/logtriage/backup.sh --with-env # server.env 포함(비밀번호 포함 — 별도 보관)
```
구동 테스트는 서버 중지 후 `log_svr/data` 전체를 복사합니다. SQLite(WAL)는 실행 중 한 파일만 복사하지 마십시오.
복원: SQLite 는 서비스 중지 → 파일 교체 → 소유자 확인 → 기동. PostgreSQL 은 `pg_restore --clean --no-owner --dbname=<URL> logtriage.pgdump`.

### 7.4 점검 체크리스트(설치·패치 후)
1. 화면 우상단 **룰 376 · 코드 1,252**. 빨간 '환경 점검' 배너가 없을 것.
2. [로그분석] 파일 끌어다 놓기 → [즉시 분석 시작] → [분석 리포트] 판정·③ 조치 방안의 '수행 절차'·인과 타임라인 요점.
3. 추이 그래프 막대 hover → [이 구간 로그 검색].
4. [보고서 기본 정보] 저장 → [장애 보고서 생성] → HWPX 다운로드.
5. [코드 조회] → 제품 → [버전] 탭.
6. [모니터링] → 서버 자신의 IP·포트를 TCP 로 등록 → 30초 내 '정상'. 같은 IP 를 ICMP 로 등록 → '정상'(수집 오류면 9장 ICMP 항목). [자원 관리] → 아무 엑셀이나 업로드 → [열기]에서 병합 셀·행 순서가 원본과 같은지, [현재 표 엑셀]이 열리는지.
7. 정식 설치: `systemctl daemon-reload; systemctl is-active logtriage-server nginx; nginx -t; ss -lntp | grep ':8088'`(127.0.0.1 바인딩), `journalctl -u logtriage-server -n 50` 권한 오류 없음, `systemctl list-timers | grep logtriage` cleanup 타이머 활성. RHEL: `getenforce`, `ls -lZ /opt/logtriage`, `ausearch -m AVC -ts recent`.
8. 자원 업로드 방어 확인(선택): 수식 셀·DOCTYPE 포함·`vbaProject`·10MB 초과 파일이 각각 거부되는지(엔진 `tests/` 25개 자동 시험이 같은 항목을 검증).

---

## 8. 화면 사용 안내(요약)

| 메뉴 | 용도 |
|---|---|
| 대시보드 | 누적 장애 현황(일별·계층별·제품별), 최근 분석 |
| 로그분석 | 로그 투입(업로드·서버 경로) → 옵션(장애 시각·제품 자동 판별) → 분석 |
| 분석 리포트 | ① 요약 ② 판정 근거 ③ 장애 유형별 조치 방안 + 수행 절차(1차 읽기 전용 확인 → 2차 복구·설정 변경 → 3차 제조사 의뢰) ④ 단계별 대응 계획 · 인과 타임라인 요점 · 이벤트 추이 |
| 로그 검색 | 분석 건의 정규화된 원본 이벤트 검색(코드·메시지·호스트·제품, 시간 구간, CSV) |
| 분석 이력 | 최근 분석 건 재열람·삭제 |
| 코드 조회 | 제품별 에러코드·룰·매뉴얼·[버전] 카탈로그, 사이트 룰 추가 |
| 보고서 양식 | 공식 HWPX 2종 + 사용자 서식 등록·항목 매핑·미리보기 |
| 룰팩 업데이트 | `.rpk` + `.key` 반입 |
| 인프라 감시 | IP·ICMP/TCP 가용성 감시, 장애·복구 이력, 확인, 응답 추이, 서버 자원 사용률(CPU·메모리·디스크·트래픽) 실시간 그래프(자체 수집 또는 에이전트) |
| 자원 관리 | 어떤 엑셀이든 업로드해 시트·병합 셀·행 순서 그대로 큰 화면에서 조회·검색·편집(셀 수정·행/열 추가·삭제·되돌리기), 원본/현재 표 엑셀 다운로드 |

### 8.1 서버 자원 사용률(CPU · 메모리 · 디스크 · 네트워크 트래픽) — 2026-09-14 추가

감시 항목 등록 창의 **자원 사용률 수집**에서 선택합니다. 목록에 CPU/MEM/DISK 게이지와 NET(↓수신 ↑송신)이 표시되고, [추이]를 누르면 항목별 실시간 그래프(5초 갱신, 1시간·6시간·24시간·7일)가 나옵니다. 75% 주의·90% 위험 점선.

| 수집 방식 | 대상 | 준비 | 주기 |
|---|---|---|---|
| 이 LogTriage 서버 자체 | LogTriage 가 도는 서버 | 없음(표준 라이브러리로 /proc·시스템 API 읽음) | 10초 |
| 원격 서버 — 에이전트 푸시 | 모니터링 대상 Linux/Unix/Windows 서버 | 설치형 zip([⬇ lt-agent.zip 받기], 8.1.4) 또는 스크립트 1개 실행(`engine/tools/agent/lt-agent.sh`·`lt-agent.py`·`lt-agent.ps1`, 화면의 [스크립트 받기]) | 30초(인수로 변경) |

- 에이전트는 `POST http://<LogTriage>:<포트>/api/nms/metrics` 로 JSON(cpu·mem·disk·load1·rx·tx bytes/s)을 보내며, 헤더 `X-Agent-Token` 이 `data/nms/agent_token.txt` 와 같아야 합니다(등록 창에 표시). 보낸 서버의 IP(또는 호스트명)가 '에이전트'로 등록된 항목과 일치할 때만 저장됩니다. 로그인 없이 받는 유일한 API 이며 본문 8KB 제한.
- Linux 상시 실행 예: `nohup bash lt-agent.sh http://10.0.0.5:8088 <토큰> 30 all > /var/log/lt-agent.log 2>&1 &` (systemd 등록 시 ExecStart 에 같은 명령). curl 또는 wget 필요.
- 트래픽은 서버의 인터페이스 합계(lo 제외) 송·수신 bytes/s 를 Mbps 로 표시합니다. **스위치·방화벽 등 네트워크 장비의 포트 트래픽(SNMP ifInOctets/ifOutOctets)은 이 판에서 수집하지 않습니다** — 대상 서버에 net-snmp(snmpget)가 있으면 다음 판에서 추가 가능합니다. Windows 자체 수집은 트래픽을 제공하지 않습니다(에이전트 ps1 은 제공).
- 보관: 측정값 7일(그래프는 3시간 초과 구간을 최대 720점으로 축약), 정리는 매시간.
- 보안(GPT 교차 검토 반영): 에이전트 토큰은 하나를 모든 서버가 공유하므로 유출 시 `data/nms/agent_token.txt` 를 지우고 서비스를 재시작해 새 토큰을 발급하십시오(파일 권한 600). 전송은 평문 HTTP 이므로 관리망 밖으로는 nginx TLS(`--tls`) 뒤에서만 받으십시오. 출발지는 소켓 IP 로 판정하며(프록시가 같은 호스트일 때만 X-Forwarded-For), 항목당 5초 미만 반복 수신은 거부합니다. 트래픽은 인터페이스 합계라 bond/VLAN/docker 인터페이스가 있으면 중복 계수될 수 있고, CPU 는 steal 포함·guest 제외 기준입니다. 디스크는 루트(/) 또는 시스템 드라이브 하나입니다.

#### 8.1.1 인프라 감시 고도화 (2026-09-15): 전체 볼륨 · 실시간 · 임계치 알림 팝업 · SNMP(방화벽)

| 항목 | 내용 |
|---|---|
| 디스크 전체 볼륨 | **패치 후 모니터링 대상 서버의 에이전트 스크립트는 자동으로 바뀌지 않습니다** — 기존 에이전트를 멈추고 `engine/tools/agent/`(또는 화면의 [스크립트 받기])의 최신 파일로 교체한 뒤 마지막 인자를 `all` 로 다시 실행하십시오(`/` 로 실행 중이면 루트만 보냅니다). 서버 자체·에이전트 모두 **모든 로컬 볼륨**을 수집합니다(Linux: /proc/mounts 의 /dev 장치, tmpfs·overlay·snap·docker 제외 / Windows: 고정 드라이브 전부). 목록·그래프·임계치는 볼륨 중 **가장 높은 사용률** 기준이고, [실시간] 카드에 볼륨별 경로·%·사용량/전체(GB)가 나옵니다. 에이전트 4번째 인자는 `all`(기본) 또는 특정 경로 |
| 실시간 | 목록의 [추이] 버튼이 **[실시간]**으로 바뀌었습니다. 5초마다 갱신되는 자원 사용률 그래프(1시간~7일 범위)와 응답 시간 추이를 함께 엽니다 |
| 알림 팝업 | 상단 [🔔 알림 설정]: CPU·메모리·디스크 임계치(50~100%, 기본 90), 장애 확정 팝업, 재표시 간격(분). 임계치는 서버 공통, 소리·브라우저 알림은 브라우저별. 초과하면 화면 우상단 팝업 + 탭 제목 `(n)` + (선택) 소리·브라우저 알림. 임계치-5% 아래로 내려가거나 복구되면 자동으로 닫히고, 계속 초과하면 재표시 간격마다 다시 알립니다. **팝업은 인프라 감시 화면을 열어 둔 브라우저에서만** 뜹니다(서버 푸시·메일·문자 없음) |
| SNMP v2c 수집 | 자원 사용률 수집 방식에 **SNMP v2c 조회**가 추가되었습니다(에이전트를 설치할 수 없는 방화벽·스위치·스토리지). 외부 프로그램 없이 서버가 UDP 161 로 직접 읽습니다. community(저장 후 화면에 노출되지 않음), CPU OID·해석(사용률 그대로 / 유휴율→100−값), 메모리 OID·해석(사용률 / 여유율 / 사용량÷전체 / 1−여유량÷전체, 전체 OID 별도), 트래픽 인터페이스 ifIndex(IF-MIB 64비트 카운터, 없으면 32비트). 30초마다 수집, 실패하면 목록에 "SNMP 오류 · 원인" 표시 |
| 연결 테스트·OID 찾기 | 등록 화면의 [연결 테스트]는 sysDescr·sysName·sysUpTime 과 입력한 OID 값을 바로 보여 주고, [OID 찾기]는 기준 OID 아래를 최대 300개까지 순회(walk)합니다. 인터페이스 이름 목록: `1.3.6.1.2.1.2.2.1.2` |

**시큐아이(SECUI) 방화벽 감시 절차**

1. 지금도 가능한 것: 관리 IP 에 ICMP, 서비스 포트(예: HTTPS 443, SSH 22)에 TCP 검사를 등록하면 가용성·응답 시간·장애/복구 이력·장애 팝업이 동작합니다.
2. CPU·메모리·트래픽까지 보려면 방화벽 관리 화면에서 SNMP v2c 를 켜고 **community** 를 정한 뒤 **허용 호스트에 LogTriage 서버 IP** 를 등록합니다(방화벽 정책에서 LogTriage → 방화벽 UDP 161 허용).
3. LogTriage [모니터링] → 등록/편집 → 자원 사용률 수집 "SNMP v2c 조회" → community 입력 → [연결 테스트]로 sysDescr 에 장비 모델이 보이면 통신 OK.
4. CPU·메모리 OID 는 시큐아이가 제공하는 MIB 파일(SECUI-*.mib, 제조사 사설 트리 `1.3.6.1.4.1.<시큐아이 번호>`)에서 확인하거나 [OID 찾기]에 `1.3.6.1.4.1` 을 넣어 값이 0~100 인 항목을 찾아 입력합니다(값이 유휴율이면 해석을 "유휴율→100−값"으로). 표준 HOST-RESOURCES(`1.3.6.1.2.1.25.3.3.1.2`)를 지원하는 장비면 그 값도 쓸 수 있습니다.
5. 트래픽은 [OID 찾기] `1.3.6.1.2.1.2.2.1.2` 로 인터페이스 이름을 보고 원하는 인터페이스 번호(ifIndex)를 입력합니다(예: WAN 포트).
6. 세션 수·정책 차단 수 등 방화벽 고유 지표와 syslog(공격·세션 로그) 수신은 아직 없습니다. 필요하면 다음 단계로 "syslog 수신(UDP 514) → 로그 분석 연계"를 추가합니다.
7. SNMP v3(인증·암호화)는 미지원입니다. community 는 평문으로 전송되므로 관리망에서만 사용하고, 장비 쪽 허용 호스트를 LogTriage 서버 IP 로 제한하십시오.

#### 8.1.2 UI/UX 고도화 (2026-09-15)

- 사이드바 메뉴 이름은 2026-09-15 부터 **[모니터링]**입니다(이전 명칭 '인프라 감시'; 화면 주소 /nms 와 API 는 그대로).
- 아이콘 전면 교체(프리미엄 스타일): 사이드바 메뉴, KPI, 자원 지표(CPU·메모리·디스크·네트워크), 알림 팝업, 장비 분류(서버·네트워크·보안·스토리지·기타), 자원 문서 카드, 빈 상태 일러스트.
- 그래프: 부드러운 곡선·그라데이션 면·0~100% 눈금·시간축·현재값 표시, 마우스를 올리면 시각과 값 툴팁. 응답 시간 추이는 평균·최소·최대와 실패(빨강)·수집 오류(주황) 마크를 함께 표시합니다.
- 알림 팝업은 화면 우하단에 쌓이며 경고·장애 아이콘으로 구분됩니다. 로그인 화면·버튼·카드 스타일도 함께 정리했습니다.

#### 8.1.3 대시보드 확장 (2026-09-17)

- 대시보드가 4개 현황을 한 화면에 보여 줍니다: **장애 현황**(총 분석 건·등급 분포·일자별·계층별·TOP5·최근 분석), **모니터링 현황**(정상/장애/확인 필요/등록, 분류별 수, 임계치 초과, 최근 장애 → [모니터링 ›]), **자원 관리 등록 현황**(문서/시트/행/수정 건수, 최근 문서 → 클릭 시 열기), **코드 등록 현황**(에러 코드·제품·시그니처 룰·계층, 제품별 상위 8 → [코드 조회 ›]).
- 모니터링·자원 카드는 서버형(및 로컬 exe 내장 서버)에서만 나타납니다. 룰·코드 사전은 기동 시 미리 읽어 두고 폴더가 바뀔 때만 다시 읽어(룰팩 적용 포함) 대시보드가 바로 뜹니다. 최다 장애 유형·최근 분석 카드는 제거했고(분석 이력 화면에서 확인), 좌측 하단 '사내망 모드' 표시도 제거했습니다. 사이드바 아이콘은 벡터(SVG)로 바꿔 어떤 화면 배율에서도 선명합니다.

#### 8.1.4 설치형 에이전트(zip, root·관리자 권한 불필요) · 링크 주소 표시 제거 · '모니터링 대상' (2026-09-17)

| 항목 | 내용 |
|---|---|
| 설치형 에이전트 | 등록 창(자원 사용률 수집: 에이전트)의 **[⬇ lt-agent.zip 받기]** — zip 안 `agent.conf` 에 이 서버 주소·토큰이 채워져 있어 대상 서버에서 압축을 풀고 `sh lt-agent-ctl.sh start` 만 하면 됩니다. 설정·로그·pid 가 모두 그 폴더 안에만 생기며 /opt·/etc·systemd 를 건드리지 않으므로 **일반 사용자 계정으로 동작**합니다(/proc·df 등 표준 명령만 읽음). |
| 명령 | `sh lt-agent-ctl.sh test`(서버 연결 + 1회 전송 시험: 401=토큰 불일치, 404=IP 미등록) · `start` · `status`(마지막 정상 전송 시각·최근 로그) · `stop` · `restart` · `log` · `enable-boot`/`disable-boot`(사용자 crontab @reboot) · `setup <주소> <토큰>` |
| 수집기 자동 선택 | python3 → `lt-agent.py`(Linux/Windows 공용) → Linux+bash → `lt-agent.sh` → 그 외 Unix(AIX·Solaris·HP-UX·FreeBSD) → `lt-agent-posix.sh`(vmstat 의 id 열·df -Pk·uptime 만 사용, 트래픽 없음, 메모리는 OS 별 시도 후 없으면 null). `agent.conf` 의 `COLLECTOR=python|bash|posix` 로 고정 가능. 필요 조건: python3 또는 curl/wget, 대상 서버 → LogTriage 서버 TCP 8088 아웃바운드 |
| Windows | 같은 zip 의 `lt-agent.cmd start|stop|status|test|enable-boot`(PowerShell 숨김 실행, 로그온 자동 시작은 사용자 작업 스케줄러 `LogTriageAgent`, 관리자 불필요) |
| 재부팅 자동 시작 | 사용자 crontab(@reboot)이 허용된 계정이면 `enable-boot`. cron 이 막힌 계정은 관리자에게 root 설치(`lt-agent-install.sh`, systemd)를 요청 |
| 검증 범위 | Linux 실서버가 아닌 Windows Git Bash 환경에서 ctl(start/status/stop/restart/test)·Python 수집기·POSIX 수집기의 전송·404/401 판정을 확인했습니다. AIX·Solaris 의 메모리 산식(svmon·kstat)은 실장비가 없어 **미검증** — 값이 이상하면 `COLLECTOR=python` 또는 null 로 두십시오 |
| 링크 주소 표시 | 사이드바·카드·버튼형 링크에 마우스를 올릴 때 브라우저 좌측 하단에 주소가 뜨던 것을 없앴습니다(링크는 `data-href` 로 이동, Ctrl/가운데 클릭은 새 탭, Enter 키 지원). 외부 문서 링크(코드 상세의 [문서])만 새 탭 열기 유지 |
| 명칭 | 모니터링 화면의 '감시 대상' 표를 **'모니터링 대상'** 으로 변경 |


#### 8.1.5 Windows exe 서버 모드 — 윈도우 PC 가 다른 서버의 모니터링 정보를 수집 (2026-09-17)

| 항목 | 내용 |
|---|---|
| 설정 | `LogTriage.exe` 옆 `server.conf`(`server.conf.example` 복사): `LISTEN=0.0.0.0` `PORT=8088` `PASSWORD=...`. CLI `--serve --listen --port --password` 가 우선 |
| 창 모드 | server.conf 가 있으면 exe 창을 연 채로 LAN 의 에이전트 푸시·브라우저 접속을 받습니다. exe 창(같은 PC, 루프백)은 로그인 면제, LAN 브라우저는 비밀번호. PASSWORD 없이 LAN 수신은 거부(127.0.0.1 로 대체, 안내 창) |
| 상시 모드 | `LogTriage-server.cmd start|stop|status|log|enable-boot|disable-boot|firewall` — `LogTriage.exe --serve` 를 창 없이 기동(로그 `logtriage_server.log`, pid `server.pid`). 상시 모드는 루프백도 로그인 필요(리눅스 설치형과 동일) |
| 자동 시작 | `enable-boot` = 사용자 작업 스케줄러(로그온 시, 관리자 불필요). 로그온 없이 부팅 직후부터는 관리자 콘솔에서 `schtasks /SC ONSTART /RU SYSTEM` |
| 방화벽 | 인바운드 TCP 8088 허용 필요 — 관리자 콘솔에서 `LogTriage-server.cmd firewall`(netsh) |
| 중복 실행 | 창·상시 모드는 같은 데이터 폴더를 쓰므로 하나만 뜹니다. 상시 모드가 떠 있을 때 exe 를 실행하면 브라우저로 `http://127.0.0.1:<PORT>/` 를 엽니다 |
| 리눅스 서버 쪽 | 브라우저로 이 PC 에 로그인 → [모니터링] 등록 창의 [⬇ lt-agent.zip 받기](agent.conf 에 이 PC 주소·토큰) → `sh lt-agent-ctl.sh start` (8.1.4) |
| 보안 주의 | LAN 은 HTTP 평문입니다(사내망 기준; 인터넷·공용망에서는 리눅스 설치형+nginx TLS 권장). `server.conf` 에 비밀번호가 있으므로 다른 계정이 읽지 못하게 하십시오(`LogTriage-server.cmd start` 가 icacls 로 현재 사용자·SYSTEM 만 허용 시도). exe 는 쓰기 가능한 폴더(예: `C:\LogTriage`)에 두십시오(Program Files 는 설정·로그 기록 불가). `--password` 인자는 명령행에 남으므로 시험용으로만. exe 창은 프로세스만 아는 부트스트랩 토큰으로 세션을 얻고, 같은 PC 의 다른 사용자·프로그램은 루프백이어도 로그인해야 합니다. LAN 수신 중 서버 로컬 경로 분석은 같은 PC(루프백) 요청에만 허용됩니다 |


#### 8.1.6 계정별 프로세스 현황 (2026-09-17)

| 항목 | 내용 |
|---|---|
| 무엇을 | 대상 서버의 **계정별 프로세스 수·CPU%·메모리** 집계(최대 40계정, 나머지는 '(기타 n계정)')와 **상위 20개 프로세스**(PID·계정·이름·CPU%·메모리). 프로세스 **이름만** 수집하고 명령행 인자는 수집하지 않습니다(비밀번호가 섞일 수 있음) |
| 어디서 | 등록 창 **계정별 프로세스 현황**: 집계+상위 20개(기본) / 집계만 / 수집 안 함. 에이전트·이 서버 자체 수집에 적용, SNMP 장비는 해당 없음 |
| 화면 | 목록의 자원 사용률에 `PROC n개 · m계정`(계정 미확인 수는 툴팁). [실시간] 패널에 프로세스 수 추이 그래프, 계정별 표(막대), 상위 프로세스 표 |
| 저장 | 최신 상세 1건만 항목별로 보관(`procs` 테이블, 항목 삭제 시 함께 삭제), 이력은 프로세스 총수(`metrics.pcount`)만 7일. 푸시 본문 한도 8KB → 64KB |
| 에이전트 | 4종 모두 지원. Python(`lt_procs.py` 동봉: Linux /proc·Windows API), bash·POSIX sh(`ps -eo user,pid,pcpu,rss,comm` + awk 집계; pcpu 는 ps 의 누적 평균), PowerShell(관리자면 `Get-Process -IncludeUserName`, 아니면 `Win32_Process.GetOwner` 캐시). 설치형 zip 의 `agent.conf` `PROCS=1`(0 이면 안 보냄), 수동 실행은 `LT_PROCS=0` 또는 `--no-procs` |
| 권한 | Linux/Unix: /proc·ps 로 일반 계정이 전 계정 프로세스를 볼 수 있음(hidepid 마운트면 자기 것만). **Windows: 관리자 권한이 아니면 다른 계정·시스템 프로세스는 계정이 `N/A`** 로 집계됩니다(이 PC 검증: 266개 중 146개 N/A). 관리자로 실행하면 SeDebugPrivilege 를 켜 전부 보입니다 |
| CPU% | Python·PowerShell 은 두 수집 사이의 CPU 시간 증가분(코어 수로 나눈 값), bash/POSIX 는 ps pcpu(프로세스 수명 평균) — 순간값과 다를 수 있음 |
| 검증 | Linux /proc 픽스처·CPU% 델타·캡·저장 수준·HTTP·zip 포함 단위 테스트(tests/test_procs.py), Windows 실수집, Python·PowerShell 에이전트 실제 푸시, ps 픽스처(awk) 확인. 실제 Linux 서버 검증은 패치 적용 후 [실시간] 패널에서 확인하십시오 |

### 8.2 자원 관리 — 업로드한 엑셀 문서가 기준 (2026-09-14 개편)

고정 양식에 맞추지 않아도 됩니다. 어떤 .xlsx 든 시트·행·열·병합 셀을 그대로 읽어 저장하고, [열기]로 큰 화면에서 봅니다.

| 기능 | 동작 |
|---|---|
| 업로드 | 여러 파일 선택 또는 끌어다 놓기. 파일 10MB·시트 30·전체 20,000행·열 120. 값이 있는 행만 저장하되 **원본 행 번호와 순서 그대로**(NO 를 재정렬하지 않음) |
| 병합 셀 | 화면에서도 병합된 채로(rowspan/colspan) 표시. 검색·내보내기에는 병합 범위 전체에 왼쪽 위 값을 적용해 기관명·그룹 정보가 빠져 보이지 않음. 검색으로 일부 행만 남으면 남은 연속 행 단위로 병합을 다시 계산 |
| 제목 행 | 자동 추정(상단 12행 안의 가로 병합 그룹 행 + 그 아래 열 이름 행). 보기 화면의 '제목 행 수'로 0~12행을 직접 지정하면 문서별로 저장 |
| 보기 | 시트 탭, 전체 셀 AND 검색(하이라이트), 칸 너비 좁게/보통/넓게/내용 맞춤/원본 너비, 줄바꿈, 숨김 행·열 표시 토글, 전체 화면(사이드바 숨김), 300행 단위 더 보기, 원본 행 번호 열 |
| 다운로드 | **원본 엑셀**(업로드한 파일 그대로 — 서식·수식·개체 모두 보존) / **현재 표 엑셀**(보이는 시트·검색 결과를 값·병합·열 너비·표시 형식 기준으로 새로 만든 파생본, 파일명 끝 `-현재표`) |
| 값 처리 | 문자열은 그대로(선행 0 보존), 숫자는 원본 표시 형식 보존, 날짜는 날짜형으로 복원, 수식은 `(수식) =…` 로 표시만(계산 안 함). 숨김 행·열은 기본적으로 숨긴 채 표시 |

- 저장: `data/inventory/resources.sqlite3` 의 `docs`(원본 파일+표 데이터), 최대 200문서. 삭제는 목록의 [삭제].
- 보안: 업로드는 로그인 사용자만, ZIP 폭탄·DTD·매크로·비정상 경로 사전 검사. 파생본은 값만 기록해 외부 링크·하이퍼링크를 복사하지 않습니다. 원본은 그대로이므로 외부 링크가 있는 파일은 Excel 이 경고할 수 있습니다.
- 이전 판의 '자원정보.xlsx 6시트 양식' 등록 표는 더 이상 화면에 없으며, 같은 양식 파일도 문서로 올리면 그대로 보입니다(참고 양식 다운로드는 유지).

#### 8.2.1 문서 편집 — 셀 수정·행/열 추가·삭제 (2026-09-14 추가)

[열기] 화면의 [✎ 편집]을 누르면 표를 직접 고칠 수 있습니다. 수정 내용은 서버에 바로 저장되고 [현재 표 엑셀]에 반영됩니다. [원본 엑셀]은 업로드 시점 파일 그대로입니다(원본은 절대 바뀌지 않음).

| 조작 | 방법 |
|---|---|
| 셀 수정 | 셀 두 번 클릭 → 입력 → Enter(저장 후 아래 칸) / Tab(저장 후 오른쪽 칸) / Esc(취소). 병합 셀을 고치면 병합 범위 전체에 같은 값이 들어감 |
| 행 선택 | 왼쪽 행 번호 클릭(여러 행은 반복 클릭, Shift 로 범위). 선택 행은 주황색 |
| 행 추가 | [행 추가 ↑] 선택 행 위 / [행 추가 ↓] 선택 행 아래(선택이 없으면 맨 끝). [개수]로 한 번에 여러 행. 새 행은 행 번호 자리에 '신규' 표시 |
| 행 복제 | 선택 행을 바로 아래에 복사(값만) |
| 행 삭제 | 선택 행 삭제(확인 창). 제목 행은 삭제되지 않음 — 먼저 '제목 행 수'를 줄이십시오 |
| 열 선택·추가·삭제 | 편집 모드에서 위쪽에 열 문자(A, B, C…) 행이 생김. 문자 클릭 → 열 선택 → [열 추가 ←/→], [열 삭제]. 병합 범위·숨김 열·너비·표시 형식이 함께 이동 |
| 되돌리기 | [↶ 되돌리기] — 가장 최근 변경부터 순서대로, 문서별 최근 20건 |
| 변경 이력 | [변경 이력] — 시각·시트·내용·rev. 문서별 500건 보관 |

- 값 규칙: 빈칸은 비움, 선행 0 없는 숫자 형태는 숫자(엑셀에서 숫자로 저장), `007` 같은 값은 문자열 그대로, `=`로 시작하면 계산하지 않고 `(수식) =…` 문자열로만 저장(수식 주입 방지).
- 동시 편집: 두 사람이 같은 문서를 고치다 충돌하면 "다른 사용자가 먼저 수정했습니다" 안내와 함께 화면이 최신으로 새로 고쳐집니다. 그 뒤 다시 고치십시오.
- 제한: 한 번에 행 200개·열 20개까지, 문서 전체 20,000행·시트당 120열.
- 목록 화면과 보기 화면 상단에 "수정 N건(마지막 시각)"이 표시됩니다. 원본을 다시 받으려면 [원본 엑셀], 수정본은 [현재 표 엑셀]/[전체 표 엑셀].

1차 담당자 원칙: 1차 절차는 읽기 전용 확인·자료 보존(스레드 덤프까지)만 수행합니다. 재기동·세션 KILL·힙 덤프·flush·삭제·커널 파라미터 변경은 2차(변경 관리 승인 후)에만 있습니다.

---


### 8.3 지식베이스 수집 라운드 2026-09-18 (Claude + GPT 동시 진행)

| 항목 | 내용 |
|---|---|
| 추가 코드 | **246건** (1,252 → 1498). Claude 직접 작성 165(Oracle·MySQL·MSSQL·PostgreSQL·WebLogic·WebSphere·JBoss·Apache·IIS·Java 예외·Windows 이벤트) + GPT 웹 대조 수집 81(Tibero·Altibase·CUBRID·Goldilocks 각 15, WebtoB 6, AIX errpt 15) |
| 교차 검증 | Claude 추가분을 GPT 가 공식 문서로 대조: OK 101 · 의미/심각도 수정 62 · 보류 2(문서 미확인, source 에 '보류' 표기). GPT 수집분 재대조: OK 70 · 수정 9 · 보류 2 |
| 파일 | `errorcodes/night0918c_*.yaml`(Claude) · `errorcodes/night0918g_*.yaml`(GPT). source 필드에 출처 URL 포함. versions 는 제품 공통값 + '버전 범위 미확인' 표기 |
| 기존 룰 검증 | 단위 테스트 44건, 룰 376·정규식 컴파일, (제품,코드) 중복 0, 필수 필드 누락 0, 샘플 로그 16종 분석 정상 종료 |
| 제외 | 의사코드 제품(Linux/Solaris/HP-UX·Tomcat·nginx 등)은 별칭 정규식이 함께 필요해 이번 라운드 제외. JEUS 는 GPT 가 공식 문서에서 신규 코드를 확인하지 못함 |
| 룰팩 | rulepack-2026.09.18.rpk(563KB, 검증 통과). 서명 키는 이전 키가 유실되어 반출/rulepack.key 로 새로 생성 — 서버·exe 에 적용할 때 새 키 파일을 함께 전달해야 함 |
| 상세 | `collect/night_2026-09-18/REPORT.md`(제품별 전후 표·판정 목록) |


### 8.4 보고서 서식 학습 · 최소 수정 제출 (2026-09-18 추가)

| 항목 | 내용 |
|---|---|
| 목적 | 실제 제출된 보고서(HWP/HWPX/DOCX 묶음)에서 **서식 통계만** 배워, 생성 보고서의 값 칸 글자 모양(글꼴·크기·굵기)·항목별 줄 수와 글자 수·글머리 기호·날짜/시간 표기 형식을 제출본과 같게 만든다. 담당자는 파란 `[기재: …]` 자리만 채우고 제출한다 |
| 학습 방법 | 화면: [분석 리포트] → [보고서 기본 정보] → **서식 학습**(zip/폴더 경로 → [서식 학습]). 서버형은 업로드 폴더(`uploads/`) 또는 `--allow-dir` 아래 경로만 허용. 명령줄: `python tools/report_style.py <보고서.zip> report-template` |
| 저장 파일 | `report-template/style_profile.json` — 글꼴 이름·크기·건수·비율, 항목별 줄 수/글자 수 분포, 글머리 기호 종류, 날짜·시간 **표기 형식 이름**, 공식 서식의 항목 이름. 문서의 문장·기관명·인명은 저장하지 않으며 저장 전 자동 검사(서식 항목 외 한글 문자열이 있으면 저장 거부) |
| 보안 | 처리는 서버/PC 안에서만, 네트워크 미사용. 원본 보고서 묶음은 설치 폴더에 두지 말 것(패치·백업 대상 아님). 프로필 파일은 통계뿐이므로 배포본에 포함됨 |
| 생성 결과 | `[기재: …]` 파란 표시(한글 Ctrl+F '[기재'), 화면의 **담당자 확인 N곳** 목록, `reports/확인목록_<분석ID>.txt`. 복구 시각 자리에는 로그상 마지막 이상 시각을 참고로 표기. 시간은 실 보고서 표기(HH:MM), 날짜는 학습된 형식(예: ’26.9.18.(금), 2026. 9. 18.(금)) |
| 기존 동작 | 프로필이 없으면 서식 자체의 글자 모양으로 생성(이전과 동일). 사용자 등록 서식(custom)에도 같은 규칙 적용 |
| 검증 | 단위 테스트 8건(`tests/test_report_forms.py`: 프로필 적용·표시 색·중복 방지·DOCX 변환·학습 프로필 무문장 검사) + 한글 2022 로 생성본 PDF 변환·육안 확인 |


### 8.5 예약 · 자동화 — 스케줄 기반 모니터링 · 정기 점검 · 보고서 · 백업 (2026-09-18 r4 개정)

| 항목 | 내용 |
|---|---|
| 화면 | 좌측 메뉴 **예약 · 자동화**(`/automation`). 탭 5개: **모니터링 스케줄** · **보고서 · 백업 스케줄** · **산출물 · 내려받기** · **저장 경로** · **알림함 · 실행 이력**. 주소 끝에 `#out`·`#path` 를 붙이면 해당 탭이 바로 열림 |
| 정기 상태 점검(신규) | 감시 장비 전체의 가용성(장애·의심)·CPU/메모리/디스크 임계 초과·수집 지연·24시간 내 실패한 예약 작업을 한 번에 점검. 이상 장비 목록이 **새로 생기거나 바뀔 때만** 알림함에 기록(같은 상태 반복 기록 없음). `결과 파일 저장`을 켜면 점검 결과를 파일로 남김 |
| 기본 스케줄 | 첫 기동(또는 r4 적용 후 첫 기동) 시 추가: **상시 상태 점검** 10분마다(알림만) · **매일 상태 점검 보고** 08:50(결과 저장). 기존 02:00 백업 · 17:00 운영 보고서 · 60초 반입 폴더 감시는 그대로 |
| 보고서 형식 | 작업마다 **HTML · PDF · 한글(HWPX)** 중 선택(선택 안 하면 저장 경로 설정의 기본 형식). PDF 는 한국어 표준 글꼴(HYGoThic)을 참조만 해 파일이 작고 인터넷 없는 환경에서도 만들어짐 — 한글 글꼴이 있는 PC(Windows)의 Edge·Chrome·Acrobat 에서 그대로 보임(리눅스 PC 에서 볼 때는 한글 글꼴 필요). HWPX 는 제품의 보고서 양식(쪽 설정·글꼴)을 바탕으로 머리 띠·요약 표·절 제목을 채워 한글 2014 이상에서 바로 편집·제출. 운영 보고서는 다른 시스템 연계용 JSON 도 함께 만듦 |
| 산출물 이름 | 정기 점검 `check-YYYYMMDD-HHMMSS.{html,pdf,hwpx}` · 운영 보고서 `periodic-YYYYMMDD-HHMMSS-<실행ID>.{html,pdf,hwpx,json}` |
| 저장 경로 탭 | 로그·보고서가 쌓이는 곳을 서버 절대 경로·파일 수·용량으로 표시: 로그 반입 폴더(`uploads/inbox`) · 업로드 원본(`uploads`) · 분석 결과(`incidents`) · 자동 산출물(기본 `reports`) · 분석 보고서(화면에서 생성) · 추가 사본 경로 · 백업(`backups`) · 본사 사본 · 서버 실행 로그 |
| 저장 설정(관리자) | **산출물 저장 경로**(절대 경로, 쓰기 시험 후 저장) · **추가 사본 경로** 최대 5곳(공유 폴더·NAS 마운트 등, 산출물을 같은 이름으로 복사, 실패 시 알림함 기록) · **기본 형식** · **보관 기간**(7~3650일, 기본 180일 — 기간이 지난 점검 결과·운영 보고서 자동 삭제). 경로를 바꿔도 이미 만든 파일은 옮기지 않음 |
| 서버와 로컬에 함께 저장 | ① 서버: 저장 경로 ② 다른 서버·공유 폴더: 추가 사본 경로 ③ 본사: 전사 연동(8.6) 시 자동 전송 ④ 내 PC: **산출물 · 내려받기** 탭의 `새 산출물을 자동으로 내려받기`(화면이 열려 있는 동안, 브라우저 다운로드 폴더) 또는 `이 PC 폴더 지정`(HTTPS 접속 또는 이 PC 접속의 Edge/Chrome). Windows 설치형은 서버가 곧 이 PC 이므로 저장 경로가 바로 PC 폴더 |
| 바로 내려받기 | 산출물 표의 **내려받기**(운영 권한 이상) · PDF/HTML 은 **열기**(새 탭 미리보기). 백업 ZIP 은 비밀번호·토큰이 들어갈 수 있어 **관리자만** 내려받음. 모든 내려받기는 감사 기록 |
| 그 밖 | 백업·복원, 반입 폴더 자동 분석, 자원 문서 → 감시 동기화(해당 사이트 자산 조회 권한 필요), 알림함, 실행 이력, 룰팩 저널 보호는 이전과 같음. 복원은 서비스 종료 후 `python -m logtriage.automation_admin verify|restore --base <설치경로> --archive <zip> [--offline-confirmed]` (Windows `LogTriage.exe --automation-admin …`) |

### 8.6 전사 배포 — 통합 로그인 · 권한 · 자산 권한 · 본사 중앙 수집 (2026-09-18 r4 추가)

**구성**: 각 사이트에 LogTriage 서버를 두고(장비 감시·로그 분석은 사이트에서), 본사 서버 한 대가 모든 사이트의 요약·보고서를 모읍니다. 원본 로그는 사이트에 남고 본사에는 요약과 보고서 사본만 갑니다. 사용자 약 200명, 감시 장비 200~500대 규모를 기준으로 설계했습니다.

| 항목 | 내용 |
|---|---|
| 통합 로그인 `conf/auth.json` | 예시 `deploy/server/conf-examples/auth.json.example`. `portal.method` 하나를 고름 — **ldap**(디렉터리 AD/LDAP 계정 ID·비밀번호, LDAPS 권장, 빈 비밀번호 거절, 이름·부서·그룹 자동 반영) · **oidc**(OpenID Connect 인가 코드, RS256 서명·발급자·만료·nonce 검증) · **header**(SSO 에이전트가 붙은 앞단 nginx/Apache 가 사용자 ID 헤더 전달 — 이 서버는 127.0.0.1 로만 열고 `trusted_proxies` 에서 온 요청만 인정) · **link**(메뉴 링크에 사용자·시각·nonce·HMAC-SHA256 서명, 2분 유효·1회용, `next=/hub` 처럼 특정 화면으로 바로 이동 가능). 모두 추가 설치 없음 |
| 비상용 로컬 관리자 | 통합 로그인 장애·초기 설정용. `python -m logtriage.auth --base <설치경로> set-admin [--login admin]` (Windows `LogTriage.exe --auth-admin set-admin`) → `/login?local=1`. PBKDF2-SHA256 24만 회 |
| 세션 | 서버 DB 에 해시로 저장(재기동해도 유지), 유휴 60분 · 최대 12시간(설정 가능). 권한·사이트·자산 권한을 바꾸거나 사용 중지하면 그 사용자의 세션을 즉시 끊음. 로그인 실패는 같은 IP·같은 계정 5분 10회, 같은 IP 전체 5분 60회에서 차단 |
| 권한 | **조회**: 화면·이력·보고서 보기 · **운영**: 분석 실행·업로드·감시 항목·예약 작업·산출물 내려받기 · **관리자**: 사용자·사이트·룰팩·저장 경로·백업 내려받기. 첫 로그인 사용자는 `default_role`(기본 조회)로 자동 등록되고, `group_map` 으로 디렉터리 그룹별 권한을 자동 부여할 수 있음(관리자가 화면에서 직접 바꾼 사용자는 그룹 매핑이 덮어쓰지 않음). `auto_create: false` 면 관리자가 미리 등록한 계정만 로그인 |
| 접근 사이트 | 사용자마다 볼 수 있는 사이트(모니터링·분석·보고서). 사이트 서버 화면은 그 사이트 권한이 있어야 열리고, 본사 [전사 현황]은 권한 있는 사이트만 보여 줌 |
| **자산 조회 권한** | 사이트별 **자산 현황**(자원 관리 문서·장비 IP 목록)은 [사용자 · 권한]에서 **사이트를 하나씩 지정받은 해당 사이트 담당자만** 조회. `전체(*)` 지정 불가, **관리자 권한이나 전체 사이트 권한으로도 볼 수 없음**. 권한이 없으면 자원 관리 메뉴가 사라지고 직접 주소로 들어가도 거절, 본사 현황의 장비 IP 는 `(자산 권한 필요)` 로 가림, 사이트 장비 목록 API 도 거절. 자원 문서 → 감시 동기화 작업 등록도 자산 권한 필요. 지정·변경·조회·거절은 모두 감사 기록. 본사로는 자원 관리 문서를 보내지 않음(사이트에만 보관) |
| 감사 기록 | 로그인·로그아웃·실패, 모든 변경 요청, 로그 원문 검색, 자산 조회, 보고서·산출물 내려받기, 권한 거절. [사용자 · 권한 → 감사 기록]에서 계정·행위·기간(최대 400일)으로 조회 |
| 본사 서버 `conf/hub.json` | `{"role":"central","site_id":"HQ","site_name":"본사"}` (예시 `hub.json.central.example`). 본사 자체 데이터도 '본사' 사이트로 포함 |
| 사이트 등록 | 본사 [사용자 · 권한 → 사이트 → 사이트 등록] → **사이트 토큰과 사이트 서버용 `conf/hub.json` 내용을 한 번만 표시** → 사이트 서버에 그대로 저장 후 재시작하면 1분 안에 연결. 토큰 재발급·사용 중지·삭제 가능(토큰은 본사 DB 에 해시로만 보관) |
| 사이트 → 본사 전송 | 주기(기본 60초)마다 HTTPS POST: 감시 장비 전체 상태·최신 사용률, 최근 장애 이력, 새 분석 결과 요약(시각·판정 계층·원인 추정·심각도 건수·파일 이름), 예약 작업 결과(실패·실제 처리분), **새로 만든 보고서 파일 사본**(HTML·PDF·HWPX·JSON 등, 1개 50MB 이하). 실패하면 다음 주기에 이어서 보냄(유실 없음). [전사 현황]에서 `지금 본사로 보내기` 가능 |
| 전사 현황 `/hub` | 사이트 카드(연결됨·끊김·미연결·중지, 마지막 수신, 버전, 정상·장애·임계·24시간 분석), 장애·임계 초과 장비, 최근 분석 결과, **보고서 사본 바로 내려받기**, 장애 이력·예약 작업 결과. 사이트 선택·검색. 사이트 서버에서는 본사 연동 상태(마지막 전송·오류) 표시 |
| 보관 | 본사: 사이트별 분석 요약 2,000건 · 보고서 사본 500개 · 닫힌 장애 90일 · 실행 이력 1,000건. 감사 기록 400일 |
| 기존 설치 호환 | `conf/auth.json` 이 없으면 이전처럼 `--password` 단일 비밀번호(또는 인증 없음), `conf/hub.json` 이 없으면 단독 설치로 동작. Windows 설치형은 `conf\auth.json` 을 두면 비밀번호 없이도 LAN 수신 가능(통합 로그인이 접속을 보호) |
| 권장 배치 | 본사·사이트 서버 모두 nginx(TLS) 뒤에서 127.0.0.1 로 수신. 사이트 → 본사 방화벽은 본사 443 한 방향만 열면 됨 |
| 검토 반영(GPT 교차 검토) | 통합 로그인 모드에서는 예전 단일 비밀번호·데스크톱 창 세션을 인정하지 않음 · `require_https`(기본 켬): 같은 PC 직접 접속 또는 같은 서버 nginx(TLS)가 `X-Forwarded-Proto: https` 를 붙인 요청만 허용(에이전트 수치 전송·/healthz 제외, TLS 앞단이 없는 Windows 서버 모드는 `false` 로 명시) · header 방식은 `trusted_proxies` 명시 필수(기본값 없음), `proxy_secret` 설정 시 앞단이 `X-Proxy-Secret` 동일 값 전달 · header 사용자 권한은 매 요청 DB 에서 확인 · link 비밀키는 32자 이상 무작위(`python -m logtriage.auth --base <설치경로> gen-secret`) · 사이트 → 본사 전송은 `hub_url` https 필수(시험 때만 `allow_http`), 전송마다 흐름(stream)·순번을 붙여 재전송(재생) 거절 — 재설치로 새 흐름이 생기면 기존 흐름이 2분 이상 멈춘 뒤에만 넘어가고 이전 흐름은 영구 폐기 · 본사 수신 동시 4건·보고서 2건, 사이트별 5초 간격·동시 1건, 보고서 사본 사이트별 5GB 한도, 같은 이름으로 다시 만든 보고서는 덮어쓰지 않고 `이름~r2` 판으로 따로 보관(같은 내용 재전송은 무시) · 감시 장비 IP 는 자산 권한 없는 사용자 응답에서 가리고, 감시 장비 등록·변경과 점검 결과·보고서 사본 내려받기도 자산 권한 필요 |
| 미검증 | 실제 사내 디렉터리/SSO 연동(표준 부호화는 ldap3 기준 바이트 일치·가짜 서버로 검증), PostgreSQL 저장소와의 조합, 200명 동시 접속 부하 |


### 8.7 사내 이메일 계정 로그인 (2026-09-21 추가 — (주)솔리데오)

**한 줄 요약**: `conf/auth.json` 의 `mode` 를 `local` 로 두면, 사내 이메일 계정(ID)과 비밀번호로 로그인합니다. 비밀번호는 서버에 원문으로 저장하지 않고 **세 겹**으로 보호해 보관합니다.

| 항목 | 내용 |
|---|---|
| ID 형식 | **회사 도메인 이메일만**(기본 `solideos.com`). 예: `adf123@solideos.com`. 다른 도메인·형식은 **등록도 로그인도 거부**하고 그 자리에서 이유를 알려 줌. 대문자로 입력해도 소문자로 정규화 |
| 비밀번호 보호 ① | **페퍼(HMAC-SHA256)** — 입력값을 서버 키 파일 `conf/secret.key`(첫 기동 때 32바이트 무작위 생성, 소유자만 읽기)로 먼저 섞음. DB 만 유출되면 대입 시도 자체가 불가능 |
| 비밀번호 보호 ② | **scrypt 메모리 하드 해시**(기본 N=16,384·r=8·p=1, 계정마다 다른 16바이트 소금). GPU 대량 대입 방어. scrypt 를 못 쓰는 환경이면 PBKDF2-HMAC-SHA512 600,000회로 자동 대체 |
| 비밀번호 보호 ③ | **ChaCha20-Poly1305 저장 암호화** — ①②로 만든 검증값을 다시 암호화해 저장(이메일을 추가 인증 자료로 묶어 다른 계정 값으로 바꿔치기 불가). 전송 구간은 `require_https` 로 강제 |
| 비밀번호 규칙 | 10자 이상(설정 가능), 영문 대·소문자·숫자·기호 중 3종 이상, ID·회사명·흔한 문자열·연속 문자·반복 문자 금지, 최근 5개 재사용 금지, 사용 기간 기본 90일 |
| 잠금·감사 | 연속 5회 실패 → 10분 잠금(관리자가 즉시 해제), 같은 IP·계정 5분 10회·같은 IP 5분 60회 차단. 로그인·실패·발급·초기화·잠금 해제·변경은 모두 감사 기록 |
| 첫 로그인 | 발급·초기화된 임시 비밀번호로 로그인하면 **비밀번호 변경 화면에서 벗어날 수 없음**(다른 화면·API 접근 차단). 변경하면 기존 접속(세션)은 모두 끊김 |
| 계정 만들기(명령) | `python -m logtriage.accounts --base <설치경로> add --email adf123@solideos.com --role operator --sites "*" --asset-sites SITE1` → 임시 비밀번호 출력. 그 밖에 `reset` · `unlock` · `delete` · `list` (Windows 설치형: `LogTriage.exe --account-admin add --email … --role operator`) |
| 계정 만들기(API) | 관리자 로그인 후 `POST /api/admin/account_add {email, role, sites, asset_sites, name, dept}` → 임시 비밀번호 반환. `account_reset` · `account_unlock` · `account_delete`, 목록은 `GET /api/admin/accounts` |
| 로그인 화면 | (주)솔리데오 CI 색(크림슨 `#C12554`) + 흰 바탕 · 3D 비주얼(유리 방패) · 카드가 마우스 움직임에 따라 살짝 기울어짐 · 비밀번호 표시 토글 · Caps Lock 안내 · 보호 방식 배지. 붉은색은 제목 강조어·상단 띠·버튼·포커스에만 쓰고 나머지는 흰색과 회색으로 둡니다. 공식 로고 파일을 받으면 `gui/login.html` 의 워드마크 SVG 만 교체하면 됩니다(가로 136 · 세로 38 기준) |
| 화면 색 기준 | 강조 `#C12554`(진한 쪽 `#9C1442`, 밝은 쪽 `#E0446E`), 글자 `#1B1E25`, 보조 글자 `#5A6472`, 선 `#E7E9EE`, 오른쪽 바탕 `#F6F7F9`. 오류 안내만 별도 빨강 `#B42318` 으로 구분합니다 |
| 권한 | 기존과 같음(조회·운영·관리자 + 접근 사이트 + 자산 조회 사이트). 계정 만들 때 함께 지정 |
| 키 파일 주의 | `conf/secret.key` 가 없어지면 **모든 비밀번호를 초기화**해야 합니다. 백업·서버 이전 시 DB 와 반드시 함께 옮기고, 백업 ZIP 과 분리 보관하십시오 |

### 8.8 처음 기동 · 비밀번호 분실 · 접속 구간 보호 (2026-09-22 추가)

| 항목 | 내용 |
|---|---|
| 처음 기동 | 설정(`conf/auth.json`)이 없으면 **회사 이메일 계정 로그인**으로 자동 설정되고, 계정이 하나도 없으면 첫 화면이 **[관리자 계정 만들기]** 가 됩니다. 계정이 하나라도 생기면 이 화면은 닫힙니다 |
| 첫 관리자 | 기본값은 **비어 있습니다**(2026-10-22) — 1회용 코드로 [관리자 계정 만들기] 를 연 사람이 ID·비밀번호를 직접 적습니다. 특정 ID 로 못 박으려면 `conf/auth.json` 의 `first_admin` 에 적고 다시 기동하십시오(그때는 **비밀번호만** 정하고, 다른 ID 를 보내도 예약된 ID 로 만들어집니다). 옛 판이 자동으로 적어 둔 개발자 계정은 기동할 때 저절로 비웁니다 |
| 초기 설정 허용 범위 | `setup_scope` 기본값 **private** — 이 서버·사내망·VPN 에서는 코드 없이 `/setup` 으로 바로 만들고, 인터넷 구간에서는 1회용 초기 설정 코드가 필요합니다(`/setup?t=…`, 화면에서 코드를 붙여 넣어도 됩니다). 코드는 기동 로그와 `conf/setup-code.txt` 에 적힐고 계정을 만들면 지워집니다. `loopback`=이 서버에서만, `token`=언제나 코드 |
| 비밀번호 분실 | 관리자가 **1회용 재설정 코드**(12자리, 기본 30분, 5회 실패 시 폐기)를 발급 → 본인이 로그인 화면의 **[비밀번호를 잊으셨나요?]** 에서 이메일·코드·새 비밀번호를 입력. 발급: `python -m logtriage.accounts --base <설치경로> code --email ○○@solideos.com` (Windows `LogTriage.exe --account-admin code --email …`), 화면에서는 [사용자 · 권한] 의 계정 목록. 코드는 본인 확인 후 직접 전달하십시오(자동 메일 발송 없음) |
| 중복 로그인 | 같은 ID 로 다른 곳에서 로그인하면 **기존 접속은 즉시 끊깁니다**. 끊긴 쪽에는 그 이유가 로그인 화면에 표시됩니다 |
| 접속 구간 | `require_https` 기본값 **auto** — 같은 PC·사내망·VPN(사설 대역)은 평문(HTTP)도 허용하고, 그 밖의 주소(인터넷 구간)는 HTTPS 로만 받습니다. 앞단 프록시가 '바깥 구간은 평문'이라고 알려 주면(`X-Forwarded-Proto: http`) 항상 거절합니다 |
| HTTPS 직접 제공 | `conf/tls.json` 에 인증서·키를 적으면 서버가 직접 TLS 로 받습니다(예시: `conf-examples/tls.json.example`). `client_ca` 를 지정하면 회사 인증서를 가진 단말만 접속하는 **상호 인증(mTLS)** 이 됩니다. nginx 를 앞단에 두는 기존 방식도 그대로 쓸 수 있습니다 |
| 저장 보호 | 계정 ID(이메일)·이름·부서는 DB 에 평문으로 남지 않습니다(조회용 색인 + 암호화). 비밀번호는 페퍼(HMAC-SHA512) → scrypt(2^15) → 암호화(ChaCha20-Poly1305)로 저장하고, 암호문은 '어느 표·어느 칸·어느 행' 인지까지 묶어 다른 계정 값으로 바꿔치기할 수 없습니다. 감사 기록은 앞 기록과 사슬(HMAC)로 이어 붙여 삭제·순서 변조를 알아챌 수 있습니다 |

### 8.9 게시판 (2026-09-22 추가)

| 항목 | 내용 |
|---|---|
| 용도 | 같은 장애·이슈를 두고 **질문 · 분석 공유 · 분석 요청** 글을 올리고 답글로 주고받는 공간. 왼쪽 메뉴 [게시판] |
| 분석 이력 붙이기 | 글을 쓸 때 내 분석 이력을 최대 10건까지 붙일 수 있고, 글에서 **[분석 보기]** 를 누르면 그 자리에서 판정·대상·로그(최근 50건)를 봅니다. 본인 것이면 [분석 화면에서 열기] 로 분석 리포트까지 바로 이동합니다 |
| 장비 정보 보호 | 붙인 분석의 IP·호스트명은 **등록한 담당자 본인에게만** 보이고 다른 계정에는 `**` 로 가려집니다. 글쓴이가 글에서 **원문 공개**를 켜면 그 글에서만 원문이 보입니다 |
| 권한 | 조회 권한(viewer)도 글·답글을 쓸 수 있습니다. 고치기·지우기는 글쓴이(관리자는 모든 글), 채택은 글쓴이 |
| 화면 구성 | 위쪽에 전체 글·미해결·답글 요약, 그 아래 종류 거르개(전체·질문·분석 공유·분석 요청·내 글)와 검색, 표 형태의 글 목록입니다. 글을 누르면 본문·붙인 분석·답글이 한 화면에 이어집니다 |
| 붙인 분석 보기 | 목록에 분석 이름·식별자·시각이 보이고, [여기서 보기] 를 누르면 판정 표와 이벤트 표(시각·등급·코드·대상·내용)가 같은 자리에 펼쳐집니다. 이벤트 원본 보관이 끝난 건은 그 사유를 알려 줍니다 |

## 9. 문제 해결

| 증상 | 원인 | 조치 |
|---|---|---|
| `/nms` `/resources` 가 `{"error": "not found"}` 또는 메뉴에 없음 | 접속한 포트의 서버가 패치 이전 소스(대개 systemd `/opt/logtriage`) | 2026-09-14 `apply_patch.sh`(정식 설치 동시 갱신) 재실행, 또는 `sudo bash <log_svr>/engine/deploy/server/install.sh --port 8088 --skip-pkgs`. `ps -ef | grep logtriage.server` 로 경로 확인 |
| 포트 사용 중 / run.sh 기동 실패 | 다른 프로세스(정식 설치 서비스 등)가 같은 포트 | `ss -ltnp | grep 8088` → 다른 포트로 기동하거나 서비스 포트를 사용 |
| install.sh `Failed dependencies` | pkgs rpm 과 설치된 postgresql 버전 불일치 | 계속 진행되면 정상, 멈추면 `--skip-pkgs` |
| `engine/logtriage : 그런 파일이나 디렉터리가 없음` | 패치 zip 을 다른 위치에 풀었거나 스크립트만 복사 | `unzip -o` 로 다시 풀고 그 폴더의 `apply_patch.sh` 실행 |
| 룰 0 · 코드 0 | data 또는 /opt/logtriage 에 rules·errorcodes 없음 | 패치 재적용 또는 install.sh 재실행 |
| ICMP 항목 '수집 오류: ping 권한/실행 환경 확인' | ping 미설치, 또는 systemd 보안 옵션(NoNewPrivileges·CapabilityBoundingSet=) 아래에서 ping 이 cap_net_raw 를 얻지 못함 | `dnf install iputils`; install.sh(2026-09-14)가 `/etc/sysctl.d/90-logtriage-ping.conf` 에 서비스 GID 만 허용하는 `net.ipv4.ping_group_range` 를 기록. 수동: `GID=$(id -g logtriage); printf 'net.ipv4.ping_group_range = %s %s\n' "$GID" "$GID" > /etc/sysctl.d/90-logtriage-ping.conf; sysctl --system`. 사전검증: `systemd-run --wait --pipe -p User=logtriage -p NoNewPrivileges=yes -p CapabilityBoundingSet= /usr/bin/ping -c 1 -W 1 127.0.0.1`. 안 되면 TCP 검사 |
| 자원 업로드 `양식 제목이 다릅니다` / `6개 시트 이름을 유지` | 시트명·제목 행 편집 | [원본 양식 다운로드] 파일에 데이터만 입력 |
| 502 Bad Gateway | nginx 는 살아 있고 앱 정지 | `systemctl restart logtriage-server`; RHEL `setsebool -P httpd_can_network_connect 1` |
| 413 / 504 | 700MB 초과 업로드 / 1GB 급 장시간 분석 | 장애 전후 구간만 잘라 업로드(앱 상한 600MB) |
| 동시 분석 한도 초과 | `LOGTRIAGE_MAX_ACTIVE` | 끝난 뒤 재시도 |
| 다른 PC 접속 불가 | 방화벽 | 포트 개방(3장) |
| `wheels 에서 설치 실패 … cp3XX` | 서버 Python 용 wheel 없음 | 전체 패치(50MB)·서버 tar 의 wheels(py3.9~3.13) 사용 |

진단 묶음:
```bash
systemctl --no-pager status logtriage-server nginx postgresql | head -40
curl -s http://127.0.0.1:8088/healthz; echo
ps -ef | grep -v grep | grep logtriage.server
tail -n 30 /var/log/logtriage-install.log   # 정식 설치
tail -n 30 /home/yms/log_svr/server.log      # 구동 테스트
```

---

## 10. 보안·반출 원칙

- 비밀번호 없이 띄운 서버는 같은 네트워크 누구나 접속합니다. 확인 후 `stop.sh` 또는 비밀번호 지정. 운영은 nginx 사용자별 인증(auth_basic)·사내 SSO·사내 CA 인증서(TLS)를 기본으로 두십시오.
- 업로드 로그 원본은 개인정보를 포함할 수 있습니다. 파서는 주민등록번호 패턴을 마스킹하지만 원본은 uploads 에 남으므로 보존 기간 정책을 적용하십시오.
- 룰팩 키(`rulepack.key`)는 서버에 저장하지 말고 적용 때만 업로드하며 zip 과 다른 매체로 전달합니다.
- 기관 서식(HWPX)·보고서 기본 정보·`자원정보.xlsx` 양식·자원 DB 는 외부 반출 금지입니다. 배포 zip 에는 공식 서식 2종만 포함됩니다.
- 자원 관리의 비밀번호 열은 저장하지 않지만 계정·연락처는 저장되어 로그인 사용자에게 표시됩니다. 접속 계정 관리를 함께 운영하십시오.
- 앱 포트(8088)·DB 포트(5432)는 루프백(정식 설치)에만 열며, 구동 테스트 포트는 필요한 대역에만 허용합니다.
- 세션: 로그인 쿠키는 HttpOnly·SameSite=Strict, TLS 종단(nginx `X-Forwarded-Proto: https`) 뒤에서는 Secure 가 붙습니다. 상태 변경 요청(POST/PUT)은 요청 Origin 이 접속 Host 와 다르면 거부합니다. 세션은 서버 메모리에만 있어 재기동·패치 시 전부 소멸(다시 로그인)하며, 사용자별 인증·감사는 nginx 인증/SSO 로 보완하십시오.
- 앱 서버는 Python 표준 라이브러리 HTTP 서버(스레드)입니다. 반드시 nginx 뒤 루프백에서 운용하고 동시 분석은 `LOGTRIAGE_MAX_ACTIVE`(기본 3)로 제한됩니다. 외부 직접 노출·대규모 동시 사용자 용도가 아니며, 정식 운영 릴리스에서는 WSGI/ASGI 서버 교체가 개선 과제입니다.
- 자원 XLSX 업로드는 defusedxml(동봉)로 XML 폭탄을 막고, 파일 10MB·압축 해제 200MB(항목 150MB)·항목 2,000개·비정상 경로·매크로·수식 셀을 열기 전에 거부합니다.
