# LogTriage 서버형(Linux) 설계 안내 — 오픈소스 스택

설치 절차·운영·문제 해결은 **설치매뉴얼.md** 를 보십시오. 이 문서는 구조·설계 결정만 적습니다.

## 1. 목표
- Windows 로컬 exe 와 **같은 분석 엔진·같은 화면(ui.html)** 을 Linux 서버에 올려 여러 담당자가 브라우저로 사용.
- OS 만 설치된 서버에 **즉시 설치**: `install.sh` 한 번으로 WEB/WAS/DBMS 까지 구성. 폐쇄망은 오프라인 번들.
- 모니터링 기능 없음(로그 파일 투입 → 즉시 분석). 상시 수집·에이전트 배포는 범위 밖.

## 2. 구조
```
브라우저 ──HTTP(S)──▶ nginx(WEB, :80/:443)  ──▶ logtriage-server(WAS, Python 3.10+, 127.0.0.1:8080, systemd)
                      · 업로드 700MB, 대기 1800s          ├─ GET /            ui.html + JS 심(SHIM) 주입
                      · TLS(자체서명/사내CA)               ├─ POST /api/<메서드> 데스크톱 Api 와 동일 (meta·detect·analyze·history·stats·search_kb·…)
                      · access/error 로그                  ├─ PUT  /api/upload  파일 업로드(스트리밍 저장, 1파일 600MB)
                                                           ├─ POST /api/rulepack .rpk + .key 업로드 적용
                                                           ├─ GET  /reports/    생성 보고서 목록·내려받기
                                                           └─ /login, /healthz(DB 상태 포함)
                                                                 │
                                                                 ▼
                                             DBMS: PostgreSQL(logtriage DB, 127.0.0.1:5432)  또는  SQLite(/opt/logtriage/data/logtriage.db)
                                                   incidents(분석 이력 JSON) · events(로그 검색용 이벤트 원본)
설치 경로(/opt/logtriage): logtriage/ rules/ rules-local/ errorcodes/ manuals/ report-template/ tools/ venv/
                            data/ uploads/ reports/ backup/  설치매뉴얼.md backup.sh uninstall.sh
```

### 계층별 선택 이유
| 계층 | 선택 | 이유 |
|---|---|---|
| WEB | nginx | 모든 배포판 기본 저장소에 있음, 대용량 업로드·긴 프록시 대기·TLS 를 설정 몇 줄로 처리, 앱을 루프백에 숨김 |
| WAS | Python 표준 라이브러리 `http.server`(스레드) + systemd | 추가 런타임(Java/Node) 불필요, exe 와 코드 공유, 폐쇄망 의존성 최소(PyYAML·psycopg2 wheel 2개) |
| DBMS | PostgreSQL 기본 / SQLite 대체 | 다수 사용자·동시 분석 이력·로그 검색(분석 건당 20만 건)을 파일 대신 DB 로. PostgreSQL 이 없으면 SQLite(표준 라이브러리)로 같은 SQL 동작 |

## 3. 저장소(storage.py)
- 같은 SQL 을 두 백엔드에 사용(자리표시자만 치환), 연결은 호출마다 열고 닫음(요청 빈도 낮음).
- `incidents(id, analyzed_at, name, layer, verdict, critical, data)` — data 는 분석 결과 JSON 전체(최근 500건 보관).
- `events(id, incident_id, ts, host, layer, product, severity, code, message, raw_ref)` — 분석 직후 jsonl 을 DB 로 옮기고 파일 삭제(최근 50건 보관).
- 기동 시 `incidents.json`(exe 형식)이 있고 DB 가 비어 있으면 자동 이관 → `.migrated` 로 이름 변경.
- 검증: Windows 에서 SQLite·PostgreSQL 17 양쪽에 실제 분석 건 12건 이관·검색·신규 분석 저장·보고서 생성 확인(2026-09-10).

## 4. 설치 스크립트(install.sh)가 하는 일
OS 판별(RHEL 계열/Debian 계열) → 패키지(nginx·postgresql·python3) 온라인 또는 `pkgs/<os>` 오프라인 설치 → 앱 복사 → venv + wheel → 서비스 계정 → PostgreSQL initdb·역할·DB(`postgres/init.sql`) 또는 SQLite → `/etc/logtriage/server.env` → systemd 유닛 → nginx 설정(`nginx/logtriage.conf`, `--tls` 시 자체서명) → 방화벽 → 헬스체크.
재실행 안전(비밀번호·DB 유지, 앱만 갱신). 로그 `/var/log/logtriage-install.log`.
PostgreSQL 은 password_encryption=scram-sha-256, pg_hba 에 logtriage 전용 127.0.0.1 규칙, 설치 중 psycopg2 로그인 검증. nginx `limit_conn` 8/IP, 앱 `LOGTRIAGE_MAX_ACTIVE` 3.
GPT 교차 검토 12건 반영: collect/gpt_review_server_2026-09-10.md

## 5. 데스크톱(exe)와의 차이
| 항목 | Windows exe | Linux 서버형 |
|---|---|---|
| 화면·판정·대응 계획 | 동일 | 동일 |
| 파일 선택 | 탐색기 대화상자·드래그 | 브라우저 업로드·드래그, 서버 경로 지정(`--allow-dir`) |
| 이력 저장 | incidents.json + jsonl | PostgreSQL / SQLite |
| 보고서 | 로컬 폴더 저장·열기 | `/reports/` 에서 다운로드 |
| 룰팩 적용 | 파일 대화상자 | .rpk + .key 업로드 |
| 사용자 | 1인 | 다수(비밀번호 공용 세션, 앞단 SSO 가능) |

## 6. 파일 목록
```
deploy/server/
  install.sh              전체 스택 설치(옵션: --db --tls --port --allow-dir --offline --no-nginx --no-firewall — 비밀번호는 인자로 받지 않음)
  설치매뉴얼.md           설치·설정·운영·문제해결·백업 매뉴얼
  nginx/logtriage.conf    리버스 프록시(80, TLS 블록 주석)
  postgres/init.sql       역할·DB 생성(재실행 안전)
  logtriage-server.service  systemd 유닛(하드닝: PrivateDevices·ProtectHome=read-only·ProtectKernel*·CapabilityBoundingSet=)
  logtriage-cleanup.service/.timer  업로드 원본 보존기간(LOGTRIAGE_UPLOAD_KEEP_DAYS) 자동 삭제
  server.env.example      환경설정 예
  backup.sh / uninstall.sh
  make_offline_bundle.sh  인터넷망에서 번들 생성(소스 + Linux wheel + pkgs)
  fetch_os_packages.sh    같은 OS 인터넷 Linux 에서 rpm/deb 수집(폐쇄망용)
  wheels/                 PyYAML·lxml·psycopg2-binary manylinux wheel(py3.9~3.13)
```
