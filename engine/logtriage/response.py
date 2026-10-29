"""3단계 대응 계획 — 분석 결과를 '누가 무엇을 하는가' 기준으로 재구성.

  ① 로그 분석 내용      : 판정 근거·코드 빈도·발생 패턴 (사실만, 임의 추정 없음)
  ② 1차 긴급 조치(운영자) : 즉시 조치 상세 + 제품별 1차 확인 명령
  ③ 2차 유지보수 엔지니어 : 확인 항목 정리 + 전달 내용 + 원본 로그 캡처(±문맥)
  ④ 3차 제조사 조치      : 상세 분석 의뢰용 정리 + 수집 자료 목록 + 중·장기 과제

manuals/*.yaml(제품 운영 참고)을 참조하며, 없으면 계층 공통 문서(os-common 등)로 대체.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

from .codes import cause_label

SEV_ORDER = {"critical": 0, "error": 1, "warn": 2, "info": 3}
LAYER_KO = {"os": "OS", "web": "WEB", "was": "WAS", "db": "DBMS", "sw": "상용SW"}
# 제조사 표준 지원이 종료된 제품 — 3차 조치를 '제조사 의뢰'가 아닌 '유지보수 계약사·전환 계획'으로 안내
_EOS = {"mesim-eai": "MESIM EAI(메타빌드) — 제조사 표준 지원 종료(EOS), ESB/APIG 로 대체",
        "bizmaster-adapter": "Tmax BizMaster EAI 어댑터 — 허브 JEUS 6 는 EOS(2018-12-31), BizMaster 자체 지원 상태는 공개 자료 미확인(유지보수 계약사 확인 필요)",
        "bizmaster-app": "Tmax BizMaster EAI 업무 앱(GISS) — 허브 JEUS 6 는 EOS(2018-12-31), BizMaster 자체 지원 상태는 공개 자료 미확인(유지보수 계약사 확인 필요)"}

# 제조사 권고 조치의 성격 — 문구로 분류(복구 조치 / 진단·확인 / 모니터링 권고)
_ACT_MON = re.compile(r"모니터링|감시|경고(를|를 설정)|추적을 유지|알림", re.I)
_ACT_DIAG = re.compile(r"^(?:.*?(확인|조사|점검|수집|분석|검토|추적|판별|식별|대조|참조|문의)).{0,12}$|^-$", re.I)
_ACT_NONE = re.compile(r"조치 불필요|조치가 필요 없|필요 없다|no action", re.I)
_ACT_FIX = re.compile(r"늘리|늘린|늘려|증가|증설|추가|변경|수정|설정|재시작|재기동|다시 시작|삭제|정리|복구|교체|활성화|비활성화|적용|설치|해제|재시도|다시 시도|재실행|다시 실행|전환|이동|부여|제거|재생성|재구성|생성|확보|조정|갱신|재부팅|재연결|다시 연결|재배포|재개|중지|정지|우회|축소|낮추|낮춰|줄이|줄여|올리|올려", re.I)


def classify_action(action: str) -> str:
    """'remediation'(복구 조치) / 'diagnostic'(진단·확인) / 'monitoring'(모니터링 권고) / '' (없음)"""
    a = (action or "").strip()
    if not a or a == "-" or _ACT_NONE.search(a):
        return "none" if a and a != "-" else ""
    if _ACT_MON.search(a) and not _ACT_FIX.search(a):
        return "monitoring"
    if _ACT_FIX.search(a):
        return "remediation"
    return "diagnostic"


ACTION_TYPE_KO = {"remediation": "복구 조치", "diagnostic": "진단·확인", "monitoring": "모니터링 권고", "none": "조치 불필요", "": ""}
_COMMON = {"os": "os-common", "web": "web-common", "was": "was-common",
           "db": "db-common", "sw": "was-common"}

# 계층별 기본 수집 자료 (매뉴얼에 없을 때의 최소 목록)
_OS_CHECK_CMDS = {  # 대상 OS 지정 시 1차 확인 명령(읽기 전용)
    "linux": "uptime; free -m; df -h; ss -ltnp | head -50; dmesg -T | tail -100; journalctl -p err -S -2h --no-pager | tail -100",
    "windows": "systeminfo | findstr /C:\"System Boot Time\"; wmic OS get FreePhysicalMemory,TotalVisibleMemorySize; wmic logicaldisk get caption,freespace,size; netstat -ano | findstr LISTENING; wevtutil qe System /q:\"*[System[(Level=1 or Level=2)]]\" /c:50 /rd:true /f:text",
    "aix": "uptime; svmon -G; df -g; netstat -an | grep LISTEN; errpt -a | head -200; lsps -a",
    "hpux": "uptime; swapinfo -tam; bdf; netstat -an | grep LISTEN; dmesg | tail -100; tail -200 /var/adm/syslog/syslog.log",
    "solaris": "uptime; vmstat 1 3; df -h; netstat -an | grep LISTEN; dmesg | tail -100; tail -200 /var/adm/messages",
}
_OS_COLLECT_BY_PRODUCT = {
    "aix": ["errpt -a 전체·snap 진단 패키지", "lspath/lsmpio·lspv·lsvg 상태와 sense data", "vmstat/iostat/svmon 수집치",
            "no/vmo/ioo/schedo 튜닝값", "/var/adm/ras·syslog(장애 전후 1시간)"],
    "windows": ["System/Application/Security EVTX(장애 전후 1시간)", "성능 카운터(메모리·디스크·네트워크)",
                "BSOD 시 MEMORY.DMP/Minidump", "설치된 드라이버·펌웨어 버전"],
    "solaris": ["/var/adm/messages·fmdump -eV(장애 전후 1시간)", "vmstat/iostat/prstat 수집치", "크래시 덤프(savecore) 존재 여부", "kernel 파라미터(/etc/system)"],
    "hpux": ["syslog.log·OLDsyslog.log(장애 전후 1시간)", "vmstat/sar/glance 수집치", "크래시 덤프 존재 여부", "kctune 커널 파라미터"],
}
_LAYER_COLLECT = {
    "os": ["syslog/messages·dmesg·journal 전체(장애 전후 1시간)", "sar/vmstat/iostat 수집치",
           "커널 덤프(vmcore/kdump) 존재 여부", "ulimit·sysctl 설정"],
    "web": ["error_log·access_log 전체(장애 전후 1시간)", "설정 파일(httpd.conf/nginx.conf/등)",
            "프로세스·워커 상태 캡처", "인증서·TLS 설정"],
    "was": ["서버 로그·GC 로그 전체(장애 전후 1시간)", "스레드 덤프(3회, 10초 간격)",
            "힙 덤프(OOM 시)", "JVM 옵션·서버 설정 파일(server.xml/domain.xml/config.xml)"],
    "db": ["alert/error 로그 전체(장애 전후 1시간)", "리스너·트레이스 로그",
           "세션·잠금·대기 이벤트 스냅샷",
           "파라미터 파일 · 성능 리포트(AWR/ASH는 Diagnostics Pack 사용 권한 확인 후, 없으면 Statspack·v$ 조회로 대체)"],
    "sw": ["서버 로그·인터페이스(어댑터) 로그 전체", "거래 로그·오류 전문 샘플",
           "스레드 덤프·GC 로그", "연계 대상 목록과 설정"],
}


def _manual_for(manuals: list[dict], product: str, layer: str) -> dict | None:
    """제품의 매뉴얼 문서들을 하나로 병합(운영 참고 문서 우선, 로그 카탈로그는 뒤에)."""
    prod = (product or "").lower()
    cands = [d for d in manuals if str(d.get("product", "")).lower() == prod]
    if not cands:
        cands = [d for d in manuals if str(d.get("product", "")).lower() == _COMMON.get(layer, "")]
    if not cands:
        return None
    cands.sort(key=lambda d: 1 if d.get("logtypes") else 0)
    merged = {"product": cands[0].get("product", prod), "sections": []}
    for d in cands:
        merged["sections"].extend(d.get("sections", []))
    return merged


def _section(doc: dict | None, *keys: str) -> str:
    if not doc:
        return ""
    for s in doc.get("sections", []):
        h = str(s.get("heading", ""))
        if any(k in h for k in keys):
            return str(s.get("body", "")).strip()
    return ""


def _parse_ref(raw_ref: str):
    """'C:\\path\\file.log:120-124' → (path, 120, 124)"""
    if not raw_ref or ":" not in raw_ref:
        return None
    path, _, rng = raw_ref.rpartition(":")
    if not path or not rng:
        return None
    a, _, b = rng.partition("-")
    try:
        s = int(a)
        e = int(b) if b else s
    except ValueError:
        return None
    return path, s, e


def _capture_lines(refs: list[tuple[str, int, int]], context: int = 10,
                   max_lines: int = 80) -> dict[tuple[str, int, int], list[tuple[int, str]]]:
    """파일별 한 번만 읽어 필요한 라인(±context)을 모은다. 대용량 파일도 순차 1회 스캔."""
    by_file: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for p, s, e in refs:
        by_file[p].append((s, e))
    out: dict[tuple[str, int, int], list[tuple[int, str]]] = {}
    for p, ranges in by_file.items():
        want: dict[int, str] = {}
        need = set()
        for s, e in ranges:
            for n in range(max(1, s - context), min(e, s + max_lines) + context + 1):
                need.add(n)
        last = max(need) if need else 0
        try:
            from .parsers import open_text, mask_pii
            with open_text(Path(p)) as f:
                for n, line in enumerate(f, 1):
                    if n in need:
                        want[n] = mask_pii(line.rstrip("\r\n")[:400])
                    if n >= last:
                        break
        except OSError:
            continue
        for s, e in ranges:
            lines = [(n, want[n]) for n in sorted(want)
                     if max(1, s - context) <= n <= min(e, s + max_lines) + context]
            out[(p, s, e)] = lines
    return out


# 1차(선 대응) 담당자용 쉬운 설명 — 장애 유형별. 전문 지식 없이도 따라 할 수 있게
# what: 한 줄 상황 설명 / steps: (할 일, 방법, 확인 기준) / dont: 하지 말 것 / escalate: 2차로 넘기는 기준
_PLAIN = {
    "memory": {
        "what": "서버(프로그램)가 쓸 수 있는 메모리가 바닥나 느려지거나 멈춘 상태입니다.",
        "steps": [
            ("메모리를 많이 쓰는 프로그램이 무엇인지 확인", "Linux: top 또는 free -m / Windows: 작업 관리자 → 성능·세부 정보(메모리 정렬)",
             "메모리 사용률 90% 이상이거나 특정 프로그램이 대부분을 차지하면 비정상"),
            ("해당 서비스(WAS·DB 등)를 정해진 절차로 재기동", "운영 절차서에 1차 재기동이 허용된 경우에만 절차서 명령으로 수행, 허용되지 않으면 2차 승인 후 수행(1단계 자료 보존 필수)",
             "재기동 후 화면·API가 정상 응답하면 1차 복구"),
            ("복구 후 5~10분간 메모리 사용률이 다시 오르는지 지켜보기", "위 확인 명령을 5분 간격으로 2~3회 반복",
             "다시 급격히 오르면 근본 원인(누수)이 남아 있으므로 2차로 즉시 전달"),
        ],
        "dont": ["원인 확인 없이 여러 번 반복 재기동(덤프·증거가 사라짐)", "서버 자체를 강제로 끄거나 리셋"],
        "escalate": ["재기동해도 10분 내 같은 증상이 재발", "재기동 명령이 먹지 않거나 프로세스가 종료되지 않음"],
    },
    "lock": {
        "what": "일부 DB 작업(트랜잭션) 사이에 잠금 대기·교착이 생겨 해당 작업이 실패하거나 지연되는 상태입니다. DB 전체 중단 여부는 별도 확인이 필요합니다.",
        "steps": [
            ("대기 중인 DB 작업이 계속 늘고 있는지 확인", "모니터링 화면(있으면)에서 세션·대기 수 추이 확인, 없으면 2차 DBA에게 조회 요청(1차가 DB 관리자 계정으로 직접 조회하지 않음)",
             "대기 수가 계속 늘면 비정상. 오래 걸리는 작업이 정상인지는 DBA가 판단"),
            ("반복 실패하는 업무(배치·화면)를 잠시 중지", "해당 배치 스케줄 정지 또는 담당 부서에 실행 보류 요청",
             "새 대기 세션이 더 늘지 않으면 조치 효과 있음"),
            ("이미 자동으로 해소됐는지 확인", "화면·API 응답이 정상으로 돌아왔는지 시험",
             "정상이면 기록만 남기고 2차에 전달, 계속 느리면 2차 호출"),
        ],
        "dont": ["DBA 승인 없이 DB 프로세스 종료(트랜잭션 롤백·세션 단절·복구 작업 유발)", "대기 세션을 임의로 종료(어떤 업무인지 모르면 금지)"],
        "escalate": ["대기 세션이 계속 늘어남", "같은 교착이 30분 내 2회 이상 반복"],
    },
    "connection": {
        "what": "서버 간 연결(또는 DB 접속)이 실패하거나 접속 자리가 모두 차서 새 요청을 받지 못하는 상태입니다.",
        "steps": [
            ("연결 대상 서버가 살아 있고 포트가 열려 있는지 확인", "ping 대상IP / Linux: curl -v http://대상:포트 또는 nc -zv 대상 포트 / Windows: Test-NetConnection 대상 -Port 포트",
             "응답 없음·Connection refused·timed out 이면 대상 서버 또는 네트워크 문제"),
            ("대상 서비스(DB·WAS 등) 프로세스 기동 여부와 최근 종료 시각 확인", "Linux: systemctl status 서비스명 또는 ps -ef | grep 서비스 / Windows: 서비스 관리자 — 확인만 하고 기동·재기동은 하지 않음",
             "중지 상태면 2차에 즉시 알림(운영 절차서에 1차 기동이 명시된 경우에만 절차대로 기동)"),
            ("접속 수 참고 지표 기록", "Linux: ss -s 또는 netstat -an | grep 포트 | wc -l (한도 초과 판단은 2차가 설정값과 비교)",
             "평소보다 수 배 많으면 '접속 폭주 의심'으로 2차에 전달"),
        ],
        "dont": ["방화벽·네트워크 설정을 임의로 변경", "접속 한도 값을 임의로 크게 올리기"],
        "escalate": ["대상 서버는 정상인데 연결만 실패", "접속 수 폭주 의심", "대상 프로세스가 중지 상태(기동은 2차 판단)"],
    },
    "thread": {
        "what": "요청을 처리하는 일꾼(스레드)이 모두 바빠서 새 요청이 줄 서서 기다리는 상태입니다.",
        "steps": [
            ("응답이 멈춘 서비스의 상태 기록(스레드 덤프)", "Java 기반이면 jcmd <PID> Thread.print > 파일 또는 kill -3 <PID> 를 10초 간격 3회(2차·3차 분석 핵심 자료)",
             "파일이 생성되면 2차 전달 자료로 보관"),
            ("느린 백엔드(DB·외부 연동)가 있는지 확인", "위 '연결' 확인 명령으로 DB·외부 서비스 응답 시험",
             "백엔드가 느리면 원인은 백엔드 — 해당 담당에 알림"),
            ("서비스 재기동으로 임시 복구", "운영 절차서에 1차 재기동이 허용된 경우에만 절차서 명령으로, 아니면 2차 승인 후",
             "재기동 후 정상 응답이면 1차 복구, 재발 시 2차"),
        ],
        "dont": ["스레드 덤프 없이 바로 재기동(원인 분석 불가)", "스레드 수 설정을 임의로 올리기"],
        "escalate": ["재기동 후 30분 내 재발", "백엔드는 정상인데 계속 멈춤"],
    },
    "disk": {
        "what": "디스크 공간이 가득 찼거나 디스크 자체에 오류가 있어 파일을 쓰지 못하는 상태입니다.",
        "steps": [
            ("어느 디스크(경로)가 얼마나 찼는지 확인", "Linux: df -h / Windows: 탐색기 → 드라이브 속성",
             "사용률 95% 이상이면 즉시 공간 확보 필요"),
            ("오래된 로그·임시 파일을 정리해 공간 확보", "Linux: du -sh /경로/* 로 큰 폴더 찾기 → 오래된 *.log.gz·임시 파일 삭제(운영 절차서에 허용된 것만)",
             "사용률이 90% 아래로 내려가면 1차 복구"),
            ("디스크 오류 메시지 여부 확인", "Linux: dmesg | grep -i error / Windows: 이벤트 뷰어 → 시스템 → 오류(Disk, NTFS)",
             "I/O error·불량 블록 메시지가 있으면 하드웨어 문제 → 2차·3차"),
        ],
        "dont": ["무엇인지 모르는 파일 삭제(DB 파일·설정 파일 삭제 금지)", "현재 쓰고 있는 로그 파일을 그냥 삭제(공간이 반환되지 않음 — 비우기(> 파일) 사용)"],
        "escalate": ["삭제할 파일이 없거나 삭제해도 계속 참", "디스크 오류 메시지 발견"],
    },
    "storage": {
        "what": "DB·서비스가 쓰는 저장 공간(테이블스페이스·볼륨·아카이브 영역)이 부족하거나 손상된 상태입니다.",
        "steps": [
            ("부족한 저장 영역이 무엇인지 확인", "장애 판정의 코드 메시지에 나온 이름(테이블스페이스·볼륨·아카이브 경로) 확인, 해당 경로 df -h",
             "해당 영역 사용률 95% 이상이면 공간 부족"),
            ("OS 디스크 여유가 있으면 DB 담당 절차로 공간 확장", "운영 절차서의 '데이터파일 추가/자동확장' 절차, 없으면 2차 DBA에 요청",
             "확장 후 오류가 멈추면 1차 복구"),
            ("아카이브·백업 영역이면 오래된 백업본 정리", "보관 정책에 따라 이관·삭제(반드시 백업 완료된 것만)",
             "공간 반환 확인"),
        ],
        "dont": ["DB 데이터 파일·로그 파일 직접 삭제", "손상 메시지가 있을 때 DB 재기동 반복"],
        "escalate": ["손상(corrupt)·복구 필요 메시지", "확장 절차를 모르거나 권한 없음"],
    },
    "hardware": {
        "what": "서버 하드웨어(디스크·스토리지 경로 등)에 결함 신호가 있는 상태입니다.",
        "steps": [
            ("서버 전면 램프·하드웨어 관리 콘솔에서 경고 확인", "관리 콘솔(x86: iLO/iDRAC/BMC · IBM Power/AIX: HMC/ASMI · HP-UX: iLO/MP · SPARC: ILOM) 접속 → 상태(Health) 화면",
             "주황/빨강 경고 항목이 있으면 하드웨어 결함"),
            ("이중화된 다른 서버가 정상이고 우회 절차가 승인돼 있으면 부하 우회", "대체 서버 상태(Health) 정상 확인 → 운영 절차서의 우회 절차대로 L4·로드밸런서 담당에게 해당 서버 제외 요청 (절차가 없으면 2차에 문의)",
             "우회 후 서비스 정상이면 1차 복구"),
            ("장비 정보(모델·시리얼·경고 내용) 기록", "관리 콘솔 화면 캡처",
             "3차(제조사) 접수 시 필수"),
        ],
        "dont": ["결함 부품을 임의로 교체·분리", "경고 상태에서 반복 재부팅"],
        "escalate": ["항상 — 하드웨어 결함은 2차·3차(제조사) 처리 대상"],
    },
    "upstream": {
        "what": "우리 서버가 아니라 연결된 상대 시스템(백엔드·연계 서버·외부 API)이 응답하지 않아 생긴 장애입니다.",
        "steps": [
            ("응답 없는 상대 시스템이 무엇인지 확인", "장애 판정 메시지의 대상 주소·서비스명 확인 후 curl -v http://대상:포트 또는 ping",
             "타임아웃·연결 거부면 상대 시스템 장애"),
            ("상대 시스템 담당자(또는 외부 업체)에 즉시 통보", "장애 시각·대상 주소·오류 메시지를 그대로 전달",
             "상대측 복구 확인 후 우리 서비스 재시험"),
            ("가능하면 우회·재시도 설정 확인", "운영 절차서에 우회 경로가 있으면 전환",
             "우회 후 정상이면 1차 복구"),
        ],
        "dont": ["우리 서버를 반복 재기동(원인이 상대 시스템이라 효과 없음)", "타임아웃 설정을 임의로 늘리기"],
        "escalate": ["상대 시스템은 정상이라고 하는데 계속 실패", "우회 경로 없음"],
    },
    "capacity": {
        "what": "요청·접속·큐가 설정된 한도를 넘어 더 이상 받지 못하는 상태(용량 초과)입니다.",
        "steps": [
            ("평소보다 요청이 많은지 확인", "접속 로그 최근 10분 건수와 평소 비교(예: wc -l 로 라인 수), 또는 모니터링 화면",
             "평소의 2배 이상이면 트래픽 폭주"),
            ("폭주 출처가 특정 IP·업무인지 확인", "접속 로그에서 IP별 건수 상위 확인(Linux: awk '{print $1}' access.log | sort | uniq -c | sort -rn | head)",
             "특정 IP가 압도적이면 비정상 접근 가능성 → 보안 담당 통보"),
            ("정상 트래픽이면 서비스 재기동으로 큐 비우기", "운영 절차서에 1차 재기동이 허용된 경우에만 절차서 명령으로, 아니면 2차 승인 후",
             "재기동 후 정상 응답이면 1차 복구"),
        ],
        "dont": ["한도 설정값을 임의로 크게 올리기(다른 자원 고갈 유발)", "차단 대상이 정상 고객인지 확인 없이 IP 차단"],
        "escalate": ["트래픽이 계속 증가", "특정 IP 공격 의심"],
    },
    "internal": {
        "what": "프로그램(제품) 내부에서 예외·오류가 발생해 기능이 실패하거나 기동하지 못하는 상태입니다.",
        "steps": [
            ("장애 직전에 바뀐 것이 있는지 확인", "배포·설정 변경·패치 이력 확인(담당자 문의, 변경 관리 기록)",
             "변경 직후 발생했다면 변경이 원인일 가능성 높음"),
            ("변경이 원인이면 정해진 절차로 이전 상태로 되돌리기(롤백)", "배포 롤백 절차 또는 설정 파일 백업본 복원",
             "롤백 후 정상이면 1차 복구"),
            ("변경이 없으면 서비스 재기동 1회 시도", "운영 절차서에 1차 재기동이 허용된 경우에만(로그 보관 후), 아니면 2차 승인 후",
             "재기동 후 같은 오류가 다시 나오면 2차"),
        ],
        "dont": ["오류 메시지를 지우거나 로그 파일 삭제", "설정 파일을 임의로 수정"],
        "escalate": ["재기동해도 같은 내부 오류 반복", "롤백할 변경이 없음"],
    },
    "undo": {
        "what": "DB 트랜잭션(작업 단위)이 취소·복구되면서 처리가 실패하거나 지연되는 상태입니다.",
        "steps": [
            ("오래 실행 중인 배치·작업이 있는지 확인", "배치 스케줄 화면 또는 담당 부서 문의",
             "장시간 실행 작업이 있으면 원인 후보"),
            ("실패한 업무를 다시 시도해도 되는지 확인", "화면에서 동일 작업 1회 재시도",
             "재시도 성공이면 일시 현상, 계속 실패면 2차"),
            ("DB 담당에게 상황 전달", "장애 시각·오류 코드·실패 업무명 전달",
             "DBA 확인 전까지 대량 배치 실행 보류"),
        ],
        "dont": ["실행 중인 트랜잭션·배치를 강제 종료(복구 시간이 더 길어짐)", "DB 재기동"],
        "escalate": ["복구가 30분 이상 진행", "동일 오류가 여러 업무에서 동시 발생"],
    },
    "security": {
        "what": "인증 실패·권한 거부·비정상 접근 시도 등 보안 관련 이상 신호가 있는 상태입니다.",
        "steps": [
            ("실패한 계정과 출처(IP)가 정상 사용자인지 확인", "장애 판정 메시지의 계정·IP 확인 → 담당 부서·사용자에게 확인",
             "모르는 IP·계정이면 침해 시도 가능성"),
            ("반복 실패 출처가 외부·비인가면 보안 담당에 즉시 통보", "로그 원본 캡처와 함께 전달",
             "보안 담당 판단 전까지 해당 IP 차단은 보안 담당이 수행"),
            ("정상 사용자면 계정 잠금 해제·비밀번호 재설정 절차 안내", "계정 관리 절차서",
             "해제 후 정상 로그인 확인"),
        ],
        "dont": ["증거(로그) 삭제·수정", "인증서·보안 설정을 임의로 변경"],
        "escalate": ["침해 의심", "인증서 만료·TLS 오류(교체 작업 필요)"],
    },
    "performance": {
        "what": "서비스가 죽지는 않았지만 처리(쿼리·요청)가 평소보다 훨씬 느려져 응답이 지연되는 상태입니다.",
        "steps": [
            ("지금 느린 것이 어떤 작업인지 확인", "판정 표의 코드 메시지(쿼리·URL·작업명)와 소요 시간 확인, 화면에서 해당 기능 응답 시간 체감 확인",
             "특정 업무(배치·조회)만 느리면 그 업무가 원인 후보"),
            ("배치·대량 작업이 돌고 있으면 담당 부서와 협의해 잠시 중지", "배치 스케줄 화면 확인 또는 담당자 문의",
             "중지 후 응답이 빨라지면 원인 확인"),
            ("DB·서버 자원 사용률 확인", "Linux: top, iostat -x 1 3 / Windows: 작업 관리자 성능 탭 / DB 담당에게 세션·대기 확인 요청",
             "CPU·디스크 대기가 90% 이상이면 자원 병목 → 2차 전달"),
        ],
        "dont": ["느린 쿼리·세션을 확인 없이 강제 종료(KILL)", "서비스 재기동으로 해결하려 하기(원인 남음)"],
        "escalate": ["동일 작업이 계속 임계(10초 이상) 초과", "자원 병목이 확인되는데 원인 작업을 모름"],
    },
    "etc": {
        "what": "알려진 유형으로 분류되지 않은 이상 신호입니다.",
        "steps": [
            ("서비스가 실제로 영향받는지 확인", "화면·API 응답 시험", "정상이면 기록만, 비정상이면 다음 단계"),
            ("장애 직전 변경 이력 확인", "배포·설정·패치 기록", "변경 직후면 롤백 검토"),
            ("서비스 재기동 1회 시도", "운영 절차서에 1차 재기동이 허용된 경우에만(로그 보관 후), 아니면 2차 승인 후", "재발 시 2차"),
        ],
        "dont": ["로그 삭제", "설정 임의 변경"],
        "escalate": ["재기동 후 재발", "원인 불명"],
    },
}
_PLAIN_NOFINDING = {
    "what": "로그에서 알려진 장애 패턴은 없지만 서비스 이상이 보고된 상황입니다.",
    "steps": [
        ("서비스가 실제로 안 되는지 직접 확인", "화면 접속·API 호출·ping", "정상이면 일시 현상, 비정상이면 다음"),
        ("네트워크·인프라 구간 확인 요청", "네트워크 담당에 L4·방화벽·회선 상태 문의", "인프라 이상이면 해당 담당 처리"),
        ("추가 로그 확보", "OS·WEB·WAS·DB 전 계층 로그를 장애 시각 전후 1시간 범위로 복사", "재분석 후 판정"),
    ],
    "dont": ["원인 확인 없이 반복 재기동"],
    "escalate": ["서비스 비정상이 15분 이상 지속"],
}


def _tier1_plain(first: dict | None, uniq: list[dict], products: list[str],
                 manuals: list[dict]) -> dict:
    """1차 선 대응(유지보수·관리 담당자용) — 쉽고 간결하지만 명확하게."""
    cat = (first or {}).get("category") or "etc"
    plain = _PLAIN.get(cat) if first else _PLAIN_NOFINDING
    if plain is None:
        plain = _PLAIN["etc"]
    situation = [plain["what"]]
    if first:
        fprod = next((f.get("product", "") for f in uniq if f["id"] == first["rule_id"]), "") or "-"
        situation.append(
            f"근거: {first['layer_ko']} 계층 {fprod} 로그에서 "
            f"'{first['verdict']}' 신호 검출 (코드 {first['rule_id']}, 최초 {first['ts']})")
    steps = [{"n": 1, "do": "조치 전에 지금 상태를 먼저 남기기",
              "how": "오류 화면 캡처, 아래 '확인 명령' 결과를 파일로 저장, 로그 파일 복사(장애 시각 전후 1시간)",
              "check": "이 자료가 2차(엔지니어)·3차(제조사) 분석의 근거 — 재기동 전에 반드시 수행"}]
    for i, (do, how, check) in enumerate(plain["steps"], 2):
        steps.append({"n": i, "do": do, "how": how, "check": check})
    steps.append({"n": len(steps) + 1, "do": "서비스 정상 여부 확인 후 결과 기록",
                  "how": "화면·API 응답 시험, 수행한 항목·시각·결과(성공/실패)를 메모",
                  "check": "정상이면 1차 복구 완료 → 기록을 2차에 전달 / 비정상이면 아래 기준으로 2차 호출"})
    detail = []
    deferred = []
    seen_vendor = set()
    for f in uniq[:6]:
        for a in f.get("immediate", [])[:2]:
            line = f"[{f['id']}] {f['verdict']}: {a}"
            (deferred if _RISKY.search(a) else detail).append(line)
        vc = f.get("vendor_code") or f.get("_code") or f["id"]
        if (f.get("cause") or f.get("action")) and vc not in seen_vendor:
            seen_vendor.add(vc)  # 룰 판정과 코드 판정이 같은 벤더 코드를 가리키면 한 번만
            if f.get("cause"):
                detail.append(f"[{vc}] {cause_label(f.get('ref', ''))}: {f['cause']}")
            if f.get("action"):
                # 제조사 권고 조치는 전문 지식이 필요한 경우가 많아 1차에서는 수행하지 않고 2차로 이관
                deferred.append(f"[{vc}] 제조사 권고 조치(2차 수행): {f['action']}")
    escalate = list(plain["escalate"]) + ["위 단계를 모두 해도 서비스가 비정상"]
    hand = ["장애 시각·현상(화면에서 무엇이 안 되는지)", "수행한 조치와 결과(성공/실패/미수행)",
            "1단계에서 남긴 캡처·명령 결과·로그 파일"]
    return {"role": "유지보수(관리) 담당자 — 전문 엔지니어 도착 전 선(先) 대응",
            "situation": situation, "steps": steps, "dont": list(plain["dont"]),
            "detail": detail, "deferred": deferred,
            "escalate": {"when": escalate, "hand": hand},
            "note": "확인 명령 중 권한이 없거나 의미를 모르는 것은 실행하지 말고 2차에 요청하십시오. 재기동·세션 종료·차단·삭제는 1차에서 하지 않습니다."}


_RISKY = re.compile(r"재기동|재시작|restart|\bkill\b|KILL|차단|(을|를|파일|로그|데이터|본)\s*삭제|drop\b|sysdba|SYSDBA|강제|shrink|resetlogs|"
                    r"reboot|리부팅|FLUSH|flush|revoke|purge|truncate|세션 정리|세션 종료|잠금 해제|unlock|"
                    r"REGISTER|autoextend|데이터파일 추가|유량 제한|throttl|경로로 우회|미러|syncvg|varyonvg|chpv|격리|재전송|재처리|파일 이동", re.I)


def build_response_plan(findings: list[dict], events, files: list[dict],
                        first: dict | None, checklist: list[dict],
                        manuals: list[dict], incident_time: str | None,
                        clusters: list[dict] | None = None, os_hint: str | None = None,
                        procedures: dict | None = None) -> dict:
    """findings 항목: _ts, layer, product, severity, id, verdict, category, message,
    raw_ref, source, immediate/short/mid/long.
    procedures: {1: [...], 2: [...], 3: [...]} — 매뉴얼 기준 조치 절차(procedures.attach_procedures 결과)."""
    procedures = procedures or {}
    if not findings:
        return {
            "analysis": {"summary": ["알려진 장애 패턴이 검출되지 않음(전 계층 CLEAR)"],
                         "codes": [], "observations": [
                             "시그니처 룰·벤더 에러코드 사전에 해당하는 항목 없음",
                             "로그 외 원인(네트워크 장비·인프라·외부 연동·설정 변경)을 우선 의심"]},
            "tier1": {**_tier1_plain(None, [], [], manuals), "commands": [], "procedures": []},
            "tier2": {"checks": ["네트워크·인프라 구간 점검 요청", "추가 로그(전 계층) 확보 후 재분석"],
                      "handover": [], "captures": [], "procedures": []},
            "tier3": {"summary": [], "collect": [], "mid_long": [], "contact": "", "procedures": []},
        }

    # ── ① 분석 내용 ──
    by_code: dict[str, dict] = {}
    for f in findings:
        d = by_code.setdefault(f["id"], {
            "code": f["id"], "verdict": f["verdict"], "severity": f["severity"],
            "layer_ko": LAYER_KO.get(f["layer"], f["layer"]), "product": f.get("product", ""),
            "source": f["source"], "count": 0, "first_ts": f["_ts"], "last_ts": f["_ts"],
            "sample": f["message"], "raw_ref": f["raw_ref"], "category": f["category"],
            "cause": f.get("cause", ""), "action": f.get("action", ""), "ref": f.get("ref", ""),
            "vendor_code": f.get("vendor_code") or f.get("_code") or "", "approx_ts": bool(f.get("approx_ts"))})
        d["count"] += 1
        d["first_ts"] = min(d["first_ts"], f["_ts"])
        d["last_ts"] = max(d["last_ts"], f["_ts"])
    codes = sorted(by_code.values(),
                   key=lambda d: (SEV_ORDER.get(d["severity"], 9), -d["count"], d["first_ts"]))
    for d in codes:
        d["first_ts"] = d["first_ts"].strftime("%H:%M:%S")
        d["last_ts"] = d["last_ts"].strftime("%H:%M:%S")

    # 이상 구간: 최초 critical(없으면 최초 판정) 기준 ±6시간 내 판정만 — 날짜가 섞인 파일 방어
    anchor = min((f["_ts"] for f in findings if f["severity"] == "critical"),
                 default=min(f["_ts"] for f in findings))
    near = [f["_ts"] for f in findings if abs((f["_ts"] - anchor).total_seconds()) <= 6 * 3600]
    span_min = max(0, int((max(near) - min(near)).total_seconds() // 60))
    multi_day = len({f["_ts"].date() for f in findings}) > 1
    products = sorted({f.get("product", "") for f in findings if f.get("product")})
    hosts = sorted({getattr(e, "host", "") for e in events if getattr(e, "host", "")})
    ongoing = bool(first and first.get("ongoing_at_start"))
    summary = [
        (f"장애 발생 시각 미확정 — 입력 로그 시작 시점({incident_time})부터 이미 진행 중(관측 시작 이전 지속 여부 확인 불가) · 최초 이상 계층 {first['layer_ko']}"
         if ongoing else
         f"장애 발생(추정) 시각 {incident_time or '-'} · 최초 이상 계층 {first['layer_ko'] if first else '-'}"),
        f"1차 판정: {first['category_ko']} — {first['verdict']} [{first['rule_id']}]" if first else "-",
        f"판정 근거 {len(findings)}건 (고유 코드 {len(codes)}종) · 이상 이벤트 구간 {span_min}분",
        f"대상 제품 {', '.join(products) or '-'} · 호스트 {', '.join(hosts[:5]) or '-'}",
        "분석 파일: " + ", ".join(f"{x['name']}({x['events']:,}건)" for x in files),
    ]

    # 발생 패턴 관찰 (사실 기반)
    observations: list[str] = []
    crit = [f for f in findings if f["severity"] == "critical"]
    if crit and first:
        t0 = min(f["_ts"] for f in crit)
        pre = [f for f in findings if f["severity"] in ("error", "warn")
               and t0 - timedelta(minutes=15) <= f["_ts"] < t0]
        ev_min = min((getattr(e, "ts", None) for e in events if getattr(e, "ts", None)), default=None)
        covers_15m = ev_min is not None and (t0 - ev_min) >= timedelta(minutes=15)
        if pre:
            pc = Counter(f["verdict"] for f in pre).most_common(3)
            observations.append(
                f"critical 최초 발생 {t0:%H:%M:%S} 이전 15분간 선행 경고 {len(pre)}건: "
                + ", ".join(f"{v}({n})" for v, n in pc))
        elif covers_15m:
            observations.append(f"critical 최초 발생 {t0:%H:%M:%S} 이전 15분간 선행 경고 미검출(입력 로그 범위 내) — 급성 장애 가능성")
        else:
            observations.append(f"critical 최초 발생 {t0:%H:%M:%S} — 입력 로그가 그 이전 15분을 포함하지 않아 선행 경고 여부 판단 불가")
        after = [f for f in crit if f["_ts"] >= t0]
        if len(after) > 1:
            observations.append(
                f"critical 이벤트 {len(after)}건이 {t0:%H:%M:%S}~"
                f"{max(f['_ts'] for f in after):%H:%M:%S} 구간에 반복 검출(입력 범위 내) — 자동 복구 여부는 서비스 상태로 확인")
    layers_hit = Counter(LAYER_KO.get(f["layer"], f["layer"]) for f in findings)
    if len(layers_hit) > 1:
        order = sorted({f["layer"]: None for f in sorted(findings, key=lambda f: f["_ts"])})
        first_by_layer = {}
        for f in sorted(findings, key=lambda f: f["_ts"]):
            first_by_layer.setdefault(f["layer"], f["_ts"])
        fmt = "%m-%d %H:%M:%S" if multi_day else "%H:%M:%S"
        seq = " → ".join(f"{LAYER_KO.get(k, k)}({v.strftime(fmt)})"
                         for k, v in sorted(first_by_layer.items(), key=lambda kv: kv[1]))
        observations.append(f"계층 전파 순서(최초 발생 기준): {seq}")
    sec = [f for f in findings if f.get("category") == "security"]
    if sec and len({f.get("category") for f in findings}) > 1:
        observations.append(
            f"보안 이벤트 {len(sec)}건({', '.join(sorted({f['id'] for f in sec})[:4])})은 같은 시간대에 발생한 '보안 이벤트 후보'로 분리 — "
            "서비스 계정·출발지 등 연계 근거가 확인될 때만 장애 인과관계에 포함")
    approx = [d for d in codes if d.get("approx_ts")]
    if approx:
        observations.append(
            "시각이 파일명 기준(개별 발생 시각 없음)인 코드: " + ", ".join(f"{d['code']}×{d['count']}" for d in approx[:5])
            + " — 타임라인 순서·분당 빈도·인과 판정에서 제외(내부 타임스탬프가 있을 때만 복원)")
    top = next((d for d in codes if not d.get("approx_ts")), codes[0])
    observations.append(
        f"최다 반복 코드: {top['code']} {top['count']}회 ({top['first_ts']}~{top['last_ts']}) — {top['verdict']}")
    if top["count"] >= 10 and span_min > 0:
        observations.append(f"분당 약 {top['count'] / max(span_min, 1):.1f}회 — 지속형 장애")
    others = [c for c in (clusters or []) if not c.get("main")]
    if others:
        mainc = next((c for c in clusters if c.get("main")), None)
        if mainc:
            observations.insert(0, f"주 구간: {mainc['start']} ~ {mainc['end']} (판정 {mainc['count']}건, critical {mainc['critical']}건) — 아래 판정·조치는 이 구간 기준")
        for c in others:
            observations.append(
                f"별도 구간 후보(시간 간격 6시간 초과로 분리): {c['start']} ~ {c['end']} · {', '.join(c['layers'])} · "
                f"판정 {c['count']}건(critical {c['critical']}) · 파일 {', '.join(c['files'])} — 같은 장애로 확인된 경우에만 병합 판단")
    elif multi_day:
        observations.append("입력 파일들의 날짜가 서로 다름 — 같은 장애 건인지 확인 필요")
    gpt_src = any("GPT" in str(d.get("source", "")) for d in codes)
    if gpt_src:
        observations.append("일부 코드 설명은 수집 자료 기반(벤더 문서 대조 필요) — 3차 제조사 문의 시 확인")

    # 제조사 제공 원인·조치 (코드 사전의 vendor_cause/vendor_action — 공식 문서 요약)
    vendor, vmap = [], {}
    for f in findings:
        key = f.get("vendor_code") or f.get("_code") or ""
        if not key or not (f.get("cause") or f.get("action")):
            continue
        v = vmap.get(key)
        if v is None:
            at = classify_action(f.get("action", ""))
            v = vmap[key] = {"code": key, "rule_id": f["id"], "verdict": f["verdict"], "severity": f["severity"],
                             "count": 0, "cause": f.get("cause", ""), "action": f.get("action", ""),
                             "url": f.get("ref", ""), "product": f.get("product", ""),
                             "action_type": at, "action_type_ko": ACTION_TYPE_KO.get(at, "")}
            vendor.append(v)
        v["count"] += 1
    vendor.sort(key=lambda v: (SEV_ORDER.get(v["severity"], 9), -v["count"]))
    no_vendor = [d["code"] for d in codes if not (d.get("cause") or d.get("action"))]
    if vendor:
        observations.append(
            f"원인·조치가 등재된 코드 {len(vendor)}종(제조사 문서 대조 {sum(1 for v in vendor if v.get('url'))}종) — 아래 '원인·조치' 표와 2차 확인 내용에 반영"
            + (f" (미등재 {len(no_vendor)}종: {', '.join(no_vendor[:6])}{' 외' if len(no_vendor) > 6 else ''})" if no_vendor else ""))

    analysis = {"summary": summary, "codes": codes[:30], "observations": observations, "vendor": vendor[:15]}

    # ── ② 1차 긴급 조치 (운영자) ──
    uniq = []
    seen = set()
    for f in sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["_ts"])):
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        uniq.append(f)
    tier1 = _tier1_plain(first, uniq, products, manuals)
    commands = []
    seen_doc = set()
    for f in uniq[:5]:
        doc = _manual_for(manuals, f.get("product", ""), f["layer"])
        if not doc or doc.get("product") in seen_doc:
            continue
        seen_doc.add(doc.get("product"))
        cmd = _section(doc, "1차 확인 명령", "확인 명령", "확인 방법")
        loc = _section(doc, "로그 위치")
        if cmd:
            if re.search(r"sysdba|sysasm|\broot\b", cmd, re.I):
                cmd = "※ 관리자(SYSDBA/root) 권한 명령이 포함됨 — 1차는 권한 없이 되는 읽기 전용 명령만 실행하고 나머지는 2차에 요청 · " + cmd
            commands.append({"product": doc.get("product", ""), "title": "확인 명령 (복사해서 실행, 결과 저장)", "body": cmd})
    if os_hint and os_hint in _OS_CHECK_CMDS:
        commands.insert(0, {"product": f"대상 OS {os_hint}(수동 지정)", "title": "OS 기본 확인 명령 (읽기 전용, 결과 저장)", "body": _OS_CHECK_CMDS[os_hint]})
        if loc:
            commands.append({"product": doc.get("product", ""), "title": "로그 위치 (복사해 둘 파일)", "body": loc})
    tier1["commands"] = commands

    # ── ③ 2차 유지보수 엔지니어 ──
    checks = []
    _lr = {"os": 0, "db": 1, "was": 2, "web": 3, "sw": 4}
    uniq = sorted(uniq, key=lambda f: (_lr.get(f["layer"], 9), SEV_ORDER.get(f["severity"], 9), f["_ts"]))
    if len({f["layer"] for f in uniq}) > 1:
        checks.append("확인 순서: 최초 이상 계층(하위: OS→DB→WAS→WEB→SW)부터 안정 여부를 확인한 뒤 상위 계층의 변경(등록·재기동 등)을 판단")
    for line in tier1.get("deferred", []):
        checks.append(f"[2차 수행·승인 필요] {line}")
    seen_vendor2 = set()
    for f in uniq[:15]:
        vc = f.get("vendor_code") or f.get("_code") or f["id"]
        if (f.get("cause") or f.get("action")) and vc not in seen_vendor2:
            seen_vendor2.add(vc)
            if f.get("cause"):
                checks.append(f"[{cause_label(f.get('ref', ''), short=True)}][{vc}] {f['cause']}")
            if f.get("action"):
                at = ACTION_TYPE_KO.get(classify_action(f["action"]), "")
                checks.append(f"[제조사 조치{'·' + at if at else ''}][{vc}] {f['action']}" + (f" (문서: {f['ref']})" if f.get("ref") else ""))
        for a in f.get("short", []):
            checks.append(f"[{f['id']}] {f['verdict']}: {a}")
        if f.get("category") == "security":
            checks.append(f"[{f['id']}] 보안 이벤트 — 장애 분석과 별도로 보안 담당자 검토(계정·출발지·승인 작업 여부) 요청")
    seen_doc = set()
    for f in uniq[:5]:
        doc = _manual_for(manuals, f.get("product", ""), f["layer"])
        if not doc or doc.get("product") in seen_doc:
            continue
        seen_doc.add(doc.get("product"))
        sig = _section(doc, "대표 장애 신호")
        if sig:
            checks.append(f"[{doc.get('product')}] 범용 점검 목록(대표 장애 신호 — 이번 분석에 없는 코드 포함, 추가 탐색용): {sig}")
    last_ts = max(f["_ts"] for f in findings)
    handover = [
        f"장애 시각(추정) {incident_time or '-'} / 최초 이상 {first['ts'] if first else '-'} · 최종 이상 신호 {last_ts:%Y-%m-%d %H:%M:%S}",
        f"대상 제품: {', '.join(products) or '-'} / 서버 hostname·IP: {', '.join(hosts[:5]) or '[담당자 기재]'}",
        "영향 업무·URL·사용자 영향 범위: [담당자 기재]",
        "현재 재현 여부(계속/간헐/해소)와 직전 배포·설정 변경: [담당자 기재]",
        "연계 대상 시스템(있으면): [담당자 기재]",
        f"1차 판정: {first['category_ko']} — {first['verdict']} [{first['rule_id']}]" if first else "-",
        "검출 코드(빈도): " + ", ".join(f"{d['code']}×{d['count']}" for d in codes[:8]),
        "분석 파일: " + ", ".join(x["name"] for x in files),
        "1차 조치 수행 내역·결과(성공/실패/미수행): [담당자 기재]",
        "현재 서비스 상태(정상/부분/중단)와 영향 범위: [담당자 기재]",
    ]
    refs = []
    for f in uniq[:8]:
        r = _parse_ref(f["raw_ref"])
        if r:
            refs.append((f, r))
    got = _capture_lines([r for _, r in refs])
    captures = []
    for f, r in refs:
        lines = got.get(r, [])
        if not lines:
            continue
        p, s, e = r
        captures.append({
            "code": f["id"], "verdict": f["verdict"], "severity": f["severity"],
            "ts": f["_ts"].strftime("%Y-%m-%d %H:%M:%S"),
            "file": Path(p).name, "path": p, "range": f"{s}-{e}",
            "lines": [{"n": n, "text": t, "hit": s <= n <= e} for n, t in lines],
        })
    tier2 = {"checks": checks, "handover": handover, "captures": captures}

    # ── ④ 3차 제조사 조치 ──
    t3_summary = [
        f"제품/버전: {', '.join(products) or '-'} / 버전·패치 레벨 [담당자 기재]",
        f"장애 시각 {incident_time or '-'} · 이상 이벤트 구간 {span_min}분 · 호스트 {', '.join(hosts[:5]) or '-'}",
    ]
    if len(products) > 1:
        t3_summary.append("※ 제조사별로 의뢰를 분리해 해당 제품의 코드·로그·조치 결과만 전달 (아래 제품 구분)")
    for prod in (products or [""]):
        pcodes = [d for d in codes[:12] if d.get("product") == prod or not prod]
        pvend = [v for v in vendor[:10] if v.get("product") == prod or not prod]
        if not pcodes and not pvend:
            continue
        if prod and len(products) > 1:
            t3_summary.append(f"── [{prod}] 제조사 의뢰 ──")
        for d in pcodes:
            t3_summary.append(
                f"{d['code']} ({d['severity']}) {d['count']}회 {d['first_ts']}~{d['last_ts']} — "
                f"{d['verdict']} / 예: {d['sample'][:100]}")
        for v in pvend:
            t3_summary.append(
                f"[{v['code']}] {cause_label(v.get('url', ''))}: {v['cause'] or '-'} / 권고 조치: {v['action'] or '-'}"
                + (f" / 문서 {v['url']}" if v.get("url") else "")
                + " — 문서 조치를 적용했는지·결과가 어땠는지 함께 기재")
    t3_summary.append("재현 조건(부하·배치·배포·설정 변경 등 장애 직전 상황): [담당자 기재]")
    t3_summary.append("1차·2차 조치 결과와 현재 상태: [담당자 기재]")
    collect = []
    seen_doc = set()
    layers_seen = set()
    for f in uniq[:6]:
        doc = _manual_for(manuals, f.get("product", ""), f["layer"])
        if doc and doc.get("product") not in seen_doc:
            seen_doc.add(doc.get("product"))
            body = _section(doc, "장애 시 수집", "수집 방법", "로그 수집")
            if body:
                collect.append(f"[{doc.get('product')}] {body}")
        if f["layer"] not in layers_seen:
            layers_seen.add(f["layer"])
            items = _LAYER_COLLECT.get(f["layer"], [])
            label = f"{LAYER_KO.get(f['layer'], f['layer'])} 공통"
            if f["layer"] == "os" and f.get("product") in _OS_COLLECT_BY_PRODUCT:
                items = _OS_COLLECT_BY_PRODUCT[f["product"]]
                label = f"{f['product']} 수집"
            for item in items:
                collect.append(f"[{label}] {item}")
    if os_hint and os_hint in _OS_COLLECT_BY_PRODUCT and "os" not in layers_seen:
        for item in _OS_COLLECT_BY_PRODUCT[os_hint]:
            collect.append(f"[{os_hint} 수집(대상 OS 지정)] {item}")
    mid_long = []
    for f in uniq[:6]:
        for k, label in (("mid", "중기"), ("long", "장기")):
            for a in f.get(k, []):
                mid_long.append(f"[{label}] [{f['id']}] {a}")
    contact = ""
    for f in uniq[:5]:
        doc = _manual_for(manuals, f.get("product", ""), f["layer"])
        c = _section(doc, "벤더 문의", "기술지원", "지원 창구")
        if c:
            contact = f"[{doc.get('product')}] {c}"
            break
    eos = [(_EOS[p], p) for p in products if p in _EOS]
    if eos:
        for label, _ in eos:
            t3_summary.insert(0, f"⚠ {label}: 제조사 표준 기술지원 대상이 아님 — 3차는 유지보수 계약사(EAI 지원 범위) 또는 유상 기술지원으로 의뢰")
        mid_long.append("[중기] [EOS] 보유 EAI 매뉴얼의 에러코드 표를 분석기 사전에 등재해 자동 판정 정확도 확보")
        mid_long.append("[장기] [EOS] 반복 장애·보안 취약점은 ESB/APIG 전환 계획으로 관리")
        if not contact:
            contact = "제조사 표준 지원 종료(EOS) — 유지보수 계약사 창구 또는 메타빌드 유상 기술지원 문의"
    tier3 = {"summary": t3_summary, "collect": collect, "mid_long": mid_long, "contact": contact}

    # 매뉴얼 기준 수행 절차(명령·설정) — 1차: 읽기 전용 확인·자료 보존 / 2차: 복구·설정 변경 / 3차: 제조사 의뢰 수집
    tier1["procedures"] = list(procedures.get(1, []))
    tier2["procedures"] = list(procedures.get(2, []))
    tier3["procedures"] = list(procedures.get(3, []))
    if tier2["procedures"]:
        checks.insert(0, f"매뉴얼 기준 수행 절차 {len(tier2['procedures'])}건(명령·설정 값 포함)은 아래 '수행 절차' 참조 — 적용 전 변경 관리 승인·백업")

    return {"analysis": analysis, "tier1": tier1, "tier2": tier2, "tier3": tier3}
