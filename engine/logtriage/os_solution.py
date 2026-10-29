"""OS × 제품 해법(12차 · 2026-10-20 마스터: "장애 로그 예시가 없더라도 각 제품의 에러코드마다 해법을 OS 와 제품의 조합으로 명령어와 함께").

에러코드 하나 × OS 하나 → 단계별 해법:
  0 개요      — 코드 뜻·심각도·제조사 원인/조치(있으면 근거 URL)·적용 판
  1 1차 확인  — (가) 제품 명령(에러코드 지식의 immediate · OS 와 무관한 SQL·관리 명령) (나) 이 제품의 상태 확인 (다) 코드별 OS 명령
                (라) 이 OS 의 확인 묶음(유형별 — 프로세스·메모리·파일시스템·포트·로그…) — 모두 읽기 전용
  2 2차 조치  — 승인·롤백 계획 뒤: 에러코드 지식의 short 조치 + 연결된 수행 절차의 2단계 명령 + 이 OS 에서의 제품 재기동
  3 3차 의뢰  — 제조사(제품·OS 벤더) 의뢰 자료 수집 명령
지식은 manuals/*_osmatrix.yaml(제품 프로필·OS 명령 표). 표에 없는 조합(제품이 그 OS 를 지원하지 않음)은 해법 대신 지원 OS 목록을 돌려준다.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

import yaml
from . import yamlsafe   # 12차: C 안전 파서(+깊이·별칭·크기 한도) — 파이썬 파서보다 수 배 빠르다

_LOCK = threading.Lock()
_CACHE: dict = {}
UNIX_ONLY = re.compile(r"(^|[\s;|(`])(grep|tail|ps -ef|ps -eo|awk|sed|cat /|ls /|df |du |kill |ulimit|lsnrctl status;? *ps)\b")


def load_matrix(manuals_dir) -> dict:
    """manuals/*_osmatrix.yaml 을 합쳐 읽는다(파일 지문이 바뀌면 다시)."""
    d = Path(manuals_dir) if manuals_dir else None
    files = sorted(d.rglob("*_osmatrix.yaml")) if d and d.exists() else []
    key = tuple((str(f), f.stat().st_mtime_ns, f.stat().st_size) for f in files)
    with _LOCK:
        hit = _CACHE.get(str(d))
        if hit and hit[0] == key:
            return hit[1]
        m: dict = {"os": {}, "checks": {}, "category_checks": {}, "os_restart": {}, "os_collect": {}, "products": {}, "legend": {}, "support": {}}
        for f in files:
            doc = yamlsafe.load(f.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict):
                raise ValueError(f"{f.name}: 최상위가 사전이 아님")
            for k in m:
                v = doc.get(k) or {}
                if not isinstance(v, dict):
                    raise ValueError(f"{f.name}: {k} 가 사전이 아님")
                m[k].update(v)
        _CACHE[str(d)] = (key, m)
        return m


def applicable_os(m: dict, product: str) -> list[str]:
    return [o for o in (m["products"].get(product, {}).get("os") or []) if o in m["os"]]


def _pick(table: dict, os_name: str, family: str):
    if not isinstance(table, dict):
        return None
    return table.get(os_name) or table.get(family)


def _winpath(s: str) -> str:
    """cmd 식 %VAR% 를 PowerShell 의 $env:VAR 로(PowerShell 에서는 %VAR% 가 풀리지 않는다 — 12차 자체 발견)."""
    return re.sub(r"%([A-Za-z_][A-Za-z0-9_]*)%", r"$env:\1", s)


def _fill(cmd: str, prof: dict, code: str, family: str) -> str:
    log = (prof.get("log") or {}).get(family) or ""
    if family == "windows":
        log = _winpath(log)
    rep = {"<PROC>": prof.get("proc") or "", "<PROC_WIN>": prof.get("proc_win") or prof.get("proc") or "",
           "<PORT>": str(prof.get("port") or "<PORT>"), "<LOG>": log or "<LOG>", "{code}": code}
    for a, b in rep.items():
        cmd = cmd.replace(a, b)
    return cmd


ACTIVE = re.compile(r"\b(ping|telnet|curl|wget|tnsping|nc|ncat|nslookup|dig|traceroute|tracert|tracepath|mtr|ssh|sftp|ftp|ldapsearch|snmpwalk|snmpget"
                    r"|Test-NetConnection|Test-Connection|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod|irm|iwr)\b|openssl\s+s_client|/dev/(tcp|udp)/", re.I)   # irm·iwr: PowerShell 별칭(GPT 88차)
# 영문 낱말은 식별자 안(startupTimeLimit·periodicRestart·LEG-…-SHUTDOWN)을 빼려고 앞뒤가 글자·_·- 가 아닐 때만(12차 전수 대조에서 발견)
RESTART_BASIS = re.compile(r"재기동|재시작|tbboot|wsboot|(?<![A-Za-z_-])(restart|reboot|startup|shutdown|bounce)(?![A-Za-z_-])", re.I)
# GPT 86차: '재기동하지 말 것'·'원인 해소 전 재기동 금지' 같은 부정·조건 문장은 근거가 아니다
# GPT 87차: '재기동 필요 없음'·'재기동 여부만 확인'·'재기동 실패 시 로그 확인' — 불필요·여부·재기동이 조건인 문장도 근거가 아니다
NEGATE = re.compile(r"하지\s*말|말\s*것|금지|않|없이|대신|보다|말고|전에는|피한다|마지막 수단|권하지|불필요|필요\s*없|여부|수\s*있")
RESTART_COND = re.compile(r"(재기동|재시작|restart|reboot)\S*\s*(이|가|은|는|을|를)?\s*"
                          r"(실패|시(?![가-힣])|시에|이면|하면|되면|된\s*경우|횟수|반복|정책|경로|전(?![가-힣])|전에|부터"
                          r"|필요하면|필요한\s*경우|필요\s*시|판단|검토|고려|은\s*다시)"
                          r"|자동\s*재시작|비계획|예정에\s*없던|기록된\s*경우|필요하다고\s*기록"
                          # 특수 기동(복구 모드)은 일반 재기동 명령과 다르다 · 일부만(해당 서버만) 기동하라는 문장도 전체 재기동 근거가 아니다
                          r"|(tbboot|startup)\S*\s+-t|RESETLOGS|NOMOUNT|(?<![A-Za-z])MOUNT(?![A-Za-z])|매체\s*복구|서버만|만\s*기동"
                          # 원인 예시('…·재기동 작업)')와 영향 메모('영향: 일부 설정은 재기동 필요')는 권고가 아니다
                          r"|(재기동|재시작)\s*작업\)|(?:^|\s)영향\s*:"
                          # GPT 88차 P0-01: 관찰 문장('DB 재기동 이력 조회'·'재기동 원인 분석')은 실행 권고가 아니다
                          r"|(재기동|재시작|restart|reboot)\S*\s*(이력|기록|내역|시각|시점|로그|원인|사유|흔적|빈도|직전)"
                          # GPT 89차 P0-01: 지난 사건 서술('DB 재기동 후 장애가 발생했다')도 권고가 아니다
                          r"|(재기동|재시작|restart|reboot)\S*\s*(후|뒤|이후|직후)\s*(\S+\s*)?(장애|오류|에러|실패|문제|증상|재발|발생)"
                          r"|(했다|됐다|되었다|되었음|하였다|했음|발생함)\s*\)?\s*$", re.I)
# GPT 87차: 재기동 '대상'이 이 제품의 재기동 명령이 다루는 대상과 같아야 한다 — '리스너 재시작'이 DB 전체 shutdown 의 근거가 되면 안 된다.
# 문장에 이름이 나온 대상을 모두 찾아, 제품 범위(SCOPE) 밖의 대상이 하나라도 있으면 근거로 치지 않는다(대상이 안 나오면 이 코드의 제품 자신).
_TW = (r"대기\s*서버|상대\s*서버|원격\s*서버|백엔드\s*서버|백엔드|backend|standby|고립\s*멤버|멤버|member|리스너|listener"
       r"|LDAP\s*클라이언트|클라이언트|client|커넥션\s*풀|연결\s*풀|WAS\s*풀|앱\s*풀|응용\s*프로그램\s*풀|app\s*pool|AppPool|풀|pool"
       r"|COM\+\s*애플리케이션|애플리케이션\s*서버|애플리케이션|application|앱|브로커|broker|CAS|MSDTC|WSFC|PgBouncer|JMS"
       r"|노드\s*매니저|Node\s*Manager|crs|has|스택|JSV|PL\s*서버|웹\s*서버|웹서버|WebtoB|JEUS|Tomcat|톰캣|WebLogic|WebSphere|JBoss|Apache|httpd|nginx"
       r"|IIS|HTTP\s*서비스|WAS|DB|데이터베이스|database|인스턴스|instance|JVM|Oracle|오라클|Tibero|티베로|Altibase|CUBRID|MySQL|PostgreSQL|postmaster"
       r"|SQL\s*Server|MSSQL|서버|server|서비스|service|프로세스|process|데몬|daemon")
TARGET = re.compile(r"(?<![A-Za-z])(" + _TW + r")(?![A-Za-z])", re.I)
_DB = r"DB|데이터베이스|database|인스턴스|instance|서버|server"
_WAS = r"WAS|서버|server|인스턴스|instance|JVM|프로세스|process"
_WEB = r"웹\s*서버|웹서버|서버|server|서비스|service|프로세스|process"
SCOPE = {
    "oracle": _DB + r"|Oracle|오라클", "mssql": _DB + r"|SQL\s*Server|MSSQL|서비스|service", "mysql": _DB + r"|MySQL|서비스|service",
    "postgresql": _DB + r"|PostgreSQL|postmaster|서비스|service", "tibero": _DB + r"|Tibero|티베로", "cubrid": _DB + r"|CUBRID",
    "altibase": _DB + r"|Altibase", "goldilocks": _DB,
    "tomcat": _WAS + r"|Tomcat|톰캣|서비스|service", "jeus": _WAS + r"|JEUS", "weblogic": _WAS + r"|WebLogic", "websphere": _WAS + r"|WebSphere|애플리케이션\s*서버",
    "jboss": _WAS + r"|JBoss", "apache": _WEB + r"|Apache|httpd", "nginx": _WEB + r"|nginx", "webtob": _WEB + r"|WebtoB",
    "iis": r"앱\s*풀|응용\s*프로그램\s*풀|app\s*pool|AppPool",
}
_OS_SCOPE = r"서비스|service|데몬|daemon|프로세스|process|서버|server|LDAP\s*클라이언트|클라이언트|client|HTTP\s*서비스"


# 숫자로 시작하는 코드 몸통(16진 Altibase ERR-410E3·ERR-0109D 포함) — 첫 구현은 \d+[A-Z]? 라 ERR-410E3 을 ERR-410E 로 잘랐다(전수 대조에서 발견)
_CODE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2,8})-(\d[0-9A-Z]{2,7})(?![0-9A-Za-z])((?:/\d[0-9A-Z]{2,7}(?![0-9A-Za-z]))*)")


def _codes_in(text: str) -> set:
    """문장에 적힌 에러코드 — 'TNS-12514/12541' 같은 줄임도 펼친다."""
    out = set()
    for m in _CODE.finditer(str(text or "")):
        out.add(f"{m.group(1)}-{m.group(2)}")
        out.update(f"{m.group(1)}-{x}" for x in m.group(3).split("/") if x)
    return out


def _clean(s: str) -> str:
    s = re.sub(r"롤백\s*:[^)]*(\)|$)", " ", s)              # '롤백: … 재기동)' 은 되돌리기 방법이지 권고가 아니다
    s = re.sub(r"'[^']*'|\"[^\"]*\"", " ", s)              # 따옴표 안은 인용(오류 문구)이지 권고가 아니다
    return re.sub(r"\(([^()]*)\)", lambda m: m.group(0) if RESTART_BASIS.search(m.group(1)) else " ", s)   # 방법·예시 괄호는 대상에서 뺀다


def restart_basis(sentences, product: str | None = None, layer: str | None = None) -> str:
    """긍정형 재기동 권고 문장(근거)을 돌려준다 — 없으면 ''.
    문장(. ; · 줄바꿈 , — / 또는 경계) 단위로: 재기동 낱말이 있고, 부정·조건·사건 표현이 없고, (product 를 주면) 이름이 나온 대상이 모두 그 제품의 재기동 범위 안."""
    scope = None
    if product:
        scope = re.compile(_OS_SCOPE if layer == "os" else SCOPE.get(product, ""), re.I)
    for s in sentences:
        # `명령` 안의 ; · 와 파일 이름의 점(altibase.properties)은 문장 경계가 아니다 — 근거가 "` 후 계획 재기동" 처럼 잘려 보이던 것(전수 대조에서 발견)
        txt = re.sub(r"`[^`]*`", lambda mm: mm.group(0).replace(";", "\x1f").replace("·", "\x1e"), _clean(str(s or "")))
        for part in re.split(r"\.(?=\s|$)|[;·\n]|, | — | / |\s또는\s", txt):
            part = part.replace("\x1f", ";").replace("\x1e", "·")
            if not RESTART_BASIS.search(part) or NEGATE.search(part) or RESTART_COND.search(part):
                continue
            if scope is not None:
                names = [t.group(1) for t in TARGET.finditer(part)]
                if scope.pattern and any(not scope.fullmatch(n.strip()) for n in names):   # 제품 이름도 SCOPE 에 있을 때만(IIS 전체 재시작 ≠ 앱 풀)
                    continue
                if not scope.pattern and names:
                    continue
            return part.strip()
    return ""


def support_status(m: dict, product: str, os_name: str) -> dict:
    """GPT 85차: 제품 × OS 지원 상태 — 지원 / 조건부 / 레거시 / 미확인."""
    s = (m.get("support") or {}).get(product, {}).get(os_name)
    if isinstance(s, dict) and s.get("status"):
        return {"status": str(s["status"]), "note": str(s.get("note") or "")}
    return {"status": "지원", "note": ""}


def _split_cmds(cmd: str) -> list[str]:
    """명령 묶음을 ';' 로 나누되 따옴표·괄호({} ()) 안과 주석(# 뒤) 안의 ';' 는 자르지 않는다
    (echo 'select …;' · PowerShell @{n='A';e={…}} · '# … select …;' 가 깨지지 않게)."""
    parts, cur, q, depth, i = [], [], "", 0, 0
    while i < len(cmd):
        ch = cmd[i]
        if q:
            cur.append(ch)
            if ch == q:
                q = ""
        elif ch in "'\"":
            q = ch
            cur.append(ch)
        elif ch in "{(":
            depth += 1
            cur.append(ch)
        elif ch in "})":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "#" and (i == 0 or cmd[i - 1] in " \t"):
            cur.append(cmd[i:])                # 주석 — 끝까지 이 조각에 붙인다
            break
        elif ch == ";" and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


# GPT 88차 P0-02: 상태를 바꾸는 원격 요청(HTTP POST/PUT/DELETE/PATCH·본문 전송)은 '능동 진단(선택)'도 아니다 — 2차 변경 통제로
MUTATING = re.compile(
    # 짧은 옵션은 대소문자 구분(curl -D - 는 응답 머리글 덤프 — 읽기)
    r"\bcurl\b[^;|&\n]*(\s(?-i:-X)\s*['\"]?(POST|PUT|DELETE|PATCH)\b|\s--request[\s=]+['\"]?(POST|PUT|DELETE|PATCH)\b|\s(?-i:-d|-F|-T)\s"
    r"|\s(--data(-\w+)?|--json|--form(-string)?|--upload-file)[\s=])"            # GPT 89차: --json 은 POST 를 만든다
    r"|\bwget\b[^;|&\n]*--(post-data|post-file|method|body-data|body-file)"
    # GPT 89차: PowerShell 6+ -CustomMethod(-CM)·따옴표 값도
    # GPT 90차: Windows PowerShell 5.1 에서는 curl·wget 도 Invoke-WebRequest 별칭 — 'curl -Method Post' 도 원격 변경
    r"|\b(Invoke-RestMethod|Invoke-WebRequest|irm|iwr|curl|wget)\b[^;|&\n]*(\s-(Method|CustomMethod|CM)\s*:?\s*['\"]?(Post|Put|Delete|Patch)\b|\s-Body\s|\s-InFile\s)", re.I)


def _split_three(cmd: str) -> tuple[str, str, str]:
    """한 줄 명령 묶음(;)을 (읽기 전용, 능동 진단, 원격 변경) 으로 나눈다."""
    keep, act, chg = [], [], []
    for part in _split_cmds(cmd):
        if not part:
            continue
        body = part.split("#", 1)[0]
        (chg if MUTATING.search(body) else act if ACTIVE.search(body) else keep).append(part)
    return "; ".join(keep), "; ".join(act), "; ".join(chg)


def _split_active(cmd: str) -> tuple[str, str]:
    """한 줄 명령 묶음(;)에서 대상과 통신하는 부분(능동 진단 + 원격 변경)을 떼어 낸다 — (읽기 전용 부분, 그 밖)."""
    keep, act, chg = _split_three(cmd)
    return keep, "; ".join(x for x in (act, chg) if x)


def _code_cmds(prof: dict, code: str, os_name: str, family: str) -> list[str]:
    out = []
    for pat, tbl in (prof.get("code_cmd") or {}).items():
        try:
            ok = re.search(pat, code) is not None
        except re.error:
            ok = False
        if ok:
            c = _pick(tbl, os_name, family)
            if c:
                out.append(c)
    return out


def solution(entry, os_name: str, manuals_dir=None, procs: list | None = None) -> dict:
    """entry: codes.CodeEntry · os_name: linux/aix/hpux/solaris/windows · procs: procedures.load_procedures 결과(있으면 2차에 붙임)."""
    m = load_matrix(manuals_dir)
    product = str(entry.product).lower()
    prof = m["products"].get(product)
    oses = applicable_os(m, product)
    head = {"code": entry.code, "product": product, "layer": entry.layer, "title": entry.title, "severity": entry.severity,
            "category": entry.category, "cause": entry.cause, "action": entry.action, "ref": entry.ref,
            "versions": list(entry.versions or []),
            "os_list": [{"id": o, "label": m["os"][o]["label"], "status": support_status(m, product, o)["status"]} for o in oses],
            "legend": m.get("legend") or {}}
    if not prof:
        return {**head, "error": f"{product} 의 OS 별 해법 지식(제품 프로필)이 아직 없습니다"}
    if os_name not in oses:
        return {**head, "error": f"{product} 는 {os_name} 에서 지원·운영되지 않습니다 — 지원 OS: {', '.join(oses)}"}
    family = m["os"][os_name].get("family", "unix")
    code = str(entry.code)
    sup = support_status(m, product, os_name)
    unverified = sup["status"] in ("미확인", "레거시")
    s1: list[dict] = []
    act: list[dict] = []   # GPT 85차: 능동 진단(대상과 통신) — 1차 읽기 전용과 분리
    for t in entry.immediate or []:
        t = str(t)
        item = {"kind": "제품", "text": t}
        notes = []
        if family == "windows" and UNIX_ONLY.search(t):
            notes.append("유닉스 명령이 섞여 있음 — Windows 에서는 아래 OS 확인 명령(PowerShell)으로 같은 것을 본다")
        if MUTATING.search(t):
            notes.append("상태를 바꾸는 원격 요청(HTTP POST/PUT/DELETE 등)이 들어 있음 — 1차에서 실행하지 않는다. 2차 승인·대상 확인·롤백 계획 뒤에만(GPT 88차)")
        elif ACTIVE.search(t):
            notes.append("대상과 통신하는 능동 진단이 들어 있음 — 그 부분은 대상 승인·1회·짧은 시한으로 사람이 선택해 실행(GPT 86차)")
        if notes:
            item["note"] = " · ".join(notes)
        s1.append(item)
    chg_items: list[dict] = []   # GPT 88차: 원격 변경 요청은 2차 변경 통제로
    def _add(kind, title, cmd, note=""):
        keep, a, ch = _split_three(cmd)
        if keep:
            it = {"kind": kind, "title": title, "cmd": keep}
            if note:
                it["note"] = note
            s1.append(it)
        if a:
            act.append({"kind": "능동(선택)", "title": title, "cmd": a})
        if ch:
            chg_items.append({"kind": "원격 변경", "title": title, "cmd": ch,
                              "note": "상태를 바꾸는 원격 요청 — 1차·능동 진단이 아니다. 대상·영향 확인, 승인, 롤백 계획 뒤에만 사람이 실행"})
    pnote = "제품 전용 명령 — 이 조합은 지원 상태가 '" + sup["status"] + "'라 미검증" if unverified else ""
    st = _pick(prof.get("status") or {}, os_name, family)
    if st:
        _add("제품 상태", f"{product} 상태 확인(프로세스·리스너 등 일부만 — 서비스 전체 정상의 증거 아님)", _fill(st, prof, code, family), pnote)
    for c in _code_cmds(prof, code, os_name, family):
        _add("코드", f"{code} 관련 확인", _fill(c, prof, code, family), pnote)
    groups = m["category_checks"].get(entry.category) or m["category_checks"].get("etc") or []
    for g in groups:
        chk = m["checks"].get(g) or {}
        c = _pick(chk, os_name, family)
        if not c:
            continue
        logv = (prof.get("log") or {}).get(family) or ""
        if g == "log" and logv.rstrip().endswith(("/", "\\")):
            c = chk.get(family + "_dir") or c          # 로그가 폴더면 가장 최근 파일을 본다
        if ("<PROC" in c and not (prof.get("proc") or prof.get("proc_win"))) or ("<PORT>" in c and not prof.get("port")) \
                or ("<LOG>" in c and not (prof.get("log") or {}).get(family)):
            continue                                   # 프로세스·포트·로그가 없는 제품(OS 자체 등)에는 그 묶음을 붙이지 않는다
        title = f"{m['os'][os_name]['label']} — {chk.get('title', g)}"
        if chk.get("active"):
            act.append({"kind": "능동(선택)", "title": title, "cmd": _fill(c, prof, code, family)})
        else:
            _add("OS", title, _fill(c, prof, code, family))
    if prof.get("port_note"):
        s1.append({"kind": "참고", "title": "포트", "text": str(prof["port_note"])})
    if prof.get("log_note"):
        s1.append({"kind": "참고", "title": "로그 위치", "text": str(prof["log_note"])})
    for it in act:
        it["note"] = "능동 진단 — 대상과 통신한다. 대상 승인·1회·짧은 시한으로 사람이 선택해 실행(자동 실행 안 함). 성공은 도달일 뿐 정상의 증거가 아니다"
    s1 += act
    s2: list[dict] = [{"kind": "제품", "text": str(t)} for t in (entry.short or [])] + chg_items
    if procs:
        from .procedures import match_procedures
        for p in match_procedures(procs, product, entry.layer, entry.category, [code], limit=1):
            for stg in p.get("stages") or []:
                if stg.get("stage") != 2:
                    continue
                for step in stg.get("steps") or []:
                    if step.get("cmd") or step.get("do"):
                        s2.append({"kind": "절차", "title": f"{p.get('title', '')} ({p.get('id', '')} · {p.get('link', '')})",
                                   "text": step.get("do", ""), "cmd": step.get("cmd", ""), "note": step.get("note", ""), "link": p.get("link", ""),
                                   "_pcodes": sorted(_codes_in(p.get("title", "")))})
    rs = _pick(prof.get("restart") or {}, os_name, family) or (m["os_restart"].get(os_name) if entry.layer == "os" else None)
    # GPT 86차: 근거는 이 코드의 2차 조치(short)와 연결 절차의 2단계 문장만 — 긍정형 권고일 때. 미확인·레거시 조합에는 변경 명령을 내지 않는다
    # 12차 전수 대조: ① 유형만으로 붙은 절차('같은 제품·유형')의 문장은 이 코드의 근거가 아니다 — 코드를 이름으로 든 절차(이 판정 전용)만.
    # ② 여러 코드를 한 절차로 묶은 경우(ORA-00020 · TNS-12514/12520/12541) 단계마다 대상 코드가 다르다 — 코드를 적은 단계는 그 코드들의 것,
    #    코드를 안 적은 단계는 절차 제목이 코드를 둘 이상 묶었으면 어느 코드의 것인지 알 수 없다 → 근거로 쓰지 않는다(안전 쪽, GPT 87차 A).
    #    (TNS-12541 리스너 없음에 ORA-00020 용 'PROCESSES 상향(재기동 필요)'이 붙어 DB 전체 재기동이 나왔다)
    own = [i for i in s2 if i.get("kind") == "절차" and i.get("link") == "이 판정 전용"]
    claimed = set().union(*[_codes_in(i.get("text", "")) for i in own]) if own else set()
    me = str(code).upper()

    def _mine(i) -> bool:
        named = _codes_in(i.get("text", ""))
        if named:
            return me in named
        title = set(i.get("_pcodes") or [])
        return me not in claimed and len(title) <= 1 and (not title or me in title)
    sentences = list(entry.short or []) + [str(i.get("text", "")) for i in own if _mine(i)]
    for i in s2:
        i.pop("_pcodes", None)
    if unverified:
        for i in s2:
            i["note"] = ((i.get("note") or "") + " · " if i.get("note") else "") + f"지원 상태 '{sup['status']}' — 지원 확인 전 실행 금지(미검증)"
    basis = "" if unverified else restart_basis(sentences, product, entry.layer)
    if rs and basis:
        # GPT 85차: 재기동은 이 코드의 지식·절차가 재기동을 근거로 들 때만 — 영향·성공 기준과 함께. GPT 87차: 근거 문장을 그대로 보여 준다
        note = str(prof.get("restart_note") or "재기동은 원인 해소가 아니다 — 영향(세션·요청 단절)·롤백·성공 기준을 승인 문서에 적고 진행")
        s2.append({"kind": "재기동", "title": f"{m['os'][os_name]['label']} 에서 {product} 재기동(이 코드의 조치 근거가 있을 때 · 승인·업무 공지 후)",
                   "text": f"근거: {basis}", "cmd": _fill(rs, prof, code, family), "note": note})
    elif rs:
        why = (f"지원 상태 '{sup['status']}' 조합이라 재기동 명령을 내지 않는다 — 제조사 지원 확인 뒤 판 매뉴얼 절차로" if unverified else
               "이 코드의 지식·절차에는 이 제품 재기동의 긍정형 근거가 없다(다른 대상의 재시작·조건·부정 문장은 근거로 치지 않음) — "
               "원인 해소 없이 재기동을 해법으로 쓰지 않는다. 필요하면 영향·롤백·성공 기준을 정해 별도 승인")
        s2.append({"kind": "판단", "title": "재기동 필요 여부 판단", "text": why})
    s3: list[dict] = []
    pc = _pick(prof.get("collect") or {}, os_name, family)
    sens = "수집물에 설정·계정·경로 등 민감정보가 들어갈 수 있다 — 생성과 외부 전달 승인을 분리하고, 전달 전 내용 확인·마스킹"
    if pc:
        s3.append({"kind": "제품", "title": f"{product} 제조사 의뢰 자료", "cmd": _fill(pc, prof, code, family), "note": sens})
    oc = m["os_collect"].get(os_name)
    if oc:
        s3.append({"kind": "OS", "title": f"{m['os'][os_name]['label']} 벤더 의뢰 자료", "cmd": oc, "note": sens})
    return {**head, "os": os_name, "os_label": m["os"][os_name]["label"], "support": sup,
            "stages": [{"stage": 1, "title": "1차 확인 — 읽기 전용", "items": s1},
                       {"stage": 2, "title": "2차 조치 — 승인·롤백 계획 뒤", "items": s2},
                       {"stage": 3, "title": "3차 제조사 의뢰 자료", "items": s3}]}


def solution_text(sol: dict) -> str:
    """CLI·복사용 텍스트."""
    if sol.get("error"):
        return f"[{sol.get('product')}:{sol.get('code')}] {sol['error']}"
    L = [f"[{sol['product']}:{sol['code']}] {sol['title']} · {sol['severity']} · OS: {sol['os_label']}"]
    sp = sol.get("support") or {}
    if sp.get("status") and sp["status"] != "지원":
        L.append(f"  ⚠ 지원 상태: {sp['status']} — {sp.get('note', '')}")
    if sol.get("cause"):
        L.append(f"  제조사 원인: {sol['cause']}")
    if sol.get("action"):
        L.append(f"  제조사 조치: {sol['action']}")
    if sol.get("ref"):
        L.append(f"  근거: {sol['ref']}")
    for stg in sol["stages"]:
        L.append(f"\n■ {stg['title']}")
        for it in stg["items"]:
            if it.get("title"):
                L.append(f"  · {it['title']}")
            if it.get("text"):
                L.append(f"    {it['text']}")
            if it.get("cmd"):
                L += [f"    $ {ln}" for ln in str(it["cmd"]).splitlines()]
            if it.get("note"):
                L.append(f"    ※ {it['note']}")
    return "\n".join(L)
