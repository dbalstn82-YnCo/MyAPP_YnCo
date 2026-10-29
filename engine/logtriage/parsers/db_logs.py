"""DBMS 파서 — MySQL/MariaDB · PostgreSQL · MS-SQL · Altibase · Tibero · CUBRID · GOLDILOCKS (에러코드 추출 포함)."""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_SEV_WORD = {"system": "info", "note": "info", "warning": "warn",
             "error": "error", "fatal": "critical", "panic": "critical",
             "log": "info", "statement": "info", "detail": "info", "hint": "info"}


def _mk(path, i, ts, host, product, sev, msg, code=None):
    return Event(ts=ts, host=host, layer="db", product=product, severity=sev,
                 code=code, message=msg, raw_ref=f"{path}:{i}-{i}")


# ── MySQL / MariaDB error log ──────────────────────────────────
# 8.x : 2026-09-02T14:02:11.123456Z 12 [ERROR] [MY-012153] [InnoDB] 메시지
# 5.6/5.7 : 2026-09-02 14:02:11 140123456 [ERROR] 메시지 / 5.7 ISO : 2026-09-02T14:02:11.123456Z 12 [ERROR] 메시지(코드 없음)
_MY8 = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})[^ ]* +\d+ +\[(\w+)\]"
                  r"(?: +\[(MY-\d+)\])?(?: +\[[\w]+\])? +(.*)$")
_MY5 = re.compile(r"^(\d{4}-\d{2}-\d{2}) +(\d{2}:\d{2}:\d{2}) +\d* *\[(\w+)\] +(.*)$")
# 5.5/5.6 : 160902 14:02:11 [ERROR] 메시지  (YYMMDD, 5.6 은 tid 가 붙기도 함)
_MY55 = re.compile(r"^(\d{6}) +(\d{1,2}:\d{2}:\d{2}) +(?:\d+ +)?\[(\w+)\] +(.*)$")


@register("mysql", "db")
def parse_mysql(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _MY8.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            events.append(_mk(path, i, ts, host, "mysql",
                              _SEV_WORD.get(m.group(3).lower(), "info"),
                              m.group(5), m.group(4)))
            continue
        m = _MY5.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            events.append(_mk(path, i, ts, host, "mysql",
                              _SEV_WORD.get(m.group(3).lower(), "info"), m.group(4)))
            continue
        m = _MY55.match(line)
        if m:
            try:
                ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%y%m%d %H:%M:%S")
            except ValueError:
                continue
            events.append(_mk(path, i, ts, host, "mysql",
                              _SEV_WORD.get(m.group(3).lower(), "info"), m.group(4)))
    return events


# ── PostgreSQL ────────────────────────────────────────────────
# 2026-09-02 14:02:11.123 KST [12345] ERROR:  deadlock detected
_PG = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?(?: \S+)? \[\d+\][^:]* "
                 r"(\w+): +(.*)$")


@register("postgresql", "db")
def parse_postgresql(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _PG.match(line)
        if not m:
            continue
        ts = fast_strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        events.append(_mk(path, i, ts, host, "postgresql",
                          _SEV_WORD.get(m.group(2).lower(), "info"), m.group(3)))
    return events


# ── MS-SQL ERRORLOG ───────────────────────────────────────────
# 2026-09-02 14:02:11.12 spid52      Error: 1205, Severity: 13, State: 45.
# 다음 줄에 상세 메시지가 오는 경우 병합.
_MS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.\d+ +(\S+) +(.*)$")
_MS_ERR = re.compile(r"Error: (\d+), Severity: (\d+)")
# 'Error: N' 줄 없이 본문만 남는 경고(룰 학습 2차, 2026-10-15) — 예전엔 'error|fail' 이 없어 이벤트가 되지 못했다.
# 코드 사전(833·17883·17884·5144·5145·825)은 이 문구에 별칭으로 이어지고, 사전에 없는 17890 은 룰이 잡는다.
_MS_SIG = re.compile(r"I/O requests taking longer than \d+ seconds to complete|appears to be non-yielding on Scheduler"
                     r"|(?:haven't|have not) been picked up by a worker thread in the last \d+ seconds"
                     r"|A significant part of sql server process memory has been paged out"
                     r"|Autogrow of file .{1,300}? (?:was cancelled by user or timed out after|took) \d+ milliseconds"
                     r"|A read of the file .{1,400}? succeeded after failing \d+ time", re.I)


@register("mssql", "db")
def parse_mssql(path: Path, host: str) -> list[Event]:
    events = EventSink()
    pending = None  # Error 라인 다음의 메시지 병합
    # ERRORLOG 는 UTF-16 이 흔함 — BOM 으로 판별 후 스트리밍(대용량 대응)
    with open(path, "rb") as fb:
        head = fb.read(2)
    enc = "utf-16" if head in (b"\xff\xfe", b"\xfe\xff") else "utf-8"

    def _lines():
        with open(path, encoding=enc, errors="replace", newline="") as f:
            for n, ln in enumerate(f, 1):
                yield n, ln.rstrip("\r\n")
    for i, line in _lines():
        m = _MS.match(line)
        if not m:
            continue
        ts = fast_strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        msg = m.group(3)
        em = _MS_ERR.search(msg)
        if em:
            sev_num = int(em.group(2))
            pending = (ts, em.group(1))
            events.append(_mk(path, i, ts, host, "mssql",
                              "critical" if sev_num >= 17 else "error",
                              msg, f"MSSQL-{em.group(1)}"))
        elif pending and pending[0] == ts and events:
            events[-1].message += " | " + msg
            pending = None
        elif re.search(r"error|fail", msg, re.I):
            events.append(_mk(path, i, ts, host, "mssql", "error", msg))
        elif _MS_SIG.search(msg):
            events.append(_mk(path, i, ts, host, "mssql", "warn", msg))
    return events


# ── Altibase ──────────────────────────────────────────────────
# altibase_boot.log / trc 로그:
#   [2026/09/02 14:02:11] [Thread-7f01] [Level-1] ERR-31024 : 메시지
#   [2026-09-02 14:02:11] ERROR 메시지  (변형 포맷 허용)
_ALTI = re.compile(r"^\[?(\d{4})[/-](\d{2})[/-](\d{2}) (\d{2}:\d{2}:\d{2})\]?\s*(.*)$")
_ALTI_CODE = re.compile(r"\b(ERR-[0-9A-Fa-f]+)\b")
# 6.1.1 이하 altibase_qp.log: "... errorcode 822329545" (10진) → 0x3103C049 → ERR-3103C (6.3.1 부터는 ERR-xxxxx 직접 출력)
_ALTI_DEC = re.compile(r"\berror ?code[ =:]+(\d{8,10})\b", re.I)


def _alti_dec_code(msg: str):
    m = _ALTI_DEC.search(msg)
    if not m:
        return None
    try:
        h = f"{int(m.group(1)):08X}"
    except ValueError:
        return None
    return f"ERR-{h[:5]}"


def _alti_sev(msg: str, code) -> str:
    if re.search(r"FATAL|PANIC|ABORT", msg, re.I):
        return "critical"
    if code or re.search(r"\bERROR\b|\bfail", msg, re.I):
        return "error"
    if re.search(r"WARNING|\[Notify\s*:", msg, re.I):
        return "warn"
    return "info"


def _continue(last, path, i, line: str, code_fn, sev_fn, limit: int = 600) -> bool:
    """시각 머리 없는 다음 줄을 직전 기록에 잇는다(룰 학습 5차) — 머리줄과 본문이 다른 줄인 형식에서
    본문(예 Goldilocks '[CLEANUP] long statement timeout', Altibase '[Notify : Query Timeout]')·오류 코드를 버리지 않게."""
    if last is None or not line.strip() or len(last.message) >= limit:
        return False
    body = line.strip()
    last.message = (last.message + " | " + body) if last.message else body
    last.raw_ref = re.sub(r"-\d+$", f"-{i}", last.raw_ref)
    if not last.code:
        c = code_fn(body)
        if c:
            last.code = c
    sev = sev_fn(last.message, last.code)
    if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(last.severity, 0):
        last.severity = sev
    return True


_SEV_RANK = {"info": 0, "warn": 1, "error": 2, "critical": 3}


@register("altibase", "db")
def parse_altibase(path: Path, host: str) -> list[Event]:
    events = EventSink()
    last = None
    def _code(s):
        cm = _ALTI_CODE.search(s)
        return cm.group(1).upper() if cm else _alti_dec_code(s)
    for i, line in iter_lines(path):
        m = _ALTI.match(line)
        if not m:
            _continue(last, path, i, line, _code, _alti_sev)
            continue
        if last is not None:
            events.append(last)       # 기록을 다 조립한 뒤에 담는다 — 담는 순간 info·코드 없음이면 수집기가 버리므로 본문이 붙기 전에 담으면 사라진다
        ts = fast_strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}",
                               "%Y-%m-%d %H:%M:%S")
        msg = m.group(5)
        code = _code(msg) if msg else None
        last = _mk(path, i, ts, host, "altibase", _alti_sev(msg, code), msg, code)
    if last is not None:
        events.append(last)
    return events


# ── Tibero ────────────────────────────────────────────────────
# [2026-09-02 14:02:11] TBR-12345: 메시지  /  일반 텍스트 alert
# Tibero 6/7 sys.log: [2025-04-08T15:25:04.096365] [COM-298] [I] Internal Error ...  (컴포넌트 코드 + I/W/E 레벨)
_TB = re.compile(r"^\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\]? *(.*)$")
_TB_CODE = re.compile(r"\b(TBR-\d+)\b")
_TB_COMP = re.compile(r"^\[([A-Z]{2,5}-\d{1,5})\] \[([IWEF])\] *")
_TB_SEV = {"I": "info", "W": "warn", "E": "error", "F": "critical"}


@register("tibero", "db")
def parse_tibero(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _TB.match(line)
        if not m or not m.group(3):
            continue
        ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        msg = m.group(3)
        cm = _TB_CODE.search(msg)
        comp = _TB_COMP.match(msg)
        if comp and not cm:
            sev = _TB_SEV.get(comp.group(2), "info")  # 명시 레벨([I]/[W]/[E]/[F]) 우선
            events.append(_mk(path, i, ts, host, "tibero", sev, msg, comp.group(1)))
            continue
        sev = "error" if cm or re.search(r"error|fail", msg, re.I) else "info"
        events.append(_mk(path, i, ts, host, "tibero", sev, msg,
                          cm.group(1) if cm else None))
    return events


# ── CUBRID ────────────────────────────────────────────────────
# $CUBRID/log/server/<db>_<yyyymmdd>_<hhmi>.err (8.4~11.4 동일):
#   Time: 10/29/10 17:32:42.360 - ERROR *** file ../../src/... ERROR CODE = -1022, Tran = 0, CLIENT = host:pid, EID = 2
#   Address(10.0.0.1) is not authorized.          ← 다음 줄(메시지 본문)은 직전 이벤트에 이어 붙임
# cub_broker/<broker>_<n>.err : Time: ... - ERROR *** CAS ... ERROR CODE = -10003 (CAS_ER_*)
_CUB = re.compile(r"^Time: (\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? - (ERROR|WARNING|NOTIFICATION|FATAL) \*\*\* ?(.*)$")
# NOTIFICATION 은 'CODE = -1125'(ERROR 없이) — 예전엔 'ERROR CODE' 만 받아 알림 코드가 사전에 닿지 못했다(룰 학습 5차, 10.2 매뉴얼 대조)
_CUB_CODE = re.compile(r"\bCODE = (-\d+)")
_CUB_SEV = {"ERROR": "error", "WARNING": "warn", "NOTIFICATION": "info", "FATAL": "critical"}
# 이벤트 로그 $CUBRID/log/server/<db>_<yyyymmdd>_<hhmi>.event(10.2 매뉴얼):
#   06/12/13 16:41:05.558 - SLOW_QUERY   client: PUBLIC@testhost|csql(13173)  sql: update …   (다음 줄들은 들여쓴 본문)
_CUB_EV = re.compile(r"^(\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? - (SLOW_QUERY|MANY_IOREADS|LOCK_TIMEOUT|DEADLOCK|TEMP_VOLUME_EXPAND)\b\s*(.*)$")
_CUB_EV_SEV = {"LOCK_TIMEOUT": "error", "DEADLOCK": "error"}


@register("cubrid", "db")
def parse_cubrid(path: Path, host: str) -> list[Event]:
    # 기록은 본문을 다 붙인 뒤에 담는다 — 담는 순간 info·코드 없음이면 수집기(EventSink)가 버려 본문까지 사라진다(룰 학습 5차)
    events = EventSink()
    last = None
    ev_mode = False

    def flush():
        nonlocal last
        if last is not None:
            events.append(last)
        last = None
    for i, line in iter_lines(path):
        m = _CUB.match(line)
        if m:
            try:
                ts = fast_strptime(m.group(1), "%m/%d/%y %H:%M:%S")
            except ValueError:
                continue
            flush()
            msg = m.group(3)
            cm = _CUB_CODE.search(msg)
            last = _mk(path, i, ts, host, "cubrid", _CUB_SEV.get(m.group(2), "info"), msg,
                       cm.group(1) if cm else None)
            ev_mode = False
            continue
        e = _CUB_EV.match(line)
        if e:
            try:
                ts = fast_strptime(e.group(1), "%m/%d/%y %H:%M:%S")
            except ValueError:
                continue
            flush()
            last = _mk(path, i, ts, host, "cubrid", _CUB_EV_SEV.get(e.group(2), "warn"), f"{e.group(2)} {e.group(3)}".strip())
            ev_mode = True
            continue
        cont_ok = not line.startswith("Time:") and (ev_mode or not line.startswith("\t"))
        if last is not None and line.strip() and cont_ok and len(last.message) < 400:
            last.message += " | " + line.strip()
            if not last.code:
                cm = _CUB_CODE.search(line)
                if cm:
                    last.code = cm.group(1)
        else:
            flush()
    flush()
    return events


# ── SUNJESOFT GOLDILOCKS ─────────────────────────────────────
# $GOLDILOCKS_DATA/trc/system.trc — 오류 표기 ERR-<SQLSTATE>(내부번호), 예 ERR-HY000(13011), ERR-42000(14006)
# 사전 코드는 내부번호 기준(ERR-13011) → 괄호 안 번호로 대응. 시각은 [YYYY-MM-DD HH:MM:SS(.ffffff)] 또는 줄 앞 YYYY-MM-DD HH:MM:SS 허용
_GD = re.compile(r"^\[?(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.\d+)?\]? *(.*)$")
_GD_CODE = re.compile(r"\bERR-([0-9A-Z]{5})\((\d{4,6})\)")


def _gd_code(s: str):
    cm = _GD_CODE.search(s)
    return f"ERR-{cm.group(2)}" if cm else None


def _gd_sev(msg: str, code) -> str:
    if re.search(r"FATAL|PANIC|ABORT", msg, re.I):
        return "critical"
    if code or re.search(r"\bERROR\b|\bfail", msg, re.I):
        return "error"
    if re.search(r"WARN", msg, re.I):
        return "warn"
    return "info"


@register("goldilocks", "db")
def parse_goldilocks(path: Path, host: str) -> list[Event]:
    # system.trc 는 '[2014-09-12 10:49:21.842179 THREAD(3972,…)] [WARNING]' 머리줄 다음 줄에 본문이 온다(26c 매뉴얼) —
    # 예전엔 본문 줄을 버려 '[CLEANUP] long statement timeout' 이나 본문 줄의 ERR-…(…) 코드가 판정에 닿지 못했다(룰 학습 5차)
    events = EventSink()
    last = None
    for i, line in iter_lines(path):
        m = _GD.match(line)
        if not m:
            _continue(last, path, i, line, _gd_code, _gd_sev)
            continue
        if not m.group(3):
            continue
        if last is not None:
            events.append(last)       # 다 조립한 뒤에 담는다(위 Altibase 와 같은 까닭)
        ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        msg = m.group(3)
        code = _gd_code(msg)
        last = _mk(path, i, ts, host, "goldilocks", _gd_sev(msg, code), msg, code)
    if last is not None:
        events.append(last)
    return events
