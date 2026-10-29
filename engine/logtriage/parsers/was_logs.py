"""WAS 파서 — JEUS · WebLogic · JBoss/WildFly · WebSphere tWAS(SystemOut.log).

JBoss/WildFly : 2026-09-02 14:02:48,120 ERROR [org.jboss...] (thread) 메시지
WebLogic      : ####<Sep 2, 2026 2:02:48 PM KST> <Error> <서브시스템> <호스트> ... <메시지>
JEUS          : [2026.09.02 14:02:48][2] [server-1] 메시지  /  [2026-09-02T14:02:48.120][ERROR] 메시지
타임스탬프 없는 줄(스택트레이스)은 직전 이벤트에 병합.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, exception_code, iter_lines, register, fast_strptime

_SEV = {
    "SEVERE": "critical", "FATAL": "critical", "EMERGENCY": "critical", "ALERT": "critical",
    "CRITICAL": "critical", "ERROR": "error", "WARNING": "warn", "WARN": "warn",
    "NOTICE": "info", "INFO": "info", "DEBUG": "info", "FINE": "info", "TRACE": "info",
}
# JEUS 구형 숫자 레벨: 0=FATAL 1=NOTICE 2=INFORMATION ... (보수적으로 0,1만 상향)
_JEUS_NUM = {"0": "critical", "1": "warn"}


def _flush(events, cur, cur_end, path):
    if cur:
        cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
        events.append(cur)


_CODE_RES = {
    "weblogic": re.compile(r"\b(BEA-\d{6})\b"),
    "jboss": re.compile(r"\b(JBAS\d{6}|WFLY[A-Z]+\d{4})\b"),
    "jeus": re.compile(r"\[([A-Z][A-Za-z]{1,10}-\d{4})\]|\b(JEUS-\d+)\b"),
    "websphere": re.compile(r"\b([A-Z][A-Z0-9]{3,4}\d{4}[EWIAFC]):"),   # WSVR0605W · J2CA0045E(앞머리에 숫자) · CWPKI0017E — 메시지 ID 뒤 ':'
}


def _run_lines(path, host, product, try_parse, max_cont: int = 200):
    """이벤트 시작 라인은 try_parse 로 인식, 나머지는 직전 이벤트의 연속 라인으로 병합.
    연속 라인은 리스트 버퍼에 모아 flush 때 한 번에 합치고(문자열 += 의 O(n²) 방지), max_cont 줄까지만 보관."""
    events = EventSink()
    code_re = _CODE_RES.get(product)
    cur, cur_end, buf = None, 0, []

    def flush():
        if cur is not None:
            if buf:
                cur.message = cur.message + "\n" + "\n".join(buf)
                if cur.severity == "info" and any(re.search(r"Exception|OutOfMemory|Error\b", b) for b in buf[:40]):
                    cur.severity = "error"
            _flush(events, cur, cur_end, path)

    for i, line in iter_lines(path):
        parsed = try_parse(line)
        if parsed:
            flush()
            ts, sev, msg = parsed
            cm = code_re.search(msg) if code_re else None
            code = None
            if cm:
                code = next((g for g in cm.groups() if g), None)
            cur = Event(ts=ts, host=host, layer="was", product=product,
                        severity=sev, message=msg, raw_ref=str(i), code=code)
            cur_end = i
            buf = []
        elif cur is not None:
            if len(buf) < max_cont:
                buf.append(line)
            cur_end = i
    flush()
    for ev in events:
        if not ev.code and ev.severity != "info" and ("Exception" in ev.message or "Error" in ev.message):
            ev.code = exception_code(ev.message)

    return events


_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[.,]\d{3})?\s+(\S+)\s+(.*)$")


@register("jboss", "was")
def parse_jboss(path: Path, host: str) -> list[Event]:
    def try_parse(line):
        m = _ISO.match(line)
        if not m:
            return None
        ts = fast_strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        return ts, _SEV.get(m.group(2).upper(), "info"), m.group(3)
    return _run_lines(path, host, "jboss", try_parse)


_WLS = re.compile(r"^####<([^>]+)>\s*<(\w+)>\s*(.*)$")


@register("weblogic", "was")
def parse_weblogic(path: Path, host: str) -> list[Event]:
    def try_parse(line):
        m = _WLS.match(line)
        if not m:
            return None
        raw = re.sub(r",\d+", "", m.group(1))
        raw = re.sub(r"\s+[A-Z]{2,5}$", "", raw)  # 타임존 제거
        for fmt in ("%b %d, %Y %I:%M:%S %p", "%b %d, %Y, %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
            try:
                ts = fast_strptime(raw.strip(), fmt)
                break
            except ValueError:
                ts = None
        if ts is None:
            return None
        return ts, _SEV.get(m.group(2).upper(), "info"), m.group(3)
    return _run_lines(path, host, "weblogic", try_parse)


# WebSphere tWAS 8.5.5/9.0 SystemOut.log·SystemErr.log 기본(Basic) 형식(2026-10-16 지식 점검에서 파서가 없던 것을 발견):
#   [10/16/26 10:15:30:123 KST] 0000001a ThreadMonitor W   WSVR0605W: Thread "WebContainer : 0" ...
#   한국어 로캘: [26. 10. 16 10:15:30:123 KST] 0000001a ...   (yy. M. d)
#   이벤트 유형 F(치명)·E(오류)·W(경고)·A(감사)·I(정보)·C(구성)·D(상세)·O(SystemOut)·R(SystemErr)·Z(알 수 없음)
_WAS_US = re.compile(r"^\[(\d{1,2})/(\d{1,2})/(\d{2,4}) (\d{1,2}):(\d{2}):(\d{2})[:.](\d{1,3})\s*[^\]]*\]\s+[0-9a-fA-F]{8}\s+(\S+)\s+([FEWAICDORZ])\s+(.*)$")
_WAS_KO = re.compile(r"^\[(\d{2,4})\. ?(\d{1,2})\. ?(\d{1,2})\.? (\d{1,2}):(\d{2}):(\d{2})[:.](\d{1,3})\s*[^\]]*\]\s+[0-9a-fA-F]{8}\s+(\S+)\s+([FEWAICDORZ])\s+(.*)$")
_WAS_SEV = {"F": "critical", "E": "error", "W": "warn", "A": "info", "I": "info", "C": "info", "D": "info", "O": "info", "R": "info", "Z": "info"}


def _yy(y: str) -> int:
    n = int(y)
    return n + 2000 if n < 100 else n


@register("websphere", "was")
def parse_websphere(path: Path, host: str) -> list[Event]:
    def try_parse(line):
        m = _WAS_US.match(line)
        if m:
            mo, d, y = int(m.group(1)), int(m.group(2)), _yy(m.group(3))
        else:
            m = _WAS_KO.match(line)
            if not m:
                return None
            y, mo, d = _yy(m.group(1)), int(m.group(2)), int(m.group(3))
        try:
            ts = datetime(y, mo, d, int(m.group(4)), int(m.group(5)), int(m.group(6)))
        except ValueError:
            return None
        sev = _WAS_SEV.get(m.group(9), "info")
        msg = f"{m.group(8)} {m.group(10)}"            # 컴포넌트 짧은 이름 + 메시지(메시지 ID 포함)
        if m.group(9) == "R" and re.search(r"Exception|OutOfMemory|Error\b", msg):
            sev = "error"                                  # SystemErr 의 예외는 오류로
        return ts, sev, msg
    return _run_lines(path, host, "websphere", try_parse)


_JEUS_OLD = re.compile(r"^\[(\d{4})\.(\d{2})\.(\d{2}) (\d{2}:\d{2}:\d{2})\]\[(\d+)\]\s*(.*)$")
_APP_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\s+(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\s+(.*)$")
_APP_LVL = re.compile(r"^\[\s*(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\s*\]\s*\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\]\s*(.*)$")
_JEUS_NEW = re.compile(r"^\[(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.\d+)?\]\[(\w+)\]\s*(.*)$")


@register("jeus", "was")
def parse_jeus(path: Path, host: str) -> list[Event]:
    def try_parse(line):
        m = _JEUS_OLD.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}",
                                   "%Y-%m-%d %H:%M:%S")
            msg = m.group(6)
            sev = _JEUS_NUM.get(m.group(5), "info")
            # 메시지에 예외·오류 키워드가 있으면 상향
            if re.search(r"Exception|OutOfMemory|Error", msg):
                sev = "error" if sev == "info" else sev
            return ts, sev, msg
        m = _JEUS_NEW.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            return ts, _SEV.get(m.group(3).upper(), "info"), m.group(4)
        # 컨테이너 로그에 섞이는 애플리케이션(log4j) 라인: 2026-02-01 00:00:00,519  INFO [root] ... / [ INFO] [2026-02-01 ...] ...
        m = _APP_ISO.match(line)
        if m:
            ts = fast_strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            return ts, _SEV.get(m.group(2).upper(), "info"), m.group(3)
        m = _APP_LVL.match(line)
        if m:
            ts = fast_strptime(m.group(2), "%Y-%m-%d %H:%M:%S")
            return ts, _SEV.get(m.group(1).upper(), "info"), m.group(3)
        return None
    return _run_lines(path, host, "jeus", try_parse)
