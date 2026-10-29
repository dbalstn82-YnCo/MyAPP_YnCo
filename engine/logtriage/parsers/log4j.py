"""범용 log4j/logback 파서 — Java 기반 솔루션 공용 (메타빌드 MESIM ESB·APIG 등).

지원 레이아웃 (타임스탬프 뒤 레벨 위치가 달라도 인식):
  2026-09-02 14:02:48,120 ERROR [thread] com.x.Y - 메시지
  2026-09-02 14:02:48.120 [thread] ERROR com.x.Y - 메시지
  [2026-09-02 14:02:48] [ERROR] [thread] 메시지
  2026-09-02T14:02:48.120+09:00 ERROR ...
스택트레이스는 직전 이벤트에 병합. 코드형 토큰(ESB-1234, APIG-001, MB-... 등)을
에러코드로 추출해 벤더 코드 사전과 연결한다.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, exception_code, iter_lines, register, fast_strptime

_TS = re.compile(r"^\[?(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?"
                 r"(?:[+-]\d{2}:?\d{2}|Z)?\]?\s*(.*)$")
# 레벨이 앞에 오는 변형: [ INFO] [2026-02-01 00:00:00,526] Class.method(53) 메시지  (DDIMS 등 사내 앱)
_LVL_FIRST = re.compile(r"^\[\s*(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)\s*\]\s*"
                        r"\[(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\]\s*(.*)$")
_LEVEL = re.compile(r"(?:^|[\[\s|<])(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|SEVERE)"
                    r"(?:[\]\s|:>]|$)")
_CODE = re.compile(r"\b([A-Z]{2,8}-\d{3,6})\b")
# logback 압축 날짜: 20250723 14:29:17.149 [thread] (IP) LEVEL logger - msg
_TS_COMPACT = re.compile(r"^(\d{4})(\d{2})(\d{2}) (\d{2}:\d{2}:\d{2})(?:[.,]\d{1,6})?\s+(.*)$")
# 앱 로그에 섞여 나오는 JEUS 6 서버 메시지: [2025.07.23 14:29:21][1] [admin-133] [SESSION-2512] msg
_TS_JEUS = re.compile(r"^\[(\d{4})\.(\d{2})\.(\d{2}) (\d{2}:\d{2}:\d{2})\]\[(\d)\]\s*(.*)$")
_JEUS_LVL = {"0": "critical", "1": "warn", "2": "info"}
_SEV = {"FATAL": "critical", "SEVERE": "critical", "ERROR": "error",
        "WARN": "warn", "WARNING": "warn",
        "INFO": "info", "DEBUG": "info", "TRACE": "info"}


def _parse(path: Path, host: str, product: str) -> list[Event]:
    events = EventSink()
    cur, cur_end = None, 0

    def flush():
        if cur:
            cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
            events.append(cur)

    for i, line in iter_lines(path):
        if line.strip() in ("<<__Exception__>>", "<<__!Exception__>>"):
            cur_end = i
            continue
        m = _TS.match(line)
        m2 = None if m else _LVL_FIRST.match(line)
        m3 = None if (m or m2) else _TS_COMPACT.match(line)
        m4 = None if (m or m2 or m3) else _TS_JEUS.match(line)
        if m3 or m4:
            flush()
            if m3:
                ts = fast_strptime(f"{m3.group(1)}-{m3.group(2)}-{m3.group(3)} {m3.group(4)}", "%Y-%m-%d %H:%M:%S")
                rest = m3.group(5)
                lm = _LEVEL.search(rest[:160])
                sev = _SEV.get(lm.group(1), "info") if lm else "info"
            else:
                ts = fast_strptime(f"{m4.group(1)}-{m4.group(2)}-{m4.group(3)} {m4.group(4)}", "%Y-%m-%d %H:%M:%S")
                rest = m4.group(6)
                sev = _JEUS_LVL.get(m4.group(5), "info")
            cm = _CODE.search(rest)
            cur = Event(ts=ts, host=host, layer="sw", product=product, severity=sev, message=rest,
                        code=cm.group(1) if cm else None, raw_ref=str(i))
            cur_end = i
            continue
        if m or m2:
            flush()
            if m:
                ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
                rest = m.group(3)
                lm = _LEVEL.search(rest[:120])
                sev = _SEV.get(lm.group(1), "info") if lm else "info"
            else:
                ts = fast_strptime(f"{m2.group(2)} {m2.group(3)}", "%Y-%m-%d %H:%M:%S")
                rest = m2.group(4)
                sev = _SEV.get(m2.group(1), "info")
            cm = _CODE.search(rest)
            cur = Event(ts=ts, host=host, layer="sw", product=product,
                        severity=sev, message=rest,
                        code=cm.group(1) if cm else None, raw_ref=str(i))
            cur_end = i
        elif cur:
            if cur_end - int(cur.raw_ref) < 200:  # 연속 라인 상한(비정상 대량 출력 방어)
                cur.message += "\n" + line
                # 스택트레이스에서 대표 예외를 심각도 판단에 반영
                if cur.severity == "info" and re.search(r"Exception|Error\b", line):
                    cur.severity = "error"
            cur_end = i
    flush()
    # 벤더 코드가 없는 이벤트는 대표 예외 클래스(FQCN)를 코드로 — 코드 사전(java 예외)과 연결
    for ev in events:
        if not ev.code and ev.severity != "info" and ("Exception" in ev.message or "Error" in ev.message):
            ev.code = exception_code(ev.message)
    return events


def _register(product: str):
    @register(product, "sw")
    def parse(path: Path, host: str, _p=product) -> list[Event]:
        return _parse(path, host, _p)
    return parse


for _p in ("java", "mesim-esb", "mesim-apig", "mesim-eai"):
    _register(_p)
