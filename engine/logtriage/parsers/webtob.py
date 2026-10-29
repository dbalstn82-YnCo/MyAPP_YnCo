"""Tmax WebtoB 파서 — 웹서버 로그 (error/system log + access log 5xx).

지원 포맷 (WebtoB 로그 레이아웃이 사이트마다 달라 유연하게 인식):
  [2026/09/02 14:03:10] [ERROR] [hth0] 메시지
  [2026-09-02 14:03:10] ... 메시지
  2026/09/02 14:03:10 [error] 메시지
  WebtoB 5 system.log: [2020-08-05T10:44:16] [HTH(22378)] [E] [HTH-00074] 메시지
  WebtoB 6 system.log: [2024-07-25 06:49:19.113263413][ERROR][HTH-0][SVR_3455]file.cpp:87 func: 메시지
  access log(CLF): 10.0.0.1 - - [02/Sep/2026:14:03:10 +0900] "GET /x HTTP/1.1" 502 123
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_TS = re.compile(r"^\[?(\d{4})[/-](\d{2})[/-](\d{2})[ T](\d{2}:\d{2}:\d{2})(?:[.,]\d+)?\]?\s*(.*)$")
_CLF = re.compile(r"^\S+ \S+ \S+ \[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})[^\]]*\] \"([^\"]*)\" (\d{3})")
# error.log: [01/Feb/2026:00:54:54 +0900] [error] [client 10.0.0.1] JSV: premature client close. POST /x HTTP/1.0
_ERRLOG = re.compile(r"^\[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})[^\]]*\]\s*\[(\w+)\]\s*(.*)$")
# system.log: [2026/02/01:00:55:11] HTH-44236818 I HTH0113: Client has closed connection. ...
_SYSLOG = re.compile(r"^\[(\d{4})/(\d{2})/(\d{2}):(\d{2}:\d{2}:\d{2})\]\s*(\S+)\s+([IWEF])\s+(.*)$")
_LEVEL = re.compile(r"\[(FATAL|ERROR|WARN(?:ING)?|INFO|DEBUG|error|warn|info)\]|\b(FATAL|ERROR|WARN(?:ING)?)\b")
_CODE = re.compile(r"\b(WBT?[A-Z]*-?\d{3,5}|[A-Z]{3,6}-\d{3,5}|HT[HL]\d{4}|[A-Z]{3}_\d{4})\b")  # 5: HTH-00074·HTH0113 / 6: SVR_3455·NET_2004
_LEVEL1 = re.compile(r"\]\s*\[([IDWEF])\]\s*\[")  # WebtoB 5 system.log: [2020-08-05T10:44:16] [HTH(22378)] [E] [HTH-00074] msg
_SEV1 = {"F": "critical", "E": "error", "W": "warn", "I": "info", "D": "info"}
_SEV = {"FATAL": "critical", "ERROR": "error", "WARN": "warn", "WARNING": "warn",
        "INFO": "info", "DEBUG": "info"}


@register("webtob", "web")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _CLF.match(line)
        if m:  # 액세스 로그: 5xx 만 이벤트화
            status = m.group(6)
            if not status.startswith("5"):
                continue
            ts = fast_strptime(f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}",
                                   "%d %b %Y %H:%M:%S")
            events.append(Event(ts=ts, host=host, layer="web", product="webtob",
                                severity="critical" if status in ("502", "503") else "error",
                                code=f"HTTP-{status}",
                                message=f"HTTP {status} {m.group(5)}",
                                raw_ref=f"{path}:{i}-{i}"))
            continue
        m = _ERRLOG.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)}", "%d %b %Y %H:%M:%S")
            lv = m.group(5).upper()
            msg = m.group(6)
            cm = _CODE.search(msg)
            events.append(Event(ts=ts, host=host, layer="web", product="webtob",
                                severity=_SEV.get(lv, "error" if lv.startswith(("ERR", "CRIT")) else "info"),
                                code=cm.group(1) if cm else None, message=msg, raw_ref=f"{path}:{i}-{i}"))
            continue
        m = _SYSLOG.match(line)
        if m:
            ts = fast_strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}", "%Y-%m-%d %H:%M:%S")
            lv = {"I": "info", "W": "warn", "E": "error", "F": "critical"}[m.group(6)]
            msg = m.group(7)
            cm = re.match(r"([A-Z]{3}\d{4})", msg)
            events.append(Event(ts=ts, host=host, layer="web", product="webtob", severity=lv,
                                code=cm.group(1) if cm else None, message=f"{m.group(5)} {msg}",
                                raw_ref=f"{path}:{i}-{i}"))
            continue
        m = _TS.match(line)
        if not m or not m.group(5):
            continue
        ts = fast_strptime(f"{m.group(1)}-{m.group(2)}-{m.group(3)} {m.group(4)}",
                               "%Y-%m-%d %H:%M:%S")
        msg = m.group(5)
        lm = _LEVEL.search(msg[:60])
        lv = (lm.group(1) or lm.group(2)).upper() if lm else ""
        if not lv:
            l1 = _LEVEL1.search(msg[:40])  # WebtoB 5 한 글자 레벨
            lv = {"F": "FATAL", "E": "ERROR", "W": "WARN", "I": "INFO", "D": "DEBUG"}[l1.group(1)] if l1 else ""
        sev = _SEV.get(lv, "error" if re.search(r"fail|error|cannot|refused", msg, re.I) else "info")
        cm = _CODE.search(msg)
        events.append(Event(ts=ts, host=host, layer="web", product="webtob", severity=sev,
                            code=cm.group(1) if cm else None, message=msg,
                            raw_ref=f"{path}:{i}-{i}"))
    return events
