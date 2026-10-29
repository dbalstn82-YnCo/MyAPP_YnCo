"""Apache HTTP Server error log 파서 — AH 에러코드 추출.

포맷(2.4): [Wed Sep 02 14:03:10.123456 2026] [proxy:error] [pid 123] AH01102: ...
포맷(1.3/2.0/2.2): [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] client denied by server configuration: ...
  → 2.2 는 AH 코드가 없으므로 메시지 별칭(_aliases.yaml apache)으로 같은 AH 코드에 대응시킨다.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_LINE = re.compile(r"^\[\w{3} (\w{3} +\d+ \d{2}:\d{2}:\d{2})(?:\.\d+)? (\d{4})\] "
                   r"\[([\w-]+):(\w+)\] (.*)$")
# Apache 1.3/2.0/2.2 형식: [Wed Oct 11 14:32:52 2000] [error] [client 127.0.0.1] message  (모듈명·AH 코드 없음)
_LINE22 = re.compile(r"^\[\w{3} (\w{3} +\d+ \d{2}:\d{2}:\d{2}) (\d{4})\] \[(\w+)\] (.*)$")
_CODE = re.compile(r"\b(AH\d{5})\b")
_SEV = {"emerg": "critical", "alert": "critical", "crit": "critical",
        "error": "error", "warn": "warn", "notice": "info", "info": "info", "debug": "info"}


@register("apache", "web")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _LINE.match(line)
        if m:
            ts_txt, year, module, level, msg = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        else:
            m2 = _LINE22.match(line)
            if not m2:
                continue
            ts_txt, year, module, level, msg = m2.group(1), m2.group(2), "2.2", m2.group(3), m2.group(4)
        ts = fast_strptime(f"{ts_txt.replace('  ', ' ')} {year}", "%b %d %H:%M:%S %Y")
        cm = _CODE.search(msg)
        events.append(Event(
            ts=ts, host=host, layer="web", product="apache",
            severity=_SEV.get(level.lower(), "info"),
            code=cm.group(1) if cm else None,
            message=f"[{module}] {msg}", raw_ref=f"{path}:{i}-{i}",
        ))
    return events
