"""Nginx error log 파서.

포맷: 2026/09/02 14:03:10 [error] 1234#0: *56 upstream timed out ...
(access log 급증 탐지는 Phase 2에서 별도 집계 파서로 처리)
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_LINE = re.compile(r"^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] (.*)$")
_SEV = {"emerg": "critical", "alert": "critical", "crit": "critical",
        "error": "error", "warn": "warn", "notice": "info", "info": "info"}


@register("nginx", "web")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _LINE.match(line)
        if not m:
            continue
        events.append(Event(
            ts=fast_strptime(m.group(1), "%Y/%m/%d %H:%M:%S"),
            host=host, layer="web", product="nginx",
            severity=_SEV.get(m.group(2), "info"),
            message=m.group(3),
            raw_ref=f"{path}:{i}-{i}",
        ))
    return events
