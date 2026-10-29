"""공용 웹 액세스 로그 파서 — CLF/Combined 형식 (Apache·Nginx·WebtoB 공통).

  10.0.0.1 - - [02/Feb/2026:14:03:10 +0900] "GET /api HTTP/1.1" 502 512 "-" "UA"
5xx 응답만 이벤트화한다(정상 요청은 히스토그램 잡음). 4xx 중 429 는 warn 으로 수집.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_CLF = re.compile(r'^(\S+) \S+ \S+ \[(\d{2})/(\w{3})/(\d{4}):(\d{2}:\d{2}:\d{2})[^\]]*\] '
                  r'"([^"]*)" (\d{3})')


@register("accesslog", "web")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _CLF.match(line)
        if not m:
            continue
        status = m.group(7)
        if not (status.startswith("5") or status == "429"):
            continue
        try:
            ts = fast_strptime(f"{m.group(2)} {m.group(3)} {m.group(4)} {m.group(5)}",
                                   "%d %b %Y %H:%M:%S")
        except ValueError:
            continue
        sev = "critical" if status in ("502", "503") else ("warn" if status == "429" else "error")
        events.append(Event(ts=ts, host=host, layer="web", product="accesslog",
                            severity=sev, code=f"HTTP-{status}",
                            message=f"HTTP {status} {m.group(6)} (client {m.group(1)})",
                            raw_ref=f"{path}:{i}-{i}"))
    return events
