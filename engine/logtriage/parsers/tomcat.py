"""Tomcat 파서 — catalina.out / 애플리케이션 로그.

지원 포맷:
  02-Sep-2026 14:02:48.123 SEVERE [http-nio-8080-exec-1] ... 메시지
  2026-09-02 14:02:48,123 ERROR [main] ... 메시지
타임스탬프 없는 줄(스택트레이스)은 직전 이벤트에 병합한다.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_PATTERNS = [
    (re.compile(r"^(\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2})(?:\.(\d{3}))?\s+(\S+)\s+(.*)$"),
     "%d-%b-%Y %H:%M:%S"),
    (re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:[.,](\d{3}))?\s+(\S+)\s+(.*)$"),
     "%Y-%m-%d %H:%M:%S"),
]

_SEV = {
    "SEVERE": "critical", "FATAL": "critical",
    "ERROR": "error",
    "WARNING": "warn", "WARN": "warn",
    "INFO": "info", "FINE": "info", "DEBUG": "info", "CONFIG": "info",
}


@register("tomcat", "was")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur: Event | None = None
    cur_end = 0
    # 12차 성능: 두 형식은 한 줄에서 동시에 맞을 수 없다(첫 글자 모양이 다름) — 직전에 맞은 형식을 먼저 시도해도 결과가 같다
    order = list(_PATTERNS)
    for i, line in iter_lines(path):
        parsed = None
        for k, (pat, fmt) in enumerate(order):
            m = pat.match(line)
            if m:
                ts = fast_strptime(m.group(1), fmt)
                if m.group(2):
                    ts = ts.replace(microsecond=int(m.group(2)) * 1000)
                parsed = (ts, m.group(3).upper(), m.group(4))
                if k:
                    order.insert(0, order.pop(k))
                break
        if parsed:
            if cur:
                cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
                events.append(cur)
            ts, level, msg = parsed
            cur = Event(ts=ts, host=host, layer="was", product="tomcat",
                        severity=_SEV.get(level, "info"), message=msg, raw_ref=str(i))
            cur_end = i
        elif cur:
            cur.message += "\n" + line  # 스택트레이스 병합
            cur_end = i
    if cur:
        cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
        events.append(cur)
    return events
