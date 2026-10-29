"""Oracle alert log 파서 (클래식 텍스트 포맷).

타임스탬프 헤더 라인 뒤에 메시지 라인들이 이어진다:
    Tue Sep 02 14:02:11 2026
    ORA-00060: deadlock detected while waiting for resource
19c 이후 ISO 형식(2026-09-02T14:02:11.123456+09:00)도 지원한다.
ORA-/TNS- 코드는 code 필드로 추출한다.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_TS_CLASSIC = re.compile(r"^[A-Za-z]{3} ([A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \d{4})$")
_TS_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_CODE = re.compile(r"\b(ORA|TNS)-(\d{5})\b")


def _severity(msg: str) -> str:
    if _CODE.search(msg):
        return "error"
    low = msg.lower()
    if "warning" in low:
        return "warn"
    return "info"


@register("oracle", "db")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur_ts: datetime | None = None
    for i, line in iter_lines(path):
        s = line.strip()
        if not s:
            continue
        m = _TS_CLASSIC.match(s)
        if m:
            cur_ts = fast_strptime(m.group(1).replace("  ", " "), "%b %d %H:%M:%S %Y")
            continue
        m = _TS_ISO.match(s)
        if m:
            cur_ts = fast_strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
            continue
        if cur_ts is None:
            continue  # 헤더 이전 라인은 시각 불명 — 버림
        code = None
        cm = _CODE.search(s)
        if cm:
            code = f"{cm.group(1)}-{cm.group(2)}"
        sev = "critical" if code in ("ORA-00060", "ORA-00600", "ORA-07445") else _severity(s)
        events.append(Event(
            ts=cur_ts, host=host, layer="db", product="oracle",
            severity=sev, message=s, code=code, raw_ref=f"{path}:{i}-{i}",
        ))
    return events
