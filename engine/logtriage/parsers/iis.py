"""IIS W3C 액세스 로그 파서 — 5xx 응답을 오류 이벤트로 수집.

#Fields: 헤더로 컬럼을 파악한다. sc-status ≥ 500 인 요청만 이벤트화.
sc-substatus 가 0 이 아니면 코드·문구에 남긴다(500.19 등 — 사전의 하위 상태 원인으로 이어지게).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime


@register("iis", "web")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    fields: list[str] = []
    for i, line in iter_lines(path):
        if line.startswith("#Fields:"):
            fields = line.split()[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        parts = line.split()
        if len(parts) != len(fields):
            continue
        row = dict(zip(fields, parts))
        status = row.get("sc-status", "")
        if not status.startswith("5"):
            continue
        try:
            ts = fast_strptime(f"{row.get('date','')} {row.get('time','')}",
                                   "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        # 하위 상태(sc-substatus)를 버리면 사전의 500.19(구성 오류)·502.5(ANCM 시작 실패) 같은 원인이 닿지 못한다(룰 학습 3차)
        sub = row.get("sc-substatus", "")
        st = f"{status}.{sub}" if sub.isdigit() and sub != "0" else status
        events.append(Event(
            ts=ts, host=host, layer="web", product="iis",
            severity="critical" if status == "503" else "error",
            code=st if st != status else f"HTTP-{status}",
            message=f"HTTP {st} {row.get('cs-method','')} {row.get('cs-uri-stem','')}"
                    f" (time-taken {row.get('time-taken','?')}ms)",
            raw_ref=f"{path}:{i}-{i}",
        ))
    return events
