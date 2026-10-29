"""공통 이벤트 스키마 — 모든 파서는 로그를 Event로 정규화한다 (설계서 04장)."""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime

# 12차(리눅스 동일 판 점검): dataclass(slots=True) 는 3.10+ — RHEL 9 install.sh 는 시스템 python3(3.9)로 깔아
# 'unexpected keyword argument slots' 로 서버가 import 에서 죽었다(tools/build/py39_compat.py 가 찾음). 3.10+ 에서만 slots
_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}

LAYERS = ("os", "web", "was", "db", "sw")
SEVERITIES = ("critical", "error", "warn", "info")


@dataclass(**_SLOTS)
class Event:
    ts: datetime
    host: str
    layer: str          # os | web | was | db | sw
    product: str        # tomcat, nginx, oracle, linux ...
    severity: str       # critical | error | warn | info
    message: str
    code: str | None = None          # ORA-00060, HTTP 504 등
    raw_ref: str = ""                # "파일경로:시작라인-끝라인"
    tags: list[str] = field(default_factory=list)

    def in_window(self, start: datetime, end: datetime) -> bool:
        return start <= self.ts <= end
