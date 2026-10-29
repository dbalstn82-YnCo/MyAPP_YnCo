"""Linux auditd 감사 로그 파서 (/var/log/audit/audit.log).

포맷: type=USER_AUTH msg=audit(1774824886.717:689067): pid=... res=success
- 타임스탬프: epoch 초 → 로컬 시각
- code: 감사 이벤트 타입(USER_AUTH, ANOM_ABEND, AVC ...) — 코드 사전 조회 가능
- 심각도: res=failed / 이상 징후(ANOM_*) / SELinux 차단(AVC) 중심으로 판정
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register

_LINE = re.compile(r"^type=(\S+) +msg=audit\((\d+)\.\d+:\d+\):\s*(.*)$")
_FIELD = re.compile(r"\b(acct|exe|addr|hostname|op|comm|unit)=(\"[^\"]*\"|'[^']*'|\S+)")

_CRIT_TYPES = {"ANOM_ABEND", "ANOM_OVERSIZED", "ANOM_PROMISCUOUS", "KERNEL_PANIC"}
_WARN_TYPES = {"AVC", "SECCOMP", "USER_AVC", "SERVICE_STOP", "SYSTEM_SHUTDOWN",
               "ANOM_LOGIN_FAILURES", "ANOM_LOGIN_SESSIONS", "RESP_ACCT_LOCK"}


def _severity(atype: str, body: str) -> str:
    if atype in _CRIT_TYPES:
        return "critical"
    if "res=failed" in body or "res=fail" in body:
        # 인증·계정 관련 실패는 error, 그 외 실패도 error
        return "error"
    if atype in _WARN_TYPES or atype.startswith("ANOM_"):
        return "warn"
    return "info"


def _summary(atype: str, body: str) -> str:
    parts = [f"{k}={v}" for k, v in _FIELD.findall(body)]
    res = "실패" if ("res=failed" in body or "res=fail" in body) else ""
    return f"{atype} {res} {' '.join(parts[:5])}".strip() or f"{atype} {body[:120]}"


@register("auditd", "os")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _LINE.match(line)
        if not m:
            continue
        atype, epoch, body = m.group(1), int(m.group(2)), m.group(3)
        events.append(Event(
            ts=datetime.fromtimestamp(epoch), host=host, layer="os",
            product="auditd", severity=_severity(atype, body),
            code=atype, message=_summary(atype, body),
            raw_ref=f"{path}:{i}-{i}",
        ))
    return events
