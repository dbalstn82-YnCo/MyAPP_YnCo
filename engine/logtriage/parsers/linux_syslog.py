"""UNIX 계열 syslog 파서 — Linux · Solaris · AIX · HP-UX 공용.

포맷(공통): Sep  2 14:01:55 host tag: message
  - Linux  : /var/log/messages, /var/log/syslog
  - Solaris: /var/adm/messages  ([ID nnnnn kern.warning] 형태 심각도 포함)
  - AIX    : errpt -a 텍스트 / syslog
  - HP-UX  : /var/adm/syslog/syslog.log
연도가 없으므로 장애 인지 시각(또는 현재)의 연도를 따른다.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_LINE = re.compile(r"^([A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): (.*)$")
_CRIT = re.compile(
    r"out of memory|oom-killer|kernel panic|panic\[|i/o error|read-only file ?system"
    r"|file system full|out of swap|no swap space|THRESHOLD REACHED|LVM.*failure",
    re.I)
_ERR = re.compile(r"\berror\b|\bfailed\b|\bfailure\b|kern\.err|daemon\.err", re.I)
_WARN = re.compile(r"warning|kern\.warning", re.I)

DEFAULT_YEAR = datetime.now().year  # CLI/GUI가 장애 시각 기준으로 덮어씀


def _parse(path: Path, host: str, product: str) -> list[Event]:
    events = EventSink()
    for i, line in iter_lines(path):
        m = _LINE.match(line)
        if not m:
            continue
        ts = fast_strptime(f"{DEFAULT_YEAR} {m.group(1).replace('  ', ' ')}",
                               "%Y %b %d %H:%M:%S")
        msg = f"{m.group(3)}: {m.group(4)}"
        if _CRIT.search(msg):
            sev = "critical"
        elif _ERR.search(msg):
            sev = "error"
        elif _WARN.search(msg):
            sev = "warn"
        else:
            sev = "info"
        events.append(Event(
            ts=ts, host=m.group(2), layer="os", product=product,
            severity=sev, message=msg, raw_ref=f"{path}:{i}-{i}",
        ))
    return events


def _register_os(product: str, canonical: str):
    @register(product, "os")
    def parse(path: Path, host: str, _p=canonical) -> list[Event]:
        return _parse(path, host, _p)
    return parse


# RHEL·Rocky·CentOS·Ubuntu 는 동일 syslog 포맷 — 선택지는 제공하되 룰 매칭은 linux 로 정규화
for _os in ("linux", "rhel", "rocky", "centos", "ubuntu"):
    _register_os(_os, "linux")
for _os in ("solaris", "aix", "hpux"):
    _register_os(_os, _os)
