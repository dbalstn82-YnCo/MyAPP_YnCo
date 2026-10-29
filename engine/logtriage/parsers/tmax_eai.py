"""Tmax BizMaster(EAI) 파서 — 실로그(2026-04 송수신서버) 기준으로 작성.

  bizmaster-adapter : 어댑터(eaiAdapter) 로그 adt_YYYYMMDD.log / start로그 — 균일 로그 형식
      [#|2026-04-30 00:00:26|WARNING||||||16|com.tmax.esb.adapter.endpoint.ClientService|메시지|#]
      여러 줄 메시지는 '|#]' 로 닫힐 때까지 병합.
  bizmaster-app     : 업무 앱(GISS) 로그 eai.log / eai.log.YYYY-MM-DD — 시각만 있고 날짜는 파일명(없으면 파일 수정일)
      [06:48:06][ERROR](A130A.java:289) - 메시지      (스택트레이스는 직전 이벤트에 병합)
      err.out.YYMMDD_HHMMSS — stderr 덤프: 시각 없음 → 파일명 시각 사용, '-407 ...' 같은 코드 줄만 이벤트화
  코드: 메시지 앞의 [-402] / -407 형태 → BM-402 / BM-407 (errorcodes/claude_sw_bizmaster.yaml 과 연결)
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

_ADT = re.compile(r"^\[#\|(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\|([A-Z]+)\|(?:[^|]*\|){5}([^|]*)\|([^|]*)\|(.*)$")
_ADT_END = "|#]"
_APP = re.compile(r"^\[(\d{2}:\d{2}:\d{2})\]\[([A-Z ]+)\]\(([^)]*)\)\s*-\s?(.*)$")
_FNAME_DATE = re.compile(r"(\d{4})-(\d{2})-(\d{2})|(\d{4})(\d{2})(\d{2})")
_ERROUT_TS = re.compile(r"err\.out\.(\d{2})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})")
_BMCODE = re.compile(r"(?:^|\[)(-\d{3})\]?")
_SEV = {"SEVERE": "critical", "FATAL": "critical", "ERROR": "error", "WARNING": "warn", "WARN": "warn",
        "INFO": "info", "CONFIG": "info", "FINE": "info", "DEBUG": "info", "TRACE": "info"}
_MEM = re.compile(r"free/total = (\d+)/(\d+)")


def _file_date(path: Path):
    m = _FNAME_DATE.search(path.name)
    if m:
        if m.group(1):
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return datetime(int(m.group(4)), int(m.group(5)), int(m.group(6)))
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).replace(hour=0, minute=0, second=0, microsecond=0)
    except OSError:
        return datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)


@register("bizmaster-adapter", "sw")
def parse_adapter(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur, cur_end = None, 0

    def flush():
        if cur:
            cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
            events.append(cur)

    for i, line in iter_lines(path):
        m = _ADT.match(line)
        if m:
            flush()
            ts = fast_strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
            lvl, logger, msg = m.group(2), m.group(4), m.group(5)
            if msg.endswith(_ADT_END):
                msg = msg[: -len(_ADT_END)]
            sev = _SEV.get(lvl, "info")
            code = None
            mm = _MEM.search(msg)
            if mm:  # 메모리 사용량 보고: 여유가 total 의 3% 미만이면 경고 코드 부여
                free, total = int(mm.group(1)), int(mm.group(2))
                if total and free < total * 0.03:
                    sev, code = "warn", "BM-MEM-LOW"
                    msg += " [BM-MEM-LOW]"
            short_logger = logger.rsplit(".", 1)[-1]
            cur = Event(ts=ts, host=host, layer="sw", product="bizmaster-adapter", severity=sev,
                        message=f"[{short_logger}] {msg}", code=code, raw_ref=str(i))
            cur_end = i
        elif cur:
            cur.message += "\n" + (line[: -len(_ADT_END)] if line.endswith(_ADT_END) else line)
            cur_end = i
            if cur.severity == "info" and re.search(r"Exception|Error\b", line):
                cur.severity = "error"
    flush()
    return events


@register("bizmaster-app", "sw")
def parse_app(path: Path, host: str) -> list[Event]:
    events = EventSink()
    name = path.name.lower()
    if name.startswith("err.out"):
        return _parse_errout(path, host, events)
    base = _file_date(path)
    cur, cur_end, last_ts = None, 0, None

    def flush():
        if cur:
            cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
            events.append(cur)

    for i, line in iter_lines(path):
        m = _APP.match(line)
        if m:
            flush()
            hh, mi, ss = (int(x) for x in m.group(1).split(":"))
            ts = base.replace(hour=hh, minute=mi, second=ss)
            if last_ts and ts < last_ts and (last_ts - ts).total_seconds() > 12 * 3600:
                base = base + timedelta(days=1)  # 자정 넘김: 다음 날로
                ts = base.replace(hour=hh, minute=mi, second=ss)
            last_ts = ts
            lvl = m.group(2).strip()
            msg = m.group(4)
            cm = _BMCODE.search(msg)
            code = f"BM{cm.group(1)}" if cm else None
            cur = Event(ts=ts, host=host, layer="sw", product="bizmaster-app", severity=_SEV.get(lvl, "info"),
                        message=f"({m.group(3)}) {msg}" if msg else f"({m.group(3)})", code=code, raw_ref=str(i))
            cur_end = i
        elif cur:
            cur.message += "\n" + line
            cur_end = i
            if cur.code is None:
                cm = _BMCODE.search(line)
                if cm and re.search(r"BizException|\[-\d{3}\]", line):
                    cur.code = f"BM{cm.group(1)}"
            if cur.severity == "info" and re.search(r"Exception|Error\b", line):
                cur.severity = "error"
    flush()
    return events


def _parse_errout(path: Path, host: str, events: EventSink) -> list[Event]:
    m = _ERROUT_TS.search(path.name)
    if m:
        y, mo, d, hh, mi, ss = (int(x) for x in m.groups())
        ts = datetime(2000 + y, mo, d, hh, mi, ss)
    else:
        ts = _file_date(path)
    cur, cur_end = None, 0

    def flush():
        if cur:
            cur.raw_ref = f"{path}:{cur.raw_ref}-{cur_end}"
            events.append(cur)

    for i, line in iter_lines(path):
        if not line.strip():
            continue
        if line.startswith(("\tat ", "    at ", "\t... ", "Caused by")) and cur:
            cur.message += "\n" + line
            cur_end = i
            continue
        flush()
        cm = _BMCODE.search(line)
        sev = "error" if (cm or re.search(r"Exception|Error\b", line)) else "info"
        cur = Event(ts=ts, host=host, layer="sw", product="bizmaster-app", severity=sev,
                    message=line, code=f"BM{cm.group(1)}" if cm else None, raw_ref=str(i),
                    tags=["approx_ts"])  # 개별 발생 시각 없음 — 파일명 시각
        cur_end = i
    flush()
    return events
