"""Windows 이벤트 로그 파서 — CSV 내보내기 형식.

대상 서버에서 다음 명령으로 뽑은 파일을 투입한다:
  Get-WinEvent -LogName System -MaxEvents 5000 |
    Select-Object TimeCreated,LevelDisplayName,ProviderName,Id,Message |
    Export-Csv events.csv -Encoding UTF8
(한글판 Level: 오류/경고/정보 도 인식)
"""
from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, register, fast_strptime

_SEV = {
    "critical": "critical", "위험": "critical",
    "error": "error", "오류": "error",
    "warning": "warn", "경고": "warn",
    "information": "info", "정보": "info", "verbose": "info",
}
# Security 로그에서 오류로 봐야 하는 이벤트 ID (Level 은 '정보'로 기록됨)
_SEC_FAIL_IDS = {"4625", "4740", "4771", "1102", "4719", "4794", "6273", "6274", "12294"}
_TS_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
               "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d %I:%M:%S %p")


def _ts(value: str) -> datetime | None:
    v = value.strip().split(".")[0]
    for fmt in _TS_FORMATS:
        try:
            return fast_strptime(v, fmt)
        except ValueError:
            continue
    return None


@register("windows", "os")
def parse(path: Path, host: str) -> list[Event]:
    events = EventSink()
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        cols = {c.lower(): c for c in (reader.fieldnames or [])}
        c_ts = cols.get("timecreated")
        c_lv = cols.get("leveldisplayname") or cols.get("level")
        c_pr = cols.get("providername") or cols.get("source")
        c_id = cols.get("id") or cols.get("eventid")
        c_msg = cols.get("message")
        c_kw = cols.get("keywordsdisplaynames") or cols.get("keywords") or cols.get("taskdisplayname")
        if not (c_ts and c_msg):
            raise ValueError("Windows CSV 형식 오류 — TimeCreated/Message 컬럼 필요 "
                             "(사용법: Get-WinEvent … | Export-Csv)")
        for i, row in enumerate(reader, 2):
            ts = _ts(row.get(c_ts, "") or "")
            if ts is None:
                continue
            level = (row.get(c_lv, "") or "").strip().lower()
            sev = _SEV.get(level, "info")
            eid = (row.get(c_id, "") or "").strip()
            kw = (row.get(c_kw, "") or "") if c_kw else ""
            # Security 로그: 감사 실패(Audit Failure) 또는 보안 실패 이벤트 ID 는 오류로 승격
            if "audit failure" in kw.lower() or "감사 실패" in kw or eid in _SEC_FAIL_IDS:
                sev = "error" if sev in ("info", "warn") else sev
            # 이벤트 ID 를 문구 맨 앞에도 남긴다(룰 학습 4차) — 본문은 서버 언어(한글판이면 한글)를 따르므로
            # '[ID] 제공자:' 로 걸어야 언어와 상관없이, 같은 번호를 쓰는 다른 제공자와 헷갈리지 않게 판정한다.
            # 맨 앞에 두는 까닭: 학습 룰은 '제공자: 본문' 을 이어 붙인 정규식이라, 가운데에 끼우면 현장에서 학습한 룰이 깨진다
            prov = (row.get(c_pr, "") or "").strip()
            events.append(Event(
                ts=ts, host=host, layer="os", product="windows",
                severity=sev,
                code=eid or None,
                message=(f"[{eid}] " if eid else "") + f"{prov}: "
                        + f"{(row.get(c_msg, '') or '').strip()}"[:2000],
                raw_ref=f"{path}:{i}-{i}",
            ))
    return events
