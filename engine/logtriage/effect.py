# -*- coding: utf-8 -*-
"""업무 절감 효과 — 측정값과 가정값을 갈라서 센다 (2026-09-23)

'몇 시간 줄었다' 는 말은 쉽고, 그래서 아무도 안 믿는다. 여기서는 두 가지를 **섞지 않는다.**

  · 측정값 — 제품이 실제로 한 일. 자동 분석 건수, 자동으로 만든 보고서 수,
             자동 공유·통지 수, 그리고 그 일에 기계가 실제로 쓴 시간(실행 기록의 시작·끝).
             사람이 손댈 수 없고, 화면에 나오는 값이 곧 실행 기록이다.
  · 가정값 — '사람이 했으면 얼마나 걸렸을까'. 이건 측정이 아니라 **담당자가 정하는 값**이다.
             기본값은 비워 두지 않되(0 이면 효과가 0), 화면에서 고칠 수 있고,
             어디까지가 가정인지 결과에 함께 적는다.

절감 = Σ(건수 × 가정 시간) − 기계가 실제로 쓴 시간
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

KEY = "effect_assumptions"

# 기본 가정값(분) — 1차 대응 담당자가 손으로 할 때를 보수적으로 잡았다. 화면에서 고칠 수 있다.
DEFAULTS = {
    "collect_min": 20,    # 로그를 받아 훑고 어느 계층 문제인지 가리기까지
    "report_min": 30,     # 장애 보고서 초안(상황관리·사후관리)을 채우기까지
    "share_min": 5,       # 담당자에게 알리고 이력을 공유하기까지
}
LABELS = {
    "collect_min": "로그 1건 수집·판독",
    "report_min": "보고서 초안 1건 작성",
    "share_min": "공유·통지 1건",
}
RANGE = (0, 480)          # 한 건에 8시간을 넘게 잡는 것은 가정이 아니라 주장이다


def assumptions(auto) -> dict:
    """저장된 가정값(없으면 기본값)."""
    try:
        saved = auto.get_value(KEY, None) or {}
    except Exception:
        saved = {}
    out = dict(DEFAULTS)
    for k in DEFAULTS:
        v = saved.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            continue
        if RANGE[0] <= v <= RANGE[1]:
            out[k] = int(v)
    return out


def set_assumptions(auto, values: dict) -> dict:
    if not isinstance(values, dict):
        raise ValueError("가정값은 객체여야 합니다")
    cur = assumptions(auto)
    for k, v in values.items():
        if k not in DEFAULTS:
            raise ValueError(f"모르는 항목입니다: {k}")
        if isinstance(v, str) and v.strip().isdigit():
            v = int(v.strip())
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError(f"{LABELS[k]}: {RANGE[0]}~{RANGE[1]} 사이 정수(분)로 적으십시오")
        if not RANGE[0] <= v <= RANGE[1]:
            raise ValueError(f"{LABELS[k]}: {RANGE[0]}~{RANGE[1]} 분 사이로 적으십시오")
        cur[k] = v
    auto.set_value(KEY, cur)
    return cur


def measure(auto, days: int = 30) -> dict:
    """실행 기록에서 '실제로 한 일' 만 센다."""
    days = max(1, min(int(days or 30), 365))
    since = (datetime.now() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0).timestamp()
    analyzed = reports = shares = 0
    machine_sec = 0.0
    per_day: dict[str, int] = {}
    with auto.db() as db:
        rows = [dict(r) for r in db.execute(
            "SELECT started,ended,output FROM runs WHERE started>=? ORDER BY started", (since,))]
    for r in rows:
        try:
            o = json.loads(r["output"] or "{}")
        except ValueError:
            continue
        n = len(o.get("analyzed") or [])
        if not n:
            continue
        analyzed += n
        day = time.strftime("%Y-%m-%d", time.localtime(r["started"] or 0))
        per_day[day] = per_day.get(day, 0) + n
        if r.get("ended"):
            machine_sec += max(0.0, float(r["ended"]) - float(r["started"] or 0))
        for f in (o.get("first_response") or []):
            did = f.get("did") or []
            if "report" in did:
                reports += 1
            shares += sum(1 for d in did if d in ("board", "notify"))
    return {"days": days, "from": time.strftime("%Y-%m-%d", time.localtime(since)),
            "analyzed": analyzed, "reports": reports, "shares": shares,
            "machine_min": round(machine_sec / 60, 1), "machine_sec": round(machine_sec, 1),
            "per_day": per_day}


def report(auto, days: int = 30) -> dict:
    """측정값 + 가정값 + 그 둘로 계산한 절감. 계산식을 그대로 돌려준다."""
    m = measure(auto, days)
    a = assumptions(auto)
    parts = [
        {"key": "collect_min", "label": LABELS["collect_min"], "count": m["analyzed"],
         "minutes": a["collect_min"], "total": m["analyzed"] * a["collect_min"]},
        {"key": "report_min", "label": LABELS["report_min"], "count": m["reports"],
         "minutes": a["report_min"], "total": m["reports"] * a["report_min"]},
        {"key": "share_min", "label": LABELS["share_min"], "count": m["shares"],
         "minutes": a["share_min"], "total": m["shares"] * a["share_min"]},
    ]
    manual = sum(p["total"] for p in parts)
    saved = max(0.0, manual - m["machine_min"])
    return {"measured": m, "assumptions": a, "parts": parts,
            "manual_min": manual, "machine_min": m["machine_min"], "machine_sec": m["machine_sec"],
            "saved_min": round(saved, 1), "saved_hour": round(saved / 60, 1),
            "formula": "절감 = (사람이 했을 때 = Σ 건수 × 가정 분) − (기계가 실제로 쓴 시간)",
            "note": "건수와 기계 시간은 실행 기록에서 센 값입니다. 분 단위 가정값은 담당자가 정한 값이며 측정이 아닙니다."}
