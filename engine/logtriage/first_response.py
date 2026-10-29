# -*- coding: utf-8 -*-
"""무인 1차 대응 — 자동 분석이 끝난 뒤의 후속 조치 (2026-09-23)

여태 자동 분석(log_watch)은 로그를 읽어 판정하고 알림함에 한 줄 남기는 데서 끝났다.
치명 판정이 나와도 보고서 초안도, 공유 글도, 담당자 통지도 사람이 손으로 해야 했다.
'1차 대응 분석기' 라면서 정작 대응이 사람 손에 걸려 있었다.

여기서 그 뒤를 잇는다 — 감지 → 분석 → 판정 → **보고서 초안 · 게시판 공유 · 통지**.

지키는 것
  · 후속 조치가 실패해도 **분석 결과는 잃지 않는다.** 조치는 하나씩 따로 감싸고,
    실패는 결과에 적어 돌려준다. 작업 전체를 실패로 만들지 않는다.
  · 사람을 사칭하지 않는다. 자동으로 쓴 글의 글쓴이는 `auto@logtriage / 무인 1차 대응(자동)`.
  · 기본값은 **아무것도 하지 않음**. 작업마다 켜야 돈다.
  · 같은 분석에 두 번 손대지 않는다 — 조치는 분석이 새로 저장된 그 자리에서 한 번만.
"""
from __future__ import annotations

from pathlib import Path

# 어느 판정부터 움직일지
WHEN = ("critical", "error", "always")
# 무엇을 할지
ACTIONS = ("report", "board", "notify")
ACTION_KO = {"report": "보고서 초안", "board": "게시판 공유", "notify": "담당자 통지"}

# 자동으로 남기는 글의 글쓴이 — 사람 계정이 아니라는 것이 이름에서 바로 보이게 한다
SYSTEM_USER = {"login": "auto@logtriage", "name": "무인 1차 대응(자동)"}

OFF = {"when": "critical", "report": False, "board": False, "notify": False}


def normalize(value) -> dict:
    """작업에 저장된 설정을 검사해 정규화한다. 모르는 값은 받지 않는다."""
    if value in (None, "", {}):
        return dict(OFF)
    if not isinstance(value, dict):
        raise ValueError("후속 조치 설정은 객체여야 합니다")
    when = str(value.get("when") or "critical")
    if when not in WHEN:
        raise ValueError(f"후속 조치 기준: {', '.join(WHEN)} 중 하나여야 합니다")
    out = {"when": when}
    for a in ACTIONS:
        v = value.get(a, False)
        if not isinstance(v, bool):
            raise ValueError(f"후속 조치 '{ACTION_KO[a]}' 는 참·거짓이어야 합니다")
        out[a] = v
    return out


def enabled(cfg: dict) -> bool:
    return any(cfg.get(a) for a in ACTIONS)


def level_of(result: dict) -> str:
    """판정 결과의 무게 — 'critical' / 'error' / 'none'."""
    t = (result or {}).get("sev_totals") or {}
    if t.get("critical"):
        return "critical"
    if t.get("error"):
        return "error"
    return "none"


def should_run(cfg: dict, result: dict) -> bool:
    if not enabled(cfg):
        return False
    when, lv = cfg.get("when", "critical"), level_of(result)
    if when == "always":
        return True
    if when == "error":
        return lv in ("critical", "error")
    return lv == "critical"


def _summary(result: dict) -> tuple:
    """(계층, 원인 추정, 치명, 오류) — 제목·본문에 함께 쓴다."""
    first = (result or {}).get("first") or {}
    t = (result or {}).get("sev_totals") or {}
    return (first.get("layer_ko") or "판정 없음",
            (first.get("verdict") or "특이 사항 없음").strip(),
            int(t.get("critical") or 0), int(t.get("error") or 0))


def _tier1_steps(result: dict) -> list:
    """1차 선 대응 절차만 꺼낸다.

    `plan` 은 목록이 아니라 {analysis, tier1, tier2, tier3} 사전이고, 1차 조치는
    tier1['steps'] 에 있다(실제로 돌려 보고서야 알았다). 모양이 또 바뀌어도
    글 한 줄 때문에 조치 전체가 실패하지 않도록 방어적으로 읽는다.
    """
    try:
        tier1 = ((result or {}).get("plan") or {}).get("tier1") or {}
        out = []
        for s in (tier1.get("steps") or []):
            text = s.get("text") or s.get("title") or s.get("do") if isinstance(s, dict) else s
            text = str(text or "").strip()
            if text:
                out.append(text)
        return out
    except Exception:
        return []


def _title(result: dict, source: str) -> str:
    layer, verdict, crit, err = _summary(result)
    head = "[자동] " + (f"치명 {crit}건 · " if crit else (f"오류 {err}건 · " if err else ""))
    return (head + f"{layer} — {verdict}"[:100] + f" ({source})")[:120]


def _body(result: dict, incident_id: str, source: str) -> str:
    layer, verdict, crit, err = _summary(result)
    lines = [
        "무인 1차 대응이 자동으로 올린 글입니다. 사람이 확인해 주십시오.",
        "",
        f"· 대상 로그   : {source}",
        f"· 분석 시각   : {result.get('analyzed_at') or '-'}",
        f"· 판정 계층   : {layer}",
        f"· 원인 추정   : {verdict}",
        f"· 치명 / 오류 : {crit} / {err}",
        f"· 분석 이력   : {incident_id}",
    ]
    steps = _tier1_steps(result)
    if steps:
        lines += ["", "1차 선 대응(분석기가 고른 절차):"]
        lines += [f"  - {s[:200]}" for s in steps[:5]]
    lines += ["", "아래 [분석 이력] 을 누르면 이 분석의 요약·이벤트·로그를 바로 볼 수 있습니다."]
    return "\n".join(lines)[:20000]


def run(worker, job: dict, incident_id: str, result: dict, source: str = "") -> dict:
    """설정된 후속 조치를 실행한다. 하나가 실패해도 나머지는 계속한다.

    `source` 는 사람이 아는 원본 로그 파일 이름이다. 분석은 임시로 복사한 파일을 읽으므로
    결과 안의 파일명은 `3f9c…log` 같은 임시 이름이다 — 그대로 쓰면 글과 알림이 읽히지 않는다.
    """
    cfg = normalize((job.get("params") or {}).get("followup"))
    if not should_run(cfg, result):
        return {}
    if not source:
        first_file = (result.get("files") or [""])[0]
        source = Path(str(first_file.get("name") if isinstance(first_file, dict) else first_file)).name
    source = source or incident_id
    done, failed = [], []

    if cfg.get("report"):
        try:
            r = worker.api.generate_report(incident_id)
            if isinstance(r, dict) and r.get("error"):
                raise RuntimeError(r["error"])
            done.append("report")
        except Exception as exc:                      # 보고서가 안 나와도 분석은 남는다
            failed.append(f"보고서 초안: {exc}")

    if cfg.get("board"):
        try:
            worker.api.board.create(SYSTEM_USER, "share", _title(result, source),
                                    _body(result, incident_id, source), incidents=[incident_id])
            done.append("board")
        except Exception as exc:
            failed.append(f"게시판 공유: {exc}")

    if cfg.get("notify"):
        try:
            layer, verdict, crit, err = _summary(result)
            lv = level_of(result)
            worker.notice("alarm" if lv == "critical" else "analysis",
                          f"무인 1차 대응 — {source}: {layer} / {verdict} (치명 {crit} · 오류 {err}) [{incident_id}]")
            done.append("notify")
        except Exception as exc:
            failed.append(f"담당자 통지: {exc}")

    out = {"level": level_of(result), "done": done}
    if failed:
        out["failed"] = failed
        try:                                           # 조치가 빠진 것을 사람이 알아야 한다
            worker.notice("failed", "무인 1차 대응 후속 조치 실패 — " + "; ".join(failed)[:300])
        except Exception:
            pass
    return out
