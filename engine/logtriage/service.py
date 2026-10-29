"""구조화된 분석 서비스 — GUI·CLI가 사용하는 판정 API.

분석 순서 (벤더 지식 우선 원칙):
  1) 시그니처 룰(정규식) 매칭
  2) 룰에 안 걸린 이벤트는 벤더 에러코드 사전(errorcodes/)에서 코드 조회
  3) 두 결과를 통합해 장애 시간 자동 추정 + 유형·즉시/단기/중기/장기 조치 제시
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path

from .codes import load_codes, lookup
from .parsers import get_parser, linux_syslog
from .rules import MATCH_MAX, build_prefilter, candidates, load_rules, match_events

SEV_ORDER = {"critical": 0, "error": 1, "warn": 2, "info": 3}
LAYER_KO = {"os": "OS", "web": "WEB", "was": "WAS", "db": "DBMS", "sw": "상용SW"}
CATEGORY_KO = {
    "memory": "메모리 고갈", "lock": "잠금/데드락", "connection": "커넥션 고갈",
    "thread": "스레드 고갈", "disk": "디스크 공간 고갈", "storage": "저장공간 부족",
    "hardware": "하드웨어/커널 이상", "upstream": "백엔드 연계 장애",
    "capacity": "용량 한계 도달", "internal": "제품 내부 오류",
    "undo": "DB 언두/스냅샷 오류", "security": "보안/인증 이상",
    "performance": "성능 저하/지연", "app": "애플리케이션(소스) 결함", "etc": "기타",
}
OS_FAMILY = {"linux", "rhel", "centos", "rocky", "ubuntu", "windows", "aix", "hpux", "solaris"}
OS_KO = {"linux": "Linux", "windows": "Windows", "aix": "AIX", "hpux": "HP-UX", "solaris": "Solaris"}



def _evidence_id(f: dict, used: set | None = None) -> str:
    """근거 ID — 원문 위치·룰·시각으로 정해지는 짧은 이름(같은 분석을 다시 열어도 같다). 원문 위치(raw_ref)는 같은 줄에
    룰 여럿이 걸리면 겹치므로 따로 둔다(GPT UI 2차 보류 과제).
    GPT UI 19차: SHA-256 앞 12자리(48비트). ID 는 **한 분석 안에서만** 쓰이고(링크·찾기는 늘 분석 ID 와 함께) 한 분석의
    근거는 최대 3,000줄이라 겹칠 일이 사실상 없지만, 겹치면 같은 순서로 '|2', '|3' 을 붙여 다시 만든다 — 결과가 늘 같다."""
    import hashlib as _h
    key = f"{f.get('raw_ref', '')}|{f.get('id', '')}|{f['_ts'].isoformat() if f.get('_ts') else ''}"
    n, k = 1, key
    while True:
        eid = "E-" + _h.sha256(k.encode("utf-8")).hexdigest()[:12].upper()
        if used is None or eid not in used:
            if used is not None:
                used.add(eid)
            return eid
        n += 1
        k = f"{key}|{n}"

def _assign_eids(findings: list) -> list[str]:
    """근거 ID 를 입력 순서와 무관하게 정한다(GPT UI 19차 후속) — 시간 정렬은 같은 시각이면 입력 순서를 따르므로,
    겹침 처리('|2')가 그 순서에 기대면 파일 순서만 바꿔도 ID 가 바뀔 수 있다. 열쇠 순 → 같은 열쇠 안에서는 내용 순으로 매긴다."""
    def key(f):
        return f"{f.get('raw_ref', '')}|{f.get('id', '')}|{f['_ts'].isoformat() if f.get('_ts') else ''}"
    order = sorted(range(len(findings)), key=lambda i: (key(findings[i]), str(findings[i].get("message", "")),
                                                         str(findings[i].get("source", "")), str(findings[i].get("verdict", ""))))
    used: set[str] = set()
    out = [""] * len(findings)
    for i in order:
        out[i] = _evidence_id(findings[i], used)
    return out


def make_keep(rules_pre):
    """info·코드 없는 이벤트 보관 여부: 해당 (계층,제품) 룰 중 하나라도 걸릴 수 있으면 보관(12차: 병렬 작업자도 같은 함수)."""
    masters: dict = {}

    def _keep(ev) -> bool:
        key = (ev.layer, ev.product)
        pre = masters.get(key)
        if pre is None:
            cand = candidates(rules_pre, ev.layer, ev.product)
            pre = masters[key] = build_prefilter(cand) if cand else (lambda text, tl: False)
        msg = ev.message
        text = msg if len(msg) <= MATCH_MAX else msg[:MATCH_MAX]
        return pre(text, text.lower())
    return _keep


class NoKnowledgeError(RuntimeError):
    """판정 지식(룰)이 0개 — 이대로 분석하면 '알려진 장애 패턴 미검출'처럼 보이는 거짓 음성이 된다(10-19 마스터 보고 '어떤 로그도 분석이 안 됨')."""


def run_analysis(inputs: list[dict], incident_time: str | None = None,
                 before: int = 30, after: int = 10,
                 rules_dir: Path | None = None,
                 local_dir: Path | None = None,
                 codes_dir: Path | None = None,
                 events_export: Path | None = None,
                 manuals_dir: Path | None = None,
                 os_hint: str | None = None,
                 progress=None) -> dict:
    """inputs: [{path, product, host}] / incident_time: 'YYYY-MM-DD HH:MM' 또는 None(자동).
    progress: 진행 단계를 받는 함수(dict) — 화면은 엔진이 실제로 잰 값만 보여 준다(퍼센트를 지어내지 않는다)."""
    def _p(**kw):
        if progress:
            try:
                progress(kw)
            except Exception:
                pass
    t: datetime | None = None
    os_hint = (os_hint or "").lower() or None
    if os_hint and os_hint not in OS_KO:
        os_hint = None
    if os_hint:  # 대상 OS 수동 지정: OS 계열 로그의 제품을 지정 OS 로 통일(리눅스 배포판 별칭 → linux 등)
        for item in inputs:
            if str(item.get("product", "")).lower() in OS_FAMILY and item.get("product") != os_hint \
                    and not (os_hint == "windows") ^ (str(item.get("product")) == "windows") is False:
                pass
        for item in inputs:
            prod = str(item.get("product", "")).lower()
            if prod in OS_FAMILY and prod != "windows" and os_hint != "windows":
                item["product"] = os_hint
    if incident_time:
        t = datetime.strptime(incident_time, "%Y-%m-%d %H:%M")
    linux_syslog.DEFAULT_YEAR = (t or datetime.now()).year

    # ── 대용량 대응: 룰·코드에 걸릴 가능성이 없는 info 이벤트는 객체로 보관하지 않고 집계만 ──
    rules_pre = load_rules(rules_dir, local_dir) if rules_dir else []
    # 10차 ①: 기본 룰 0개로 '미검출' 리포트를 내지 않는다 — 오류로 멈춘다. 사이트 룰(rules-local)만으로는 거의 다 놓치므로 합계가 아니라 기본 룰로 센다(GPT 76차)
    if rules_dir is not None and not any(getattr(r, "source", "") != "local" for r in rules_pre):
        where = Path(rules_dir)
        raise NoKnowledgeError(
            f"판정 지식(룰)이 0개라 분석하지 않습니다 — {'룰 폴더가 없습니다' if not where.is_dir() else '룰 폴더가 비었거나 읽지 못했습니다'}: {where}\n"
            "LogTriage.exe 만 따로 옮기지 말고 배포 폴더(rules·errorcodes·manuals·report-template 포함)를 통째로 두고 실행하십시오. "
            "이 상태의 '미검출'은 믿을 수 없습니다.")
    from . import rules as _rules_mod
    kb_skipped = list(getattr(_rules_mod.SKIPPED, "files", []) or [])   # 읽지 못한 룰 파일(판정 범위 제한)
    _keep = make_keep(rules_pre)

    from .parsers import set_event_filter
    set_event_filter(_keep)
    all_events = []
    dropped_minutes: dict[datetime, int] = {}
    files = []
    _p(stage="check", files=len(inputs))
    # 12차 성능: 큰 입력은 작업자 프로세스 여러 개로(파일별·조각별) — 결과는 순차와 같다. 안 쓰거나 실패하면 None → 순차
    from .parallel import parse_all
    par = parse_all(inputs, rules_dir if rules_dir is not None else None, local_dir, linux_syslog.DEFAULT_YEAR, progress=lambda d: _p(**d))
    try:
        for i, item in enumerate(inputs):
            path = Path(item["path"])
            layer, parser = get_parser(item["product"])
            _p(stage="read", i=i, name=path.name, product=item["product"], done=sum(f["events"] for f in files))
            if par is not None:
                got = par[i]["events"]
                total = par[i]["total"]
                got_dropped = par[i]["dropped"]
            else:
                got = parser(path, item.get("host") or "unknown")
                total = getattr(got, "total", len(got))
                got_dropped = getattr(got, "dropped", {})
            files.append({"name": path.name, "product": item["product"], "layer": layer, "events": total,
                          "host": str(item.get("host") or "")[:120],   # 7차 아이디어 9: 판 지정·확인은 호스트별   # 계층은 엔진(파서 등록)이 정한다
                          "instance": str(item.get("instance") or "")[:60]})   # 8차 아이디어 8: 같은 호스트의 인스턴스(비우면 모름)
            _p(stage="read_done", i=i, name=path.name, events=total, done=sum(f["events"] for f in files))
            all_events.extend(got)
            for mk, c in got_dropped.items():
                dropped_minutes[mk] = dropped_minutes.get(mk, 0) + c
    finally:
        set_event_filter(None)
    events_total_all = len(all_events) + sum(dropped_minutes.values())

    if t is not None:
        start, end = t - timedelta(minutes=before), t + timedelta(minutes=after)
        events = [e for e in all_events if e.in_window(start, end)]
        dropped_minutes = {k: v for k, v in dropped_minutes.items() if start <= k <= end}
        window = f"{start:%Y-%m-%d %H:%M} ~ {end:%H:%M}"
    else:
        events = all_events
        window = "전체 로그 (장애 시각 자동 탐지 모드)"
    events_window_n = len(events) + sum(dropped_minutes.values())

    # ── 로그 검색용 이벤트 원본 저장 (분석 건별 jsonl) ──
    if events_export is not None:
        import json as _json
        try:
            events_export.parent.mkdir(parents=True, exist_ok=True)
            with open(events_export, "w", encoding="utf-8") as f:
                for e in events[:200_000]:
                    f.write(_json.dumps({
                        "ts": e.ts.strftime("%Y-%m-%d %H:%M:%S"),
                        "host": e.host, "layer": e.layer, "product": e.product,
                        "severity": e.severity, "code": e.code,
                        "message": e.message.splitlines()[0][:300],
                        "raw_ref": e.raw_ref,
                    }, ensure_ascii=False) + "\n")
        except Exception:
            pass  # 저장 실패해도 분석은 계속

    # ── 1) 시그니처 룰 매칭 ──
    rules = rules_pre
    _p(stage="match", events=len(events), rules=len(rules))
    matches = match_events(rules, events)
    _p(stage="judge", matches=len(matches))
    # 학습 룰·'defer_to_code' 룰(예: IIS 500/502 일반 룰)은 벤더 코드 사전이 이미 뜻을 정한 이벤트를 덮지 않는다 — 그 이벤트는 코드 판정으로
    if any(m.rule.source == "learned" or m.rule.defer_to_code for m in matches):
        _cdb = load_codes(codes_dir)
        from .codes import alias_code as _ac, load_aliases as _la
        _al = _la(codes_dir)

        def _coded(e):
            c = e.code or (_ac(_al, e.product, e.message) if _al else None)
            return bool(c and lookup(_cdb, e.product, c))
        matches = [m for m in matches if not (m.rule.source == "learned" or m.rule.defer_to_code) or not _coded(m.event)]
    # 보조 룰만 걸린 줄은 '판정됨' 으로 세지 않는다 — 사전의 주 원인(예 IIS 502.5)이 보조 판정(30초 이상 5xx)에 가려지지 않게
    matched_ids = {id(m.event) for m in matches if not m.rule.auxiliary}

    findings: list[dict] = []
    for m in matches:
        findings.append({
            "_ts": m.event.ts, "layer": m.event.layer, "product": m.event.product,
            "severity": m.rule.severity, "id": m.rule.id,
            "verdict": m.rule.verdict, "category": m.rule.category,
            "message": m.event.message.splitlines()[0][:140],
            "raw_ref": m.event.raw_ref, "source": "시그니처 룰", "origin": m.rule.source,
            "immediate": m.rule.immediate, "short": m.rule.short,
            "mid": m.rule.mid, "long": m.rule.long,
            "_code": m.event.code, "cause": "", "action": "", "ref": "",
            "approx_ts": "approx_ts" in (m.event.tags or []),
            "_aux": m.rule.auxiliary,
        })

    # ── 2) 벤더 에러코드 사전 조회 (룰 미적중 이벤트) ──
    codedb = load_codes(codes_dir)
    from . import codes as _codes_mod
    kb_skipped += list(getattr(_codes_mod.SKIPPED, "files", []) or [])
    code_count = len({k for k in codedb if ":" in k})
    from .codes import alias_code, load_aliases
    aliases = load_aliases(codes_dir)
    # 별칭 검색은 심각도 있는 이벤트만 (info 대량 로그 성능 보호)
    code_hit_ids: set = set()
    for e in events:
        if id(e) in matched_ids:
            continue
        code = e.code
        if not code and aliases and e.severity != "info":
            code = alias_code(aliases, e.product, e.message)
        if not code:
            continue
        entry = lookup(codedb, e.product, code)
        if not entry:
            continue
        code_hit_ids.add(id(e))
        sev = entry.severity
        if e.severity == "info" and sev in ("critical", "error"):
            sev = "warn"  # 로그 자체는 정보 등급 — 사전 심각도를 그대로 쓰지 않음
        findings.append({
            "_ts": e.ts, "layer": e.layer, "product": e.product,
            "severity": sev, "id": entry.code,
            "verdict": entry.title, "category": entry.category,
            "message": e.message.splitlines()[0][:140],
            "raw_ref": e.raw_ref, "source": "벤더 에러코드",
            "immediate": entry.immediate, "short": entry.short,
            "mid": entry.mid, "long": entry.long,
            "_code": entry.code, "cause": entry.cause, "action": entry.action, "ref": entry.ref,
            "_src": entry.source, "_vnote": entry.verify_note,
            "approx_ts": "approx_ts" in (e.tags or []),
        })

    # ── 2.2) 룰 학습 후보: 룰에도 코드 사전에도 안 걸린 오류·경고(문구 틀로, 값·개인정보 제거) — 판정에는 쓰지 않는다 ──
    try:
        from .learn import collect as _learn_collect
        learn_items = _learn_collect(events, matched_ids | code_hit_ids)
    except Exception:   # 학습 수집이 실패해도 분석은 그대로
        learn_items = []

    # 룰 판정에도 이벤트 코드가 있으면 제조사 원인·조치(사전)를 덧붙인다
    for f in findings:
        if f.get("cause") or f.get("action") or not f.get("_code"):
            continue
        entry = lookup(codedb, f["product"], f["_code"])
        if entry:
            f["cause"], f["action"], f["ref"] = entry.cause, entry.action, entry.ref
            f["vendor_code"] = entry.code
            f.setdefault("_src", entry.source); f.setdefault("_vnote", entry.verify_note)

    findings.sort(key=lambda f: f["_ts"])

    # ── 2.5) 구간 분리: 판정 사이 간격이 6시간을 넘으면 별도 구간(날짜가 섞인 파일 방어) ──
    #   주 구간 = critical 수 → 판정 수 → 최신 순. 대표 판정·통계·대응 계획은 주 구간만으로 계산
    clusters: list[list[dict]] = []
    for f in findings:
        if clusters and (f["_ts"] - clusters[-1][-1]["_ts"]).total_seconds() <= 6 * 3600:
            clusters[-1].append(f)
        else:
            clusters.append([f])
    all_findings = findings
    cluster_info = []
    if clusters:
        def _rank(c):
            return (sum(1 for x in c if x["severity"] == "critical"), len(c), c[0]["_ts"])
        main = max(clusters, key=_rank)
        for c in clusters:
            layers_c = sorted({LAYER_KO[x["layer"]] for x in c})
            cluster_info.append({
                "start": c[0]["_ts"].strftime("%Y-%m-%d %H:%M:%S"),
                "end": c[-1]["_ts"].strftime("%Y-%m-%d %H:%M:%S"),
                "count": len(c), "critical": sum(1 for x in c if x["severity"] == "critical"),
                "layers": layers_c, "main": c is main,
                "files": sorted({str(x["raw_ref"]).rpartition(":")[0].replace("\\", "/").rsplit("/", 1)[-1] for x in c}),
            })
        findings = main

    # ── 3) 대표 판정: 최초 critical 5분 창 안에서 하위 계층(OS→DB→WAS→WEB→SW) 우선, 반복 횟수 가중 ──
    first = None
    incident_est = None
    if findings:
        exact = [f for f in findings if not f.get("approx_ts")] or findings
        exact = [f for f in exact if not f.get("_aux")] or exact   # 보조 판정(예 30초 이상 5xx 성능)은 주 판정이 있으면 대표가 되지 않는다
        for sev in ("critical", "error", "warn", "info"):
            group = [f for f in exact if f["severity"] == sev]
            if group:
                break
        t0 = min(f["_ts"] for f in group)
        cands = [f for f in group if (f["_ts"] - t0).total_seconds() <= 300]
        cnt = {}
        for f in group:
            cnt[f["id"]] = cnt.get(f["id"], 0) + 1
        _layer_rank = {"os": 0, "db": 1, "was": 2, "web": 3, "sw": 4}
        # 기존 도구에서 변환한 룰(origin=legacy)은 같은 심각도 안에서 서명 룰팩·사이트 룰보다 뒤로
        fm = min(cands, key=lambda f: (f.get("origin") in ("legacy", "learned"), _layer_rank.get(f["layer"], 9), -cnt.get(f["id"], 0), f["_ts"]))
        first = {"layer": fm["layer"], "layer_ko": LAYER_KO[fm["layer"]],
                 "ts": fm["_ts"].strftime("%H:%M:%S"),
                 "verdict": fm["verdict"], "rule_id": fm["id"], "severity": fm["severity"],
                 "category": fm["category"],
                 "category_ko": CATEGORY_KO.get(fm["category"], fm["category"])}
        incident_est = fm["_ts"].strftime("%Y-%m-%d %H:%M:%S")
        # 입력 로그의 첫 이벤트와 거의 같은 시각이면 '로그 시작 시점에 이미 진행 중'(발생 시각 미확정)
        _ev_min = min((e.ts for e in events), default=None)
        if _ev_min is not None and (fm["_ts"] - _ev_min).total_seconds() <= 120:
            first["ongoing_at_start"] = True

    _multi_day = len({f["_ts"].date() for f in findings}) > 1
    _tfmt = "%m-%d %H:%M:%S" if _multi_day else "%H:%M:%S"
    _eids = _assign_eids(findings)   # 한 분석 안 중복 막기 — 입력 순서와 무관
    timeline = [{
        "ts": f["_ts"].strftime(_tfmt), "layer": f["layer"],
        "layer_ko": LAYER_KO[f["layer"]], "severity": f["severity"],
        "rule_id": f["id"], "verdict": f["verdict"], "source": f["source"],
        "message": f["message"], "raw_ref": f["raw_ref"],
        "eid": _eids[_i],   # 근거별 고유 ID(2026-10-15) — 리포트·1장 요약·메신저에서 '근거 E-…'로 가리킨다
    } for _i, f in enumerate(findings)]
    _eid_of = {id(f): _eids[_i] for _i, f in enumerate(findings)}   # 판정별 요점이 첫 근거 ID 를 갖게(아이디어 6)
    timeline_total = len(timeline)
    _timeline_full = timeline
    timeline = timeline[:3000]  # 화면·이력 저장 상한(원본 전체는 로그 검색 jsonl 에 있음)

    checklist, seen = [], set()
    for f in sorted(findings, key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["_ts"])):
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        checklist.append({
            "rule_id": f["id"], "verdict": f["verdict"],
            "severity": f["severity"], "source": f["source"],
            "category_ko": CATEGORY_KO.get(f["category"], f["category"]),
            "immediate": f["immediate"], "short": f["short"],
            "mid": f["mid"], "long": f["long"],
            "vendor_cause": f.get("cause", ""), "vendor_action": f.get("action", ""),
            "vendor_url": f.get("ref", ""),
            "product": f.get("product", ""), "code_key": f"{f.get('product', '')}:{f.get('vendor_code') or f.get('_code') or f['id']}",
            "_src": f.get("_src", ""), "_vnote": f.get("_vnote", ""),
            "eid": _eid_of.get(id(f), ""),   # 아이디어 4: 이 조치를 권하는 근거 줄(가장 이른 발생) — 화면·분석요약에서 바로 찾아간다
        })

    layer_stats: dict[str, dict] = {}
    for f in findings:
        s = layer_stats.setdefault(f["layer"], {
            "layer_ko": LAYER_KO[f["layer"]], "rules": set(),
            "critical": 0, "error": 0, "first_ts": f["_ts"].strftime("%H:%M:%S")})
        s["rules"].add(f["id"])
        if f["severity"] == "critical":
            s["critical"] += 1
        elif f["severity"] == "error":
            s["error"] += 1
    for s in layer_stats.values():
        s["rules"] = len(s["rules"])

    # ── 시각화 데이터: 분 단위 이벤트 히스토그램 + 심각도 총계 ──
    sev_totals = {"critical": 0, "error": 0, "warn": 0, "info": 0}
    minute_counts: dict[datetime, dict] = {}
    for e in events:
        sev_totals[e.severity] = sev_totals.get(e.severity, 0) + 1
        mk = e.ts.replace(second=0, microsecond=0)
        b = minute_counts.setdefault(mk, {"critical": 0, "error": 0, "other": 0})
        b["critical" if e.severity == "critical"
          else "error" if e.severity == "error" else "other"] += 1
    for mk, c in dropped_minutes.items():  # 집계만 남긴 info 이벤트
        sev_totals["info"] += c
        minute_counts.setdefault(mk, {"critical": 0, "error": 0, "other": 0})["other"] += c
    hist_keys = sorted(minute_counts)
    group = max(1, (len(hist_keys) + 119) // 120)  # 최대 120개 막대로 축약
    # 분 단위 판정(룰·코드) 집계 — 막대에 마우스를 올렸을 때 '이 구간의 주요 판정'과 로그 검색 구간을 제공
    minute_rules: dict[datetime, dict] = {}
    for f in all_findings:
        mk = f["_ts"].replace(second=0, microsecond=0)
        d = minute_rules.setdefault(mk, {})
        d[f["id"]] = d.get(f["id"], 0) + 1
    histogram = []
    for idx in range(0, len(hist_keys), group):
        chunk = hist_keys[idx:idx + group]
        agg = {"t": chunk[0].strftime("%H:%M"), "critical": 0, "error": 0, "other": 0,
               "t0": chunk[0].strftime("%Y-%m-%d %H:%M:%S"),
               "t1": (chunk[-1] + timedelta(minutes=1) - timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")}
        top: dict[str, int] = {}
        for k in chunk:
            for kk in ("critical", "error", "other"):
                agg[kk] += minute_counts[k][kk]
            for rid, n in minute_rules.get(k, {}).items():
                top[rid] = top.get(rid, 0) + n
        agg["top"] = [{"id": rid, "n": n} for rid, n in sorted(top.items(), key=lambda x: -x[1])[:4]]
        agg["findings"] = sum(top.values())
        histogram.append(agg)

    # ── 인과 타임라인 요점: 룰·코드별 최초 발생 1건(횟수·구간 포함) + 최초 이상·최초 critical·계층별 최초 표시 ──
    key_points = []
    seen_rule: dict[str, dict] = {}
    for f in findings:
        d = seen_rule.get(f["id"])
        if d is None:
            d = seen_rule[f["id"]] = {
                "ts": f["_ts"].strftime(_tfmt), "ts_full": f["_ts"].strftime("%Y-%m-%d %H:%M:%S"),
                "last_full": f["_ts"].strftime("%Y-%m-%d %H:%M:%S"), "last": f["_ts"].strftime(_tfmt),
                "layer": f["layer"], "layer_ko": LAYER_KO[f["layer"]], "severity": f["severity"],
                "rule_id": f["id"], "verdict": f["verdict"], "source": f["source"],
                "code": f.get("vendor_code") or f.get("_code") or "",
                "message": f["message"], "raw_ref": f["raw_ref"], "count": 0, "marks": [],
                "category_ko": CATEGORY_KO.get(f["category"], f["category"]), "_ts": f["_ts"],
                "eid": _eid_of.get(id(f), "")}   # 이 판정의 첫 근거 ID — 보고서·분석요약에서 같은 줄을 가리킨다
            key_points.append(d)
        d["count"] += 1
        d["last_full"] = f["_ts"].strftime("%Y-%m-%d %H:%M:%S")
        d["last"] = f["_ts"].strftime(_tfmt)
    if key_points:
        key_points[0]["marks"].append("최초 이상")
        crit = next((k for k in key_points if k["severity"] == "critical"), None)
        if crit is not None and "최초 이상" not in crit["marks"]:
            crit["marks"].append("최초 critical")
        seen_layer = set()
        for k in key_points:
            if k["layer"] not in seen_layer:
                seen_layer.add(k["layer"])
                if len(seen_layer) > 1:
                    k["marks"].append(f"{k['layer_ko']} 계층 최초")
        if first:
            for k in key_points:
                if k["rule_id"] == first["rule_id"] and "대표 판정" not in k["marks"]:
                    k["marks"].append("대표 판정")
                    break
    # 표시 상한: 표시 표식이 있는 항목 + 심각도·횟수 상위 — 최대 24건, 시간순
    def _kp_rank(k):
        return (0 if k["marks"] else 1, SEV_ORDER.get(k["severity"], 9), -k["count"], k["_ts"])
    keep = sorted(key_points, key=_kp_rank)[:24]
    timeline_key = sorted(keep, key=lambda k: k["_ts"])
    for k in timeline_key:
        k.pop("_ts", None)
    # 요점이 가리키는 근거 줄은 3,000 상한 밖이어도 남긴다 — 보고서·분석요약·근거 딥링크의 ID 가 늘 찾아지게(GPT 27차)
    _want = ({k.get("eid") for k in timeline_key if k.get("eid")} | {c.get("eid") for c in checklist if c.get("eid")}) - {t["eid"] for t in timeline}
    if _want:
        timeline = timeline + [t for t in _timeline_full[3000:] if t["eid"] in _want]
    for c in cluster_info:
        if not c.get("main"):
            timeline_key.append({"ts": c["start"][5:] if _multi_day else c["start"][11:], "ts_full": c["start"], "last_full": c["end"], "last": c["end"][11:],
                                 "layer": "", "layer_ko": "/".join(c["layers"]), "severity": "info", "rule_id": "", "verdict": f"별도 구간 후보 — 판정 {c['count']}건(critical {c['critical']})",
                                 "source": "", "code": "", "message": "시간 간격 6시간 초과로 분리된 구간 · 같은 장애로 확인된 경우에만 병합", "raw_ref": "",
                                 "count": c["count"], "marks": ["별도 구간"], "category_ko": ""})

    # ── 3단계 대응 계획 (① 분석 내용 ② 1차 긴급 ③ 2차 유지보수 ④ 3차 제조사) ──
    from .kb import load_manuals
    from .response import build_response_plan
    if manuals_dir is None and codes_dir is not None:
        manuals_dir = Path(codes_dir).parent / "manuals"
    manuals = load_manuals(manuals_dir)
    # 조치 절차 카탈로그(매뉴얼 기준 명령·설정) — 판정별로 붙이고 단계별로 묶어 대응 계획에 전달
    from .procedures import attach_procedures, load_procedures
    procs = load_procedures(manuals_dir)
    # GPT 53차: 매뉴얼·절차 파일도 깨지면 조용히 넘어가지 않는다 — 룰·코드와 같은 '읽지 못한 지식 파일' 알림으로
    from . import kb as _kb_mod, procedures as _proc_mod
    kb_skipped += list(getattr(_kb_mod.SKIPPED, "files", []) or []) + list(getattr(_proc_mod.SKIPPED, "files", []) or [])
    # 설치 때 남긴 지식 매니페스트(룰·코드 수)보다 적게 읽혔으면 알린다 — 파일이 빠졌거나 지워진 경우
    try:
        import json as _jsonm
        _mf = _jsonm.loads((Path(codes_dir).parent / "knowledge-manifest.json").read_text(encoding="utf-8")) if codes_dir else {}
        _n_codes = len(codedb)
        _n_rules = len({r.id for r in rules_pre if r.source != "local"})
        _n_local = sum(1 for r in rules_pre if r.source == "local")
        if _mf.get("codes") and _n_codes < int(_mf["codes"]):
            kb_skipped.append(f"코드 수가 설치 기록보다 적음({_n_codes}/{_mf['codes']})")
        if _mf.get("rules") and _n_rules + _n_local < int(_mf["rules"]):
            kb_skipped.append(f"룰 수가 설치 기록보다 적음({_n_rules}/{_mf['rules']})")
    except (OSError, ValueError, TypeError):
        pass
    proc_by_stage = attach_procedures(procs, checklist, findings) if findings else {1: [], 2: [], 3: []}
    # 2026-10-16 아이디어 1·6·7·10 — 검증 축, 판 추정, 1차 명령 모음(안전 검사 통과·판 어긋남 제외), 지식 지문
    from . import knowledge_quality as KQ
    _ver = KQ.load_verification(codes_dir)
    _metrics = KQ.load_metrics(codes_dir)
    versions = KQ.detect_versions([{"path": i.get("path"), "product": i.get("product")} for i in inputs])
    for c in checklist:
        pr = (c.get("product") or "").split("-")[0]
        c["axes"] = KQ.axes(c.get("code_key", ""), ref=c.get("vendor_url", ""), source=c.pop("_src", ""), product=c.get("product", ""),
                            verify_note=c.pop("_vnote", ""), ver=_ver)
        cmds = KQ.first_commands(c.get("immediate") or [])
        for x in cmds:
            x["fit"] = KQ.version_fit(x.get("tail", ""), pr, versions.get(pr))
            x["copy"] = x["safe"] and x["fit"] != "어긋남"
            _ms = KQ.metric_for(_metrics, c.get("code_key", ""), x["cmd"])
            x["metric"] = _ms["id"] if _ms else ""      # 지표가 고정된 짝만 결과 해석이 충족·미충족을 정한다(7차 아이디어 3)
            x["metric_part"] = bool(_ms and _ms.get("part"))   # 8차 ⑨: 수치 부분만 결속(나머지 조건은 사람 판단)
        c["cmds"] = cmds
    kb_base = Path(codes_dir).parent if codes_dir else None
    kb_changed, kb_fp = None, ""
    if kb_base:
        try:
            cmpm = KQ.compare_manifest(kb_base)
            kb_fp = cmpm["fingerprint"] if cmpm else KQ.fingerprint(KQ.file_hashes(kb_base))
            if cmpm and (cmpm["added"] or cmpm["deleted"] or cmpm["changed"]):
                kb_changed = {k: cmpm[k][:20] for k in ("added", "deleted", "changed")}
                kb_changed["count"] = len(cmpm["added"]) + len(cmpm["deleted"]) + len(cmpm["changed"])
        except OSError:
            pass
    plan = build_response_plan(findings, events, files, first, checklist, manuals,
                               incident_time or incident_est, clusters=cluster_info, os_hint=os_hint,
                               procedures=proc_by_stage)

    return {
        "plan": plan,
        "timeline_key": timeline_key,
        "procedures_total": len(procs),
        "clusters": cluster_info,
        "findings_total": len(all_findings),
        "histogram": histogram,
        "hist_group_min": group,
        "incident_mark": (incident_time or incident_est or "")[11:16],
        "sev_totals": sev_totals,
        "auto_detected": t is None,
        "incident_time": incident_time or incident_est,
        "window": window,
        "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "os_hint": os_hint, "os_hint_ko": OS_KO.get(os_hint or "", ""),
        "files": files,
        "events_total": events_total_all,
        "events_window": events_window_n,
        "rule_count": len(rules),
        "code_count": code_count,
        "match_count": len(findings),
        "first": first,
        "timeline": timeline, "timeline_total": timeline_total,
        "checklist": checklist,
        "layers": layer_stats,
        "kb_skipped": sorted(set(kb_skipped)),
        "kb_changed": kb_changed,          # 설치 매니페스트 대비 추가·삭제·변경된 지식 파일(아이디어 10)
        "kb_fingerprint": kb_fp,           # 이 분석에 쓴 지식의 지문 — 이력에 고정(GPT 55차)
        "versions_detected": versions,     # 로그 머리에서 추정한 제품 판(추정 — 실제 실행 판과 다를 수 있음)   # 읽지 못한 룰·코드 파일 — 있으면 판정 범위 제한(GPT 7차)
        "learn": learn_items,   # 호출자가 꺼내 LearnStore 에 기록하고 결과·이력에서는 뺀다
    }
