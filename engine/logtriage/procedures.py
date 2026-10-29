"""조치 절차 카탈로그 — 제품 매뉴얼 기준의 '실제 수행 가능한' 명령·설정 절차.

manuals/*_procedures.yaml:
  product: jeus                      # 제품(또는 계층 공통: os-common / was-common / web-common / db-common / sw-common)
  procedures:
    - id: JEUS-PROC-MEMORY
      category: memory               # 룰·코드의 category 와 대응
      match: [WAS-JVM-001, JEUS-OOM] # (선택) 특정 룰·코드 ID 우선 매칭
      title: 힙/Metaspace 메모리 고갈
      source: "JEUS 8.5 Server Guide 8장 …"   # 근거 매뉴얼(장/절·URL)
      stages:
        - stage: 1                   # 1차 선 대응(읽기 전용 확인·자료 보존) / 2 유지보수 엔지니어(복구·설정 변경) / 3 제조사 의뢰 자료
          steps:
            - do: …                  # 할 일
              cmd: |                 # 그대로 실행 가능한 명령(자리표시자 <PID> <server> …)
              config:                # 설정 변경 (파일 → 항목 → 예시값)
                file: …
                snippet: |
              check: …               # 정상 판단 기준
              note: …                # 주의
분석 결과의 판정(룰/코드)마다 제품+유형으로 절차를 찾아 checklist 와 대응 계획(tier1/2/3)에 붙인다.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from . import yamlsafe   # 12차: C 안전 파서(+깊이·별칭·크기 한도) — 파이썬 파서보다 수 배 빠르다

_COMMON = {"os": "os-common", "web": "web-common", "was": "was-common", "db": "db-common", "sw": "sw-common"}
LINK = {3: "이 판정 전용", 2: "같은 제품·유형", 1: "계층 공통·유형"}
STAGE_KO = {1: "1차 선 대응 (읽기 전용 확인·자료 보존)", 2: "2차 유지보수 엔지니어 (복구·설정 변경)", 3: "3차 제조사 의뢰 (수집 자료)"}


import threading as _threading
SKIPPED = _threading.local()   # 이 스레드의 마지막 load_procedures 가 읽지 못한 파일 — 화면 '지식 파일 손상' 알림으로(GPT 53차: 조용히 건너뛰지 않는다)


def load_procedures(manuals_dir: Path | None) -> list[dict]:
    out: list[dict] = []
    SKIPPED.files = []
    if not manuals_dir or not manuals_dir.exists():
        return out
    for f in sorted(manuals_dir.rglob("*_procedures.yaml")):
        try:
            doc = yamlsafe.load(f.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict):
                raise ValueError("최상위가 사전이 아님")
        except Exception:
            SKIPPED.files.append(f"{f.parent.name}/{f.name}")
            continue
        prods = doc.get("products") or ([doc.get("product")] if doc.get("product") else [])
        for p in doc.get("procedures", []) or []:
            if not isinstance(p, dict) or not p.get("stages"):
                continue
            p = dict(p)
            p["products"] = [str(x).lower() for x in (p.get("products") or prods)]
            p["category"] = str(p.get("category", "etc"))
            p["match"] = [str(x) for x in (p.get("match") or [])]
            p["_file"] = f.name
            out.append(p)
    # 아이디어 3(2026-10-16): *_proclinks.yaml — 사람이 적합성을 확인한 판정 ID 를 기존 절차에 '전용'으로 잇는다(절차 파일은 고치지 않는다)
    #   links: [{procedure: <절차 ID>, match: [<룰/코드 ID>…], reviewed: "<언제·무엇을 확인>"}]
    by_id = {p.get("id"): p for p in out}
    for f in sorted(manuals_dir.rglob("*_proclinks.yaml")):
        try:
            doc = yamlsafe.load(f.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict) or not isinstance(doc.get("links", []), list):
                raise ValueError("links 목록이 아님")
        except Exception:
            SKIPPED.files.append(f"{f.parent.name}/{f.name}")
            continue
        for ln in doc.get("links", []) or []:
            if not isinstance(ln, dict):
                continue
            p = by_id.get(str(ln.get("procedure", "")))
            if p is None:
                SKIPPED.files.append(f"{f.parent.name}/{f.name}: 없는 절차 {str(ln.get('procedure', ''))[:40]}")
                continue
            p["match"] = p["match"] + [str(x) for x in (ln.get("match") or []) if str(x) not in p["match"]]
            if ln.get("primary") is True:   # 같은 ID 를 여러 전용 절차가 가질 때 사람이 고른 1순위(검토 사유는 reviewed 에)
                p["_primary_u"] = set(p.get("_primary_u") or set()) | {str(x).upper() for x in (ln.get("match") or [])}
    for p in out:
        p["_match_u"] = {x.upper() for x in p["match"]}
    return out


def _norm_steps(stage: dict) -> list[dict]:
    steps = []
    for s in stage.get("steps", []) or []:
        if not isinstance(s, dict):
            continue
        cfg = s.get("config")
        if isinstance(cfg, dict):
            cfg = {"file": str(cfg.get("file", "")), "snippet": str(cfg.get("snippet", "")).rstrip("\n"), "note": str(cfg.get("note", ""))}
        else:
            cfg = None
        steps.append({"do": str(s.get("do", "")), "cmd": str(s.get("cmd", "")).rstrip("\n"),
                      "config": cfg, "check": str(s.get("check", "")), "note": str(s.get("note", ""))})
    return steps


def _pack(p: dict) -> dict:
    stages = []
    for st in p.get("stages", []) or []:
        if not isinstance(st, dict):
            continue
        n = int(st.get("stage", 2))
        stages.append({"stage": n, "stage_ko": STAGE_KO.get(n, f"{n}차"), "steps": _norm_steps(st)})
    stages.sort(key=lambda s: s["stage"])
    return {"id": p.get("id", ""), "title": p.get("title", ""), "category": p["category"],
            "product": p["products"][0] if p["products"] else "", "source": str(p.get("source", "")),
            "stages": stages}


def _product_ok(p: dict, product: str, layer: str) -> bool:
    """ID 가 같아도 제품이 다르면 전용 연결이 아니다(2026-10-16 GPT 56차 — GOLDILOCKS ERR-11030 에 Altibase 절차가 붙던 결함:
    두 제조사가 같은 ERR-xxxxx 꼴을 쓴다). 공통 절차(*-common)·제품 미지정·자바 절차(WAS·SW 위의 자바)는 허용."""
    prods = p.get("products") or []
    if not prods or product in ("", "*") or product in prods:
        return True
    if any(t.endswith(("-common", "-common-match")) for t in prods):
        return True
    if any(product.split("-")[0] == t.split("-")[0] for t in prods):
        return True
    return "java" in prods and layer in ("was", "sw")


def match_procedures(procs: list[dict], product: str, layer: str, category: str,
                     ids: list[str] | None = None, limit: int = 2) -> list[dict]:
    """우선순위: (1) match 에 룰/코드 ID 명시 → (2) 제품+유형 → (3) 계층 공통+유형."""
    product = (product or "").lower()
    ids = [str(x).upper() for x in (ids or []) if x]   # 대소문자 무시 — match 에 소문자 클래스명(java.lang.…)이 있어 대문자 코드와 안 맞던 문제(10-16)
    common = _COMMON.get(layer, "")
    scored = []
    for p in procs:
        s = 0
        mu = p.get("_match_u")
        if mu is None:
            mu = {str(x).upper() for x in p.get("match") or []}
        if ids and any(i in mu for i in ids) and _product_ok(p, product, layer):
            s = 3
        elif p.get("scope") == "id":
            continue   # 전용 절차(scope: id) — 이름 붙인 판정에만. 같은 제품·유형의 다른 판정에 대체 절차로 끼어들지 않는다(2026-10-16)
        elif product in p["products"] and p["category"] == category:
            s = 2
        elif common and common in p["products"] and p["category"] == category:
            s = 1
        if s:
            scored.append((s, p))
    # 같은 점수면 사람이 고른 1순위(primary) → 전용(scope: id) 절차 → 같은 제품 절차 → 나머지(공통·자바) 순(10-16)
    def _key(x):
        sc, p = x
        prim = sc == 3 and any(i in (p.get("_primary_u") or ()) for i in ids)
        return (-sc, not prim, p.get("scope") != "id", product not in (p.get("products") or []))
    scored.sort(key=_key)
    # GPT 58차: 이름 붙인 전용 절차가 둘 이상 같은 순위면 임의로 하나를 '전용'이라 하지 않는다 — '매칭 모호'로 밝힌다
    tied = [p for sc, p in scored if sc == 3 and scored and _key((sc, p)) == _key(scored[0])]
    tied_ids = {p.get("id") for p in tied}
    out, seen = [], set()
    for sc, p in scored:
        if p.get("id") in seen:
            continue
        seen.add(p.get("id"))
        pk = _pack(p)
        # 연결 강도(2026-10-16 GPT 50차): 유형만으로 붙은 절차는 그 코드에 꼭 맞지 않을 수 있다 — 화면에 그대로 밝힌다
        pk["link"] = LINK[sc]
        if sc == 3 and len(tied_ids) > 1 and p.get("id") in tied_ids:
            pk["link"] = f"이 판정 전용 후보 {len(tied_ids)}개 — 매칭 모호"
        out.append(pk)
        if len(out) >= limit:
            break
    return out


def attach_procedures(procs: list[dict], checklist: list[dict], findings: list[dict]) -> dict:
    """checklist 항목마다 procedures 를 붙이고, 단계별 묶음(tier1/2/3 용)을 돌려준다."""
    prod_of = {}
    for f in findings:
        prod_of.setdefault(f["id"], (f.get("product", ""), f["layer"], f.get("category", "etc"), f.get("_code") or f.get("vendor_code") or ""))
    by_stage: dict[int, list[dict]] = {1: [], 2: [], 3: []}
    seen_proc = set()
    for c in checklist:
        product, layer, category, code = prod_of.get(c["rule_id"], ("", "", "etc", ""))
        found = match_procedures(procs, product, layer, category, [c["rule_id"], code])
        c["procedures"] = found
        for p in found:
            if p["id"] in seen_proc:
                continue
            seen_proc.add(p["id"])
            for st in p["stages"]:
                by_stage.setdefault(st["stage"], []).append({
                    "proc_id": p["id"], "title": p["title"], "product": p["product"], "rule_id": c["rule_id"], "link": p.get("link", ""),
                    "verdict": c.get("verdict", ""), "source": p["source"], "steps": st["steps"]})
    return by_stage


def procedure_text(p: dict, stage: int | None = None) -> list[str]:
    """텍스트 복사·보고서용 줄 목록."""
    L = [f"[{p.get('product', '')}] {p.get('title', '')} ({p.get('id', '')})" + (f" · 연결: {p['link']}" if p.get("link") else "") + (f" — 근거: {p['source']}" if p.get("source") else "")]
    for st in p.get("stages", []):
        if stage is not None and st["stage"] != stage:
            continue
        L.append(f"  ▶ {st['stage_ko']}")
        for i, s in enumerate(st["steps"], 1):
            L.append(f"   {i}) {s['do']}")
            for line in (s.get("cmd") or "").splitlines():
                L.append(f"      $ {line}")
            cfg = s.get("config")
            if cfg and (cfg.get("file") or cfg.get("snippet")):
                L.append(f"      설정: {cfg.get('file', '')}")
                for line in (cfg.get("snippet") or "").splitlines():
                    L.append(f"        {line}")
            if s.get("check"):
                L.append(f"      확인: {s['check']}")
            if s.get("note"):
                L.append(f"      ※ {s['note']}")
    return L
