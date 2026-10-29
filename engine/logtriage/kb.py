"""로컬 지식베이스 검색 — 룰 · 벤더 에러코드 · 제품 매뉴얼 통합 검색.

외부 연결 없이 완전 오프라인으로 동작한다. 매뉴얼(manuals/*.yaml)은
룰·에러코드와 함께 룰팩(.rpk)으로 갱신된다.
검색: 공백 구분 다중 키워드 AND, 대소문자 무시.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from . import yamlsafe   # 12차: C 안전 파서(+깊이·별칭·크기 한도) — 파이썬 파서보다 수 배 빠르다


import threading as _threading
SKIPPED = _threading.local()   # 마지막 load_manuals 가 읽지 못한 매뉴얼 파일


def load_manuals(manuals_dir: Path | None) -> list[dict]:
    out = []
    SKIPPED.files = []
    if not manuals_dir or not manuals_dir.exists():
        return out
    for f in sorted(manuals_dir.rglob("*.yaml")):
        if f.name.endswith(("_versions.yaml", "_procedures.yaml", "_proclinks.yaml", "_osmatrix.yaml")):
            continue  # 버전 카탈로그·조치 절차 카탈로그(별도 로더) — 매뉴얼 문서가 아님
        try:
            doc = yamlsafe.load(f.read_text(encoding="utf-8")) or {}
            doc.setdefault("product", f.stem)
            doc.setdefault("sections", [])
            out.append(doc)
        except Exception:
            SKIPPED.files.append(f"{f.parent.name}/{f.name}")   # GPT 53차: 조용히 건너뛰지 않고 화면에 알린다
            continue
    return out


def _hit(terms: list[str], *texts) -> bool:
    blob = " ".join(str(t) for t in texts).lower()
    return all(term in blob for term in terms)


def search_kb(query: str, rules, codes: dict, manuals: list[dict],
              limit: int = 40) -> dict:
    """rules: Rule 목록 / codes: {키: CodeEntry} / manuals: 매뉴얼 문서 목록."""
    terms = [t.lower() for t in (query or "").split() if t.strip()]

    rule_hits = []
    for r in rules:
        if not terms or _hit(terms, r.id, r.layer, " ".join(r.products),
                             r.verdict, r.pattern.pattern, r.category,
                             " ".join(r.immediate + r.short + r.mid + r.long)):
            rule_hits.append({
                "id": r.id, "layer": r.layer, "products": r.products,
                "verdict": r.verdict, "severity": r.severity,
                "source": r.source, "pattern": r.pattern.pattern,
                "immediate": r.immediate, "short": r.short,
                "mid": r.mid, "long": r.long})
        if len(rule_hits) >= limit:
            break

    code_hits, seen = [], set()
    for key, e in codes.items():
        if ":" not in key or e.code in seen:
            continue
        if not terms or _hit(terms, e.code, e.product, e.layer, e.title,
                             e.category, " ".join(e.immediate + e.short + e.mid + e.long)):
            seen.add(e.code)
            code_hits.append({
                "code": e.code, "product": e.product, "layer": e.layer,
                "severity": e.severity, "title": e.title,
                "immediate": e.immediate, "short": e.short,
                "mid": e.mid, "long": e.long})
        if len(code_hits) >= limit:
            break

    manual_hits = []
    for doc in manuals:
        secs = []
        for s in doc.get("sections", []):
            if not terms or _hit(terms, doc.get("product"), doc.get("title"),
                                 s.get("heading"), s.get("body")):
                secs.append({"heading": s.get("heading", ""),
                             "body": s.get("body", "")})
        if secs:
            manual_hits.append({"product": doc.get("product"),
                                "title": doc.get("title", doc.get("product")),
                                "sections": secs[:6]})
        if len(manual_hits) >= 15:
            break

    return {"query": query, "rules": rule_hits, "codes": code_hits,
            "manuals": manual_hits}
