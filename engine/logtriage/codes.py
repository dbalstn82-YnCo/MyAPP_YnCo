"""벤더 에러코드 지식베이스 로더.

인터넷망에서 제조사 공식 문서(Oracle KB, MS Docs, Apache 문서 등)를 기준으로
수집·갱신되고 룰팩(.rpk)에 포함되어 인터넷이 없는 설치 환경에도 반입된다.

분석 시 파서가 추출한 코드(event.code)를 이 사전에서 조회하여
정규식 룰에 걸리지 않은 이벤트라도 장애 유형·조치 방안을 제시한다.
조회 키: "제품:코드" 우선, 없으면 "코드" (ORA- 처럼 전역 고유한 코드).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# YAML 읽기는 yamlsafe.load — C 안전 파서(약 8배 빠름) + 깊이·별칭·크기 한도(C 파서는 깊은 중첩에서 프로세스가 죽는다)


@dataclass
class CodeEntry:
    code: str
    layer: str
    product: str            # 소유 제품 (windows, oracle, ...)
    severity: str
    category: str
    title: str              # 장애 유형 제목
    immediate: list[str] = field(default_factory=list)
    short: list[str] = field(default_factory=list)
    mid: list[str] = field(default_factory=list)
    long: list[str] = field(default_factory=list)
    source: str = "vendor"  # 출처 표기 (벤더 문서)
    cause: str = ""         # 제조사 문서가 제시하는 원인 (Cause)
    action: str = ""        # 제조사 문서가 제시하는 조치 (Action)
    ref: str = ""           # 제조사 문서 URL — 있을 때만 원인·조치를 '제조사 문서'라 부른다(없으면 '분석기 지식')
    versions: list[str] = field(default_factory=list)  # 적용 버전(확인된 범위, 예: "RHEL 6~9", "Ubuntu 16.04+")
    version_note: str = ""  # 버전별 메시지 차이·검증 메모
    verify_note: str = ""   # 공식 근거로 확인하지 못한 부분(있으면 화면에 '미검증 포함') — 2026-10-16


import threading as _threading
SKIPPED = _threading.local()   # 이 스레드의 마지막 load_codes 가 건너뛴 파일


def cause_label(ref: str, short: bool = False) -> str:
    """원인 설명의 출처 표시 — 제조사 문서 URL 이 있으면 제조사 문서, 없으면 분석기 지식(제조사 문서 미대조)."""
    if ref:
        return "제조사 원인" if short else "제조사 문서 원인"
    return "원인(분석기 지식)" if short else "원인(분석기 지식 — 제조사 문서 미대조)"


def load_codes(codes_dir: Path | None) -> dict[str, CodeEntry]:
    """반환 dict 키: '제품:코드' 및 '코드' (대문자)."""
    SKIPPED.files = []
    db: dict[str, CodeEntry] = {}
    if not codes_dir or not codes_dir.exists():
        return db
    from .yamlsafe import load as _yload
    for f in sorted(codes_dir.rglob("*.yaml")):
        try:                                   # 파일 하나가 깨져도 그 파일만 건너뛴다(코드 사전 전체를 잃지 않게)
            doc = _yload(f.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict):
                raise ValueError("최상위가 사전이 아님")
            _codes_from(doc, db)
        except Exception as e:
            import sys
            sys.stderr.write(f"[codes] {f.name} 건너뜀 — {type(e).__name__}: {str(e)[:160]}\n")
            SKIPPED.files.append(f"{f.parent.name}/{f.name}")
    return db


def unreadable_files(codes_dir: Path | None) -> list[dict]:
    """읽지 못해 건너뛰는 코드 파일(이름·사유) — 화면에 알리기용."""
    from .yamlsafe import load as _yload
    out = []
    if not codes_dir or not codes_dir.exists():
        return out
    for f in sorted(codes_dir.rglob("*.yaml")):
        try:
            doc = _yload(f.read_text(encoding="utf-8")) or {}
            if not isinstance(doc, dict):
                raise ValueError("최상위가 사전이 아님")
            if f.name != "_aliases.yaml":
                _codes_from(doc, {})
        except Exception as e:
            out.append({"file": str(f.relative_to(codes_dir.parent)), "why": f"{type(e).__name__}: {str(e)[:120]}"})
    return out


def _codes_from(doc: dict, db: dict) -> None:
    product = str(doc.get("product", "")).lower()
    layer = doc.get("layer", "sw")
    for e in doc.get("codes", []):
        entry = CodeEntry(
            code=str(e["code"]).upper(),
            layer=e.get("layer", layer),
            product=str(e.get("product", product)).lower(),
            severity=e.get("severity", "error"),
            category=e.get("category", "etc"),
            title=e.get("title", str(e["code"])),
            immediate=e.get("immediate", []),
            short=e.get("short", []),
            mid=e.get("mid", []),
            long=e.get("long", []),
            source=str(e.get("source", "vendor")),
            cause=str(e.get("vendor_cause", "") or ""),
            action=str(e.get("vendor_action", "") or ""),
            ref=str(e.get("vendor_url", "") or ""),
            versions=[str(v) for v in (e.get("versions") or [])],
            version_note=str(e.get("version_note", "") or ""),
            verify_note=str(e.get("verify_note", "") or ""),
        )
        db[f"{entry.product}:{entry.code}"] = entry
        db.setdefault(entry.code, entry)


def load_aliases(codes_dir: Path | None) -> list[tuple[str, str, "re.Pattern"]]:
    """메시지 패턴 → 의사코드 별칭 (errorcodes/_aliases.yaml). (제품, 코드, 정규식) 목록."""
    import re
    out = []
    if not codes_dir:
        return out
    f = codes_dir / "_aliases.yaml"
    if not f.exists():
        return out
    from .yamlsafe import load as _yload
    try:
        doc = _yload(f.read_text(encoding="utf-8")) or {}
    except Exception as e:
        import sys
        sys.stderr.write(f"[codes] _aliases.yaml 건너뜀 — {type(e).__name__}: {str(e)[:160]}\n")
        return out
    for a in (doc.get("aliases", []) if isinstance(doc, dict) else []):
        try:
            out.append((str(a["product"]).lower(), str(a["code"]).upper(),
                        re.compile(a["regex"], re.IGNORECASE)))
        except Exception:
            continue
    return out


def alias_code(aliases, product: str, message: str) -> str | None:
    p = product.lower()
    for prod, code, pat in aliases:
        if prod == p and pat.search(message):
            return code
    return None


def lookup(db: dict[str, CodeEntry], product: str, code: str | None) -> CodeEntry | None:
    if not code:
        return None
    c = code.upper()
    return db.get(f"{product.lower()}:{c}") or db.get(c)
