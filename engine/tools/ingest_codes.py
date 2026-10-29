"""GPT 협업 수집 결과(';;' 구분 텍스트) → errorcodes/*.yaml 등재.

입력 형식(한 줄 = 한 항목):
  제품;;코드;;심각도;;유형;;제목;;즉시조치;;단기조치;;중기조치;;장기조치
- 기존 사전에 있는 (제품,코드)는 건너뜀
- 심각도/유형 값이 허용 목록 밖이면 보정(error/etc)
- 출처 표기: source=GPT 수집(벤더 문서 대조 필요)

사용: python tools/ingest_codes.py <입력텍스트파일> <errorcodes폴더> <출력파일명접두>
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

SEV = {"critical", "error", "warn"}
CAT = {"memory", "lock", "connection", "thread", "disk", "storage", "hardware",
       "upstream", "capacity", "internal", "undo", "security"}
LAYER_OF = {"oracle": "db", "mysql": "db", "mssql": "db", "postgresql": "db",
            "tibero": "db", "altibase": "db", "cubrid": "db", "goldilocks": "db", "db2": "db",
            "tomcat": "was", "jeus": "was", "weblogic": "was", "jboss": "was", "websphere": "was",
            "nginx": "web", "apache": "web", "iis": "web", "webtob": "web",
            "linux": "os", "windows": "os", "solaris": "os", "aix": "os", "hpux": "os",
            "auditd": "os", "java": "sw", "mesim-esb": "sw", "mesim-apig": "sw", "mesim-eai": "sw"}


def existing_codes(codes_dir: Path) -> set[tuple[str, str]]:
    seen = set()
    for f in codes_dir.rglob("*.yaml"):
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        prod = str(doc.get("product", "")).lower()
        for e in doc.get("codes", []):
            seen.add((str(e.get("product", prod)).lower(), str(e["code"]).upper()))
    return seen


def normalize_code(product: str, code: str) -> str:
    code = code.strip().upper()
    if product == "mssql" and re.fullmatch(r"\d+", code):
        return f"MSSQL-{code}"
    if product == "mysql" and re.fullmatch(r"\d+", code):
        return f"MY-{code}"
    return code


def main() -> int:
    src, codes_dir, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    seen = existing_codes(codes_dir)
    by_product: dict[str, list] = defaultdict(list)
    bad = dup = 0
    raw = src.read_text(encoding="utf-8")
    if raw.lstrip().startswith("["):  # 도구 결과 파일(JSON [{type,text}]) 형식 지원
        try:
            import json as _json
            raw = "\n".join(str(x.get("text", "")) for x in _json.loads(raw) if isinstance(x, dict))
        except Exception:
            pass
    for line in raw.splitlines():
        line = line.strip().strip("`")
        if ";;" not in line:
            continue
        parts = [p.strip() for p in line.split(";;")]
        if len(parts) < 9 or parts[0].lower() not in LAYER_OF:
            bad += 1
            continue
        prod = parts[0].lower()
        code = normalize_code(prod, parts[1])
        if not code or (prod, code) in seen:
            dup += 1
            continue
        seen.add((prod, code))
        sev = parts[2].lower() if parts[2].lower() in SEV else "error"
        cat = parts[3].lower() if parts[3].lower() in CAT else "internal"
        by_product[prod].append({
            "code": code, "severity": sev, "category": cat, "title": parts[4][:40],
            "immediate": [parts[5]] if parts[5] else [],
            "short": [parts[6]] if parts[6] else [],
            "mid": [parts[7]] if parts[7] else [],
            "long": [parts[8]] if parts[8] else [],
            "source": "GPT 수집(벤더 문서 대조 필요)",
        })
    total = 0
    for prod, entries in by_product.items():
        out = codes_dir / f"{prefix}_{prod}.yaml"
        # 같은 접두어 파일이 이미 있으면 덮어쓰지 않고 병합(코드 기준 중복 제거)
        if out.exists():
            try:
                prev = yaml.safe_load(out.read_text(encoding="utf-8")) or {}
                have = {str(e.get("code")).upper() for e in prev.get("codes", [])}
                entries = list(prev.get("codes", [])) + [e for e in entries if str(e.get("code")).upper() not in have]
            except Exception:
                pass
        doc = {"product": prod, "layer": LAYER_OF[prod],
               "note": "GPT 협업 수집분 — 벤더 공식 문서와 대조 후 확정", "codes": entries}
        out.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
        total += len(entries)
        print(f"  {prod}: {len(entries)}건 → {out.name}")
    print(f"등재 {total}건 · 중복/기존 {dup} · 형식 불량 {bad}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
