"""로그 종류 카탈로그(';;' 구분 텍스트) → manuals/<prefix>_<product>_logs.yaml

입력 한 줄: 제품;;로그종류;;기본 경로/파일명;;형식;;장애 시 확인 포인트[;;샘플]
'#' 주석과 'SRC;;URL' 줄은 출처로만 기록.
결과 문서는 지식 검색(kb)과 3단계 대응 계획(로그 위치·수집 자료)에서 참조된다.

사용: python tools/ingest_logtypes.py <txt> manuals <prefix>
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

LAYER_OF = {
    "windows": "os", "linux": "os", "solaris": "os", "aix": "os", "hpux": "os",
    "oracle": "db", "mysql": "db", "mssql": "db", "postgresql": "db", "tibero": "db",
    "altibase": "db", "cubrid": "db", "goldilocks": "db",
    "tomcat": "was", "weblogic": "was", "jboss": "was", "websphere": "was", "jeus": "was",
    "apache": "web", "nginx": "web", "iis": "web", "webtob": "web",
    "java": "sw", "mesim-esb": "sw", "mesim-apig": "sw", "mesim-eai": "sw", "bizmaster-adapter": "sw", "bizmaster-app": "sw",
}


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    src, out_dir, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    by_prod: dict[str, list[dict]] = defaultdict(list)
    sources: list[str] = []
    bad = 0
    for raw in src.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(";;")]
        if parts[0].upper() == "SRC" and len(parts) >= 2:
            sources.append(parts[1])
            continue
        if len(parts) < 5:
            bad += 1
            continue
        prod = parts[0].lower()
        by_prod[prod].append({
            "name": parts[1], "path": parts[2], "format": parts[3],
            "check": parts[4], "sample": parts[5] if len(parts) > 5 else "",
        })
    out_dir.mkdir(parents=True, exist_ok=True)
    total = 0
    for prod, items in by_prod.items():
        # 로그 종류별 섹션 + 요약 섹션 (경로 목록) — 대응 계획의 '로그 위치' 참조용
        sections = [{
            "heading": "로그 종류 카탈로그 (전수)",
            "body": " · ".join(f"{it['name']}: {it['path']}" for it in items),
        }]
        for it in items:
            body = f"경로 {it['path']} / 형식 {it['format']} / 확인 {it['check']}"
            if it["sample"]:
                body += f" / 샘플 {it['sample']}"
            sections.append({"heading": f"로그: {it['name']}", "body": body})
        doc = {
            "product": prod,
            "layer": LAYER_OF.get(prod, "sw"),
            "title": f"{prod} 로그 종류 카탈로그 (GPT 수집 — 벤더 문서 대조 필요)",
            "source": "GPT 수집(벤더 문서 대조 필요)",
            "sources": sources,
            "logtypes": items,
            "sections": sections,
        }
        path = out_dir / f"{prefix}_{prod}_logs.yaml"
        path.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=200),
                        encoding="utf-8")
        total += len(items)
        print(f"  {path.name}: {len(items)}종")
    print(f"로그 종류 {total}건 등재 · 제품 {len(by_prod)} · 형식 불량 {bad}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
