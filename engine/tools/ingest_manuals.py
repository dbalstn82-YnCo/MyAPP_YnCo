"""GPT 협업 수집 매뉴얼(';;' 구분 텍스트) → manuals/*.yaml 등재.

입력 형식(한 줄 = 한 섹션):
  제품;;제품명(표시용);;섹션제목;;본문
같은 제품의 줄들은 하나의 매뉴얼 문서로 묶인다. 출처 표기: GPT 수집(벤더 문서 대조 필요)
사용: python tools/ingest_manuals.py <입력텍스트파일> <manuals폴더> <출력파일명접두>
"""
from __future__ import annotations
import sys
from collections import OrderedDict
from pathlib import Path
import yaml

def main() -> int:
    src, out_dir, prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    docs: "OrderedDict[str, dict]" = OrderedDict()
    bad = 0
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
        if len(parts) < 4 or not parts[0]:
            bad += 1
            continue
        prod = parts[0].lower()
        d = docs.setdefault(prod, {"product": prod, "title": f"{parts[1]} 운영 참고 (GPT 수집 — 벤더 문서 대조 필요)", "sections": []})
        d["sections"].append({"heading": parts[2][:40], "body": parts[3][:600]})
    total = 0
    for prod, d in docs.items():
        out = out_dir / f"{prefix}_{prod}.yaml"
        out.write_text(yaml.safe_dump(d, allow_unicode=True, sort_keys=False), encoding="utf-8")
        total += len(d["sections"])
        print(f"  {prod}: 섹션 {len(d['sections'])}개 → {out.name}")
    print(f"매뉴얼 {len(docs)}개 제품 · 섹션 {total}개 · 형식 불량 {bad}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
