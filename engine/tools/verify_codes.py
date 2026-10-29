"""GPT 수집 코드의 벤더 문서 대조 캠페인 도구.

  batch   : 미검증 코드(source 에 '대조 필요')를 제품별로 N개씩 묶어 GPT 검토 프롬프트 텍스트 생성
  apply   : GPT 응답(';;' 형식)을 코드 사전에 반영 — 판정 OK→source 'GPT 수집·벤더 문서 대조 완료(URL)',
            수정→title/severity/category 갱신 후 동일 표기, 삭제→항목 제거(불확실·존재하지 않는 코드)

응답 형식(한 줄): 제품;;코드;;판정(OK|수정|삭제);;정확한 의미(한글 20자);;심각도;;유형;;출처 URL;;비고
사용:
  python tools/verify_codes.py batch <출력폴더> [제품당 개수=40]
  python tools/verify_codes.py apply <응답txt>
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import yaml

E = Path(__file__).resolve().parents[1]
CODES = E / "errorcodes"
PENDING = "대조 필요"


def _load_all():
    docs = {}
    for f in sorted(CODES.glob("*.yaml")):
        if f.name.startswith("_"):
            continue
        docs[f] = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    return docs


def batch(out_dir: Path, per: int = 40):
    out_dir.mkdir(parents=True, exist_ok=True)
    by_prod: dict[str, list] = defaultdict(list)
    for f, d in _load_all().items():
        for e in d.get("codes", []):
            if PENDING in str(e.get("source", "")):
                by_prod[str(d.get("product", "")).lower()].append(e)
    n = 0
    for prod, entries in sorted(by_prod.items()):
        for i in range(0, len(entries), per):
            chunk = entries[i:i + per]
            lines = [f"{prod};;{e['code']};;{e.get('title', '')};;{e.get('severity', '')};;{e.get('category', '')}"
                     for e in chunk]
            (out_dir / f"verify_{prod}_{i // per + 1:02d}.txt").write_text("\n".join(lines), encoding="utf-8")
            n += 1
    print(f"배치 {n}개 생성 · 미검증 코드 {sum(len(v) for v in by_prod.values())}건")


def apply(resp: Path):
    docs = _load_all()
    verdicts = {}
    for raw in resp.read_text(encoding="utf-8").splitlines():
        p = [x.strip() for x in raw.split(";;")]
        if len(p) < 4 or p[0].upper() == "SRC":
            continue
        verdicts[(p[0].lower(), p[1].upper())] = p
    ok = fixed = removed = 0
    for f, d in docs.items():
        prod = str(d.get("product", "")).lower()
        changed = False
        keep = []
        for e in d.get("codes", []):
            v = verdicts.get((prod, str(e["code"]).upper()))
            if not v:
                keep.append(e)
                continue
            verdict = v[2].upper()
            url = v[6] if len(v) > 6 else ""
            if verdict.startswith("삭제") or verdict == "DELETE":
                # 실존 코드를 '공식 문서 미확인'만으로 지우지 않는다 — 보류로 남기고 근거·사유 기록
                e["source"] = "GPT 수집·공식 문서 미확인(보류)" + (f"({url})" if url and url != "-" else "")
                if len(v) > 7 and v[7]:
                    e["note"] = v[7][:120]
                removed += 1
                keep.append(e)
                changed = True
                continue
            if verdict.startswith("수정") or verdict == "FIX":
                if len(v) > 3 and v[3]:
                    e["title"] = v[3][:40]
                if len(v) > 4 and v[4] in ("critical", "error", "warn", "info"):
                    e["severity"] = v[4]
                if len(v) > 5 and v[5]:
                    e["category"] = v[5]
                fixed += 1
            else:
                ok += 1
            e["source"] = f"GPT 수집·벤더 문서 대조 완료({url})" if url else "GPT 수집·벤더 문서 대조 완료"
            if len(v) > 7 and v[7]:
                e["note"] = v[7][:120]
            keep.append(e)
            changed = True
        if changed:
            d["codes"] = keep
            f.write_text(yaml.safe_dump(d, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    print(f"반영: OK {ok} · 수정 {fixed} · 삭제 {removed} · 응답 {len(verdicts)}건")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    if sys.argv[1] == "batch":
        batch(Path(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 40)
    elif sys.argv[1] == "apply":
        apply(Path(sys.argv[2]))
