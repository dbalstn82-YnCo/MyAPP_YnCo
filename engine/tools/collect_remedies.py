"""에러 코드별 제조사 제공 원인(Cause)·조치(Action) 수집 캠페인 도구.

  batch : 벤더 문서 대조 완료 코드 중 vendor_cause/vendor_action 이 없는 것을 제품별 N개씩 묶어
          GPT 요청용 텍스트 생성 (한 줄: 제품;;코드;;의미;;출처URL)
  apply : GPT 응답(';;' 형식)을 코드 사전에 반영
          응답 한 줄: 제품;;코드;;원인;;조치;;출처 URL  ('-' 또는 빈칸이면 미기재)

의사코드(메시지 별칭 기반)·보류 코드는 제조사 문서가 없으므로 대상에서 제외한다.
사용:
  python tools/collect_remedies.py batch <출력폴더> [제품당 개수=50]
  python tools/collect_remedies.py apply <응답txt>
  python tools/collect_remedies.py stat
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml

E = Path(__file__).resolve().parents[1]
CODES = E / "errorcodes"
VERIFIED = "대조 완료"


def _load_all():
    docs = {}
    for f in sorted(CODES.glob("*.yaml")):
        if f.name.startswith("_"):
            continue
        docs[f] = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
    return docs


def _url_of(src: str) -> str:
    m = re.search(r"\((https?://[^)]+)\)", src or "")
    return m.group(1) if m else ""


def _targets():
    by_prod: dict[str, list] = defaultdict(list)
    for f, d in _load_all().items():
        for e in d.get("codes", []):
            src = str(e.get("source", ""))
            if VERIFIED not in src:
                continue
            if e.get("vendor_cause") or e.get("vendor_action") or e.get("vendor_note"):
                continue
            by_prod[str(d.get("product", "")).lower()].append(e)
    return by_prod


def batch(out_dir: Path, per: int = 50):
    out_dir.mkdir(parents=True, exist_ok=True)
    by_prod = _targets()
    n = 0
    for prod, entries in sorted(by_prod.items()):
        for i in range(0, len(entries), per):
            chunk = entries[i:i + per]
            lines = [f"{prod};;{e['code']};;{e.get('title', '')};;{_url_of(str(e.get('source', '')))}"
                     for e in chunk]
            (out_dir / f"remedy_{prod}_{i // per + 1:02d}.txt").write_text("\n".join(lines), encoding="utf-8")
            n += 1
    print(f"배치 {n}개 생성 · 원인·조치 미수집 코드 {sum(len(v) for v in by_prod.values())}건")


def apply(resp: Path):
    docs = _load_all()
    rows = {}
    for raw in resp.read_text(encoding="utf-8").splitlines():
        p = [x.strip() for x in raw.split(";;")]
        if len(p) < 4 or p[0].upper() == "SRC":
            continue
        rows[(p[0].lower(), p[1].upper())] = p
    filled = skipped = 0
    for f, d in docs.items():
        prod = str(d.get("product", "")).lower()
        changed = False
        for e in d.get("codes", []):
            v = rows.get((prod, str(e["code"]).upper()))
            if not v:
                continue
            cause = v[2] if v[2] not in ("-", "") else ""
            action = v[3] if len(v) > 3 and v[3] not in ("-", "") else ""
            url = v[4] if len(v) > 4 and v[4] not in ("-", "") else _url_of(str(e.get("source", "")))
            if not cause and not action:
                e["vendor_cause"] = ""
                e["vendor_action"] = ""
                e["vendor_note"] = "제조사 문서에 원인·조치 항목 없음"
                skipped += 1
            else:
                e["vendor_cause"] = cause[:200]
                e["vendor_action"] = action[:240]
                e.pop("vendor_note", None)
                filled += 1
            if url:
                e["vendor_url"] = url
            changed = True
        if changed:
            f.write_text(yaml.safe_dump(d, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    print(f"반영: 원인·조치 등재 {filled} · 문서에 없음 {skipped} · 응답 {len(rows)}건")


def stat():
    tot = have = none = 0
    for f, d in _load_all().items():
        for e in d.get("codes", []):
            if VERIFIED not in str(e.get("source", "")):
                continue
            tot += 1
            if e.get("vendor_cause") or e.get("vendor_action"):
                have += 1
            elif e.get("vendor_note"):
                none += 1
    print(f"대조 완료 코드 {tot} · 원인·조치 등재 {have} · 문서에 없음 {none} · 미수집 {tot - have - none}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    if sys.argv[1] == "batch":
        batch(Path(sys.argv[2]), int(sys.argv[3]) if len(sys.argv) > 3 else 50)
    elif sys.argv[1] == "apply":
        apply(Path(sys.argv[2]))
    elif sys.argv[1] == "stat":
        stat()
