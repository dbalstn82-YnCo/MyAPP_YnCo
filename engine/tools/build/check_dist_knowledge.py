"""배포 폴더 지식(룰·코드·별칭) 정합성 검사 — GPT UI 20차 권고(2026-10-15).

exe 와 따로 복사되는 rules·errorcodes 가 설치 때 빠지거나(10-14 설치에서 1차 학습 룰 26개 누락) 배포 폴더에만 있는
지식이 덮여 사라지지 않게, 복사 **전후**에 엔진과 배포 폴더를 비교한다. 의도하지 않은 차이가 있으면 1 로 끝나 배포를 멈춘다.

  --before : 복사 전. 배포 폴더에만 있는 룰 ID·코드·별칭·파일이 있으면 멈춘다(덮으면 사라짐 — 룰팩 반입분인지 먼저 확인).
             단 retired_knowledge.txt 에 적은 '일부러 고친/뺀' 항목은 예외.
  --after  : 복사 후. 엔진과 배포 폴더의 rules·errorcodes 파일 SHA-256 이 모두 같아야 한다. 매니페스트를 배포 폴더에 남긴다.
사이트 룰(rules-local)·사용자 서식(report-template/custom)은 현장 것이라 비교하지 않는다.

사용: python tools/build/check_dist_knowledge.py --before|--after [--dist deploy/local/dist]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage.codes import load_codes  # noqa: E402
from logtriage.rules import load_rules  # noqa: E402
from logtriage import yamlsafe  # noqa: E402

KNOW = ("rules", "errorcodes", "manuals")   # 매뉴얼·절차도 해시로 묶는다(2026-10-16 아이디어 10 — 추가·삭제·변경 감지)
RETIRED = Path(__file__).with_name("retired_knowledge.txt")
MANIFEST = "knowledge-manifest.json"


def _files(root: Path, sub: str) -> dict[str, str]:
    d = root / sub
    out = {}
    if d.is_dir():
        for f in sorted(d.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and f.suffix.lower() in (".yaml", ".yml", ".json", ".txt", ".md"):
                out[f.relative_to(root).as_posix()] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def _aliases(root: Path) -> set[str]:
    p = root / "errorcodes" / "_aliases.yaml"
    if not p.exists():
        return set()
    data = yamlsafe.load(p.read_text(encoding="utf-8"))   # 못 읽으면 예외 그대로 — 조용히 0개로 통과시키지 않는다
    items = data.get("aliases", data) if isinstance(data, dict) else data
    return {f"alias|{x.get('product')}|{x.get('code')}|{x.get('regex')}" for x in (items or []) if isinstance(x, dict)}


def inventory(root: Path) -> dict:
    rules = {f"rule|{r.id}" for r in load_rules(root / "rules", None)}
    codes = {f"code|{k}" for k in load_codes(root / "errorcodes")}
    files = {}
    for s in KNOW:
        files.update(_files(root, s))
    return {"rules": rules, "codes": codes, "aliases": _aliases(root), "files": files}


def retired() -> set[str]:
    if not RETIRED.exists():
        return set()
    return {ln.strip() for ln in RETIRED.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")}


def check(engine: Path, dist: Path, phase: str) -> list[str]:
    e, d = inventory(engine), inventory(dist)
    problems = []
    if phase == "before":
        ok = retired()
        for kind in ("rules", "codes", "aliases"):
            extra = sorted(d[kind] - e[kind] - ok)
            if extra:
                problems.append(f"배포 폴더에만 있는 {kind} {len(extra)}건(덮으면 사라짐): {extra[:5]}")
        only = sorted(set(d["files"]) - set(e["files"]) - {x.split("|", 1)[1] for x in ok if x.startswith("file|")})
        if only:
            problems.append(f"배포 폴더에만 있는 파일 {len(only)}개: {only[:5]}")
    else:
        diff = sorted(k for k in set(e["files"]) | set(d["files"]) if e["files"].get(k) != d["files"].get(k))
        if diff:
            problems.append(f"복사 뒤에도 엔진과 다른 파일 {len(diff)}개: {diff[:5]}")
        for kind in ("rules", "codes", "aliases"):
            if len(e[kind]) != len(d[kind]):
                problems.append(f"{kind} 개수 다름: 엔진 {len(e[kind])} · 배포 {len(d[kind])}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--before", action="store_true")
    g.add_argument("--after", action="store_true")
    ap.add_argument("--dist", default=str(ENGINE / "deploy" / "local" / "dist"))
    ap.add_argument("--engine", default=str(ENGINE))
    a = ap.parse_args(argv)
    dist, eng = Path(a.dist), Path(a.engine)
    phase = "before" if a.before else "after"
    if phase == "before" and not (dist / "rules").exists():
        print("[지식 검사] 배포 폴더에 rules 없음 — 새 설치로 보고 통과")
        return 0
    probs = check(eng, dist, phase)
    if probs:
        print(f"[지식 검사 · {phase}] 멈춤 — 의도하지 않은 차이:")
        for p in probs:
            print("  -", p)
        print("  룰팩으로 들어온 지식이면 엔진에 먼저 반영하고, 일부러 뺀 것이면 tools/build/retired_knowledge.txt 에 적으십시오.")
        return 1
    if phase == "after":
        inv = inventory(dist)
        (dist / MANIFEST).write_text(json.dumps({"rules": len(inv["rules"]), "codes": len(inv["codes"]), "aliases": len(inv["aliases"]),
                                                 "files": inv["files"],
                                                 # GPT 71차: 세대 기록 시대의 설치 — 기록 파일이 사라지면 '옛 설치'로 넘기지 않고 기동 거부(knowledge_gen.check_gen)
                                                 "gen_era": (dist / "knowledge-gen.json").is_file()}, ensure_ascii=False, indent=1), encoding="utf-8")
    inv = inventory(eng)
    print(f"[지식 검사 · {phase}] 통과 — 룰 {len(inv['rules'])} · 코드 {len(inv['codes'])} · 별칭 {len(inv['aliases'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
