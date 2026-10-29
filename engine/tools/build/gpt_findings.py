"""GPT 지적 장부(9차 아이디어 ⑨) — 교차 검증이 대화창에만 남지 않게, 회차마다 지적·우리 판단·고친 곳·지키는 시험을 구조화해 남긴다.

  · 줄 = {round, id, area, finding, decision(수용|불수용|부분 수용), reason, where, test}
  · check: ① '수용'인데 test 칸이 비었거나 그 시험 함수가 tests/ 에 없음 → 실패(고쳤다는 말을 시험이 지키지 않음)
           ② 서로 다른 회차에서 같은 영역·비슷한 지적(낱말 겹침 0.5 이상)이 '수용' 뒤 다시 나옴 → '되풀이 지적'(고친 것이 안 고쳐졌거나 범위가 좁았음)
  · GPT 는 답이 아니라 반대 검토자다 — 불수용도 사유와 함께 남긴다.
사용: python tools/build/gpt_findings.py add --round 70 --id 70-P0-1 --area ③ --finding "…" --decision 수용 --reason "…" --where 파일 --test 시험이름
      python tools/build/gpt_findings.py check
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
LEDGER = ENGINE / "deploy" / "local" / "지식검증" / "GPT지적장부.jsonl"
DECISIONS = ("수용", "불수용", "부분 수용")
TOK = re.compile(r"[A-Za-z][A-Za-z0-9_$.-]{2,}|[가-힣]{2,}")


def rows() -> list:
    try:
        return [json.loads(l) for l in LEDGER.read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError:
        return []


def add(a) -> int:
    if a.decision not in DECISIONS:
        print("decision 은", DECISIONS)
        return 2
    if a.decision != "불수용" and not a.test.strip():
        print("수용한 지적은 그것을 지키는 시험 이름(test)을 적어야 합니다")
        return 2
    if not a.reason.strip():
        print("판단 사유를 적으십시오")
        return 2
    if any(r["id"] == a.id for r in rows()):
        print("같은 id 가 이미 있습니다:", a.id)
        return 2
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    row = {"at": time.strftime("%Y-%m-%d %H:%M"), "round": str(a.round), "id": a.id, "area": a.area, "finding": a.finding[:400],
           "decision": a.decision, "reason": a.reason[:400], "where": a.where[:200], "test": a.test[:200]}
    with LEDGER.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("기록:", row["id"], row["decision"])
    return 0


def _test_names() -> set:
    out = set()
    for f in (ENGINE / "tests").glob("test_*.py"):
        out |= set(re.findall(r"^\s+def (test_\w+)", f.read_text(encoding="utf-8"), re.M))
    return out


def _toks(t: str) -> set:
    return {w.lower() for w in TOK.findall(t or "")}


def check(_a=None) -> dict:
    rs = rows()
    names = _test_names()
    missing = [r for r in rs if r["decision"] != "불수용" and not all(t.strip().split(".")[-1] in names for t in r["test"].split(",") if t.strip())]
    no_test = [r for r in rs if r["decision"] != "불수용" and not r["test"].strip()]
    repeat = []
    for i, a in enumerate(rs):
        for b in rs[i + 1:]:
            if a["round"] == b["round"] or a["area"] != b["area"] or a["decision"] == "불수용":
                continue
            ta, tb = _toks(a["finding"]), _toks(b["finding"])
            if ta and tb and len(ta & tb) / len(ta | tb) >= 0.5:
                repeat.append((a["id"], b["id"]))
    out = {"rows": len(rs), "missing_test": [r["id"] for r in missing + no_test], "repeat": repeat}
    md = ["# GPT 지적 장부 — 점검\n", f"지적 {len(rs)}건 · 수용 {sum(r['decision'] == '수용' for r in rs)} · 부분 수용 {sum(r['decision'] == '부분 수용' for r in rs)}"
          f" · 불수용 {sum(r['decision'] == '불수용' for r in rs)}",
          f"시험 없는 수용 {len(out['missing_test'])}건 · 되풀이 지적 {len(repeat)}쌍\n",
          "| 회차 | id | 영역 | 지적 | 판단 | 사유 | 고친 곳 | 지키는 시험 |", "|---|---|---|---|---|---|---|---|"]
    md += [f"| {r['round']} | {r['id']} | {r['area']} | {r['finding'][:80]} | {r['decision']} | {r['reason'][:80]} | {r['where']} | {r['test']} |" for r in rs]
    if repeat:
        md += ["\n## 되풀이 지적\n"] + [f"- {x} ↔ {y}" for x, y in repeat]
    LEDGER.with_name("GPT지적장부.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"지적 {len(rs)}건 · 시험 없는 수용 {len(out['missing_test'])}건 {out['missing_test'][:5]} · 되풀이 {len(repeat)}쌍 {repeat[:5]}")
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add")
    for k in ("--round", "--id", "--area", "--finding", "--decision", "--reason"):
        p.add_argument(k, required=True)
    p.add_argument("--where", default="")
    p.add_argument("--test", default="")
    c = sub.add_parser("check")
    c.add_argument("--run", action="store_true", help="장부에 적힌 시험을 실제로 돌려 통과하는지(존재만이 아니라)")
    a = ap.parse_args(argv)
    if a.cmd == "add":
        return add(a)
    r = check(a)
    if getattr(a, "run", False):
        fails = run_tests()
        r["failed_tests"] = fails
        print(f"장부 시험 실행: 실패 {len(fails)} {fails[:5]}")
        return 1 if (r["missing_test"] or fails) else 0
    return 1 if r["missing_test"] else 0


def run_tests() -> list:
    """GPT 70차: 시험 이름이 있다는 것만으로는 지적이 지켜진다는 보장이 없다 — 적힌 시험을 실제로 돌린다(돌연변이 연결은 따로)."""
    import subprocess
    names = sorted({t.strip().split(".")[-1] for r in rows() if r["decision"] != "불수용" for t in r["test"].split(",") if t.strip()})
    where = {}
    for f in (ENGINE / "tests").glob("test_*.py"):
        src = f.read_text(encoding="utf-8")
        cls = None
        for line in src.splitlines():
            m = re.match(r"class (\w+)\(", line)
            if m:
                cls = m.group(1)
            m = re.match(r"\s+def (test_\w+)", line)
            if m and m.group(1) in names and cls:
                where.setdefault(m.group(1), f"tests.{f.stem}.{cls}.{m.group(1)}")
    ids = [where[n] for n in names if n in where]
    r = subprocess.run([sys.executable, "-m", "unittest"] + ids, cwd=str(ENGINE), capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})
    return re.findall(r"^(?:FAIL|ERROR): (\w+)", r.stderr, re.M) + ([] if r.returncode == 0 or re.search(r"^(?:FAIL|ERROR):", r.stderr, re.M) else ["(실행 실패)"])


if __name__ == "__main__":
    sys.exit(main())
