"""절차 연결 감사 도구 — 본체는 logtriage/kb_audit.py(설치본 화면과 같은 코드). 결과를 지식검증 폴더에 md·json 으로 남긴다.
사용: python tools/build/knowledge_link_audit.py [--out deploy/local/지식검증]"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage.kb_audit import audit, fitness, toks, verdicts, reviewed_pairs, known_ids  # noqa: E402,F401


def import_approvals(src: Path) -> int:
    """현장 결정 이력(jsonl)을 엔진 manuals/_link_approvals.json 에 합친다 — 같은 (시각·절차·ID·결정·결정자) 줄은 한 번만."""
    from logtriage.link_review import DECISIONS, ENGINE_FILE
    dst = ENGINE / ENGINE_FILE
    try:
        cur = json.loads(dst.read_text(encoding="utf-8")).get("decisions") or []
    except (OSError, ValueError):
        cur = []
    key = lambda r: (round(float(r.get("ts") or 0), 3), r.get("procedure"), str(r.get("id", "")).upper(), r.get("decision"), r.get("by"))  # noqa: E731
    have = {key(r) for r in cur}
    n = 0
    for ln in src.read_text(encoding="utf-8").splitlines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(r, dict) or r.get("decision") not in DECISIONS or key(r) in have:
            continue
        cur.append({k: r.get(k) for k in ("ts", "at", "procedure", "id", "decision", "by", "note", "via")})
        have.add(key(r))
        n += 1
    cur.sort(key=lambda r: float(r.get("ts") or 0))
    dst.write_text(json.dumps({"note": "관리자 [연결 승인] 결정 이력 — 마지막 줄이 현재 결정(logtriage/link_review.py)", "decisions": cur},
                              ensure_ascii=False, indent=1), encoding="utf-8")
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ENGINE / "deploy" / "local" / "지식검증"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--import-approvals", default="", help="설치본 data/link_approvals.jsonl — 관리자 결정을 manuals/_link_approvals.json 에 합친다(8차 ②)")
    a = ap.parse_args(argv)
    if a.import_approvals:
        n = import_approvals(Path(a.import_approvals))
        print(f"결정 {n}줄 새로 들여옴 → {ENGINE / 'manuals' / '_link_approvals.json'}")
    r = audit(ENGINE)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "연결감사.json").write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")
    md = [f"# 절차 연결 감사\n", f"- 유령 연결(사전·룰·별칭에 없는 ID): {len(r['ghosts'])}건",
          f"- '이 판정 전용'인데 판정 제목 핵심어가 절차에 하나도 없음(검토 대상, 오류 확정 아님): {len(r['low_fit'])}건",
          f"- 매칭 모호: {sum(1 for x in r['rows'] if x['ambiguous'])}건\n", "## 적합성 낮음(낮은 순)\n", "| 판정 | 제품 | 절차 | 겹침 |", "|---|---|---|---|"]
    md += [f"| `{x['key']}` | {x['product']} | {x['procedure']} | {x['fit']} |" for x in r["low_fit"]]
    from logtriage import link_review as LR
    its = LR.items(ENGINE)
    cnt = {k: sum(1 for x in its if x["state"] == k) for k in ("대기", "승인", "묶음 승인", "반려")}
    ind = sum(1 for x in its if x["state"] == "대기" and x["individual"])
    md += [f"\n## 검토 기록으로 대기열에서 뺀 연결 — 승인 {cnt['승인']} · 묶음 승인(개별 검토 아님) {cnt['묶음 승인']} · 대기 {cnt['대기']}"
           f"(그중 한 건씩 볼 것 {ind}) · 반려 {cnt['반려']}(반려는 위 대기열로 돌아감)\n",
           "fit_reviewed 는 '이 절차의 1차가 이 판정을 진단한다'는 검토자 판단과 사유일 뿐 승인이 아닙니다(GPT 60차). 승인·반려는 관리자 화면 [연결 승인]에서 하고\n"
           "`--import-approvals <설치본 data/link_approvals.jsonl>` 로 엔진에 들여옵니다(8차 ②).\n",
           "| 절차 | 판정 | 위험도 | 한 건씩 볼 까닭 | 상태 | 결정자 |", "|---|---|---|---|---|---|"] + [
           f"| {x['procedure']} | `{x['id']}` | {x['danger']} | {' · '.join(x['individual'])} | {x['state']} | {x['by']} |" for x in its]
    md += ["\n## 유령 연결\n", "| 절차 | 파일 | ID |", "|---|---|---|"] + [f"| {g['procedure']} | {g['file']} | `{g['id']}` |" for g in r["ghosts"]]
    (out / "연결감사.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"유령 {len(r['ghosts'])} · 적합성 낮음 {len(r['low_fit'])} · 판정 {len(r['rows'])} → {out / '연결감사.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
