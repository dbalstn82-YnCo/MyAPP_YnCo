"""현장 시범 묶음(9차 아이디어 ④) — 상용 DB 처럼 시험 환경이 없는 제품의 '실행' 근거를 처음으로 현장에서 받는다.

  make  : 그 제품의 **읽기 전용(복사 허용) 1차 명령** N개를 고른다 — 미검증 표시가 있는 판정 먼저, 그다음 치명·오류 순.
          현장 담당자용 안내(md)와 보고 양식(csv: 번호·판정 키·명령 지문·명령·결과(성공/오류)·오류 코드·머리글 한 줄)을 만든다.
          명령 원문만 들어간다 — 고객 로그·호스트·계정은 없다. 비밀번호가 들어가는 명령은 애초에 복사 불가라 고르지 않는다.
  import: 돌아온 양식을 앱과 **같은 검사 규칙**(storage.add_exec_report — 머리글 이름 꼴·숫자 4개 이상 거절·오류 코드 꼴)으로 읽어
          임시 사이트 DB 에 넣고 import_field_exec 로 _verification.yaml field_exec 에 '현장 보고'로 들인다(출처 = --site, 다시 넣어도 두 번 안 셈).
          한 줄이라도 규칙에 어긋나면 그 줄만 거절하고 사유를 보고한다(통째 실패 아님 — 현장 손 기록이라). 들인 기록은 반입기록.jsonl.
  한계(GPT 70차): --site 는 들이는 사람이 정한다 — 출처 위조를 막지 못한다(엔진 PC 운영자의 책임). 양식은 사람이 적은 보고이지 실행의 독립 증거가 아니다.
사용: python tools/build/field_pilot.py make --product tibero [--n 20]
      python tools/build/field_pilot.py import <양식.csv> --site <사이트ID> [--actor 담당자]
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import knowledge_quality as KQ  # noqa: E402

OUT = ENGINE / "deploy" / "local" / "지식검증" / "현장시범"
COLS = ["번호", "판정 키", "명령 지문", "명령", "결과(성공/오류)", "오류 코드", "머리글 한 줄(칼럼 이름만)"]
LOG = OUT / "반입기록.jsonl"
_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def cell(v: str) -> str:
    """GPT 70차: 양식을 표 계산 프로그램으로 열 때 = + - @ 로 시작하는 칸이 수식으로 실행되지 않게 앞에 ' 를 붙인다(OWASP CSV injection)."""
    v = str(v)
    return "'" + v if _risky(v) else v


def _risky(v: str) -> bool:
    # GPT 72차 전 자체 왕복 시험에서 발견: 원래 값이 '-rf · '=x 처럼 따옴표+수식 문자면 uncell 이 따옴표를 떼 값이 바뀌었다.
    # 따옴표를 걷어 낸 첫 글자가 수식 문자인 칸은 모두 하나 더 붙이고(cell), 하나만 뗀다(uncell) — 손대지 않은 칸은 정확히 왕복.
    # 한계: 표 계산 프로그램에서 고쳐 저장하면 그 프로그램이 맨 앞 ' 를 표시 기호로 먹을 수 있다(그 경우는 값 그대로 반입·사람 확인).
    return v.lstrip("'")[:1] in _FORMULA and v.lstrip("'") != ""


def uncell(v: str) -> str:
    v = str(v)
    return v[1:] if v.startswith("'") and _risky(v) else v


def pick(product: str, n: int) -> list:
    import knowledge_sample_queue as q
    out, seen = [], set()
    ents = [x for x in q.entries() if str(x["product"]).lower().startswith(product.lower())]
    ents.sort(key=lambda x: (not x["verify_note"], {"critical": 0, "error": 1}.get(x["severity"], 2), x["key"]))
    for x in ents:
        for c in KQ.first_commands(x["immediate"]):
            if not c["safe"] or c["hash"] in seen:
                continue
            seen.add(c["hash"])
            out.append({"key": x["key"], "hash": c["hash"], "cmd": c["cmd"], "unverified": bool(x["verify_note"])})
            break
        if len(out) >= n:
            break
    return out


def make(a) -> int:
    cmds = pick(a.product, a.n)
    if not cmds:
        print("고를 읽기 전용 명령이 없습니다")
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    stem = f"{a.product}-시범"
    with (OUT / f"{stem}-보고양식.csv").open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(COLS)
        for i, c in enumerate(cmds, 1):
            w.writerow([i, cell(c["key"]), c["hash"], cell(c["cmd"]), "", "", ""])
    md = [f"# 현장 시범 — {a.product} 읽기 전용 1차 명령 {len(cmds)}개\n",
          "담당자께: 아래 명령을 **시험·운영 영향이 없는 시간에** 그대로 실행하고, 보고 양식(csv)에 결과만 적어 주십시오.",
          "- 결과: 성공 / 오류  · 오류 코드: ORA-00942 · TBR-17004 같은 코드만(문장 쓰지 않음)",
          "- 머리글 한 줄: 출력 첫 줄의 **칼럼 이름만**(예: `TYPE ID1 ID2 SESS_ID`). 값 줄·호스트·계정은 적지 마십시오.",
          "- `<…>` 자리는 현장 값으로 바꿔 실행하되, 양식에는 바꾼 값을 적지 않습니다. 비밀번호는 접속 프롬프트에서만 입력합니다.",
          "- 이 보고는 '명령이 돌았다'의 근거일 뿐 진단이 맞았다는 뜻이 아닙니다.\n",
          "| # | 판정 | 미확인 표시 | 명령 |", "|---|---|---|---|"]
    md += [f"| {i} | `{c['key']}` | {'있음' if c['unverified'] else ''} | `{c['cmd'][:160]}` |" for i, c in enumerate(cmds, 1)]
    (OUT / f"{stem}-안내.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"{len(cmds)}개(미확인 표시 {sum(c['unverified'] for c in cmds)}) → {OUT / (stem + '-안내.md')} · {stem}-보고양식.csv")
    return 0


def do_import(a) -> int:
    from logtriage import storage
    import import_field_exec as ife
    rows = list(csv.reader(Path(a.csv).read_text(encoding="utf-8-sig").splitlines()))
    if not rows or rows[0][:len(COLS)] != COLS:
        print("양식 머리글이 다릅니다 — make 로 만든 양식을 그대로 쓰십시오")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="lt-pilot-"))
    try:
        st = storage.Storage("sqlite:///" + (tmp / "logtriage.db").as_posix())
        ok, bad = 0, []
        for r in rows[1:]:
            r = [uncell(x) for x in r]
            if len(r) < len(COLS) or not r[4].strip():
                continue   # 아직 안 돌린 줄
            status = {"성공": "ok", "오류": "error"}.get(r[4].strip(), "")
            heads = [h for h in r[6].replace("|", " ").replace(",", " ").split() if h]
            try:
                st.add_exec_report(r[1], r[2], status, r[5].strip(), heads, actor={"login": a.actor}, incident_id=f"pilot-{r[0]}")
                ok += 1
            except ValueError as e:
                bad.append(f"{r[0]}번: {e}")
        if ok:
            ife.main(["--db", str(tmp / "logtriage.db"), "--site", a.site])
        import hashlib as _h
        import time as _t
        LOG.parent.mkdir(parents=True, exist_ok=True)
        with LOG.open("a", encoding="utf-8") as fh:   # GPT 70차: 누가·어느 양식(지문)을·어느 사이트로 들였는지, 거절 줄과 사유
            fh.write(json.dumps({"at": _t.strftime("%Y-%m-%d %H:%M:%S"), "csv_sha": _h.sha256(Path(a.csv).read_bytes()).hexdigest()[:16],
                                 "site": a.site, "actor": a.actor, "ok": ok, "rejected": bad}, ensure_ascii=False) + "\n")
        print(f"들임 {ok}줄 · 거절 {len(bad)}줄" + (" — " + " / ".join(bad[:5]) if bad else ""))
        return 0 if not bad else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--product", required=True)
    m.add_argument("--n", type=int, default=20)
    i = sub.add_parser("import")
    i.add_argument("csv")
    i.add_argument("--site", required=True)
    i.add_argument("--actor", default="현장 담당")
    a = ap.parse_args(argv)
    return make(a) if a.cmd == "make" else do_import(a)


if __name__ == "__main__":
    sys.exit(main())
