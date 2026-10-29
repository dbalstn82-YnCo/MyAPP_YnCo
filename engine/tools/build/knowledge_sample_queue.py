"""지식 표본 실검증 대기열(2026-10-16 아이디어 2 · GPT 55차) — 판마다 판정 몇 건을 골라 사람이(또는 교차 검증으로) 실제 맞는지 본다.

고르는 순서(8차 ⑫ — 층을 나눠 적는다. 어느 층도 전체 지식의 정확도로 말하지 않는다):
  0) 무작위 층(30% 이상): 아직 교차 검증 안 한 판정 집합에서 먼저 — 그 미검증 집합의 작은 표본일 뿐(GPT 64차)
  1) 가중 층 · 위험: 치명이거나 전용 절차 2차에 명령이 있는 판정 — 2차 명령의 되돌리기 어려운 동작 종류 수로 가중(1+3×종류)
  2) 가중 층 · 미확인: verify_note 가 있는 판정
  3) 가중 층 · 바뀜: 배포본 매니페스트와 해시가 다른(또는 새) 지식 파일에서 온 판정 · 새로 붙은 전용 절차(r6_*)
  4) 모자라면 다시 무작위 층에서
검토자와 승인자는 다른 사람이어야 한다(같으면 기록하지 않음 — GPT 55차 권고 ③).

사용:
  python tools/build/knowledge_sample_queue.py make [--n 10] [--seed 문자열]
      → deploy/local/지식검증/대기열.md · 대기열.json
  python tools/build/knowledge_sample_queue.py record --round R --key 제품:ID --verdict 정확|부분|오류 --reviewer 이름 --approver 이름 [--fixed] [--note 글] [--sent-sha 해시]
      → deploy/local/지식검증/결과.jsonl 에 한 줄(빌드 장부 '표본 실검증' 칸이 읽는다). 재검증 회차(R-re)에서 '정확'이면
        errorcodes/_verification.yaml 의 gpt_reverified 에 올라 배지가 '수정 후 재확인'이 된다(7차 아이디어 2).
  python tools/build/knowledge_sample_queue.py pending
      → 고침 표시 뒤 다음 회차(R-re, R-re2 …)에서 다시 보지 않은 항목과 상태(바뀜/원문 그대로) — 원문 그대로가 있으면 1(8차 ①).
  python tools/build/knowledge_sample_queue.py reverify [--round R] [--chunk 5500]
      → 고침 표시 뒤 다시 보지 않은(원문이 바뀐) 항목을 지금 지식으로 **잘림 없이** 다시 묶고 항목마다 sha256 을 붙인 문서·메시지 조각을 만든다(7차 아이디어 11).
  python tools/build/knowledge_sample_queue.py sent-check --sent 조각.txt --seen 화면에서_읽은_글.txt
      → 보낸 원문과 대화창에 실제로 올라간 글이 같은지(공백 정규화 후 sha256 대조). 같아야 기록에 '전달 확인'을 적는다.
        GPT 가 그 해시를 계산·확인했다는 뜻은 아니다 — '보낸 글 = 올라간 글'까지만(GPT 60차).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage import knowledge_quality as KQ  # noqa: E402
from logtriage.codes import load_codes  # noqa: E402
from logtriage.procedures import load_procedures, match_procedures  # noqa: E402
from logtriage.yamlsafe import load as yload  # noqa: E402

QDIR = ENGINE / "deploy" / "local" / "지식검증"
DIST = ENGINE / "deploy" / "local" / "dist"
VERDICTS = ("정확", "부분", "오류")


def entries() -> list[dict]:
    out = []
    for k, e in load_codes(ENGINE / "errorcodes").items():
        if ":" in k:
            out.append({"key": k.upper(), "kind": "code", "id": e.code, "product": e.product, "layer": e.layer, "category": e.category,
                        "severity": e.severity, "title": e.title, "cause": e.cause, "immediate": e.immediate, "verify_note": e.verify_note,
                        "file": ""})
    for f in sorted((ENGINE / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                prods = r.get("product") or ["*"]
                lay = r.get("layer")
                out.append({"key": str(r["id"]).upper(), "kind": "rule", "id": r["id"],
                            "product": str((prods if isinstance(prods, list) else [prods])[0]).lower(),
                            "layer": lay[0] if isinstance(lay, list) else lay, "category": r.get("category", "etc"),
                            "severity": r.get("severity", "error"), "title": r.get("title", r["id"]), "cause": r.get("cause", ""),
                            "immediate": r.get("immediate") or [], "verify_note": r.get("verify_note", ""),
                            "file": f.relative_to(ENGINE).as_posix()})
    return out


def changed_files() -> set[str]:
    try:
        mf = json.loads((DIST / "knowledge-manifest.json").read_text(encoding="utf-8")).get("files") or {}
    except (OSError, ValueError):
        return set()
    now = KQ.file_hashes(ENGINE)
    return {k for k, v in now.items() if mf.get(k) != v}


def make(a) -> int:
    ver = KQ.load_verification(ENGINE / "errorcodes")
    procs = load_procedures(ENGINE / "manuals")
    ch = changed_files()
    rnd = random.Random(a.seed or time.strftime("%Y-%m-%d"))
    ents = entries()
    done = {k.upper() for k in ver["gpt"]}
    for x in ents:
        m = match_procedures(procs, x["product"], x["layer"], x["category"], [x["id"]], limit=1)
        p = m[0] if m else None
        x["procedure"] = p["id"] if p else ""
        x["procedure_title"] = p["title"] if p else ""
        x["link"] = p["link"] if p else ""
        x["stage1"] = [s["cmd"] for st in (p["stages"] if p else []) if st["stage"] == 1 for s in st["steps"] if s.get("cmd")][:5]
        s2 = [s["cmd"] for st in (p["stages"] if p else []) if st["stage"] == 2 for s in st["steps"] if s.get("cmd")]
        x["stage2_cmd"] = bool(s2)
        x["danger"] = danger_score(x, s2)
        x["_pfile"] = (p or {}).get("_file", "")
    pool = [x for x in ents if x["key"] not in done]
    pick, seen = [], set()

    def take(cands, n, why, stratum, weighted=False):
        cands = [x for x in cands if x["key"] not in seen]
        if weighted:   # 8차 ⑫: 틀리면 피해가 큰 판정(2차 세션 종료·삭제·잠금 등)일수록 자주 — 가중 표본은 정확도 추정에 쓰지 않는다
            got = []
            while cands and len(got) < n:
                w = [1 + 3 * x["danger"] for x in cands]
                got.append(cands.pop(rnd.choices(range(len(cands)), weights=w)[0]))
            cands = got
        else:
            rnd.shuffle(cands)
        for x in cands[:n]:
            seen.add(x["key"])
            pick.append({**x, "why": why, "stratum": stratum})

    # 무작위 층을 **먼저** 미검증 집합에서 고른다 — 이 층만 그 미검증 집합의 (작은) 표본이다. 전체 지식 대표 표본이 아니고, 가중 층과 섞어 읽지 않는다(GPT 64차)
    nr = max(1, -(-a.n * 3 // 10))
    take(pool, nr, "무작위(미검증 집합)", "무작위")
    take([x for x in pool if x["severity"] == "critical" or x["stage2_cmd"]], max(1, a.n * 3 // 10), "위험(치명·2차 명령, 위험도 가중)", "가중",
         weighted=True)
    take([x for x in pool if x["verify_note"]], max(1, a.n * 2 // 10), "미확인 표시", "가중")
    take([x for x in pool if (x["file"] and x["file"] in ch) or "/r6_" in "/" + str(x["_pfile"]) or str(x["procedure"]).find("-R6-") > 0],
         max(1, a.n * 2 // 10), "바뀜(새 전용 절차·바뀐 파일)", "가중")
    take(pool, a.n - len(pick), "무작위(미검증 집합)", "무작위")
    rid = time.strftime("%Y-%m-%d") + "-" + hashlib.sha256(",".join(x["key"] for x in pick).encode()).hexdigest()[:4]
    QDIR.mkdir(parents=True, exist_ok=True)
    keep = ("key", "why", "stratum", "danger", "product", "title", "severity", "cause", "immediate", "verify_note", "procedure",
            "procedure_title", "link", "stage1")
    body = json.dumps({"round": rid, "pool": len(pool), "items": [{k: x.get(k) for k in keep} for x in pick]}, ensure_ascii=False, indent=1)
    (QDIR / "대기열.json").write_text(body, encoding="utf-8")
    (QDIR / f"대기열-{rid}.json").write_text(body, encoding="utf-8")   # 회차별 사본 — 결과 기록이 층(가중/무작위)을 찾는다
    md = [f"# 지식 표본 실검증 대기열 — 회차 {rid}\n",
          "층: **무작위**(아직 교차 검증 안 한 판정 집합에서 먼저 고름 — 그 **미검증 집합**의 작은 표본일 뿐 전체 지식의 대표 표본이 아님) · **가중**(위험도 가중·미확인·바뀜 — 결함 찾기용, 오류율 계산에 쓰지 않음). "
          "**표본 결과를 전체 정확도로 말하지 않습니다.** 검토자와 승인자는 다른 사람이어야 합니다.",
          "결과 기록: `python tools/build/knowledge_sample_queue.py record --round " + rid + " --key 제품:ID --verdict 정확|부분|오류 --reviewer … --approver …`\n",
          "| # | 판정 | 층 | 고른 까닭 | 위험도 | 제목 | 절차 | 판정(정확/부분/오류) | 검토자 | 승인자 |", "|---|---|---|---|---|---|---|---|---|---|"]
    for i, x in enumerate(pick, 1):
        md.append(f"| {i} | `{x['key']}` | {x['stratum']} | {x['why']} | {x['danger']} | {str(x['title'])[:40]} | {x['procedure']} | | | |")
    md.append("\n## 항목별 내용\n")
    for i, x in enumerate(pick, 1):
        md.append(f"### {i}. {x['key']} — {x['title']}\n- 원인: {x['cause'] or '(없음)'}\n- 즉시 조치:\n" +
                  "\n".join(f"  - {l}" for l in x["immediate"]) + f"\n- 절차: {x['procedure']} {x['procedure_title']} ({x['link']})\n- 절차 1차 명령:\n" +
                  "\n".join(f"  - `{c}`" for c in x["stage1"]) + (f"\n- 미확인: {x['verify_note']}" if x["verify_note"] else "") + "\n")
    (QDIR / "대기열.md").write_text("\n".join(md), encoding="utf-8")
    print(f"회차 {rid}: {len(pick)}건 → {QDIR / '대기열.md'}")
    for x in pick:
        print(f"  {x['stratum']:4} {x['why']:14} {x['key']}")
    return 0


def danger_score(x: dict, stage2: list) -> int:
    """8차 ⑫ 위험도 = 2차 명령의 되돌리기 어려운 동작 종류 수(kb_audit.DANGER — 연결 승인 화면과 같은 정의) + 치명이면 1."""
    from logtriage.kb_audit import danger_kinds_text
    return len(danger_kinds_text("\n".join(stage2))) + (1 if x.get("severity") == "critical" else 0)


def next_round(r: str) -> str:
    """b982 → b982-re → b982-re2 → b982-re3 (7차까지 손으로 붙인 이름 규칙을 도구가 잇는다)."""
    import re as _re
    m = _re.search(r"-re(\d*)$", r)
    if not m:
        return r + "-re"
    return r[:m.start()] + "-re" + str(int(m.group(1) or 1) + 1)


def _rows() -> list:
    try:
        return [json.loads(l) for l in (QDIR / "결과.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    except (OSError, ValueError):
        return []


def _current_item(k: str, by: dict, procs) -> dict | None:
    x = by.get(k)
    if not x:
        return None
    m = match_procedures(procs, x["product"], x["layer"], x["category"], [x["id"]], limit=1)
    p = m[0] if m else {"id": "", "title": "", "link": "", "stages": []}
    x = {**x, "procedure": p["id"], "procedure_title": p["title"], "link": p["link"],
         "stage1": [s["cmd"] for st in p["stages"] if st["stage"] == 1 for s in st["steps"] if s.get("cmd")]}
    t = _item_text(x)
    return {"key": k, "text": t, "sha": hashlib.sha256(_norm(t).encode("utf-8")).hexdigest()}


def pending_items() -> list:
    """8차 ①: '고침'으로 표시됐는데 다음 회차에서 다시 보지 않은 항목. 지금 원문 해시가 그 회차에 보낸 해시와 같으면
    '고쳤다는데 원문이 그대로' — 재검증으로 보내지 않고 경고(고침 표시가 틀렸거나 다른 파일을 고친 것)."""
    rows = _rows()
    by_round: dict = {}
    for r in rows:
        by_round.setdefault(r.get("round", ""), {})[r["key"]] = r     # 같은 회차·같은 판정은 마지막 줄
    procs = load_procedures(ENGINE / "manuals")
    by = {x["key"]: x for x in entries()}
    out = []
    for rnd_id, keys in by_round.items():
        nxt = by_round.get(next_round(rnd_id), {})
        for k, r in keys.items():
            if not r.get("fixed") or r.get("verdict") == "정확" or k in nxt:
                continue
            cur = _current_item(k, by, procs)
            if not cur:
                out.append({"round": rnd_id, "next": next_round(rnd_id), "key": k, "state": "판정 없음(지식에서 빠짐)", "sha": ""})
                continue
            sent = str(r.get("sent_sha") or "")
            streak = misses_in_a_row(by_round, rnd_id, k)
            state = ("원문 그대로(고침 표시와 모순)" if sent and sent == cur["sha"] else
                     f"수렴 실패(연속 {streak}회 부분·오류) — 교차 검증 대신 제조사 문의로" if streak >= MAX_MISSES else
                     "바뀜 — 재검증 대상" if sent else "보낸 원문 해시 없음 — 재검증 대상(바뀜 확인 못 함)")
            out.append({"round": rnd_id, "next": next_round(rnd_id), "key": k, "state": state, "sha": cur["sha"], "text": cur["text"],
                        "streak": streak})
    return out


MAX_MISSES = 3   # 9차 ②: 같은 항목이 이만큼 연속 '부분·오류'면 교차 검증을 멈추고 원문 보유자(제조사)에게 넘긴다 — 지적이 계속 바뀌며 끝없이 도는 것 방지


def _chain_pos(rnd_id: str) -> tuple:
    import re as _re
    m = _re.search(r"-re(\d*)$", rnd_id)
    return (rnd_id[:m.start()], int(m.group(1) or 1)) if m else (rnd_id, 0)


def misses_in_a_row(by_round: dict, rnd_id: str, key: str) -> int:
    """같은 사슬(R, R-re, R-re2 …)에서 rnd_id 까지 그 판정이 연속으로 '부분·오류'였던 횟수."""
    base, pos = _chain_pos(rnd_id)
    hist = sorted((_chain_pos(r)[1], rows[key]["verdict"]) for r, rows in by_round.items()
                  if _chain_pos(r)[0] == base and _chain_pos(r)[1] <= pos and key in rows)
    n = 0
    for _, v in reversed(hist):
        if v == "정확":
            break
        n += 1
    return n


def pending(a) -> int:
    items = pending_items()
    QDIR.mkdir(parents=True, exist_ok=True)
    (QDIR / "재검증대기.json").write_text(json.dumps([{k: v for k, v in x.items() if k != "text"} for x in items], ensure_ascii=False, indent=1),
                                     encoding="utf-8")
    md = ["# 재검증 대기 — 고침 표시 뒤 다시 보지 않은 항목\n", "| 회차 | 다음 회차 | 판정 | 상태 |", "|---|---|---|---|"]
    md += [f"| {x['round']} | {x['next']} | `{x['key']}` | {x['state']} |" for x in items]
    (QDIR / "재검증대기.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    bad = [x for x in items if x["state"].startswith("원문 그대로")]
    stuck = [x for x in items if x["state"].startswith("수렴 실패")]
    (QDIR / "수렴실패.json").write_text(json.dumps([{k: x[k] for k in ("round", "key", "streak", "state")} for x in stuck], ensure_ascii=False, indent=1),
                                    encoding="utf-8")   # make_vendor_requests 가 '우선' 묶음으로 읽는다
    print(f"재검증 대기 {len(items)}건 · 원문 그대로 {len(bad)}건 · 수렴 실패 {len(stuck)}건 → {QDIR / '재검증대기.md'}")
    for x in items:
        print(f"  {x['round']} → {x['next']}  {x['key']}  {x['state']}")
    return 1 if bad else 0


def _norm(t: str) -> str:
    import re as _re
    return _re.sub(r"\s+", " ", t).strip()


def _item_text(x: dict) -> str:
    """재검증용 항목 원문 — 자르지 않는다(59차까지 110자 절단으로 오판한 일 방지)."""
    return (f"[{x['key']}] {x['title']}\n원인: {x['cause'] or '(룰: 원인 칸 없음)'}\n즉시 조치:\n" +
            "\n".join(f"- {l}" for l in x["immediate"]) + f"\n연결 절차: {x['procedure']} {x['procedure_title']} ({x['link']})\n절차 1차 명령:\n" +
            "\n".join(f"- {c}" for c in x["stage1"]) + (f"\n미확인: {x['verify_note']}" if x["verify_note"] else ""))


def reverify(a) -> int:
    """고침 표시 뒤 다시 보지 않은 항목(pending_items)을 지금 지식으로 잘림 없이 묶는다 — 회차 이름은 next_round 로 잇는다(8차 ①).
    원문이 그대로인 항목은 보내지 않는다(pending 이 경고)."""
    back = {k.strip().upper() for k in (getattr(a, "include_stuck", "") or "").split(",") if k.strip()}   # 제조사 회신 뒤 다시 넣을 항목(GPT 70차)
    items = [x for x in pending_items() if (not a.round or x["round"] == a.round) and x.get("sha")
             and not x["state"].startswith("원문 그대로") and (not x["state"].startswith("수렴 실패") or x["key"] in back)]
    QDIR.mkdir(parents=True, exist_ok=True)
    groups: dict = {}
    for x in items:
        groups.setdefault(x["next"], []).append(x)
    for rid, its in groups.items():
        (QDIR / f"재검증-{rid}.json").write_text(json.dumps({"round": rid, "items": [{k: x[k] for k in ("key", "text", "sha")} for x in its]},
                                                         ensure_ascii=False, indent=1), encoding="utf-8")
        chunks, cur = [], ""
        for i, it in enumerate(its, 1):
            piece = f"({i}) h:{it['sha'][:12]} {it['text']}\n\n"
            if cur and len(cur) + len(piece) > a.chunk:
                chunks.append(cur)
                cur = ""
            cur += piece
        if cur:
            chunks.append(cur)
        for j, c in enumerate(chunks, 1):
            head = (f"[재검증 {rid} · {j}/{len(chunks)}] 앞 회차에서 고친 항목을 잘림 없이 다시 보냅니다(항목 앞 h: 는 원문 sha256 앞 12자). "
                    "각 항목을 정확/부분/오류로 다시 판정하고, 부분·오류면 남은 결함과 근거 문서를 표로 주십시오.\n\n")
            (QDIR / f"재검증-{rid}-{j}.txt").write_text(head + c, encoding="utf-8")
        print(f"재검증 {rid}: {len(its)}건 · 메시지 {len(chunks)}개 → {QDIR}")
    if not groups:
        print("재검증할 항목 없음")
    return 0


def sent_check(a) -> int:
    sent = _norm(Path(a.sent).read_text(encoding="utf-8"))
    seen = _norm(Path(a.seen).read_text(encoding="utf-8"))
    if a.render:   # 대화창은 `…` 를 코드 모양으로 그리고 백틱 글자는 없앤다(10-16 실측: 20자 차이 = 백틱 20개) — 양쪽에서 같은 규칙으로만 뺀다
        sent, seen = _norm(sent.replace("`", "")), _norm(seen.replace("`", ""))
    hs, hv = hashlib.sha256(sent.encode()).hexdigest(), hashlib.sha256(seen.encode()).hexdigest()
    # GPT 61차: 백틱을 양쪽에서 뺀 뒤 같다는 것은 '표시 텍스트 일치'일 뿐 원문 바이트 무결성 증명이 아니다(백틱은 셸에서 뜻이 있다)
    label = ("표시 텍스트 일치(렌더 규칙 적용 — 원문 바이트 증명 아님)" if a.render else "전달 확인(정규화 원문 일치)") if hs == hv else "불일치"
    print(label, hs[:16], hv[:16])
    return 0 if hs == hv else 1


def stratum_of(rnd_id: str, key: str) -> str:
    """결과 줄의 층 — 재검증 회차는 '재검증', 첫 회차는 그 회차 대기열 사본의 층(사본이 없는 옛 회차는 '구분 없음')."""
    import re as _re
    if _re.search(r"-re\d*$", rnd_id):
        return "재검증"
    try:
        q = json.loads((QDIR / f"대기열-{rnd_id}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "구분 없음"
    return next((str(x.get("stratum") or "구분 없음") for x in q.get("items") or [] if str(x.get("key", "")).upper() == key), "구분 없음")


def record(a) -> int:
    if a.verdict not in VERDICTS:
        print("판정은 정확·부분·오류 중 하나")
        return 2
    if not a.reviewer.strip() or not a.approver.strip() or a.reviewer.strip() == a.approver.strip():
        print("검토자와 승인자는 둘 다 있어야 하고 서로 달라야 합니다")
        return 2
    QDIR.mkdir(parents=True, exist_ok=True)
    row = {"at": time.strftime("%Y-%m-%d %H:%M"), "round": a.round, "key": a.key.upper(), "verdict": a.verdict,
           "reviewer": a.reviewer, "approver": a.approver, "fixed": bool(a.fixed), "note": (a.note or "")[:300],
           "sent_sha": (a.sent_sha or "")[:64], "stratum": stratum_of(a.round, a.key.upper())}
    with (QDIR / "결과.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print("기록:", row["key"], row["verdict"])
    if __import__("re").search(r"-re\d*$", a.round) and a.verdict == "정확":   # 재검증 통과 → 배지 '수정 후 재확인'
        import yaml
        vp = ENGINE / "errorcodes" / "_verification.yaml"
        txt = vp.read_text(encoding="utf-8")
        head = "".join(l + "\n" for l in txt.splitlines() if l.startswith("#"))
        doc = yaml.safe_load(txt) or {}
        lst = doc.get("gpt_reverified") or []
        if row["key"] not in {str(k).upper() for k in lst}:
            lst.append(row["key"])
        doc["gpt_reverified"] = lst
        vp.write_text(head + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make")
    m.add_argument("--n", type=int, default=10)
    m.add_argument("--seed", default="")
    r = sub.add_parser("record")
    for k in ("--round", "--key", "--verdict", "--reviewer", "--approver"):
        r.add_argument(k, required=True)
    r.add_argument("--fixed", action="store_true")
    r.add_argument("--note", default="")
    r.add_argument("--sent-sha", default="")
    v = sub.add_parser("reverify")
    v.add_argument("--round", default="", help="비우면 고침 표시 뒤 다시 보지 않은 모든 회차")
    v.add_argument("--include-stuck", default="", help="수렴 실패 항목 중 제조사 회신으로 고친 것을 다시 넣는다(판정 키, 쉼표로)")
    sub.add_parser("pending")
    v.add_argument("--chunk", type=int, default=5500)
    c = sub.add_parser("sent-check")
    c.add_argument("--sent", required=True)
    c.add_argument("--seen", required=True)
    c.add_argument("--render", action="store_true", help="마크다운 백틱 제거 규칙을 양쪽에 적용")
    a = ap.parse_args(argv)
    return {"make": make, "record": record, "reverify": reverify, "sent-check": sent_check, "pending": pending}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
