"""연결 승인(8차 아이디어 ②) — 에이전트가 '이 절차의 1차가 이 판정을 진단한다'고 검토한 연결(proclinks 의 fit_reviewed)을
마스터(관리자)가 승인·반려한다. 검토 ≠ 승인(GPT 60차) — 승인 기록이 생기기 전까지 연결감사는 '승인 대기'로 센다.

  · 결정 저장: 설치본은 <자료 폴더>/data/link_approvals.jsonl(이력 — 지우지 않고 마지막 줄이 현재 결정).
              엔진은 manuals/_link_approvals.json(현장 기록을 tools/build/knowledge_link_audit.py --import-approvals 로 들여온 것).
              둘 다 있으면 시각이 늦은 쪽.  ※ .json 으로 둔다 — manuals 의 *.yaml 은 매뉴얼 문서로 읽힌다.
  · 반려한 연결은 fit_reviewed 로 대기열에서 빼지 않는다(kb_audit.reviewed_pairs) → 다시 '적합성 낮음' 대기열로 → 지식 출시가 멈춘다.
  · 위험도 순: 그 절차의 2차 명령에 세션 종료·삭제·중지·설정 변경 등이 몇 종류 있나(kb_audit.danger_kinds).
  · 묶음 승인(GPT 64차 P0): 표본 3건을 연 것은 나머지를 검토했다는 증거가 아니다 → 결과는 '승인'이 아니라 **'묶음 승인'**(따로 센다,
    개별 검토 아님). 위험 명령·매칭 모호·제품 불일치·미확인 표시·치명 판정이 걸린 연결은 묶음에 넣을 수 없고 한 건씩 상세를 본 뒤 승인한다.
    고른 연결 중 무작위 3건을 서버가 정하고, 관리자가 그 3건의 상세를 이 서버에서 열어 본 뒤에만 받는다(30분 안·같은 묶음).
  · 동시 결정(GPT 64차 P1): 연결마다 개정 번호(rev = 지금까지 결정 줄 수). 화면이 본 rev 와 다르면 거절 — 두 관리자가 겹쳐 뒤집지 않게.
    한 건 승인은 그 관리자가 그 연결의 상세를 이 서버에서 연 뒤에만(열람 기록 30분).
"""
from __future__ import annotations

import json
import random
import threading
import time
from pathlib import Path

ENGINE_FILE = "manuals/_link_approvals.json"
LOCAL_FILE = "data/link_approvals.jsonl"
DECISIONS = ("승인", "반려", "묶음 승인")
SAMPLE_N, SAMPLE_TTL = 3, 1800.0
_LOCK = threading.Lock()
_SAMPLES: dict = {}     # actor → {"pairs": frozenset, "sample": [..], "opened": set(), "at": t}
_OPENED: dict = {}      # (actor, 절차|ID) → 상세를 연 시각 — 한 건 승인은 상세를 연 뒤에만


def _pk(proc: str, vid: str) -> str:
    return f"{proc}|{str(vid).upper()}"


def decisions(base: Path) -> dict:
    """(절차|판정 ID) → 마지막 결정 줄. 엔진 병합본과 현장 이력을 시각으로 합친다."""
    base = Path(base)
    out: dict = {}
    rows = []
    try:
        rows += json.loads((base / ENGINE_FILE).read_text(encoding="utf-8")).get("decisions") or []
    except (OSError, ValueError):
        pass
    try:
        for ln in (base / LOCAL_FILE).read_text(encoding="utf-8").splitlines():
            if ln.strip():
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    continue
    except OSError:
        pass
    seen: dict = {}
    for r in rows:
        if not isinstance(r, dict) or r.get("decision") not in DECISIONS:
            continue
        k = _pk(str(r.get("procedure", "")), str(r.get("id", "")))
        ident = (round(float(r.get("ts") or 0), 3), r.get("decision"), r.get("by"))
        if ident in seen.setdefault(k, set()):   # 엔진 병합본과 현장 이력에 같은 줄이 둘 다 있으면 한 번
            continue
        seen[k].add(ident)
        if k not in out or float(r.get("ts") or 0) >= float(out[k].get("ts") or 0):
            out[k] = dict(r)
    for k, r in out.items():
        r["rev"] = len(seen.get(k, ()))
    return out


def rejected(base: Path) -> set:  # noqa: D401
    return {(r["procedure"], str(r["id"]).upper()) for r in decisions(base).values() if r.get("decision") == "반려"}


_STATIC: dict = {}


def _stamp(base: Path) -> tuple:
    """지식 파일(manuals·errorcodes·rules)의 이름·크기·수정 시각 — 바뀌면 다시 읽는다(결정 기록은 매번 새로 읽는다)."""
    out = []
    for d in ("manuals", "errorcodes", "rules"):
        for f in sorted((base / d).rglob("*.y*ml")):
            st = f.stat()
            out.append((f.name, st.st_size, st.st_mtime_ns))
    return tuple(out)


def _static(base: Path) -> tuple:
    from .kb_audit import reviewed_rows, verdicts
    from .procedures import load_procedures
    key, stamp = str(base.resolve()), _stamp(base)
    c = _STATIC.get(key)
    if c and c[0] == stamp:
        return c[1]
    procs = {p["id"]: p for p in load_procedures(base / "manuals")}
    vt: dict = {}
    for v in verdicts(base):
        vt.setdefault(str(v["id"]).upper(), []).append({"key": v["key"], "title": v["text"][0], "product": v["product"],
                                                       "unverified": bool(v.get("verify_note")), "severity": v.get("severity", "")})
    val = (procs, vt, reviewed_rows(base, include_rejected=True))
    _STATIC[key] = (stamp, val)
    return val


def individual_reasons(p: dict, vs: list, kinds: list) -> list:
    """묶음 승인에 넣을 수 없는 까닭(GPT 64차 P0) — 하나라도 있으면 한 건씩."""
    why = []
    if kinds:
        why.append("2차 위험 명령(" + ", ".join(kinds) + ")")
    prods = {str(x).lower().split("-")[0] for x in p.get("products") or []}
    vp = {str(v.get("product", "")).lower().split("-")[0] for v in vs}
    if prods and vp and not (vp & prods) and not any(x.endswith("common") or x in ("*", "java") for x in prods):
        why.append("판정 제품과 절차 제품이 다름")
    if len(vs) > 1 and len({str(v.get("product", "")).lower() for v in vs}) > 1:
        why.append("같은 ID 를 여러 제품이 씀(매칭 모호 가능)")
    if any(v.get("unverified") for v in vs):
        why.append("판정에 미확인 표시")
    if any(v.get("severity") == "critical" for v in vs):
        why.append("치명 판정")
    return why


def items(base: Path) -> list:
    """승인 대상 — fit_reviewed 로 대기열에서 뺀 연결 전부(결정 상태 포함), 위험도 높은 순."""
    from .kb_audit import danger_kinds
    base = Path(base)
    procs, vt, rows = _static(base)
    dec = decisions(base)
    out = []
    for r in rows:
        p = procs.get(r["procedure"]) or {"title": "", "stages": [], "products": []}
        kinds = danger_kinds(p)
        d = dec.get(_pk(r["procedure"], r["id"]))
        vs = vt.get(r["id"], [])
        out.append({"procedure": r["procedure"], "id": r["id"], "reason": r["reason"], "file": r["file"],
                    "proc_title": p.get("title", ""), "verdicts": vs[:4], "danger": len(kinds), "danger_kinds": kinds,
                    "individual": individual_reasons(p, vs, kinds),
                    "state": d["decision"] if d else "대기", "by": (d or {}).get("by", ""), "at": (d or {}).get("at", ""),
                    "note": (d or {}).get("note", ""), "rev": int((d or {}).get("rev", 0))})
    out.sort(key=lambda x: (x["state"] != "대기", -x["danger"], x["procedure"], x["id"]))
    return out


def detail(base: Path, proc: str, vid: str, actor: str) -> dict:
    p = _static(Path(base))[0].get(proc)
    if not p:
        raise ValueError("절차를 찾지 못했습니다")
    it = next((x for x in items(base) if x["procedure"] == proc and x["id"] == str(vid).upper()), None)
    if not it:
        raise ValueError("승인 대상 연결이 아닙니다")
    with _LOCK:
        s = _SAMPLES.get(actor)
        if s and _pk(proc, vid) in s["sample"]:
            s["opened"].add(_pk(proc, vid))
        _OPENED[(actor, _pk(proc, vid))] = time.time()
    st = [{"stage": st["stage"], "steps": [{"do": x.get("do", ""), "cmd": x.get("cmd", ""), "check": x.get("check", "")} for x in st["steps"]]}
          for st in p["stages"] if st["stage"] in (1, 2)]
    return {**it, "stages": st}


def _append(base: Path, row: dict) -> None:
    f = Path(base) / LOCAL_FILE
    f.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, f.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")


QUESTIONS = {   # 9차 ①: 한 건 승인의 근거 — 세 질문 모두 '예'여야 승인(되돌리기는 2차 위험 명령이 없으면 '해당 없음' 가능)
    "symptom": "1차 명령이 이 판정의 증상(제목·원인)을 직접 확인하는가",
    "version": "명령·옵션이 이 제품의 지원 판에 맞는가(판 표기 확인)",
    "rollback": "2차 위험 명령에 되돌리기 계획(백업/롤백 칸)이 있는가",
}


def check_answers(it: dict, answers) -> dict:
    a = answers if isinstance(answers, dict) else {}
    out = {}
    for k in QUESTIONS:
        v = str(a.get(k, "")).strip()
        ok = v == "예" or (k == "rollback" and v == "해당 없음" and not it.get("danger"))
        if not ok:
            raise ValueError(f"승인하려면 세 질문에 모두 '예'여야 합니다 — '{QUESTIONS[k]}'"
                             + (" (2차 위험 명령이 있어 '해당 없음'은 안 됩니다)" if k == "rollback" and v == "해당 없음" else "")
                             + ". 아니면 반려하십시오")
        out[k] = v
    return out


def assist(base: Path) -> dict:
    """9차 ①: 한 건씩 볼 대기 연결을 제품별로 묶고, 승인 질문을 함께 준다."""
    by: dict = {}
    for x in items(base):
        if x["state"] != "대기":
            continue
        prod = (x["verdicts"][0]["product"] if x["verdicts"] else "") or "(제품 모름)"
        g = by.setdefault(prod, {"product": prod, "individual": 0, "batchable": 0})
        g["individual" if x["individual"] else "batchable"] += 1
    return {"groups": sorted(by.values(), key=lambda g: (-g["individual"], g["product"])), "questions": QUESTIONS}


def decide(base: Path, proc: str, vid: str, decision: str, actor: str, note: str = "", via: str = "한 건", _valid: set | None = None,
           rev: int | None = None, answers: dict | None = None) -> dict:
    if decision not in ("승인", "반려") and not (decision == "묶음 승인" and _valid is not None):
        raise ValueError("결정은 승인·반려 중 하나")
    if decision != "묶음 승인":
        if rev is None:
            raise ValueError("화면이 본 개정 번호(rev)가 없습니다 — 목록을 새로 불러 다시 하십시오")
        cur = int((decisions(base).get(_pk(proc, vid)) or {}).get("rev", 0))
        if int(rev) != cur:
            raise ValueError("그사이 다른 결정이 있었습니다 — 목록을 새로 불러 다시 보십시오")
        if decision == "승인" and time.time() - _OPENED.get((actor, _pk(proc, vid)), 0) > SAMPLE_TTL:
            raise ValueError("상세를 연 뒤에 승인하십시오(30분 안)")
        if decision == "승인":   # GPT 65차: 판정 제품과 절차 제품이 다른 연결은 승인 금지 — 연결을 고치거나 반려
            it = next((x for x in items(base) if x["procedure"] == proc and x["id"] == str(vid).upper()), None)
            if it and any(r.startswith("판정 제품과 절차 제품이 다름") for r in it["individual"]):
                raise ValueError("판정 제품과 절차 제품이 다른 연결은 승인할 수 없습니다 — 지식에서 연결을 고치거나 반려하십시오")
            answers = check_answers(it or {}, answers)
    note = str(note or "").strip()[:300]
    if decision == "반려" and len(note) < 5:
        raise ValueError("반려 사유를 적어 주십시오(5자 이상) — 무엇이 진단과 안 맞는지")
    valid = _valid if _valid is not None else {_pk(x["procedure"], x["id"]) for x in items(base)}
    if _pk(proc, vid) not in valid:
        raise ValueError("승인 대상 연결이 아닙니다")
    row = {"ts": time.time(), "at": time.strftime("%Y-%m-%d %H:%M"), "procedure": proc, "id": str(vid).upper(), "decision": decision,
           "by": actor, "note": note, "via": via}
    if decision == "승인":
        row["answers"] = answers   # 승인 근거(세 질문의 답)
    _append(base, row)
    return {"ok": True, **row}


def sample(base: Path, pairs: list, actor: str) -> dict:
    """묶음 승인 전 표본 3건 — 서버가 고른다(화면이 고르지 않는다)."""
    keys = sorted({_pk(str(p.get("procedure", "")), str(p.get("id", ""))) for p in pairs if isinstance(p, dict)})
    its = {_pk(x["procedure"], x["id"]): x for x in items(base) if x["state"] == "대기"}
    if not keys or any(k not in its for k in keys):
        raise ValueError("대기 중인 연결만 고를 수 있습니다")
    ind = [k for k in keys if its[k]["individual"]]
    if ind:
        raise ValueError(f"한 건씩 승인해야 하는 연결 {len(ind)}건이 섞였습니다(위험 명령·제품 불일치·미확인 등) — 빼고 다시 고르십시오")
    if len(keys) <= SAMPLE_N:
        raise ValueError(f"{SAMPLE_N}건 이하는 한 건씩 승인하십시오")
    pick = random.SystemRandom().sample(keys, SAMPLE_N)
    with _LOCK:
        _SAMPLES[actor] = {"pairs": frozenset(keys), "sample": pick, "opened": set(), "at": time.time()}
    return {"sample": [dict(zip(("procedure", "id"), k.split("|", 1))) for k in pick], "count": len(keys)}


def batch(base: Path, pairs: list, actor: str) -> dict:
    keys = frozenset(_pk(str(p.get("procedure", "")), str(p.get("id", ""))) for p in pairs if isinstance(p, dict))
    with _LOCK:
        s = _SAMPLES.get(actor)
        if not s or s["pairs"] != keys:
            raise ValueError("표본을 먼저 받으십시오(고른 묶음이 바뀌면 표본도 다시)")
        if time.time() - s["at"] > SAMPLE_TTL:
            raise ValueError("표본을 받은 지 30분이 지났습니다 — 다시 받으십시오")
        left = [k for k in s["sample"] if k not in s["opened"]]
        if left:
            raise ValueError(f"표본 {len(left)}건을 아직 열어 보지 않았습니다")
        _SAMPLES.pop(actor, None)
    its = {_pk(x["procedure"], x["id"]): x for x in items(base) if x["state"] == "대기"}
    if any(k not in its or its[k]["individual"] for k in keys):   # 그사이 다른 관리자가 결정했거나 한 건씩 대상이 되면 통째 거절
        raise ValueError("그사이 결정됐거나 한 건씩 승인할 연결이 섞였습니다 — 목록을 새로 불러 다시 고르십시오")
    done = [decide(base, *k.split("|", 1), "묶음 승인", actor, note="개별 검토 아님 — 표본 3건만 열람",
                   via=f"묶음 {len(keys)}건(표본 {SAMPLE_N}건 열람)", _valid=set(its)) for k in sorted(keys)]
    return {"ok": True, "approved": len(done)}


def counts(base: Path) -> dict:
    its = items(base)
    return {k: sum(1 for x in its if x["state"] == k) for k in ("대기", "승인", "묶음 승인", "반려")}
