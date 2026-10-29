"""절차 연결 감사(2026-10-16 7차 아이디어 1·7·12) — 지식의 '연결'이 맞는지 기계로 1차 선별한다(최종 판단은 사람).

  1) 적합성: '이 판정 전용' 연결마다 판정 제목의 핵심어가 절차(제목·1차 할 일·명령·확인·match)에 하나라도 나오는지 본다.
     하나도 안 나오면 '제목 핵심어 0' 대기열로 — 57차 표본 오류 AppArmor→SSH 실패 절차가 이렇게 걸렸다(0 → 고친 뒤 0.71).
     한계(실측): 같은 낱말을 쓰지만 진단이 다른 연결(CNTR0020E→일반 WebSphere 검색, TBR-12033→통계 잠금 조회)은 이 방법으로 못 잡는다.
     전체 낱말 겹침(Jaccard)도 재 봤으나 오류 연결 0.07~0.14 · 전체 중앙값 0.146 으로 가르지 못해 쓰지 않는다. 대기열은 검토 대상이지 오류 목록이 아니다.
  2) 유령 연결: 절차 match·proclinks 에 있지만 코드 사전·룰·별칭 어디에도 없는 ID.
  3) 주의 목록(화면 '확인이 필요한 지식'): 판정별 매칭 모호·미확인·실행 안 됨·적합성 낮음.

도구: tools/build/knowledge_link_audit.py · 화면: 룰팩 화면 '확인이 필요한 지식'(server.kb_attention)
"""
from __future__ import annotations

import re
from pathlib import Path

from .codes import load_codes
from .procedures import load_procedures, match_procedures
from .yamlsafe import load as yload

ENGINE = Path(__file__).resolve().parents[1]   # 기본값(엔진 폴더) — 설치본은 base(자료 폴더)를 넘긴다

STOP = set("""확인 조회 상태 로그 원인 발생 오류 실패 경우 이상 확인한다 있으면 없으면 기록 판단 확정 1차 2차 3차 읽기 전용 명령 결과 대조
          tail head grep sort uniq awk sed wc cat ls ps the and for from with select show where order by limit desc asc null not
          error fail failed log logs file 대상 해당 같은 시각 최근 마지막 여부 값 수 및 또는 후 전 중 시 위 아래 이후 이전 n e i v x c""".split())
TOK = re.compile(r"[A-Za-z][A-Za-z0-9_.$-]{2,}|[가-힣]{2,}|\d{3,}")
LOW = 0.0    # 제목 핵심어 겹침 비율이 이 값 이하(= 0)면 검토 대상


def toks(*texts) -> set:
    out = set()
    for t in texts:
        for w in TOK.findall(str(t or "")):
            w = w.lower().strip(".-$")
            if w and w not in STOP and len(w) >= 2:
                out.add(w)
    return out


def verdicts(base: Path = ENGINE) -> list[dict]:
    out = []
    for k, e in load_codes(Path(base) / "errorcodes").items():
        if ":" in k:
            out.append({"key": k.upper(), "id": e.code, "product": e.product, "layer": e.layer, "category": e.category,
                        "text": [e.title, e.cause, " ".join(map(str, e.immediate))], "verify_note": e.verify_note,
                        "severity": str(getattr(e, "severity", "") or "")})
    for f in sorted((Path(base) / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                prods = r.get("product") or ["*"]
                prods = prods if isinstance(prods, list) else [prods]
                lay = r.get("layer")
                for p in prods:
                    out.append({"key": str(r["id"]).upper(), "id": r["id"], "product": str(p).lower(),
                                "layer": lay[0] if isinstance(lay, list) else lay, "category": r.get("category", "etc"),
                                "text": [r.get("title", ""), r.get("verdict", ""), r.get("cause", ""), " ".join(map(str, r.get("immediate") or []))],
                                "verify_note": r.get("verify_note", ""), "severity": str(r.get("severity", "") or "")})
    return out


def known_ids(base: Path = ENGINE) -> set:
    ids = {k.split(":", 1)[1].upper() for k in load_codes(Path(base) / "errorcodes") if ":" in k}
    for f in sorted((Path(base) / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                ids.add(str(r["id"]).upper())
    al = Path(base) / "errorcodes" / "_aliases.yaml"
    if al.exists():
        doc = yload(al.read_text(encoding="utf-8")) or {}
        for a in (doc.get("aliases", doc) if isinstance(doc, dict) else doc) or []:
            if isinstance(a, dict) and a.get("code"):
                ids.add(str(a["code"]).upper())
    return ids


def reviewed_rows(base: Path = ENGINE, include_rejected: bool = False) -> list:
    """proclinks 의 fit_reviewed: true 연결을 (절차, 판정 ID) 마다 한 줄로 — 사유(reviewed)·파일 포함.
    8차 ②: 관리자가 '반려'한 연결은 빼서(include_rejected=False) 다시 적합성 대기열로 돌아가게 한다."""
    out, seen = [], set()
    rej = set()
    if not include_rejected:
        from .link_review import rejected
        rej = rejected(base)
    for f in sorted((Path(base) / "manuals").rglob("*_proclinks.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for ln in (doc.get("links") or []) if isinstance(doc, dict) else []:
            if isinstance(ln, dict) and ln.get("fit_reviewed") is True and str(ln.get("reviewed", "")).strip():
                for x in ln.get("match") or []:
                    k = (str(ln.get("procedure")), str(x).upper())
                    if k in seen or k in rej:
                        continue
                    seen.add(k)
                    out.append({"procedure": k[0], "id": k[1], "reason": str(ln.get("reviewed", ""))[:400], "file": f.name})
    return out


def reviewed_pairs(base: Path = ENGINE) -> set:
    """검토자가 '이 연결은 맞다'고 확인한 (절차, 판정 ID) — proclinks 의 fit_reviewed: true. 대기열에서 뺀다(사유는 reviewed 칸).
    관리자가 반려한 연결은 빠진다(8차 ②)."""
    return {(r["procedure"], r["id"]) for r in reviewed_rows(base)}


# 8차 ②·⑫ 위험도 — 그 절차 2차 명령에 되돌리기 어려운 동작이 몇 종류 있나(같은 kill 이 10번 나와도 1). 표본 대기열·연결 승인이 같이 쓴다
DANGER = {"세션·프로세스 종료": r"\bkill\b|kill\s+session|pkill|taskkill|Stop-Process",
          "삭제·비우기": r"\brm\s+-|\bdrop\s+(table|index|user|tablespace|database)|\btruncate\b|\bdelete\s+from\b|Remove-Item|\bdel\s",
          "중지·재기동": r"\bshutdown\b|\breboot\b|systemctl\s+(stop|restart)|Restart-Service|Stop-Service|\bstop\b[^\n]*(server|service|instance)",
          "설정·권한 변경": r"alter\s+system|\bchmod\b|\bchown\b|setenforce|Set-ItemProperty|\bsed\s+-i\b",
          "잠금·트랜잭션": r"\block\s+table\b|\brollback\b|\bcommit\b"}


def rollback_gaps(base: Path = ENGINE) -> list:
    """9차 ⑪: 2차 단계의 위험 명령(knowledge_quality.RISKY_CMD — 복사 막는 기준과 같음)마다 note 에 '백업/롤백:'(또는 '롤백:'·'되돌리기:')
    칸이 내용과 함께 있어야 한다. 없으면 [절차, 단계 할 일] 목록 — 지식 출시가 멈춘다. '없음'·'-' 만 적은 것도 빈 칸으로 본다."""
    from .knowledge_quality import RISKY_CMD
    out = []
    for p in load_procedures(Path(base) / "manuals"):
        for st in p["stages"]:
            if st["stage"] != 2:
                continue
            for s in st["steps"]:
                c = s.get("cmd", "") or ""
                if not RISKY_CMD.search(re.sub(r"\"[^\"\n]*\"|'[^'\n]*'", '""', c)):
                    continue
                note = s.get("note", "") or ""
                segs = [x for x in (_RB_LABEL.match(seg) for seg in re.split(r"\s+·\s+", note)) if x]   # 칸 구분은 ' · '
                v = segs[0].group(2).strip() if segs else ""
                # GPT 70차 P0: 글자만 채운 계획(없음·추후 확인·미정·TBD)은 거절, 되돌릴 수 없는 동작이면 승인 조건이 같은 note 에 있어야
                # GPT 71차: '승인' 글자는 승인 절차가 적혔다는 뜻일 뿐 승인 증거가 아니다 — 실제 승인은 2단계 실행 전 승인 관문이 따로 맡는다
                why = ("칸 없음" if not segs else "내용 비어 있음·미정" if len(v) < 4 or _RB_VAGUE.search(v) else
                       "되돌릴 수 없는데 승인 조건 없음" if _RB_IRREV.search(v) and "승인" not in note else "")
                if why:
                    out.append({"procedure": p["id"], "do": str(s.get("do", ""))[:60], "file": p.get("_file", ""), "why": why})
    return out


_RB_LABEL = re.compile(r"^\s*(백업/롤백|롤백|되돌리기)\s*[:：]\s*(.*)$", re.S)
_RB_VAGUE = re.compile(r"^\s*(없음|-|미정|TBD|확인 필요|해당 없음)\s*\.?\s*$|추후|나중에|확인 예정|TBD|미정", re.I)
_RB_IRREV = re.compile(r"되돌릴 수 없|롤백 불가|복구 불가|되돌리기 불가|되돌림 불가")


def danger_kinds_text(text: str) -> list:
    return [k for k, pat in DANGER.items() if re.search(pat, text or "", re.I)]


def danger_kinds(p: dict) -> list:
    return danger_kinds_text("\n".join(s.get("cmd", "") for st in (p or {}).get("stages") or [] if st["stage"] == 2 for s in st["steps"]))


def fitness(v: dict, p: dict, match=()) -> float | None:
    """판정 제목 핵심어 중 절차에 나오는 비율. 제목에 핵심어가 없으면 None(판단 안 함)."""
    st1 = [s for st in p["stages"] if st["stage"] == 1 for s in st["steps"]]
    a = toks(v["text"][0]) - {str(v["product"]).lower(), str(v["id"]).lower()}
    b = toks(p["title"], *[s["do"] + " " + s["cmd"] + " " + s["check"] for s in st1], " ".join(match or p.get("match") or []))
    if not a:
        return None
    return len(a & b) / len(a)


def audit(base: Path = ENGINE) -> dict:
    procs = load_procedures(Path(base) / "manuals")
    raw = {p["id"]: p for p in procs}
    ids = known_ids(base)
    ghosts = []
    for p in procs:
        for m in p["match"]:
            if str(m).upper() not in ids:
                ghosts.append({"procedure": p["id"], "file": p.get("_file", ""), "id": str(m)})
    low, rows, rv = [], [], reviewed_pairs(base)
    for v in verdicts(base):
        m = match_procedures(procs, v["product"], v["layer"], v["category"], [v["id"]], limit=1)
        if not m:
            continue
        p = m[0]
        f = fitness(v, p, raw[p["id"]]["match"]) if p["link"] == "이 판정 전용" else None
        row = {"key": v["key"], "product": v["product"], "procedure": p["id"], "link": p["link"], "fit": None if f is None else round(f, 3),
               "ambiguous": "매칭 모호" in p["link"], "unverified": bool(v["verify_note"])}
        rows.append(row)
        if f is not None and f <= LOW and (p["id"], str(v["id"]).upper()) not in rv:
            low.append(row)
    return {"ghosts": ghosts, "low_fit": sorted(low, key=lambda r: r["fit"]), "rows": rows, "threshold": LOW}
