"""벤더 원문 반입함(8차 아이디어 ⑤) — 반입이 허가된 벤더 문서(PDF·HTML·TXT·MD)를 이 PC 의 한 폴더에 두면, 지식의 '미검증' 주장마다
그 문서 안에서 **확인할 위치 후보**(파일·쪽·맞은 식별어)를 찾아 준다. 사람이 그 쪽을 열어 보고 맞으면 confirm 으로 근거를 남긴다.

  · 이 도구는 주장이 맞다고 판정하지 않는다 — 식별어(V$LOCK·WLOCK_DD_OBJ·--option 따위)가 같은 쪽에 함께 나온다는 것까지만.
    같은 쪽에 식별어가 있어도 그 주장의 근거가 아닐 수 있고, 발췌가 그 쪽에 있다는 것도 문맥상 맞다는 증거가 아니다 — 판단은 확인자(GPT 64차).
    PDF 는 글 추출 순서가 화면 순서와 다를 수 있어 쪽 번호로만 가리킨다. 파일 200MB·3,000쪽·전체 300초 상한.
  · 문서는 이 PC 밖으로 내보내지 않는다(외부 전송·GPT 전달 없음). 결과 파일에도 발췌는 160자까지만, 근거 기록에는 사람이 고른 한 줄만.
  · 근거 기록: errorcodes/_evidence_local.yaml — {claim, doc, doc_sha256, page, excerpt, sha256, verdict(맞음|틀림), checked, by}.
    confirm 은 그 발췌가 **그 쪽 글에 실제로 있는지** 다시 확인한 뒤에만 적는다(정규화 공백 기준). 틀림이면 지식을 고칠 목록에 올린다.

사용:
  python tools/build/vendor_doc_match.py scan [--docs deploy/local/벤더원문] [--out deploy/local/지식검증]
  python tools/build/vendor_doc_match.py confirm --claim 제품:ID --doc 파일이름 --page N --excerpt "한 줄" --verdict 맞음|틀림 --by 이름
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_vendor_requests import collect  # noqa: E402

DOCS = ENGINE / "deploy" / "local" / "벤더원문"
OUT = ENGINE / "deploy" / "local" / "지식검증"
EVID = ENGINE / "errorcodes" / "_evidence_local.yaml"
KINDS = (".pdf", ".html", ".htm", ".txt", ".md")
# 식별어: 대문자·밑줄·$·# 이 든 이름(V$LOCK, WLOCK_DD_OBJ, LOCKFAIL_IN_NOWAIT), 점 이름(dba_objects.object_id), 옵션(--parallel, -thread)
IDENT = re.compile(r"(?<![\w$#])(?:[A-Za-z][A-Za-z0-9]*[_$#][A-Za-z0-9_$#]*|[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*|--?[a-z][a-z0-9-]{2,}|[A-Z]{2,}[0-9]*-?[0-9]{2,})")
STOP = {"tb_home", "tb_sid", "jboss_home", "catalina_base", "profile_root", "oracle_home"}


def norm(t: str) -> str:
    return re.sub(r"\s+", " ", t or "").strip()


def idents(text: str) -> list:
    out = []
    for m in IDENT.findall(text or ""):
        k = m.strip(".").lower()
        if len(k) >= 4 and k not in STOP and k not in out:
            out.append(k)
    return out


def pages(f: Path) -> list:
    """(쪽 번호, 글) 목록 — PDF 는 쪽, 나머지는 60줄 묶음을 '쪽'으로."""
    suf = f.suffix.lower()
    if suf == ".pdf":
        try:
            import fitz  # PyMuPDF — 이 PC 에 있음. 없으면 PDF 는 건너뛴다(목록에 사유)
        except ImportError:
            return []
        with fitz.open(str(f)) as d:
            return [(i + 1, d[i].get_text()) for i in range(d.page_count)]
    t = f.read_text(encoding="utf-8", errors="replace")
    if suf in (".html", ".htm"):
        t = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", t)
        t = html.unescape(re.sub(r"(?s)<[^>]+>", "\n", t))
    ls = t.splitlines()
    return [(i // 60 + 1, "\n".join(ls[i:i + 60])) for i in range(0, max(1, len(ls)), 60)]


MAX_BYTES, MAX_PAGES, MAX_SECONDS = 200 << 20, 3000, 300.0   # GPT 64차 P1-⑤: 파일 크기·쪽 수·처리 시간 상한(넘으면 건너뛰고 사유 기록)


def index(docs: Path) -> tuple[list, list]:
    import time as _t
    idx, skipped = [], []
    t0 = _t.time()
    for f in sorted(docs.rglob("*")) if docs.is_dir() else []:
        if not f.is_file() or f.is_symlink() or f.suffix.lower() not in KINDS:
            continue
        if _t.time() - t0 > MAX_SECONDS:
            skipped.append(f"{f.name}(시간 상한)")
            continue
        if f.stat().st_size > MAX_BYTES:
            skipped.append(f"{f.name}(200MB 넘음)")
            continue
        try:
            ps = pages(f)
        except Exception as e:   # noqa: BLE001 — 깨진 PDF 하나가 전체를 막지 않게
            skipped.append(f"{f.name}(못 읽음 {type(e).__name__})")
            continue
        if len(ps) > MAX_PAGES:
            skipped.append(f"{f.name}({MAX_PAGES}쪽 넘음 — 앞 {MAX_PAGES}쪽만)")
            ps = ps[:MAX_PAGES]
        if not ps:
            skipped.append(f.name)
            continue
        sha = hashlib.sha256(f.read_bytes()).hexdigest()
        for no, t in ps:
            idx.append({"doc": f.name, "doc_sha256": sha, "page": no, "text": t, "low": t.lower()})
    return idx, skipped


def candidates(claim: str, idx: list, top: int = 3) -> tuple[list, list]:
    keys = idents(claim)
    if not keys:
        return keys, []
    need = 1 if len(keys) == 1 else 2
    hits = []
    for pg in idx:
        got = [k for k in keys if k in pg["low"]]
        if len(got) >= need:
            i = pg["low"].find(got[0])
            hits.append({"doc": pg["doc"], "doc_sha256": pg["doc_sha256"][:16], "page": pg["page"], "keys": got,
                         "snippet": norm(pg["text"][max(0, i - 60):i + 100])[:160]})
    hits.sort(key=lambda h: (-len(h["keys"]), h["doc"], h["page"]))
    return keys, hits[:top]


def claim_key(x: dict) -> str:
    w = x["where"]
    m = re.match(r"에러코드 ([^:\s]+):(\S+)", w)
    if m:
        return f"{m.group(1)}:{m.group(2)}".upper()
    m = re.match(r"(?:룰|절차) (\S+)", w)
    return m.group(1).upper() if m else w[:60]


def scan(a) -> int:
    docs, out = Path(a.docs), Path(a.out)
    idx, skipped = index(docs)
    items = collect()
    rows = []
    for x in items:
        keys, hits = candidates(x["claim"], idx)
        rows.append({"claim": claim_key(x), "where": x["where"], "vendor": x["vendor"], "keys": keys, "candidates": hits})
    found = [r for r in rows if r["candidates"]]
    out.mkdir(parents=True, exist_ok=True)
    (out / "원문대조.json").write_text(json.dumps({"at": time.strftime("%Y-%m-%d %H:%M"), "docs": sorted({p["doc"] for p in idx}),
                                               "skipped": skipped, "rows": rows}, ensure_ascii=False, indent=1), encoding="utf-8")
    md = ["# 벤더 원문 대조 — 확인할 위치 후보\n",
          f"반입 문서 {len({p['doc'] for p in idx})}개 · 쪽 {len(idx)} · 못 읽은 문서 {len(skipped)}개{(' ' + ', '.join(skipped)) if skipped else ''}",
          f"미검증 주장 {len(rows)}건 중 후보 위치가 있는 것 {len(found)}건. **후보는 식별어가 같은 쪽에 나온다는 뜻일 뿐 — 사람이 열어 보고 confirm 으로 남깁니다.**\n",
          "| 주장 | 위치 | 식별어 | 후보(문서 · 쪽 · 맞은 식별어) |", "|---|---|---|---|"]
    for r in found:
        md.append(f"| `{r['claim']}` | {r['where'][:50]} | {', '.join(r['keys'][:5])} | " +
                  "<br>".join(f"{h['doc']} · {h['page']}쪽 · {', '.join(h['keys'])}" for h in r["candidates"]) + " |")
    (out / "원문대조.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"반입 문서 {len({p['doc'] for p in idx})}개 · 미검증 {len(rows)}건 중 후보 {len(found)}건 → {out / '원문대조.md'}")
    return 0


DOC_KINDS = [   # 9차 ③: 식별어 꼴 → 그것이 실릴 문서 종류(반입 요청 단위)
    ("참조 안내서(동적 뷰·데이터 사전)", re.compile(r"^(g?v\$|dba_|all_|user_|sys\.|pg_stat|information_schema|performance_schema)", re.I)),
    ("오류 메시지 안내서", re.compile(r"^([a-z]{2,6}-\d{2,6}|ah\d{4,}|ora-|tbr-|err-)", re.I)),
    ("명령어 안내서(man·CLI 옵션)", re.compile(r"^-{1,2}[a-z]")),
    ("설정·매개변수 안내서", re.compile(r"[a-z]+[._][a-z]+", re.I)),
]


DB_PRODUCTS = ("tibero", "oracle", "mysql", "postgresql", "mssql", "altibase", "cubrid", "goldilocks")


def doc_kind(ident: str, product: str = "") -> str | None:
    """식별어 → 문서 종류. 문서 주소(docs.…·.com)는 식별어가 아니므로 None. DB 제품의 밑줄 이름(SESS_ID·WLOCK_DD_OBJ)은 칼럼·잠금 유형 → 참조 안내서."""
    k = ident.lower()
    if k.startswith(("docs.", "www.")) or k.endswith((".com", ".net", ".org", ".io")):
        return None
    if k.startswith(("error_", "err_")) or "_error" in k:
        return "오류 메시지 안내서"
    if any(str(product).lower().startswith(p) for p in DB_PRODUCTS) and "_" in k and "." not in k:
        return "참조 안내서(동적 뷰·데이터 사전)"
    return next((name for name, rx in DOC_KINDS if rx.search(ident)), "운영·관리자 안내서")


def plan(a) -> int:
    """반입 요청 우선순위 — (제조사, 제품, 문서 종류)마다 그 문서로 풀릴 수 있는 미검증 주장 수 순. 수렴 실패 항목이 든 묶음을 맨 앞에."""
    items = collect()
    try:
        stuck = {str(x["key"]).upper() for x in json.loads((OUT / "수렴실패.json").read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        stuck = set()
    groups: dict = {}
    for x in items:
        keys = [k for k in idents(x["claim"]) if doc_kind(k, x["product"])]
        kinds = {doc_kind(k, x["product"]) for k in keys} or {"운영·관리자 안내서"}
        for kd in kinds:
            g = groups.setdefault((x["vendor"], x["product"], kd), {"claims": set(), "idents": {}, "stuck": False})
            g["claims"].add(x["where"])
            for k in keys:
                if doc_kind(k, x["product"]) == kd:
                    g["idents"][k] = g["idents"].get(k, 0) + 1
            if claim_key(x) in stuck:
                g["stuck"] = True
    rows = sorted(groups.items(), key=lambda kv: (not kv[1]["stuck"], -len(kv[1]["claims"])))
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# 벤더 원문 반입 요청 — 우선순위\n",
          f"미검증 주장 {len(items)}건을 식별어 꼴로 문서 종류에 나눴습니다. 한 문서 묶음이 풀 수 있는 주장 수(많은 순)이며, **교차 검증이 수렴하지 않은 항목**이 든 묶음을 맨 앞에 둡니다.",
          "식별어 꼴로 나눈 추정이라 실제로 그 문서에 실렸는지는 반입 뒤 scan 으로 확인합니다. 반입은 허가된 문서만, 이 PC 밖으로 보내지 않습니다.\n",
          "| 순위 | 제조사 | 제품 | 문서 종류 | 풀릴 수 있는 주장 | 대표 식별어 | 우선 |", "|---|---|---|---|---|---|---|"]
    for i, ((v, p, kd), g) in enumerate(rows[:60], 1):
        top = ", ".join(k for k, _ in sorted(g["idents"].items(), key=lambda kv: -kv[1])[:6])
        md.append(f"| {i} | {v} | {p} | {kd} | {len(g['claims'])} | {top} | {'수렴 실패 포함' if g['stuck'] else ''} |")
    (OUT / "반입요청우선순위.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"묶음 {len(rows)}개 → {OUT / '반입요청우선순위.md'} · 1순위: {rows[0][0] if rows else '-'}")
    return 0


def confirm(a) -> int:
    import yaml
    if a.verdict not in ("맞음", "틀림"):
        print("판정은 맞음·틀림")
        return 2
    f = next((p for p in Path(a.docs).rglob("*") if p.is_file() and p.name == a.doc), None)
    if not f:
        print("반입함에 그 문서가 없습니다:", a.doc)
        return 2
    pg = dict(pages(f)).get(int(a.page))
    ex = norm(a.excerpt)
    if not pg or not ex or ex not in norm(pg):
        print("그 쪽 글에 발췌가 없습니다 — 문서·쪽·발췌를 다시 확인하십시오")
        return 1
    if len(ex) > 200:
        print("발췌는 한 줄(200자 이하)만 — 근거 위치를 가리키는 데 필요한 만큼")
        return 2
    if not a.by.strip():
        print("확인자를 적으십시오")
        return 2
    try:
        doc = yaml.safe_load(EVID.read_text(encoding="utf-8")) or {}
    except OSError:
        doc = {}
    lst = doc.get("evidence") or []
    lst.append({"claim": a.claim.upper(), "doc": f.name, "doc_sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "page": int(a.page),
                "excerpt": ex, "sha256": hashlib.sha256(ex.encode("utf-8")).hexdigest(), "verdict": a.verdict,
                "checked": time.strftime("%Y-%m-%d"), "by": a.by.strip()})
    head = ("# 반입 원문 대조 근거(8차 아이디어 ⑤) — 사람이 반입 문서의 그 쪽을 열어 확인한 것만. 문서 자체는 이 PC 밖으로 보내지 않는다.\n"
            "# verdict 틀림 = 지식이 문서와 다름 → 고칠 목록. doc_sha256 = 확인한 문서 파일 해시(판이 바뀌면 다시 확인).\n")
    EVID.write_text(head + yaml.safe_dump({"evidence": lst}, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print("근거 기록:", a.claim.upper(), a.verdict, f.name, a.page, "쪽")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--docs", default=str(DOCS))
    s.add_argument("--out", default=str(OUT))
    c = sub.add_parser("confirm")
    for k in ("--claim", "--doc", "--page", "--excerpt", "--verdict", "--by"):
        c.add_argument(k, required=True)
    c.add_argument("--docs", default=str(DOCS))
    sub.add_parser("plan")
    a = ap.parse_args(argv)
    return {"scan": scan, "confirm": confirm, "plan": plan}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
