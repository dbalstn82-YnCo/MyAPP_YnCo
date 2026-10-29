"""제조사 자료 요청서(2026-10-16 아이디어 11 · GPT 55차) — 지식에 '미검증'으로 남긴 주장을 제조사·제품·판별로 묶어
'무엇을 확인해 달라'는 요청서로 만든다. 요청서에는 고객 로그·호스트·계정이 들어가지 않는다(지식 문구와 확인할 주장만).

모으는 곳: 에러코드·룰의 verify_note, 절차(procedure)·단계(step)의 verify_note, 단계 note 의 '미검증 — …' 문구.
사용: python tools/build/make_vendor_requests.py [--out deploy/local/제조사자료요청] [--docx]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage.codes import load_codes  # noqa: E402
from logtriage.yamlsafe import load as yload  # noqa: E402

VENDOR = {"oracle": "Oracle", "mysql": "Oracle(MySQL)", "solaris": "Oracle(Solaris)", "weblogic": "Oracle(WebLogic)",
          "tibero": "TmaxTibero", "jeus": "TmaxSoft", "webtob": "TmaxSoft", "altibase": "Altibase", "cubrid": "CUBRID",
          "goldilocks": "SUNJESOFT(GOLDILOCKS)", "mssql": "Microsoft", "windows": "Microsoft", "iis": "Microsoft",
          "postgresql": "PostgreSQL(커뮤니티·지원 업체)", "aix": "IBM", "websphere": "IBM", "hpux": "HPE", "linux": "Red Hat 등 배포판",
          "jboss": "Red Hat(JBoss·WildFly)", "tomcat": "Apache(Tomcat)", "apache": "Apache(httpd)", "nginx": "F5(NGINX)",
          "java": "Oracle·OpenJDK(Java)", "mesim": "제품 공급사(MESIM)", "bizmaster": "제품 공급사(BizMaster)", "indigo": "제품 공급사(Indigo)"}
MIS = re.compile(r"미검증\s*[—:-]?\s*([^·]{6,})")


def vendor_of(products) -> str:
    for p in products or []:
        p = str(p).lower()
        for k, v in VENDOR.items():
            if p == k or p.startswith(k):
                return v
    return "공급사 확인 필요"


def collect() -> list[dict]:
    out = []
    for k, e in load_codes(ENGINE / "errorcodes").items():
        if ":" in k and e.verify_note:
            out.append({"vendor": vendor_of([e.product]), "product": e.product, "versions": ", ".join(e.versions) or "판 미기재",
                        "where": f"에러코드 {e.product}:{e.code} ({e.title})", "claim": e.verify_note, "ref": e.ref})
    for f in sorted((ENGINE / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("verify_note"):
                prods = r.get("product") or ["*"]
                prods = prods if isinstance(prods, list) else [prods]
                out.append({"vendor": vendor_of(prods), "product": ",".join(map(str, prods)), "versions": "판 미기재",
                            "where": f"룰 {r['id']} ({r.get('title', '')})", "claim": str(r["verify_note"]), "ref": ""})
    for f in sorted((ENGINE / "manuals").glob("*_procedures.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for p in (doc.get("procedures") or []) if isinstance(doc, dict) else []:
            if not isinstance(p, dict):
                continue
            prods = p.get("products") or []
            base = {"vendor": vendor_of(prods), "product": ",".join(map(str, prods)), "ref": ""}
            if p.get("verify_note"):
                out.append({**base, "versions": "판 미기재", "where": f"절차 {p.get('id')} ({p.get('title', '')})", "claim": str(p["verify_note"])})
            for st in p.get("stages") or []:
                for s in (st.get("steps") or []) if isinstance(st, dict) else []:
                    if not isinstance(s, dict):
                        continue
                    note = str(s.get("note", ""))
                    ver = re.search(r"적용:\s*([^·]+)", note)
                    claims = [str(s["verify_note"])] if s.get("verify_note") else [m.group(0).strip() for m in MIS.finditer(note)]
                    for c in claims:
                        out.append({**base, "versions": ver.group(1).strip() if ver else "판 미기재",
                                    "where": f"절차 {p.get('id')} {st.get('stage')}차 — {str(s.get('do', ''))[:60]}", "claim": c})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ENGINE / "deploy" / "local" / "제조사자료요청"))
    ap.add_argument("--docx", action="store_true")
    a = ap.parse_args(argv)
    items = collect()
    try:   # 9차 ②: 재검증 수렴 실패 목록(knowledge_sample_queue pending 이 씀)
        stuck = {str(x["key"]).upper(): f"연속 {x['streak']}회 부분·오류(회차 {x['round']})"
                 for x in json.loads((ENGINE / "deploy" / "local" / "지식검증" / "수렴실패.json").read_text(encoding="utf-8"))}
    except (OSError, ValueError):
        stuck = {}
    for x in items:
        m = re.match(r"에러코드 ([^:\s]+):(\S+)", x["where"])
        k = f"{m.group(1)}:{m.group(2)}".upper() if m else (x["where"].split(" ")[1].upper() if x["where"].startswith(("룰 ", "절차 ")) else "")
        if k in stuck:
            x["stuck"] = stuck[k]
    by = defaultdict(lambda: defaultdict(list))
    for x in items:
        by[x["vendor"]][(x["product"], x["versions"])].append(x)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for old in list(out.glob("*.md")) + list(out.glob("*.docx")):   # 지난번 요청서가 남아 섞이지 않게
        old.unlink()
    index = ["# 제조사 자료 요청 — 목록\n", f"미검증 주장 {len(items)}건 · 제조사 {len(by)}곳. 요청서에는 고객 로그·호스트·계정이 들어 있지 않습니다.\n",
             "| 제조사 | 건수 | 파일 |", "|---|---|---|"]
    for v in sorted(by, key=lambda k: -sum(len(x) for x in by[k].values())):
        n = sum(len(x) for x in by[v].values())
        fn = re.sub(r"[^\w가-힣]+", "_", v).strip("_") + ".md"
        md = [f"# {v} — 기술 자료 확인 요청\n",
              "아래는 장애 1차 대응 지식에 들어 있으나 공식 문서 원문으로 확인하지 못한 내용입니다. 항목마다 **맞는지, 해당 판, 근거 문서(제목·문서 번호)**를 회신해 주십시오.",
              "고객 환경의 로그·호스트 정보는 포함하지 않았습니다.\n"]
        i = 0
        hot = [x for xs in by[v].values() for x in xs if x.get("stuck")]
        if hot:   # 9차 ②: 교차 검증이 수렴하지 않은 항목 — 맨 앞 '우선'으로
            md.append("## 우선 — 교차 검증이 수렴하지 않은 항목(같은 항목이 연속 3회 이상 '부분·오류')\n")
            md.append("| # | 위치 | 확인할 주장 | 회신(맞음/틀림·근거) |")
            md.append("|---|---|---|---|")
            for x in hot:
                i += 1
                md.append(f"| {i} | {x['where'].replace('|', '/')} — {x['stuck']} | {x['claim'].replace('|', '/')[:600]} | |")
            md.append("")
        for (prod, ver), xs in sorted(by[v].items()):
            md.append(f"## {prod} · {ver}\n")
            md.append("| # | 위치 | 확인할 주장 | 회신(맞음/틀림·근거) |")
            md.append("|---|---|---|---|")
            for x in xs:
                i += 1
                md.append(f"| {i} | {x['where'].replace('|', '/')} | {x['claim'].replace('|', '/')[:400]} | |")
            md.append("")
        (out / fn).write_text("\n".join(md), encoding="utf-8")
        index.append(f"| {v} | {n} | {fn} |")
        if a.docx:
            subprocess.run([sys.executable, str(Path(__file__).with_name("md2docx.py")), str(out / fn), str((out / fn).with_suffix(".docx"))],
                           check=False, capture_output=True)
    (out / "_목록.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    print(f"미검증 주장 {len(items)}건 · 제조사 {len(by)}곳 → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
