# -*- coding: utf-8 -*-
"""빌드 관문 — 한글 렌더링 점검(2026-10-15 아이디어 8).

1·3·10줄짜리 긴 내용(한글·영문 섞임)을 서식 2종에 내장·사용자 서식 두 길로 채우고, 한글 2022 로 열어 PDF 로 저장한 뒤
넣은 고유 표식이 PDF 글에 빠짐없이 있는지(내용 누락 0)·쪽 수가 터무니없이 늘지 않는지 본다.
실보고서는 쓰지 않는다(가짜 분석 결과). 한글이 없는 PC 에서는 '건너뜀'으로 끝난다(빌드는 이어 간다 — 장부에 건너뜀으로 남는다).
결과는 deploy/local/build/render_gate.json 에 남겨 build_ledger.py 가 읽는다.
사용: python tools/build/render_gate.py [--require]   (--require: 한글이 없으면 실패로 본다)
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
RESULT = ENGINE / "deploy" / "local" / "build" / "render_gate.json"
TPL = ENGINE / "report-template"
PROFILE = {"org": "가상기관", "system": "가상업무시스템", "service": "가상 민원 서비스", "dept": "정보화팀", "person": "홍길동",
           "rank": "주무관", "phone": "000-0000-0000", "location": "본관 전산실", "operator": "가상운영팀"}
MAX_PAGES = 12


def fake_inc(n: int) -> tuple[dict, list[str]]:
    toks, key = [], []
    for i in range(n):
        tok = f"MARK{n:02d}X{i:02d}"
        toks.append(tok)
        key.append({"ts": f"2026-10-12 09:{i:02d}:00", "ts_full": f"2026-10-12 09:{i:02d}:00", "layer_ko": "WAS",
                    "verdict": f"{tok} 커넥션 풀 고갈 Connection pool exhausted — 대기 스레드 증가 waiting threads",
                    "message": f"{tok} java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30000ms 한글 설명 포함",
                    "count": 3, "last": f"2026-10-12 09:{i:02d}:30", "marks": ["최초"] if i == 0 else [], "eid": f"E-{i:012d}"})
    first = {"verdict": f"{toks[0]} 커넥션 풀 고갈", "category_ko": "자원 고갈", "layer_ko": "WAS", "rule_id": "WAS-POOL-002",
             "ts": "09:00:00", "severity": "critical", "category": "resource", "layer": "was"}
    chk = [{"rule_id": "WAS-POOL-002", "verdict": first["verdict"], "category": "resource",
            "immediate": [f"{t} 풀 사용량 확인 check pool usage via console" for t in toks[:3]], "vendor_cause": f"{toks[0]} 풀 크기 부족"}]
    inc = {"id": f"INC-LONG{n}", "incident_time": "2026-10-12 09:00", "first": first, "timeline_key": key,
           "timeline": [{"ts": k["ts"], "layer_ko": "WAS", "verdict": k["verdict"], "message": k["message"]} for k in key],
           "checklist": chk, "files": [{"name": "catalina.out", "product": "tomcat"}], "events_window": 100, "plan": {}}
    return inc, toks


def layout_issues(doc) -> dict:
    """아이디어 8: 글자 겹침·종이 밖 넘침을 센다(PDF 글 조각 위치로). 사람이 눈으로 보던 것을 관문이 맡는다.
    겹침 = 같은 쪽의 서로 다른 글 조각이 작은 쪽 넓이의 30% 이상 포개짐. 넘침 = 글 조각이 종이 가장자리 밖으로 나감."""
    overlap = outside = cross = nlines = 0
    for page in doc:
        W, H = page.rect.width, page.rect.height
        spans = []
        # 표 세로선(그림 선·사각형 변) — 글 조각이 이 선을 가로지르면 칸 밖으로 넘친 것(3차 아이디어 8)
        vlines = []
        try:
            for d in page.get_drawings():
                for it in d.get("items", []):
                    if it[0] == "l":
                        a, b = it[1], it[2]
                        if abs(a.x - b.x) < 0.6 and abs(a.y - b.y) > 4:
                            vlines.append((a.x, min(a.y, b.y), max(a.y, b.y)))
                    elif it[0] == "re":
                        r = it[1]
                        if r.height > 4 and r.width > 0.6:
                            vlines += [(r.x0, r.y0, r.y1), (r.x1, r.y0, r.y1)]
                        elif r.height > 4:          # 아주 가는 사각형 = 세로선
                            vlines.append(((r.x0 + r.x1) / 2, r.y0, r.y1))
        except Exception:   # noqa: BLE001 — 그림 정보를 못 읽으면 넘침 검사만 건너뛴다
            vlines = []
        for b in page.get_text("dict").get("blocks", []):
            for ln in b.get("lines", []):
                for sp in ln.get("spans", []):
                    if sp.get("text", "").strip():
                        x0, y0, x1, y1 = sp["bbox"]
                        if x1 - x0 > 0.5 and y1 - y0 > 0.5:
                            spans.append((x0, y0, x1, y1))
                            if x0 < -1 or y0 < -1 or x1 > W + 1 or y1 > H + 1:
                                outside += 1
        nlines += len(vlines)
        for (x0, y0, x1, y1) in spans:
            h = y1 - y0
            for (lx, ly0, ly1) in vlines:
                if x0 + 1.5 < lx < x1 - 1.5 and min(y1, ly1) - max(y0, ly0) >= 0.6 * h:
                    cross += 1
                    break
        spans.sort()
        for i, a in enumerate(spans):
            for b2 in spans[i + 1:]:
                if b2[0] >= a[2]:
                    break
                ix = min(a[2], b2[2]) - max(a[0], b2[0])
                iy = min(a[3], b2[3]) - max(a[1], b2[1])
                if ix > 0 and iy > 0:
                    small = min((a[2] - a[0]) * (a[3] - a[1]), (b2[2] - b2[0]) * (b2[3] - b2[1]))
                    if small and ix * iy / small >= 0.3:
                        overlap += 1
    return {"overlap": overlap, "outside": outside, "cross": cross, "vlines": nlines}


def save(res: dict) -> None:
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")


def main(argv=None) -> int:
    require = "--require" in (argv if argv is not None else sys.argv[1:])
    res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "result": "skip", "checked": 0, "failed": 0, "why": ""}
    try:
        try:
            import pymupdf as fitz
        except ImportError:
            import fitz
        import win32com.client as win32
    except Exception as e:   # 렌더러가 없는 PC
        res["why"] = f"점검 도구 없음({type(e).__name__})"
        save(res)
        print("한글 렌더링 관문: 건너뜀 —", res["why"])
        return 1 if require else 0
    from logtriage import report_custom as rc, report_forms as rf
    out = Path(tempfile.mkdtemp(prefix="lt_render_"))
    try:
        tdir = out / "tdir"
        tdir.mkdir()
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            if (TPL / f).exists():
                shutil.copyfile(TPL / f, tdir / f)
        sp = rf.StyleProfile.load(tdir)
        made = []
        for n in (1, 3, 10):
            inc, toks = fake_inc(n)
            for key, fname in (("status", "form_status.hwpx"), ("postmortem", "form_postmortem.hwpx")):
                a = out / f"L{n}_{key}_A.hwpx"
                rf.fill_hwpx(tdir / fname, inc, PROFILE, key, a, sp)
                # 사용자 서식 길 — 기본 서식과 같은 파일은 중복으로 막히므로 한 바이트 다른 사본으로 등록한다
                cp = out / f"L{n}_{key}_form.hwpx"
                rf_bytes = (tdir / fname).read_bytes()
                cp.write_bytes(rf_bytes)
                import zipfile
                with zipfile.ZipFile(cp, "a") as z:
                    z.writestr("lt_render_gate.txt", "x")
                saved = rc.save_template(tdir, cp, f"L{n}{key}", rc.analyze_form(cp)["fields"])
                t = rc.load_template(tdir, saved["id"])
                b = out / f"L{n}_{key}_B.hwpx"
                rc.fill_template(Path(t["form"]), t["fields"], inc, PROFILE, b)
                rc.delete_template(tdir, saved["id"])
                made += [(a, toks), (b, toks)]
        try:
            hwp = win32.gencache.EnsureDispatch("HWPFrame.HwpObject")
        except Exception as e:
            res["why"] = f"한글 없음({type(e).__name__})"
            save(res)
            print("한글 렌더링 관문: 건너뜀 —", res["why"])
            return 1 if require else 0
        bad = []
        try:
            hwp.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule")
            for f, toks in made:
                pdf = f.with_suffix(".pdf")
                ok = hwp.Open(str(f), "HWPX", "forceopen:true")
                saved = bool(ok) and hwp.SaveAs(str(pdf), "PDF", "")
                hwp.Clear(1)
                time.sleep(0.2)
                text, pages, lay = "", 0, {"overlap": 0, "outside": 0, "cross": 0}
                if saved:
                    d = fitz.open(pdf)
                    pages = d.page_count
                    text = "".join(pg.get_text() for pg in d)
                    lay = layout_issues(d)
                    d.close()
                flat = "".join(text.split())
                missing = [t for t in toks if t not in flat]
                res["overlap"] = res.get("overlap", 0) + lay["overlap"]
                res["outside"] = res.get("outside", 0) + lay["outside"]
                res["cross"] = res.get("cross", 0) + lay["cross"]
                res["vlines"] = res.get("vlines", 0) + lay.get("vlines", 0)   # 검사할 표 선을 실제로 읽었는지(0 이면 넘침 검사가 빈 검사)
                if not (ok and saved and not missing and pages <= MAX_PAGES and not lay["overlap"] and not lay["outside"] and not lay["cross"]):
                    bad.append(f"{f.name}: 열기 {bool(ok)} · 저장 {bool(saved)} · 쪽 {pages} · 표식 {len(toks) - len(missing)}/{len(toks)}"
                               f" · 겹침 {lay['overlap']} · 종이 밖 {lay['outside']} · 칸 넘침 {lay['cross']}")
        finally:
            hwp.Quit()
        res.update(result="fail" if bad else "pass", checked=len(made), failed=len(bad), why="; ".join(bad)[:500])
        save(res)
        print(f"한글 렌더링 관문: {'통과' if not bad else '실패'} — {len(made)}개 중 문제 {len(bad)} · 글자 겹침 {res.get('overlap', 0)} · 종이 밖 {res.get('outside', 0)} · 칸 넘침 {res.get('cross', 0)} (표 선 {res.get('vlines', 0)}개 대조)")
        for x in bad:
            print("  ", x)
        return 1 if bad else 0
    finally:
        shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
