"""사용자 서식 등록 ↔ 내장 서식 채우기 동등성 · 서식 학습(자간·장평) — 2026-10-15 마스터 지시
"첨부한 hwpx 를 장애보고서 양식으로 등록하고, 추가 등록 시 보고서에 맞게 로그 분석 내용을 적용 · 최소한의 수정".

- 공식 서식을 '사용자 서식' 으로 등록(분석 → 저장 → 불러오기 → 채우기)해도 내장 채우기와 글·글자 모양이 같다(예전 14곳 다름)
- 작성 안내 문단(※ 서버위치…기재)·제목 뒤 '#…' 안내 정리, 표 머리줄(항목/내용/비고) 무시, '담당자(연락처)' 겹친 칸
- 저장 때 작성 안내 자리(para_note)가 버려지지 않는다 · 같은 서식 두 번 등록 막기
- 서식 학습: 자간·장평을 배우고 적용(HWPX·DOCX), 예전 최빈 모양 비율은 그대로, 표 통계는 실행마다 같다
실보고서는 쓰지 않는다 — 공식 서식 + 합성 샘플 로그 + 생성물만.
"""
import json
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent)); import _privtmp  # noqa: E402,E702
from lxml import etree  # noqa: E402

from logtriage import report_custom as rc, report_forms as rf, report_style as rs  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

TPL = ENGINE / "report-template"
S = ENGINE / "samples"
HH = "http://www.hancom.co.kr/hwpml/2011/head"
HPN = "http://www.hancom.co.kr/hwpml/2011/paragraph"
PROFILE = {"org": "가상기관", "parent_org": "가상상위기관", "system": "가상업무시스템", "service": "가상 민원 서비스", "grade": "2등급",
           "location": "본관 전산실", "operator": "가상운영팀", "dept": "정보화팀", "person": "홍길동", "rank": "주무관",
           "phone": "000-0000-0000", "intro_year": "2020년 / 7년", "ha": "이중화"}


def styled_texts(hwpx: Path) -> list[str]:
    z = zipfile.ZipFile(hwpx)
    root = etree.fromstring(z.read(sorted(n for n in z.namelist() if re.match(r"Contents/section\d+\.xml$", n))[0]))
    hdr = etree.fromstring(z.read("Contents/header.xml"))
    cps = {}
    for cp in hdr.iter("{%s}charPr" % HH):
        sp, ra, fr = cp.find("{%s}spacing" % HH), cp.find("{%s}ratio" % HH), cp.find("{%s}fontRef" % HH)
        cps[cp.get("id")] = (fr.get("hangul") if fr is not None else "", cp.get("height"), cp.find("{%s}bold" % HH) is not None,
                             cp.get("textColor"), sp.get("hangul") if sp is not None else "", ra.get("hangul") if ra is not None else "")
    out = []
    for p in root.iter("{%s}p" % HPN):
        parts = ["".join(x.text or "" for x in r.findall("{%s}t" % HPN)) + str(cps.get(r.get("charPrIDRef")))
                 for r in p.findall("{%s}run" % HPN) if "".join(x.text or "" for x in r.findall("{%s}t" % HPN)).strip()]
        if parts:
            out.append(re.sub(r"\s+", " ", "".join(parts)).strip())
    return out


class Parity(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))
        self.tdir = self.td / "tdir"; self.tdir.mkdir()
        if (TPL / "style_profile.json").exists():
            shutil.copyfile(TPL / "style_profile.json", self.tdir / "style_profile.json")
        (self.td / "clean.log").write_text("12-Oct-2026 09:00:01.123 INFO [main] Server startup in 1234 ms\n", encoding="utf-8")

    def _inc(self, files):
        return run_analysis([{"path": str(f), "product": p, "host": "h"} for f, p in files], None,
                            rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")

    def test_custom_registration_equals_builtin(self):
        sp = rf.StyleProfile.load(self.tdir)
        scen = [(PROFILE, [(S / "alert_orcl.log", "oracle"), (S / "catalina.out", "tomcat")]),
                ({}, [(S / "nginx_error.log", "nginx")]),
                (PROFILE, [(self.td / "clean.log", "tomcat")])]
        for si, (prof, files) in enumerate(scen):
            inc = self._inc(files); inc["id"] = f"INC-P{si}"
            for key, fname in (("status", "form_status.hwpx"), ("postmortem", "form_postmortem.hwpx")):
                a, b = self.td / f"A{si}{key}.hwpx", self.td / f"B{si}{key}.hwpx"
                rf.fill_hwpx(TPL / fname, inc, prof, key, a, sp)
                saved = rc.save_template(self.tdir, TPL / fname, f"시험{si}{key}", rc.analyze_form(TPL / fname)["fields"])
                t = rc.load_template(self.tdir, saved["id"])
                rc.fill_template(Path(t["form"]), t["fields"], inc, prof, b)
                rc.delete_template(self.tdir, saved["id"])
                self.assertEqual(styled_texts(a), styled_texts(b), f"{si} {key}")

    def test_form_analysis_details(self):
        st = {f["field"] for f in rc.analyze_form(TPL / "form_status.hwpx")["fields"]}
        self.assertIn("server_note", st)
        pm = rc.analyze_form(TPL / "form_postmortem.hwpx")["fields"]
        labels = {f["label"]: f["field"] for f in pm if f["kind"] == "cell"}
        self.assertNotIn("내 용", labels); self.assertNotIn("비 고", labels)          # 표 머리줄은 칸 이름이 아니다
        self.assertEqual(labels.get("정보시스템명"), "system")
        self.assertEqual(labels.get("운영 담당자(연락처)"), "person_phone")
        self.assertEqual(labels.get("제조사"), "vendors")
        self.assertEqual(rc.suggest("(무중단 운영) 시스템 임계치 관리 현황"), "obs_threshold")
        self.assertEqual(rc.suggest("장애 근본원인 조치 여부"), "actions")

    def test_note_kind_survives_save_and_duplicates_blocked(self):
        fields = rc.analyze_form(TPL / "form_status.hwpx")["fields"]
        saved = rc.save_template(self.tdir, TPL / "form_status.hwpx", "시험", fields)
        kinds = {f["kind"] for f in rc.load_template(self.tdir, saved["id"])["fields"]}
        self.assertIn("para_note", kinds)                                           # 예전엔 저장하면서 버려졌다
        with self.assertRaises(ValueError) as cm:                                   # 같은 파일 다시 등록
            rc.save_template(self.tdir, TPL / "form_status.hwpx", "시험2", fields)
        self.assertIn("등록된 사용자 서식", str(cm.exception))
        shutil.copyfile(TPL / "form_status.hwpx", self.tdir / "form_status.hwpx")   # 기본 서식과 같은 파일
        self.assertIn("기본 서식", rc.same_form(self.tdir, TPL / "form_status.hwpx", exclude_id=saved["id"]))

    def test_variant_form_maps(self):
        v = self.td / "variant.hwpx"
        zi = zipfile.ZipFile(TPL / "form_status.hwpx")
        rep = [("○ 장애시간", "○ 장애 발생 일시"), ("○ 장애원인", "○ 발생 원인"), ("○ 서비스명", "○ 업무명"), (">소속<", ">부서<"),
               (">직급<", ">직위<"), (">담당자<", ">작성자<"), (">연락처<", ">전화<"), ("○ 장애내용", "○ 장애 현상")]
        with zipfile.ZipFile(v, "w", zipfile.ZIP_DEFLATED) as zo:
            for n in zi.namelist():
                b = zi.read(n)
                if re.match(r"Contents/section\d+\.xml", n):
                    t = b.decode("utf-8")
                    for x, y in rep:
                        t = t.replace(x, y)
                    b = t.encode("utf-8")
                zo.writestr(n, b)
        got = {f["label"]: f["field"] for f in rc.analyze_form(v)["fields"]}
        for lb, key in (("부서", "dept"), ("직위", "rank"), ("작성자", "person"), ("전화", "phone"), ("장애 발생 일시", "incident_period"),
                        ("업무명", "service"), ("장애 현상", "content"), ("발생 원인", "cause")):
            self.assertEqual(got.get(lb), key, lb)


def cell_values(hwpx: Path) -> dict:
    """표마다 '칸 이름 → 오른쪽 값 칸 글' — 표 순서가 바뀌어도 같은 칸 이름에 같은 값이 들어갔는지 대조."""
    z = zipfile.ZipFile(hwpx)
    root = etree.fromstring(z.read(sorted(n for n in z.namelist() if re.match(r"Contents/section\d+\.xml$", n))[0]))
    out = {}
    for tb in rf.top_tables(root):
        cells = rc._cells(tb)
        for (c, r), x in cells.items():
            right = cells.get((c + x["cs"], r))
            if x["text"] and right is not None:
                out.setdefault(x["text"], right["text"])
    return out


class GptRound21(unittest.TestCase):
    """GPT 21차 필수 시험 — T1 변형 서식(표 순서·모호한 이름) · T3 저장→재시작→생성. (T2 긴 내용·줄바꿈 렌더링은 검증도구/report_render_check.py — 한글 필요)"""

    def setUp(self):
        self.td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))
        self.tdir = self.td / "tdir"; self.tdir.mkdir()
        shutil.copyfile(TPL / "style_profile.json", self.tdir / "style_profile.json")
        self.inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                                rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        self.inc["id"] = "INC-T"

    def _fill_custom(self, form: Path, out: Path):
        saved = rc.save_template(self.tdir, form, form.stem, rc.analyze_form(form)["fields"])
        t = rc.load_template(self.tdir, saved["id"])
        rc.fill_template(Path(t["form"]), t["fields"], self.inc, PROFILE, out)
        rc.delete_template(self.tdir, saved["id"])

    def test_t1_table_order_swapped_same_cell_values(self):
        src = TPL / "form_postmortem.hwpx"
        swapped = self.td / "swapped.hwpx"
        zi = zipfile.ZipFile(src)
        with zipfile.ZipFile(swapped, "w", zipfile.ZIP_DEFLATED) as zo:
            for n in zi.namelist():
                b = zi.read(n)
                if re.match(r"Contents/section\d+\.xml$", n):
                    root = etree.fromstring(b)
                    tops = [p for p in root if p.find(".//{%s}tbl" % HPN) is not None]
                    a, c = tops[1], tops[2]                       # 시스템 개요 표 ↔ 그다음 표 자리 바꾸기
                    ia, ic = list(root).index(a), list(root).index(c)
                    root.remove(c); root.insert(ia, c); root.remove(a); root.insert(ic, a)
                    b = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
                zo.writestr(n, b)
        o1, o2 = self.td / "o1.hwpx", self.td / "o2.hwpx"
        self._fill_custom(src, o1)
        shutil.copyfile(swapped, self.td / "swapped2.hwpx")
        self._fill_custom(self.td / "swapped2.hwpx", o2)
        labels = {f["label"] for f in rc.analyze_form(src)["fields"] if f["kind"] == "cell"}   # 원래 서식의 칸 이름만(값 칸은 대조하지 않는다)
        v1 = {k: v for k, v in cell_values(o1).items() if k in labels}
        v2 = {k: v for k, v in cell_values(o2).items() if k in labels}
        self.assertGreaterEqual(len(v1), 15)
        self.assertTrue(v1 and v1 == v2, {k: (v1.get(k), v2.get(k)) for k in set(v1) | set(v2) if v1.get(k) != v2.get(k)})

    def test_t1_ambiguous_label_not_auto(self):
        for lb in ("내용", "내 용", "비고", "기타", "구분", "결과"):
            self.assertEqual(rc.suggest(lb), "blank", lb)
        self.assertEqual(rc.suggest("장애 내용"), "content")                         # 뜻이 분명하면 그대로

    def test_t3_save_restart_generate(self):
        import hashlib, subprocess
        before = hashlib.sha256((TPL / "form_status.hwpx").read_bytes()).hexdigest()
        saved = rc.save_template(self.tdir, TPL / "form_status.hwpx", "재시작", rc.analyze_form(TPL / "form_status.hwpx")["fields"])
        incf = self.td / "inc.json"; incf.write_text(json.dumps(self.inc, ensure_ascii=False, default=str), encoding="utf-8")
        here = self.td / "here.hwpx"
        t = rc.load_template(self.tdir, saved["id"]); rc.fill_template(Path(t["form"]), t["fields"], self.inc, PROFILE, here)
        code = ("import sys,json; sys.path.insert(0,%r); from pathlib import Path; from logtriage import report_custom as rc;"
                "inc=json.loads(Path(%r).read_text(encoding='utf-8')); t=rc.load_template(Path(%r),%r);"
                "rc.fill_template(Path(t['form']),t['fields'],inc,%r,Path(%r))") % (str(ENGINE), str(incf), str(self.tdir), saved["id"], PROFILE, str(self.td / "there.hwpx"))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertEqual(styled_texts(here), styled_texts(self.td / "there.hwpx"))     # 새 프로세스(재시작)에서도 같은 결과
        self.assertEqual(hashlib.sha256((TPL / "form_status.hwpx").read_bytes()).hexdigest(), before)   # 원본 서식 그대로
        kinds = {f["kind"] for f in rc.load_template(self.tdir, saved["id"])["fields"]}
        self.assertIn("para_note", kinds)


class NoTruncation(unittest.TestCase):
    """GPT 21차: 실보고서 줄 수(p75)는 맞추되 내용은 자르지 않는다 — 합치거나 줄을 늘리거나 전체 근거 파일을 가리킨다."""

    def _F(self, inc):
        sp = rf.StyleProfile({"fields": {k: {"lines": {"n": 10, "min": 1, "p25": 1, "median": 1, "p75": 1, "max": 2}}
                                         for k in ("장애 근본원인", "장애 근본원인 조치 여부", "문제관리 이관 여부", "조치내용")}})
        return rf.Facts(inc, {}, None, sp)

    def test_nothing_dropped(self):
        key = [{"ts": f"2026-10-12 09:{i:02d}:00", "layer_ko": "WAS", "verdict": f"V{i:02d}", "message": "m", "count": 1, "marks": []} for i in range(9)]
        inc = {"id": "INC-NT", "incident_time": "2026-10-12 09:00", "timeline_key": key,
               "first": {"verdict": "판정 가능성", "category_ko": "자원", "layer_ko": "WAS", "rule_id": "R1", "origin": "legacy"},
               "checklist": [{"vendor_cause": "제조사 원인", "immediate": ["a1", "a2", "a3", "a4"]}],
               "plan": {"tier1": {"escalate": {"when": ["기준1", "기준2", "기준3"]}}, "tier3": {"summary": ["제품/버전: x / 버전·패치 레벨 [담당자 기재]"]}}}
        F = self._F(inc)
        cause = "\n".join(F.cause_lines(root=True))
        self.assertIn("제조사 원인", cause); self.assertIn("원인 확정 여부", cause)          # 합치되 버리지 않는다
        self.assertEqual(len(F.fix_lines()), 4)                                            # 1차 조치 4개 모두
        esc = "\n".join(F.escalation_lines())
        for w in ("이관 여부", "버전·패치 레벨", "기준1", "기준2", "기준3"):
            self.assertIn(w, esc)
        tl = "\n".join(F.timeline_lines("조치내용", 3))
        for i in range(9):
            self.assertIn(f"V{i:02d}", tl)                                                  # 남은 판정은 '그 밖의 관측' 줄로
        self.assertIn("분석요약_INC-NT.html", tl)

    def test_summary_html_holds_everything_pointed_to(self):
        """GPT 22차: 본문이 '그 밖의 관측 … 분석요약(첨부)' 로 넘긴 판정이 분석요약에 빠짐없이(예전엔 25건 중 1건). 이스케이프 유지, 골격 없어도 생성."""
        from logtriage import report as rp
        td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        key = [{"ts": f"2026-10-12 09:{i:02d}:00", "layer_ko": "WAS", "verdict": f"TOK{i:02d}" + ("<script>x</script>" if i == 24 else ""),
                "message": "m", "count": 1, "marks": []} for i in range(25)]
        inc = {"id": "INC-H", "incident_time": "2026-10-12 09:00", "timeline_key": key, "checklist": [], "plan": {},
               "first": {"verdict": "TOK00", "category_ko": "자원", "layer_ko": "WAS", "rule_id": "R0", "ts": "09:00:00"},
               "timeline": [{"ts": k["ts"][11:], "layer_ko": "WAS", "verdict": k["verdict"], "message": "m"} for k in key],
               "files": [{"name": "c.out", "product": "tomcat"}]}
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            shutil.copyfile(TPL / f, td / f)                                      # 서식은 골격 파일과 같은 폴더에서 찾는다
        r = rp.generate(td / "골격없음.yaml", inc, td / "out")
        h = Path(r["html"]).read_text(encoding="utf-8")
        self.assertEqual(sum(1 for i in range(25) if f"TOK{i:02d}" in h), 25)
        self.assertNotIn("<script>x", h); self.assertIn("&lt;script&gt;", h)
        body = "".join(re.findall(r"<hp:t[^>]*>([^<]*)</hp:t>", zipfile.ZipFile(r["hwpx_all"][0]).read("Contents/section0.xml").decode()))
        self.assertIn("분석요약_INC-H.html", body)

    def test_weak_spacing_evidence_keeps_form(self):
        weak = {"face": "맑은 고딕", "size": 11.0, "n": 4, "share": 0.9, "spacing": -5, "ratio": 95, "sr_share": 0.9, "sr_margin": 0.9}
        self.assertIsNone(rf.StyleProfile._style({"char": weak})["spacing"])               # 표본 4 < 5
        mixed = dict(weak, n=9, sr_share=0.55, sr_margin=0.1)
        self.assertIsNone(rf.StyleProfile._style({"char": mixed})["ratio"])                # 60%·20%p 미만
        strong = dict(weak, n=9)
        self.assertEqual(rf.StyleProfile._style({"char": strong})["spacing"], -5)


class StyleLearning(unittest.TestCase):
    def test_spacing_ratio_learned_applied_and_deterministic(self):
        td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        corpus = td / "corpus"; corpus.mkdir()
        inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                           rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        inc["id"] = "INC-SL"
        # 학습 재료: 값 글자의 자간을 -5·장평 95 로 바꾼 생성 보고서 4건(실보고서 대신)
        sp = rf.StyleProfile({"fields": {"장애원인": {"char": {"face": "맑은 고딕", "size": 11.0, "bold": False, "color": "#000000",
                                                         "spacing": -5, "ratio": 95, "n": 9, "share": 0.9,
                                                         "sr_share": 0.9, "sr_margin": 0.9}}}})
        for k in range(4):
            rf.fill_hwpx(TPL / "form_status.hwpx", inc, PROFILE, "status", corpus / f"r{k}.hwpx", sp)
        h = zipfile.ZipFile(corpus / "r0.hwpx").read("Contents/header.xml").decode("utf-8")
        self.assertRegex(h, r'<hh:spacing hangul="-5"')                               # 적용: HWPX 글자 모양
        self.assertRegex(h, r'<hh:ratio hangul="95"')
        docx = td / "r0.docx"; rf.hwpx_to_docx(corpus / "r0.hwpx", docx)
        dx = zipfile.ZipFile(docx).read("word/document.xml").decode("utf-8")
        self.assertIn('<w:w w:val="95"/>', dx); self.assertRegex(dx, r'<w:spacing w:val="-\d+"/>')   # DOCX 도 같은 모양
        outs = []
        for k in range(2):
            o = td / f"p{k}.json"; rs.learn(corpus, TPL, o)
            d = json.loads(o.read_text(encoding="utf-8")); d.pop("generated", None); outs.append(d)
        self.assertEqual(outs[0], outs[1])                                           # 실행마다 같다(예전 id(요소) 섞임)
        ch = outs[0]["fields"]["장애원인"]["char"]
        self.assertEqual((ch["spacing"], ch["ratio"]), (-5, 95))                      # 배움
        self.assertEqual(rs.Agg.key(rs.char_style("x", 10, spacing=-5, ratio=95))[5:], (-5, 95))

    def test_field_label_longest_match(self):
        labels = rs.form_labels(TPL)
        paras = [rs.Para("○ 장애 근본원인", [("○ 장애 근본원인", rs.char_style())], rs.para_style()),
                 rs.Para("- 원인 한 줄", [("- 원인 한 줄", rs.char_style())], rs.para_style()),
                 rs.Para("○ 장애 근본원인 조치 여부", [("○ 장애 근본원인 조치 여부", rs.char_style())], rs.para_style()),
                 rs.Para("- 조치 하나", [("- 조치 하나", rs.char_style())], rs.para_style()),
                 rs.Para("- 조치 둘", [("- 조치 둘", rs.char_style())], rs.para_style())]
        agg = rs.Agg(); rs.learn_doc(paras, "postmortem", labels, agg)
        self.assertEqual(agg.field_lines["장애 근본원인"], [1])                        # 예전엔 3(조치 여부 줄까지 합쳐짐)
        self.assertEqual(agg.field_lines["장애 근본원인 조치 여부"], [2])


if __name__ == "__main__":
    unittest.main()


class StaleBackupSweep(unittest.TestCase):
    """강제 종료로 남은 임시 백업(.backup-*, 자료 사본) 정리 — GPT 24차: 주인 프로세스가 끝난 것만, 오래 도는·동시 백업은 지우지 않는다,
    링크·정션은 따라가지 않는다. 반출 zip 은 늘 뺀다(2026-10-15 설치 폴더에서 2개 발견)."""

    def setUp(self):
        self.td = Path(_privtmp.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))

    def _mk(self, name, pid=None, age=0):
        import os, time
        d = self.td / name
        (d / "stage" / "data").mkdir(parents=True); (d / "stage" / "data" / "x.db").write_text("x")
        if pid is not None:
            (d / ".owner").write_text(json.dumps({"pid": pid, "started": time.time() - age}), encoding="utf-8")
        t = time.time() - age
        os.utime(d, (t, t))
        return d

    def test_owner_rules(self):
        import os, subprocess
        from logtriage import safe_backup
        dead = subprocess.Popen([sys.executable, "-c", "pass"]); dead.wait()
        running = self._mk(".backup-running", pid=os.getpid(), age=5 * 3600)      # 5시간째 도는 백업(주인 살아 있음)
        orphan = self._mk(".backup-orphan", pid=dead.pid, age=60)                  # 주인 끝남(강제 종료) — 방금이라도 정리
        legacy_new = self._mk(".backup-legacy1", age=2 * 3600)                     # 표식 없는 옛 폴더 2시간
        legacy_old = self._mk(".backup-legacy2", age=30 * 3600)                    # 표식 없는 옛 폴더 30시간
        safe_backup._sweep_stale(self.td)
        self.assertTrue(running.exists()); self.assertFalse(orphan.exists())
        self.assertTrue(legacy_new.exists()); self.assertTrue(legacy_old.exists())      # GPT 25차: 표식 없으면 오래돼도 지우지 않는다
        self.assertEqual(sorted(d.name for d in safe_backup.stale_unowned(self.td)), [".backup-legacy1", ".backup-legacy2"])   # 관리자 확인 대상

    def test_inner_junction_blocks_delete(self):
        import _winapi, subprocess
        from logtriage import safe_backup
        dead = subprocess.Popen([sys.executable, "-c", "pass"]); dead.wait()
        target = self.td / "outside"; target.mkdir(); (target / "precious.txt").write_text("x")
        d = self._mk(".backup-withlink", pid=dead.pid)
        _winapi.CreateJunction(str(target), str(d / "stage" / "j"))
        safe_backup._sweep_stale(self.td)
        self.assertTrue(d.exists()); self.assertTrue((target / "precious.txt").exists())   # 하위 정션이 있으면 지우지 않는다

    def test_junction_not_followed(self):
        import _winapi, os
        from logtriage import safe_backup
        target = self.td / "keep"; target.mkdir(); (target / "precious.txt").write_text("x")
        j = self.td / ".backup-junction"
        _winapi.CreateJunction(str(target), str(j))
        old = __import__("time").time() - 40 * 3600
        os.utime(target, (old, old))
        safe_backup._sweep_stale(self.td)
        self.assertTrue((target / "precious.txt").exists())

    def test_concurrent_snapshots_survive(self):
        import threading
        from logtriage import safe_backup
        base = self.td / "base"
        for r in safe_backup.ROOTS:
            (base / r).mkdir(parents=True, exist_ok=True)
            (base / r / "f.txt").write_text("x" * 2000)
        out, err = [], []
        def run():
            try: out.append(safe_backup.snapshot(base))
            except Exception as e: err.append(e)
        ts = [threading.Thread(target=run) for _ in range(3)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(err, []); self.assertEqual(len(out), 3)
        for r in out:
            safe_backup.verify(r["file"])                                          # 묶음에 주인 표식이 섞이지 않고 검증 통과
            with zipfile.ZipFile(r["file"]) as z:
                self.assertNotIn(".owner", z.namelist())
        self.assertEqual(list(base.glob(".backup-*")), [])                       # 정상 종료면 남지 않는다
        src = (ENGINE / "tools" / "build" / "make_export_zip.py").read_text(encoding="utf-8")
        self.assertIn('startswith(".backup-")', src)
