# -*- coding: utf-8 -*-
"""보고서 서식 채우기·서식 학습 프로필·[기재] 표시 — 공식 서식 2종 + 합성 판정 데이터만 사용(사내 문서 불사용)."""
import json
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from lxml import etree

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from logtriage import report_forms as rf  # noqa: E402
from logtriage.report_style import learn, _forbidden_check, form_labels  # noqa: E402

TDIR = ROOT / "report-template"


def _inc() -> dict:
    return {
        "id": "INC-UT-0001", "incident_time": "2026-09-02 14:02:11", "events_window": 1234, "match_count": 7,
        "files": [{"name": "alert_orcl.log", "product": "oracle"}, {"name": "weblogic.log", "product": "weblogic"}],
        "first": {"verdict": "데드락 (ORA-00060)", "category_ko": "잠금/데드락", "layer_ko": "DBMS", "ts": "14:02:11", "rule_id": "DB-ORA-004"},
        "timeline_key": [
            {"ts": "14:02:11", "ts_full": "2026-09-02 14:02:11", "last": "14:05:40", "last_full": "2026-09-02 14:05:40", "count": 3,
             "layer_ko": "DBMS", "verdict": "데드락 (ORA-00060)", "marks": ["최초 이상"], "message": "ORA-00060: deadlock detected while waiting for resource " * 3},
            {"ts": "14:02:20", "ts_full": "2026-09-02 14:02:20", "last": "14:02:20", "last_full": "2026-09-02 14:02:20", "count": 1,
             "layer_ko": "WAS", "verdict": "stuck 스레드", "marks": [], "message": "<WebLogicServer> <BEA-000337> stuck thread"},
        ],
        "timeline": [], "checklist": [{"rule_id": "DB-ORA-004", "verdict": "데드락", "immediate": ["trace 파일에서 데드락 그래프 확인", "세션·SQL 식별"],
                                       "vendor_cause": "트랜잭션들이 자원을 기다리며 서로 교착상태에 빠졌다."}],
        "plan": {"tier1": {"escalate": {"when": ["대기 세션 증가", "30분 내 재발"]}},
                 "tier3": {"summary": ["제품/버전: oracle / 버전·패치 레벨 [담당자 기재]"]}},
    }


class StyleHelpers(unittest.TestCase):
    def test_hhmm_and_dates(self):
        self.assertEqual(rf._hhmm("2026-09-02 14:02:11"), "14:02")
        self.assertEqual(rf._hhmm("14:02:11"), "14:02")
        self.assertEqual(rf._hhmm("09-02 14:02:11"), "09-02 14:02")
        self.assertEqual(rf.fmt_date("2026-09-02 14:02", "’YY.M.D.(요일)"), "’26.9.2.(수)")
        self.assertEqual(rf.fmt_date("2026-09-02 14:02", "YYYY.M.D.(요일)"), "2026. 9. 2.(수)")
        self.assertEqual(rf.mark(" 복구 시각 "), "[기재: 복구 시각]")
        self.assertEqual(rf.marks_in("a [기재: x] b [기재: y]"), ["x", "y"])

    def test_profile_lookup(self):
        sp = rf.StyleProfile.load(TDIR)
        if sp.empty:
            self.skipTest("style_profile.json 없음")
        self.assertGreaterEqual(sp.lines_limit("조치내용", 8), 3)
        self.assertGreaterEqual(sp.chars_budget("장애내용", 60), 40)
        self.assertIn(sp.bullet("조치내용"), ("- ", "· ", "▸ "))
        self.assertTrue(sp.table_style(["시스템명", "등급", "설치 위치", "기관명"]))
        self.assertFalse(sp.table_style(["없는라벨"]))


class FillForms(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="lt_rf_"))
        self.tdir = self.tmp / "report-template"
        self.tdir.mkdir()
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            if (TDIR / f).exists():
                shutil.copy(TDIR / f, self.tdir / f)
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _section(hwpx: Path):
        z = zipfile.ZipFile(hwpx)
        names = z.namelist()
        assert names[0] == "mimetype" and z.getinfo("mimetype").compress_type == zipfile.ZIP_STORED
        return etree.fromstring(z.read("Contents/section0.xml")), etree.fromstring(z.read("Contents/header.xml"))

    def test_generate_with_profile(self):
        r = rf.generate_forms(self.tdir, _inc(), self.out)
        self.assertEqual(len(r["files"]), 2, r)
        self.assertTrue(r["todo"]) and self.assertTrue(Path(r["todo_file"]).exists())
        self.assertIn("총", Path(r["todo_file"]).read_text(encoding="utf-8"))
        for f in r["files"]:
            root, header = self._section(Path(f["hwpx"]))
            text = " ".join(rf.para_text(p) for p in root.iter("{%s}p" % rf.HP))
            self.assertNotIn("[담당자 기재]", text)
            self.assertNotIn("(복구 시각 기재)", text)
            self.assertIn("[기재:", text)
            self.assertIn("14:02", text)
            self.assertNotIn("14:02:11", text)  # 실 보고서 표기(HH:MM)
            # [기재] 표시는 파란 charPr, 값은 검정
            colors = {c.get("id"): c.get("textColor", "#000000").lower() for c in header.iter("{%s}charPr" % rf.HH)}
            for run in root.iter("{%s}run" % rf.HP):
                t = "".join(x.text or "" for x in run.findall("hp:t", rf.NS))
                if t.startswith("[기재:"):
                    self.assertEqual(colors[run.get("charPrIDRef")], rf.MARK_COLOR.lower(), t)
                elif t.strip() and "[기재" not in t and run.get("charPrIDRef") in colors:
                    self.assertNotEqual(colors[run.get("charPrIDRef")], rf.MARK_COLOR.lower(), t)
            if f["form"] == "status":
                self.assertIn("’26.9.2.(수) 14:02 ~ [기재: 복구 시각 — 로그상 마지막 이상 14:05]", text)
                self.assertIn("데드락 (ORA-00060)", text)
            else:
                self.assertIn("2026. 9. 2.(수)", text)
                self.assertIn("[기재: 버전·패치 레벨]", text)
                # 학습 프로필: 시스템명 표 값 칸은 12pt·굵기 없음(라벨 칸은 12pt 굵게)
                sizes = {c.get("id"): (int(c.get("height")), c.find("hh:bold", rf.NS) is not None) for c in header.iter("{%s}charPr" % rf.HH)}
                tb = [t for t in rf.top_tables(root) if rf.find_cell(t, 0, 0) is not None
                      and rf.norm("".join(rf.find_cell(t, 0, 0).itertext())) == "시스템명"][0]
                tc = rf.find_cell(tb, 1, 3)  # 상위기관 값 칸
                cp = next(run.get("charPrIDRef") for run in tc.iter("{%s}run" % rf.HP) if run.find("hp:t", rf.NS) is not None)
                self.assertEqual(sizes[cp], (1200, False))
            # 중복 [기재] 없음(원형 복제 오류 방지)
            self.assertNotRegex(text, r"\]\[기재:")

    def test_generate_without_profile(self):
        (self.tdir / "style_profile.json").unlink(missing_ok=True)
        r = rf.generate_forms(self.tdir, _inc(), self.out)
        self.assertEqual(len(r["files"]), 2)
        self.assertFalse(r["style"]["loaded"])
        root, _ = self._section(Path(r["files"][0]["hwpx"]))
        self.assertIn("[기재:", " ".join(rf.para_text(p) for p in root.iter("{%s}p" % rf.HP)))

    def test_profile_values_reduce_todo(self):
        rf.save_profile(self.tdir, {"org": "테스트기관", "system": "테스트시스템", "service": "테스트서비스", "dept": "정보팀",
                                    "person": "홍길동", "rank": "주무관", "phone": "02-000-0000", "grade": "3등급",
                                    "location": "전산실", "parent_org": "상위기관", "intro_year": "2020", "ha": "예"})
        r0 = rf.generate_forms(self.tdir, _inc(), self.out / "a")
        (self.tdir / "report_profile.json").unlink()
        r1 = rf.generate_forms(self.tdir, _inc(), self.out / "b")
        self.assertLess(len(r0["todo"]), len(r1["todo"]))
        root, _ = self._section(Path(r0["files"][1]["hwpx"]))
        text = " ".join(rf.para_text(p) for p in root.iter("{%s}p" % rf.HP))
        self.assertIn("홍길동", text)
        self.assertNotIn("[기재: 기관명]", text)

    def test_docx_conversion_still_works(self):
        r = rf.generate_forms(self.tdir, _inc(), self.out)
        st = rf.hwpx_to_docx(Path(r["files"][0]["hwpx"]), self.out / "a.docx")
        self.assertTrue((self.out / "a.docx").exists() and st["paragraphs"] > 10)


class StyleLearning(unittest.TestCase):
    def test_learn_on_public_forms_only(self):
        tmp = Path(tempfile.mkdtemp(prefix="lt_st_"))
        try:
            src = tmp / "docs"
            src.mkdir()
            for f in ("form_status.hwpx", "form_postmortem.hwpx"):
                shutil.copy(TDIR / f, src / f)
            r = learn(src, TDIR, tmp / "profile.json")
            self.assertEqual(r["input_files"], 2)
            self.assertEqual(r["docs"], {"status": 1, "postmortem": 1})
            prof = json.loads((tmp / "profile.json").read_text(encoding="utf-8"))
            self.assertIn("h2", prof["form_labels"]["status"])
            self.assertEqual(_forbidden_check(prof, form_labels(TDIR)), [])
            # 프로필의 한글 문자열은 서식 라벨·글꼴 이름·형식 이름뿐이다(문장 없음)
            allowed = set(sum((v["h1"] + v["h2"] + v["cells"] for v in form_labels(TDIR).values()), []))
            for m in set(re.findall(r'"([^"]*[가-힣][^"]*)"', json.dumps(prof, ensure_ascii=False))):
                self.assertTrue(len(m) <= 12 or m in allowed, m)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_shipped_profile_has_no_sentences(self):
        p = TDIR / "style_profile.json"
        if not p.exists():
            self.skipTest("style_profile.json 없음")
        prof = json.loads(p.read_text(encoding="utf-8"))
        self.assertEqual(_forbidden_check(prof, form_labels(TDIR)), [])
        for k in prof["fields"]:
            self.assertLessEqual(len(k), 40)


if __name__ == "__main__":
    unittest.main()
