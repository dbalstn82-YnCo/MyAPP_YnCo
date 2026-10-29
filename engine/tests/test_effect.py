# -*- coding: utf-8 -*-
"""업무 절감 효과 (2026-09-23)

경쟁 제안들이 정량지표 자리에 하나같이 '실측 예정' 이라고 쓴다. 우리는 숫자를 내되,
**측정값과 가정값을 섞지 않는 것**으로 신뢰를 얻는다.

  측정값 — 실행 기록에서 센 값(건수·기계가 실제로 쓴 시간). 화면에서 못 고친다.
  가정값 — '사람이 했으면 얼마나 걸렸을까'. 담당자가 정하고, 측정이 아니라고 화면에 적는다.
"""
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

from logtriage import effect as E  # noqa: E402
from logtriage.server import ServerApi  # noqa: E402


class AssumptionTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.api = ServerApi(self.base, allow_dirs=[])
        self.auto = self.api.automation

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_defaults_are_used_when_nothing_saved(self):
        self.assertEqual(E.assumptions(self.auto), E.DEFAULTS)

    def test_saved_values_round_trip(self):
        E.set_assumptions(self.auto, {"collect_min": 35})
        self.assertEqual(E.assumptions(self.auto)["collect_min"], 35)
        self.assertEqual(E.assumptions(self.auto)["report_min"], E.DEFAULTS["report_min"])

    def test_refuses_nonsense(self):
        for bad in ({"collect_min": -1}, {"collect_min": 10**6}, {"collect_min": True},
                    {"collect_min": "많이"}, {"없는항목": 1}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                E.set_assumptions(self.auto, bad)

    def test_zero_is_allowed_and_means_no_effect(self):
        E.set_assumptions(self.auto, {"collect_min": 0, "report_min": 0, "share_min": 0})
        r = E.report(self.auto, 30)
        self.assertEqual(r["manual_min"], 0)
        self.assertEqual(r["saved_min"], 0)


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.api = ServerApi(self.base, allow_dirs=[])
        self.auto = self.api.automation

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _run(self, analyzed, did=(), seconds=2.0, ago_days=0):
        t = time.time() - ago_days * 86400
        out = {"analyzed": analyzed, "observed": len(analyzed),
               "first_response": ([{"id": "x", "level": "critical", "did": list(did)}] if did else [])}
        with self.auto.db() as db:
            db.execute("INSERT INTO runs(id,job_id,name,started,ended,state,output) VALUES(?,?,?,?,?,?,?)",
                       (str(time.time()) + str(len(analyzed)) + str(ago_days), "j", "j",
                        t, t + seconds, "success", json.dumps(out)))

    def test_counts_only_runs_that_did_something(self):
        self._run(["A"], ["report", "board"], 3.0)
        self._run([], [], 9999.0)              # 아무것도 안 한 실행은 기계 시간에 넣지 않는다
        m = E.measure(self.auto, 30)
        self.assertEqual(m["analyzed"], 1)
        self.assertEqual(m["reports"], 1)
        self.assertEqual(m["shares"], 1)
        self.assertAlmostEqual(m["machine_sec"], 3.0, places=0)

    def test_period_is_respected(self):
        self._run(["A"], ["board"], 2.0, ago_days=0)
        self._run(["B"], ["board"], 2.0, ago_days=20)
        self.assertEqual(E.measure(self.auto, 7)["analyzed"], 1)
        self.assertEqual(E.measure(self.auto, 30)["analyzed"], 2)

    def test_formula_is_measured_minus_machine(self):
        self._run(["A", "B"], ["report", "board", "notify"], 6.0)
        E.set_assumptions(self.auto, {"collect_min": 10, "report_min": 20, "share_min": 5})
        r = E.report(self.auto, 30)
        # 분석 2건×10 + 보고서 1건×20 + 공유·통지 2건×5 = 50분
        self.assertEqual(r["manual_min"], 50)
        self.assertAlmostEqual(r["machine_sec"], 6.0, places=0)
        self.assertAlmostEqual(r["saved_min"], 50 - r["machine_min"], places=1)

    def test_saving_never_goes_negative(self):
        self._run(["A"], [], 36000.0)          # 기계가 10시간 걸린 이상한 경우
        E.set_assumptions(self.auto, {"collect_min": 1, "report_min": 0, "share_min": 0})
        self.assertEqual(E.report(self.auto, 30)["saved_min"], 0)

    def test_result_says_which_part_is_an_assumption(self):
        r = E.report(self.auto, 30)
        self.assertIn("측정이 아닙니다", r["note"])
        self.assertIn("절감 =", r["formula"])


class ScreenTests(unittest.TestCase):
    SRC = (GUI / "automation.html").read_text(encoding="utf-8")

    def test_measured_and_assumed_are_shown_apart(self):
        self.assertIn('id="ef_measured"', self.SRC)
        self.assertIn('id="ef_assume"', self.SRC)
        self.assertIn("제품이 실제로 한 일", self.SRC)
        self.assertIn("담당자가 정하는 값(측정 아님)", self.SRC)

    def test_sub_minute_is_shown_in_seconds(self):
        """기계가 얼마나 빠른지가 핵심 숫자인데 '0분' 으로 뭉개졌던 자리."""
        self.assertIn("if(m<1)return (m*60).toFixed", self.SRC)

    def test_minutes_are_rounded_before_splitting(self):
        """먼저 나누고 반올림하면 '2시간 60분' 이 나온다(실제로 나왔다)."""
        self.assertIn("var t=Math.round(m),h=Math.floor(t/60),x=t%60;", self.SRC)

    def test_api_is_read_for_everyone_but_write_is_admin(self):
        import logtriage.server as S
        self.assertIn("effect_report", S.READ_APIS)
        self.assertIn("effect_set", S.ADMIN_APIS)
        self.assertNotIn("effect_set", S.READ_APIS)


if __name__ == "__main__":
    unittest.main()
