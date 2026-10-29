# -*- coding: utf-8 -*-
"""대시보드의 '무인 1차 대응 — 오늘' (2026-09-23)

자료를 넣고 보니 대시보드 자체는 멀쩡했다(0 투성이는 룰이 없던 시험 환경 탓).
진짜 빈 곳은 **제품의 핵심인 무인 1차 대응이 첫 화면에 없다** 는 것이었다.

여기서 지키는 것
  · 숫자는 실행 기록에서만 뽑는다
  · 요약을 못 만들어도 대시보드는 그대로 뜬다(카드만 빠진다)
  · 켜 둔 것이 없으면 숫자 대신 '무엇을 켜면 되는지' 를 적는다
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

from logtriage.server import ServerApi  # noqa: E402

UI = (GUI / "ui.html").read_text(encoding="utf-8")


class DashCardMarkupTests(unittest.TestCase):
    def test_card_is_first_on_the_dashboard(self):
        self.assertIn('$("#dashwrap").innerHTML=auto+', UI,      # 2026-10-14 배치 개편 뒤에도 무인 대응 카드가 맨 앞
                      "무인 대응 카드가 맨 위에 오지 않습니다")

    def test_card_is_skipped_when_there_is_no_summary(self):
        """이 PC 설치형에는 자동화가 없다 — 카드가 빠져야지 화면이 깨지면 안 된다."""
        self.assertIn('if(!a) return "";', UI)

    def test_empty_states_tell_what_to_turn_on(self):
        for need in ("반입 폴더를 지켜보는 작업이 아직 없습니다", "분석만</b> 하고 끝납니다"):
            with self.subTest(need=need):
                self.assertIn(need, UI)


class StatsSummaryTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.api = ServerApi(self.base, allow_dirs=[])

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def _job(self, jid, followup, enabled=1):
        with self.api.automation.db() as db:
            db.execute("INSERT OR REPLACE INTO jobs(id,name,kind,schedule,params,enabled,next_due)"
                       " VALUES(?,?,?,?,?,?,0)",
                       (jid, jid, "log_watch", "{}", json.dumps({"followup": followup}), enabled))

    def _run(self, jid, analyzed, level=None, did=()):
        out = {"analyzed": analyzed, "observed": len(analyzed),
               "first_response": ([{"id": "x", "level": level, "did": list(did)}] if level else [])}
        with self.api.automation.db() as db:
            db.execute("INSERT INTO runs(id,job_id,name,started,state,output) VALUES(?,?,?,?,?,?)",
                       (jid + str(time.time()), jid, jid, time.time(), "success", json.dumps(out)))

    def test_summary_is_present_and_counts_real_runs(self):
        self._job("w1", {"when": "critical", "board": True})
        self._run("w1", ["A"], "critical", ["board", "notify"])
        self._run("w1", ["B"], "error", ["board"])
        a = self.api.stats().get("auto")
        self.assertIsNotNone(a, "대시보드 자료에 무인 대응 요약이 없습니다")
        self.assertEqual(a["analyzed"], 2)
        self.assertEqual(a["critical"], 1)
        self.assertEqual(a["actions"], 3)
        self.assertEqual((a["watch"], a["armed"]), (1, 1))
        self.assertTrue(a["last"], "마지막 처리 시각이 비었습니다")

    def test_job_without_actions_is_not_counted_as_armed(self):
        self._job("w2", {"when": "critical"})          # 아무 조치도 안 켰다
        a = self.api.stats()["auto"]
        self.assertEqual((a["watch"], a["armed"]), (1, 0))

    def test_paused_job_is_not_armed(self):
        self._job("w3", {"when": "critical", "board": True}, enabled=0)
        a = self.api.stats()["auto"]
        self.assertEqual(a["armed"], 0)

    def test_nothing_yet_says_so(self):
        a = self.api.stats()["auto"]
        self.assertEqual((a["watch"], a["analyzed"], a["last"]), (0, 0, ""))

    def test_dashboard_survives_a_broken_summary(self):
        class Broken:
            def db(self):
                raise OSError("잠김")
        self.api.automation = Broken()
        out = self.api.stats()
        self.assertNotIn("error", out, "요약이 실패했다고 대시보드가 죽으면 안 됩니다")
        self.assertNotIn("auto", out)


if __name__ == "__main__":
    unittest.main()
