# -*- coding: utf-8 -*-
"""무인 1차 대응 — 분석 뒤 조치 시험 (2026-09-23)

여태 자동 분석은 알림 한 줄로 끝났다. 여기서는 그 뒤가 실제로 이어지는지,
그리고 **조치가 실패해도 분석 결과를 잃지 않는지**를 본다.
"""
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage import first_response as FR  # noqa: E402


def result(critical=0, error=0, verdict="디스크 가득 참", layer="OS"):
    return {"sev_totals": {"critical": critical, "error": error, "warn": 0, "info": 0},
            "first": {"layer_ko": layer, "verdict": verdict},
            "analyzed_at": "2026-09-23 15:03:12",
            "files": [{"name": "/var/log/messages"}],
            "plan": [{"text": "디스크 사용량을 확인하고 오래된 로그를 정리합니다"}]}


class Worker:
    """가짜 작업자 — 무엇이 불렸는지만 기록한다."""

    def __init__(self, fail=()):
        self.notices, self.posts, self.reports = [], [], []
        self.fail = set(fail)
        outer = self

        class Board:
            def create(self, user, kind, title, body, incidents=None):
                if "board" in outer.fail:
                    raise RuntimeError("게시판 잠김")
                outer.posts.append({"user": user, "kind": kind, "title": title,
                                    "body": body, "incidents": incidents})
                return {"id": len(outer.posts)}

        class Api:
            board = Board()

            def generate_report(self, incident_id):
                if "report" in outer.fail:
                    return {"error": "서식 파일 없음"}
                outer.reports.append(incident_id)
                return {"hwpx": "/reports/x.hwpx"}

        self.api = Api()

    def notice(self, category, message):
        if "notify" in self.fail and category != "failed":
            raise RuntimeError("알림함 오류")
        self.notices.append((category, message))


def job(**fu):
    base = {"when": "critical", "report": False, "board": False, "notify": False}
    base.update(fu)
    return {"id": "j1", "name": "감시", "params": {"followup": base}}


class SettingsTests(unittest.TestCase):
    def test_default_is_do_nothing(self):
        self.assertEqual(FR.normalize(None), FR.OFF)
        self.assertFalse(FR.enabled(FR.normalize(None)))

    def test_unknown_values_are_refused(self):
        for bad in ({"when": "가끔"}, {"when": "critical", "report": "yes"}, "critical", 3):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                FR.normalize(bad)

    def test_settings_round_trip(self):
        got = FR.normalize({"when": "error", "report": True, "board": False, "notify": True})
        self.assertEqual(got, {"when": "error", "report": True, "board": False, "notify": True})


class TriggerTests(unittest.TestCase):
    def test_level_reading(self):
        self.assertEqual(FR.level_of(result(critical=1)), "critical")
        self.assertEqual(FR.level_of(result(error=3)), "error")
        self.assertEqual(FR.level_of(result()), "none")

    def test_critical_only_waits_for_critical(self):
        cfg = FR.normalize({"when": "critical", "notify": True})
        self.assertTrue(FR.should_run(cfg, result(critical=1)))
        self.assertFalse(FR.should_run(cfg, result(error=9)))

    def test_error_includes_critical(self):
        cfg = FR.normalize({"when": "error", "notify": True})
        self.assertTrue(FR.should_run(cfg, result(critical=1)))
        self.assertTrue(FR.should_run(cfg, result(error=1)))
        self.assertFalse(FR.should_run(cfg, result()))

    def test_nothing_chosen_means_nothing_runs(self):
        self.assertFalse(FR.should_run(FR.normalize({"when": "always"}), result(critical=9)))


class RunTests(unittest.TestCase):
    def test_all_three_actions(self):
        w = Worker()
        out = FR.run(w, job(report=True, board=True, notify=True), "INC-1", result(critical=2))
        self.assertEqual(out["level"], "critical")
        self.assertEqual(sorted(out["done"]), ["board", "notify", "report"])
        self.assertEqual(w.reports, ["INC-1"])
        self.assertEqual(w.posts[0]["kind"], "share")
        self.assertEqual(w.posts[0]["incidents"], ["INC-1"])

    def test_post_is_not_signed_as_a_person(self):
        w = Worker()
        FR.run(w, job(board=True), "INC-1", result(critical=1))
        self.assertEqual(w.posts[0]["user"], FR.SYSTEM_USER)
        self.assertIn("자동", w.posts[0]["user"]["name"])

    def test_post_carries_the_verdict_and_the_incident(self):
        w = Worker()
        FR.run(w, job(board=True), "INC-42", result(critical=1, verdict="힙 메모리 부족", layer="WAS"))
        title, body = w.posts[0]["title"], w.posts[0]["body"]
        self.assertIn("힙 메모리 부족", title)
        self.assertIn("WAS", body)
        self.assertIn("INC-42", body)
        self.assertLessEqual(len(title), 120)

    def test_real_plan_shape_is_read(self):
        """plan 은 목록이 아니라 {analysis, tier1, tier2, tier3} 사전이다.

        처음에 목록으로 보고 `plan[:5]` 를 썼다가, 실제로 돌려 보고서야
        '게시판 공유: slice(None, 5, None)' 로 조치가 통째로 실패하는 것을 잡았다.
        """
        r = result(critical=1)
        r["plan"] = {"analysis": {}, "tier1": {"steps": ["df -h 로 사용량 확인", {"text": "오래된 로그 정리"}]},
                     "tier2": {}, "tier3": {}}
        w = Worker()
        out = FR.run(w, job(board=True), "INC-9", r)
        self.assertEqual(out["done"], ["board"])
        body = w.posts[0]["body"]
        self.assertIn("df -h 로 사용량 확인", body)
        self.assertIn("오래된 로그 정리", body)

    def test_odd_plan_shapes_never_break_the_action(self):
        for weird in ([], "글자", {"tier1": None}, {"tier1": {"steps": [None, 3]}}, None):
            with self.subTest(plan=str(weird)[:24]):
                r = result(critical=1)
                r["plan"] = weird
                w = Worker()
                out = FR.run(w, job(board=True), "INC-9", r)
                self.assertEqual(out["done"], ["board"], f"plan={weird!r} 에서 글쓰기가 죽었습니다")

    def test_the_original_file_name_is_used(self):
        """분석은 임시 복사본을 읽는다 — 글·알림에는 사람이 아는 원본 이름이 나와야 한다."""
        r = result(critical=1)
        r["files"] = [{"name": "/tmp/3f9c1a2b4d5e.log"}]
        w = Worker()
        FR.run(w, job(board=True, notify=True), "INC-9", r, source="messages.log")
        self.assertIn("messages.log", w.posts[0]["title"] + w.posts[0]["body"])
        self.assertTrue(any("messages.log" in m for _, m in w.notices))
        self.assertFalse(any("3f9c1a2b4d5e" in m for _, m in w.notices))

    def test_one_failed_action_does_not_stop_the_others(self):
        w = Worker(fail=("report",))
        out = FR.run(w, job(report=True, board=True, notify=True), "INC-1", result(critical=1))
        self.assertEqual(sorted(out["done"]), ["board", "notify"])
        self.assertTrue(any("보고서 초안" in f for f in out["failed"]))

    def test_failures_are_written_to_the_notice_box(self):
        """조치가 빠진 것을 사람이 알아야 한다 — 조용히 넘어가면 안 된다."""
        w = Worker(fail=("board",))
        FR.run(w, job(board=True), "INC-1", result(critical=1))
        self.assertTrue(any(c == "failed" and "게시판 공유" in m for c, m in w.notices))

    def test_nothing_happens_below_the_threshold(self):
        w = Worker()
        self.assertEqual(FR.run(w, job(notify=True), "INC-1", result(error=5)), {})
        self.assertEqual(w.notices, [])


if __name__ == "__main__":
    unittest.main()
