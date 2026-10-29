# -*- coding: utf-8 -*-
"""자산화 — 누가 했는지, 실제로 무엇을 해서 해결했는지 (2026-09-29)

사용자 지시: 전사 장애 이력·조치·조치 방법을 모아 우리 자산(레거시)으로.

여태 분석 건에는 **규칙이 제안한 조치**만 있었다. 그것만 쌓이면 남는 것은
'우리 규칙이 뭐라고 했는가' 일 뿐 '우리가 무엇을 배웠는가' 가 아니다.
여기서 지키는 것 —
  · 분석 건에 누가·어느 사이트·지금 어떤 상태인지가 남는다
  · 실제 조치가 남는다(무엇을 했는지는 비울 수 없다)
  · 같은 증상이 다시 오면 **지난번 우리가 한 조치**를 찾아올 수 있다
  · 옛 DB(칼럼이 없던 판)도 그대로 열린다
"""
import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage.storage import (ACTION_KIND, ACTION_RESULT, STATUS, Storage,  # noqa: E402
                               signature_of, sqlite_url)

KIM = {"login": "kim@solideos.com", "name": "김운영"}
AUTO = {"login": "auto@logtriage", "name": "무인 1차 대응(자동)"}


def incident(i="INC-1", rule="OS-OOM-001", verdict="메모리 부족"):
    return {"id": i, "analyzed_at": "2026-01-01 00:00:00", "name": f"{i}.log",
            "first": {"layer_ko": "OS", "verdict": verdict, "rule_id": rule},
            "sev_totals": {"critical": 1}}


class SignatureTests(unittest.TestCase):
    def test_rule_id_is_the_most_precise_key(self):
        self.assertEqual(signature_of(incident()), "rule:OS-OOM-001")

    def test_falls_back_to_layer_and_verdict(self):
        r = incident(rule="")
        self.assertEqual(signature_of(r), "vd:OS|메모리 부족")

    def test_nothing_to_key_on_is_empty_not_a_lie(self):
        self.assertEqual(signature_of({"first": {}}), "")
        self.assertEqual(signature_of({}), "")


class AssetColumnTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.st = Storage(sqlite_url(self.base / "d.db"))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_who_and_where_are_kept(self):
        self.st.save_incident(incident(), actor=KIM, site="본사")
        h = self.st.history(5)[0]
        self.assertEqual(h["actor"], "kim@solideos.com")
        self.assertEqual(h["actor_name"], "김운영")
        self.assertEqual(h["site"], "본사")
        self.assertEqual(h["status"], "open")
        self.assertEqual(h["signature"], "rule:OS-OOM-001")

    def test_the_unattended_run_is_named_too(self):
        """무인 1차 대응이 한 일도 '누가 했는지' 가 남아야 한다 — 사람을 사칭하지 않는다."""
        self.st.save_incident(incident(), actor=AUTO)
        self.assertEqual(self.st.history(5)[0]["actor"], "auto@logtriage")

    def test_analysis_body_is_not_touched(self):
        self.st.save_incident(incident(), actor=KIM)
        h = self.st.history(5)[0]
        self.assertEqual(h["first"]["verdict"], "메모리 부족")
        self.assertEqual(h["sev_totals"], {"critical": 1})

    def test_reanalysis_does_not_wipe_the_status_a_person_set(self):
        """같은 건을 다시 분석했다고 '해결' 을 '대응 필요' 로 되돌리면 이력이 거짓이 된다."""
        self.st.save_incident(incident(), actor=KIM)
        self.st.set_status("INC-1", "resolved")
        self.st.save_incident(incident(), actor=KIM)
        self.assertEqual(self.st.history(5)[0]["status"], "resolved")

    def test_status_must_be_one_of_ours(self):
        self.st.save_incident(incident(), actor=KIM)
        with self.assertRaises(ValueError):
            self.st.set_status("INC-1", "대충")
        self.assertIn("resolved", STATUS)


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.st = Storage(sqlite_url(self.base / "d.db"))
        self.st.save_incident(incident(), actor=KIM, site="본사")

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_what_was_done_cannot_be_blank(self):
        for bad in ("", "   ", None):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.st.add_action("INC-1", bad, actor=KIM)

    def test_kind_and_result_are_from_our_list(self):
        with self.assertRaises(ValueError):
            self.st.add_action("INC-1", "뭔가 함", kind="없는종류")
        with self.assertRaises(ValueError):
            self.st.add_action("INC-1", "뭔가 함", result="몰라")
        self.assertIn("restart", ACTION_KIND)
        self.assertIn("resolved", ACTION_RESULT)

    def test_minutes_are_checked(self):
        with self.assertRaises(ValueError):
            self.st.add_action("INC-1", "뭔가 함", minutes="이십분")
        with self.assertRaises(ValueError):
            self.st.add_action("INC-1", "뭔가 함", minutes=-1)
        self.st.add_action("INC-1", "뭔가 함", minutes=0)

    def test_unknown_incident_is_refused(self):
        with self.assertRaises(ValueError):
            self.st.add_action("없는건", "뭔가 함")

    def test_the_record_keeps_who_did_it(self):
        self.st.add_action("INC-1", "스왑 정리 후 재기동", actor=KIM, kind="restart",
                           result="resolved", minutes=25, note="야간 배치와 겹치면 재발 소지")
        a = self.st.actions("INC-1")[0]
        self.assertEqual((a["actor"], a["actor_name"]), ("kim@solideos.com", "김운영"))
        self.assertEqual((a["kind"], a["result"], a["minutes"]), ("restart", "resolved", 25))
        self.assertIn("야간 배치", a["note"])
        self.assertEqual(a["signature"], "rule:OS-OOM-001", "지난 조치를 찾을 표가 없습니다")

    def test_writing_an_action_moves_the_status(self):
        self.st.add_action("INC-1", "설정만 바꿔 둠", result="pending")
        self.assertEqual(self.st.history(5)[0]["status"], "acting")
        self.st.add_action("INC-1", "재기동으로 해결", result="resolved")
        self.assertEqual(self.st.history(5)[0]["status"], "resolved")

    def test_actions_come_back_in_the_order_they_happened(self):
        for i in range(3):
            self.st.add_action("INC-1", f"조치 {i}")
        self.assertEqual([a["what"] for a in self.st.actions("INC-1")],
                         ["조치 0", "조치 1", "조치 2"])

    def test_deleting_the_incident_takes_its_actions(self):
        self.st.add_action("INC-1", "뭔가 함")
        self.st.delete_incident("INC-1")
        self.assertEqual(self.st.actions("INC-1"), [])


class PastActionTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.st = Storage(sqlite_url(self.base / "d.db"))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_same_symptom_brings_back_what_we_did(self):
        self.st.save_incident(incident("INC-1"), actor=KIM)
        self.st.add_action("INC-1", "스왑 정리 후 재기동", result="resolved")
        self.st.save_incident(incident("INC-2"), actor=AUTO)
        past = self.st.past_actions(signature_of(incident("INC-2")), exclude="INC-2")
        self.assertEqual([a["what"] for a in past], ["스왑 정리 후 재기동"])

    def test_a_different_symptom_does_not_leak_in(self):
        self.st.save_incident(incident("INC-1", rule="DB-DEADLOCK-002"), actor=KIM)
        self.st.add_action("INC-1", "데드락 세션 정리", result="resolved")
        self.st.save_incident(incident("INC-2"), actor=KIM)
        self.assertEqual(self.st.past_actions(signature_of(incident("INC-2")), exclude="INC-2"), [])

    def test_what_worked_comes_first_but_failures_are_kept(self):
        """'저건 해 봤는데 안 됐다' 도 자산이다 — 지우지 않고 뒤에 둔다."""
        for i, res in enumerate(("failed", "pending", "resolved", "partial")):
            self.st.save_incident(incident(f"INC-{i}"), actor=KIM)
            self.st.add_action(f"INC-{i}", f"조치 {res}", result=res)
        past = self.st.past_actions("rule:OS-OOM-001", exclude="없음")
        self.assertEqual([a["result"] for a in past], ["resolved", "partial", "pending", "failed"])

    def test_the_current_incident_is_not_quoted_back_at_itself(self):
        self.st.save_incident(incident("INC-1"), actor=KIM)
        self.st.add_action("INC-1", "내가 방금 한 조치", result="resolved")
        self.assertEqual(self.st.past_actions("rule:OS-OOM-001", exclude="INC-1"), [])

    def test_no_signature_means_no_guessing(self):
        self.assertEqual(self.st.past_actions("", exclude="INC-1"), [])


class OldDatabaseTests(unittest.TestCase):
    """칼럼이 없던 판의 DB 도 그대로 열려야 한다 — 자료를 옮기지 않고 자리만 넓힌다."""

    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.db = self.base / "old.db"
        c = sqlite3.connect(self.db)
        c.execute("""CREATE TABLE incidents(id TEXT PRIMARY KEY, analyzed_at TEXT NOT NULL,
                     name TEXT, layer TEXT, verdict TEXT, critical INTEGER DEFAULT 0,
                     data TEXT NOT NULL)""")
        c.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?)",
                  ("OLD-1", "2025-05-05 10:00:00", "old.log", "OS", "메모리 부족", 1,
                   json.dumps(incident("OLD-1"), ensure_ascii=False)))
        c.commit()
        c.close()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_old_records_still_open_and_gain_the_new_fields(self):
        st = Storage(sqlite_url(self.db))
        h = st.history(5)
        self.assertEqual(len(h), 1, "옛 자료가 사라졌습니다")
        self.assertEqual(h[0]["id"], "OLD-1")
        self.assertEqual(h[0]["status"], "open", "상태가 비면 '대응 필요' 로 읽어야 합니다")
        self.assertEqual(h[0]["actor_name"], "")
        # 그 위에 조치를 적을 수 있어야 한다
        st.add_action("OLD-1", "지금 와서 적는 조치", actor=KIM, result="resolved")
        self.assertEqual(len(st.actions("OLD-1")), 1)


if __name__ == "__main__":
    unittest.main()
