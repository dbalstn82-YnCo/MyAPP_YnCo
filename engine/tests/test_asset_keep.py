# -*- coding: utf-8 -*-
"""자산화 — 오래됐다는 이유로는 아무것도 지우지 않는다 (2026-09-29)

사용자 지시: "장애 이력, 조치, 조치 방법 등 전사에서 발생한 모든 이슈들을 하나로 모아서
우리만의 자산(레거시)으로 만드는 첫걸음."

그런데 지금까지 제품은 자산을 쌓는 게 아니라 버리고 있었다.
  · 분석 501번째가 들어오면 가장 오래된 분석 건을 삭제(HISTORY_KEEP=500)
  · 51번째부터는 그 판정의 근거인 로그 원본을 삭제(EVENTS_KEEP=50)

이 시험이 지키는 것 — **지우는 길은 사람이 그 건을 지울 때 하나뿐이다.**
"""
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage import storage as ST  # noqa: E402
from logtriage.storage import sqlite_url  # noqa: E402


def incident(i: int) -> dict:
    return {"id": f"INC-{i:05d}", "analyzed_at": f"2026-01-01 00:{i % 60:02d}:00",
            "name": f"샘플 {i}.log", "first": {"layer_ko": "OS", "verdict": "메모리 부족"},
            "sev_totals": {"critical": 1}}


class KeepEverythingTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.st = ST.Storage(sqlite_url(self.base / "data" / "logtriage.db"))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_no_cap_is_set(self):
        self.assertIsNone(ST.HISTORY_KEEP, "분석 이력에 보관 상한이 다시 생겼습니다")
        self.assertIsNone(ST.EVENTS_KEEP, "로그 원본에 보관 상한이 다시 생겼습니다")

    def test_old_analyses_are_not_thrown_away(self):
        """예전 상한(500)을 넘겨도 첫 번째 건이 그대로 있어야 한다."""
        for i in range(520):
            self.st.save_incident(incident(i))
        self.assertEqual(len(self.st.history(limit=10_000)), 520)
        self.assertIsNotNone(self.st.get("INC-00000"),
                             "가장 오래된 분석 건이 사라졌습니다 — 자산이 되지 않습니다")

    def test_the_evidence_is_not_thrown_away(self):
        """판정의 근거(로그 원본)가 없으면 나중에 그 판단을 검증할 수 없다."""
        jl = self.base / "ev.jsonl"
        for i in range(60):
            self.st.save_incident(incident(i))
            jl.write_text(json.dumps({"ts": "2026-01-01 00:00:00", "host": "h1", "layer": "os",
                                      "product": "linux", "severity": "critical",
                                      "code": "OOM", "message": f"이벤트 {i}"},
                                     ensure_ascii=False) + "\n", encoding="utf-8")
            self.st.import_events(f"INC-{i:05d}", jl)
        have = self.st.incidents_with_events()
        self.assertIn("INC-00000", have,
                      "가장 오래된 건의 로그 원본이 지워졌습니다 — 근거 없는 판정만 남습니다")
        self.assertEqual(len(have), 60)

    def test_deleting_one_on_purpose_still_works(self):
        """지울 수 있어야 한다 — 다만 사람이 그 건을 지목했을 때만."""
        for i in range(3):
            self.st.save_incident(incident(i))
        self.assertTrue(self.st.delete_incident("INC-00001"))
        left = [h["id"] for h in self.st.history(limit=10)]
        self.assertNotIn("INC-00001", left)
        self.assertEqual(len(left), 2)

    def test_missing_evidence_says_why(self):
        """예전 판에서 지워진 건을 열면 '왜 없는지' 를 말해야 한다 — 상한 탓을 지금 규칙으로 설명하면 안 된다."""
        src = (ENG / "logtriage" / "storage.py").read_text(encoding="utf-8")
        self.assertIn("보관 상한이 있던 판(2026-09-28 이전)에서 지워진 건입니다", src)
        self.assertIn("지금 판부터는 지우지 않습니다", src)
        self.assertNotIn("최근 {EVENTS_KEEP}건만 보관", src)


if __name__ == "__main__":
    unittest.main()
