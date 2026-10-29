"""22차(2026-10-27 마스터: '발표자료 · 시연영상 만들면서 나온 기능 추가 · 수정') —
① 시범 운영 지표(pilot_metrics): 발표 37 · 38장 '시범에서 잴 것'을 제품이 남긴 기록만으로 센다. 가정값 없음, 모아 센 숫자만.
② 지난 조치 위치 안내: 07b 녹화가 「5 우리 조치」에서 지난 조치를 찾다 헤맸다 — 2번 탭 이름에 건수, 5번 탭에 안내와 [지난 조치 보기].
③ 발표 장표의 숫자 · 주장이 코드 사실과 같은지(규칙 427 · 코드 1,605 · 36종 · 이력 자동 삭제 없음 · 토큰 유효기간 · 비밀번호 규칙)."""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
ROOT = ENGINE.parent
sys.path.insert(0, str(ENGINE))

from logtriage.server import API_NAMES, READ_APIS, make_server  # noqa: E402


def _rec(i, mins_ago, rid):
    at = (datetime.now() - timedelta(minutes=mins_ago)).strftime("%Y-%m-%d %H:%M:%S")
    return {"id": f"T-{i}", "analyzed_at": at, "name": "x", "first": {"rule_id": rid, "verdict": "v", "layer_ko": "DB"},
            "timeline": [{"rule_id": rid}], "checklist": [], "elapsed_sec": 2.0 + i, "sev_totals": {}}


class PilotMetricsTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.httpd, h = make_server("127.0.0.1", 0, Path(self.td.name), None)
        self.api = h.api
        s = self.api.store
        s.save_incident(_rec(1, 300, "DB-ORA-001"))
        s.save_incident(_rec(2, 100, "DB-ORA-001"))
        s.save_incident(_rec(3, 50, "LRN-LINUX-ABC"))
        s.add_action("T-1", "재기동", kind="restart", result="resolved", minutes=25, actor={"login": "a"})
        s.add_action("T-2", "파라미터 조정", kind="etc", result="partial", minutes=10, actor={"login": "a"})
        s.set_postmortem("T-1", "원인", "probable", "yes")
        s.set_postmortem("T-2", "원인2", "confirmed", "no", note="제조사 RCA 확인")

    def tearDown(self):
        self.httpd.server_close()
        self.td.cleanup()

    def test_counts_only_recorded_facts(self):
        m = self.api.pilot_metrics(30)
        self.assertEqual(m["analyses"], 3)
        self.assertEqual(m["engine_sec_median"], 4.0)
        self.assertEqual(m["first_action_n"], 2)
        self.assertAlmostEqual(m["first_action_min_median"], 200.0, delta=2)
        self.assertEqual((m["action_n"], m["action_min_sum"], m["action_min_median"]), (2, 35, 17.5))
        self.assertEqual(m["recur"], 1)                     # T-2 는 T-1 과 같은 증상
        self.assertEqual(m["recur_with_past"], 0)           # 지난 조치는 T-2 분석 **뒤에** 기록됨 — 그때는 없었다
        self.assertEqual(m["learned_hits"], 1)
        self.assertEqual(m["verdict"], {"yes": 1, "partial": 0, "no": 1})
        self.assertEqual(m["miss_confirmed"], 1)

    def test_review_rate_and_same_log_and_past_before(self):
        """GPT 170: 미검토 · 검토율 함께 / 같은 로그 재분석은 재등장에서 제외 / 분석 **이전** 조치만 '보유'로."""
        m = self.api.pilot_metrics(30)
        self.assertEqual((m["unreviewed"], m["review_rate"]), (1, 66.7))
        s = self.api.store
        a = _rec(4, 30, "DB-ORA-001"); a["files"] = [{"name": "alert_orcl.log"}]
        b = _rec(5, 20, "DB-ORA-001"); b["files"] = [{"name": "alert_orcl.log"}]
        s.save_incident(a); s.save_incident(b)
        m = self.api.pilot_metrics(30)
        self.assertEqual(m["same_log_reanalysis"], 1)          # T-5 는 T-4 와 같은 로그 — 재등장이 아님
        self.assertEqual(m["recur"], 2)                         # T-2 · T-4 (T-4 는 다른 로그로 같은 증상)
        self.assertEqual(m["recur_with_past"], 0)               # 조치는 모두 '지금' 적힘 — 어느 분석 때도 아직 없었다
        import time as _t
        with s._conn() as c:                                    # T-1 조치를 200분 전에 적은 것으로
            c.cursor().execute(s._q("UPDATE actions SET at=? WHERE incident_id=?"), (_t.time() - 200 * 60, "T-1"))
        self.assertEqual(self.api.pilot_metrics(30)["recur_with_past"], 2)   # T-2(100분 전) · T-4(30분 전) 분석 때 이미 있었다
        self.assertIn("MTTR", " ".join(m["notes"]))
        c = _rec(6, 10, "DB-ORA-001"); c["files"] = [{"name": "alert_orcl.log", "events": 99}]   # 이름은 같아도 내용(이벤트 수)이 다르면 별개
        s.save_incident(c)
        self.assertEqual(self.api.pilot_metrics(30)["same_log_reanalysis"], 1)

    def test_no_hosts_no_assumptions(self):
        blob = json.dumps(self.api.pilot_metrics(30), ensure_ascii=False)
        for bad in ("host", "assum", "가정 시간"):
            self.assertNotIn(bad, blob)
        self.assertTrue(self.api.pilot_metrics(30)["manual"])   # 재지 못하는 것은 '수기로 잴 것'으로 따로

    def test_exposed_read_only(self):
        self.assertIn("pilot_metrics", API_NAMES)
        self.assertIn("pilot_metrics", READ_APIS)
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn('"pilot_metrics"', ui)
        self.assertIn('id="pilotcard"', ui)
        self.assertIn("renderPilot().catch(", ui)               # 따로 불러 실패해도 전체 현황은 그대로


class PastActsPointerTest(unittest.TestCase):
    def test_tab_count_and_pointer(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn('"2 1차 선 대응"+(ACTS.past.length?` · 지난 조치 ${ACTS.past.length}`:"")', ui)
        self.assertIn('id="pastptr"', ui)
        self.assertIn('data-click="showPastActs"', ui)
        self.assertIn("showPastActs:()=>", ui)


class DeckClaimsTest(unittest.TestCase):
    """발표 정본(full_slides.js)의 숫자 · 주장이 코드 사실과 같은지 — 장표만 고치고 코드가 바뀌면(또는 반대) 여기서 잡힌다."""
    def setUp(self):
        f = ROOT / "발표" / "_build" / "full_slides.js"
        if not f.exists():
            self.skipTest("발표 정본 생성기 없음")
        self.deck = f.read_text(encoding="utf-8")

    def test_knowledge_counts(self):
        from logtriage.codes import load_codes
        from logtriage.rules import load_rules
        rules = len(load_rules(ENGINE / "rules", None))
        codes = len({k for k in load_codes(ENGINE / "errorcodes") if ":" in k})
        self.assertIn(f'"{rules}"', self.deck.replace(",", ""), f"룰 {rules}개가 장표에 없음")
        self.assertIn(f"{codes:,}", self.deck, f"코드 {codes:,}개가 장표에 없음")

    def test_history_kept(self):
        from logtriage import storage
        self.assertIsNone(getattr(storage, "HISTORY_KEEP", None))
        self.assertIn("자동 삭제 없음", self.deck)

    def test_token_expiry_and_password_rules_match_screen(self):
        nms = (ENGINE / "logtriage" / "gui" / "nms.html").read_text(encoding="utf-8")
        self.assertIn('id="agdays"', nms)
        self.assertIn("30분", self.deck)                         # 1회용 등록 코드 30분
        from logtriage.server import weak_shared_password
        self.assertTrue(weak_shared_password("admin2026"))

    def test_no_overclaims(self):
        for bad in ("버튼 한 번에", "추가 비용 없이", "룰팩으로만", "빠르고 일관되게", "영구 보존", "동일 원인", "14 / 21", "21개 항목 중 14"):   # 14/21 은 근거 없음(실측 13 · 23칸)
            self.assertNotIn(bad, self.deck, bad)


if __name__ == "__main__":
    unittest.main()
