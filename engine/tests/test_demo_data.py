# -*- coding: utf-8 -*-
"""시연 자료 (2026-09-23)

처음 설치한 서버는 화면이 전부 0 이라 제품을 보여 줄 수 없다. 그렇다고 숫자를 박아 넣으면
거짓말이다. 그래서 **표본 로그를 만들어 진짜 분석기에 태운다.**

여기서 지키는 것
  · 표본이 실제로 판정까지 간다 — 빈 줄이 섞이면 시연이 더 나빠진다
    (제품마다 로그 형식이 다른데 syslog 접두사를 일률로 붙였다가 5건 중 3건이 판정 0 이었다)
  · 시연 자료임이 이름으로 구분된다
  · 지울 수 있고, **실제 자료는 건드리지 않는다**
  · 실제 자료가 있으면 기본으로 거절한다
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage import demo_data as D  # noqa: E402
from logtriage.server import ServerApi  # noqa: E402


class SampleShapeTests(unittest.TestCase):
    """표본 자체의 생김새 — 형식을 잘못 주면 분석기가 한 줄도 못 읽는다."""

    def test_every_sample_carries_its_own_time_format(self):
        for row in D.SAMPLES:
            self.assertEqual(len(row), 6, f"표본 항목이 6칸이 아닙니다: {row[0]}")
            name, product, host, ago, tfmt, lines = row
            with self.subTest(sample=name):
                self.assertTrue(tfmt, "시각 형식이 없습니다")
                self.assertTrue(lines, "줄이 없습니다")
                self.assertTrue(all("{t}" in ln for ln in lines), "모든 줄에 시각 자리가 있어야 합니다")

    def test_access_log_is_not_given_a_syslog_prefix(self):
        """웹 접근 로그에 syslog 접두사를 붙이면 줄 해석이 0 이 된다(실제로 겪은 일)."""
        web = next(r for r in D.SAMPLES if r[1] == "accesslog")
        for ln in web[5]:
            self.assertFalse(ln.startswith("{t} "), f"접근 로그에 syslog 접두사가 붙었습니다: {ln[:40]}")

    def test_products_are_spread_over_layers(self):
        prods = {r[1] for r in D.SAMPLES}
        self.assertGreaterEqual(len(prods), 4, f"계층이 너무 좁습니다: {prods}")


class SeedAndClearTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        for d in ("rules", "errorcodes", "manuals"):
            shutil.copytree(ENG / d, self.base / d)
        self.api = ServerApi(self.base, allow_dirs=[])

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_every_sample_reaches_a_verdict(self):
        r = D.seed(self.api)
        self.assertTrue(r.get("ok"), r)
        self.assertEqual(r["incidents"], len(D.SAMPLES))
        self.assertNotIn("blank", r, f"판정이 나오지 않은 표본이 있습니다: {r.get('blank')}")
        for m in r["made"]:
            with self.subTest(sample=m["name"]):
                self.assertTrue(m["layer"], "판정 계층이 비었습니다")
                self.assertTrue(m["verdict"], "원인 추정이 비었습니다")

    def test_demo_rows_are_marked(self):
        r = D.seed(self.api)
        for m in r["made"]:
            self.assertTrue(m["id"].startswith(D.PREFIX))
            self.assertTrue(m["name"].startswith(D.MARK))

    def test_clear_removes_only_demo_rows(self):
        D.seed(self.api)
        self.api._save_history({"id": "REAL-1", "name": "진짜", "analyzed_at": "2026-09-23 10:00:00",
                                "sev_totals": {"critical": 1}, "first": {"layer_ko": "OS", "verdict": "실제"},
                                "files": []})
        D.clear(self.api)
        st = D.status(self.api)
        self.assertEqual((st["incidents"], st["posts"]), (0, 0))
        self.assertIsNotNone(self.api.store.get("REAL-1"), "실제 자료를 지웠습니다")

    def test_refuses_when_real_data_exists(self):
        self.api._save_history({"id": "REAL-2", "name": "진짜", "analyzed_at": "2026-09-23 10:00:00",
                                "sev_totals": {}, "first": {}, "files": []})
        self.assertIn("error", D.seed(self.api))
        self.assertTrue(D.seed(self.api, force=True).get("ok"), "강제 선택은 통해야 합니다")

    def test_refuses_to_seed_twice(self):
        D.seed(self.api)
        self.assertIn("error", D.seed(self.api))

    def test_storage_can_delete(self):
        """지울 수 없는 자료는 넣으면 안 된다 — 삭제가 실제로 지우는지."""
        self.api._save_history({"id": "X-1", "name": "x", "analyzed_at": "2026-09-23 10:00:00",
                                "sev_totals": {}, "first": {}, "files": []})
        self.assertTrue(self.api.store.delete_incident("X-1"))
        self.assertIsNone(self.api.store.get("X-1"))
        self.assertFalse(self.api.store.delete_incident("X-1"), "없는 것을 지웠다고 하면 안 됩니다")


class AdminWiringTests(unittest.TestCase):
    def test_apis_are_admin_only(self):
        import logtriage.server as S
        for n in ("demo_seed", "demo_clear", "demo_status"):
            with self.subTest(api=n):
                self.assertIn(n, S.API_NAMES)
                self.assertIn(n, S.ADMIN_APIS, f"{n} 은 관리자 전용이어야 합니다")
                self.assertNotIn(n, S.READ_APIS)

    def test_admin_screen_has_no_demo_tab(self):
        """16차(마스터: '관리 - 사용자/권한에 시연자료 항목 삭제'): 관리 화면에서 시연 자료 탭·단추를 뺐다.
        시연 API 는 홈 [30초 체험]이 쓰므로 남긴다(관리자 전용 그대로)."""
        src = (ENG / "logtriage" / "gui" / "admin.html").read_text(encoding="utf-8")
        for gone in ('data-t="demo"', "시연 자료", "demo_seed", "demoseed"):
            self.assertNotIn(gone, src)
        ui = (ENG / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn("api().demo_seed(false)", ui)


if __name__ == "__main__":
    unittest.main()
