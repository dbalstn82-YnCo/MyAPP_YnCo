"""룰 계층·심각도·분류는 정해진 값만 — 2026-10-15 XSS 전수 점검에서 발견: 지역 룰의 layer 에 스크립트를 넣으면
코드 조회 화면(계층 묶음 제목·검색 결과 꼬리표)에 그대로 그려졌다(저장형 XSS, 운영 권한 → 관리자 세션).
엄격 로더·사이트 룰 추가·학습 룰 승인 세 입구 모두 막고, 화면도 이스케이프한다."""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import rules as R  # noqa: E402

EVIL = '<img src=x onerror="window.__pwn=1">'


class RuleFields(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)

    def test_checker(self):
        R.check_rule_fields({"layer": "db", "severity": "critical", "category": "lock"})
        R.check_rule_fields({"layer": ["os", "was"]})
        for bad in ({"layer": EVIL}, {"layer": ["os", EVIL]}, {"layer": []}, {"layer": None},
                    {"layer": "os", "severity": EVIL}, {"layer": "os", "category": "constructor"}, {"layer": "os", "category": EVIL}):
            with self.subTest(bad=str(bad)[:40]):
                with self.assertRaises(ValueError):
                    R.check_rule_fields(bad)

    def test_strict_loader_rejects_file(self):
        f = self.td / "x.yaml"
        f.write_text('rules:\n- id: X-1\n  layer: "' + EVIL.replace('"', '\\"') + '"\n  match: {regex: "boom"}\n', encoding="utf-8")
        with self.assertRaises(ValueError):
            R._load_file_strict(f, "local")

    def test_all_shipped_rules_pass(self):
        for d in (ENGINE / "rules", ENGINE / "rules-local"):
            for f in d.rglob("*.yaml"):
                with self.subTest(f=f.name):
                    R._load_file_strict(f, "check")

    def test_site_rule_entry_refuses(self):
        from logtriage.gui.app import Api
        with mock.patch("logtriage.gui.app.base_dir", return_value=self.td):
            api = Api()
        r = api.add_local_rule({"regex": "boom", "verdict": "v", "layer": EVIL})
        self.assertIn("계층", r.get("error", ""))
        self.assertFalse((self.td / "rules-local" / "site_rules.yaml").exists())
        r = api.add_local_rule({"regex": "boom", "verdict": "v", "layer": "was", "category": "toString"})
        self.assertIn("분류", r.get("error", ""))
        r = api.add_local_rule({"regex": "boom", "verdict": "v", "layer": "was"})
        self.assertFalse(r.get("error"), r)

    def test_ui_escapes_layer_labels(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertNotIn("${LY[p.layer]||p.layer}", ui)
        self.assertNotIn("${LY[r.layer]||r.layer}", ui)


if __name__ == "__main__":
    unittest.main()
