"""WebSphere tWAS SystemOut.log 파서(2026-10-16) — 지식(코드 74종)은 있었으나 파서가 없어 실로그가 판정에 닿지 않던 결함.
형식·자동 판별·코드 추출·연속 줄 병합·SystemErr 예외 등급·한국어 로캘 날짜를 시험한다(합성 표본, 실로그 아님)."""
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.detect import detect_product  # noqa: E402
from logtriage.parsers import get_parser  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

SAMPLE = ENGINE / "samples" / "SystemOut.log"


class WebSphereParser(unittest.TestCase):
    def test_detect_and_parse(self):
        self.assertEqual(detect_product(SAMPLE), "websphere")
        layer, parse = get_parser("websphere")
        self.assertEqual(layer, "was")
        ev = parse(SAMPLE, "h")
        codes = [e.code for e in ev]
        self.assertIn("WSVR0605W", codes)
        self.assertIn("J2CA0045E", codes)
        hung = next(e for e in ev if e.code == "WSVR0605W")
        self.assertEqual(hung.severity, "warn")
        self.assertIn("socketRead0", hung.message)                 # 스택트레이스 연속 줄은 직전 이벤트에 병합
        self.assertEqual(next(e for e in ev if e.code == "J2CA0045E").severity, "error")
        err = [e for e in ev if "SQLTransientConnectionException" in e.message]
        self.assertTrue(err and err[0].severity == "error")         # SystemErr(R) 예외는 오류로 올린다
        self.assertEqual(hung.ts.strftime("%Y-%m-%d %H:%M:%S"), "2026-10-16 10:12:44")

    def test_korean_locale_date(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "SystemOut.log"
            p.write_text("[26. 10. 16 10:12:44:501 KST] 0000004d ThreadMonitor W   WSVR0605W: Thread \"WebContainer : 3\" may be hung.\n",
                         encoding="utf-8")
            self.assertEqual(detect_product(p), "websphere")
            ev = get_parser("websphere")[1](p, "h")
            self.assertEqual((ev[0].code, ev[0].ts.month, ev[0].ts.day), ("WSVR0605W", 10, 16))

    def test_codes_reach_verdicts_with_procedures(self):
        inc = run_analysis([{"path": str(SAMPLE), "product": "websphere", "host": "h"}], None, rules_dir=ENGINE / "rules",
                           codes_dir=ENGINE / "errorcodes", manuals_dir=ENGINE / "manuals")
        ids = {c["rule_id"] for c in inc["checklist"]}
        self.assertIn("WSVR0605W", ids)
        for c in inc["checklist"]:
            self.assertTrue(c.get("procedures"), c["rule_id"])
            self.assertTrue(c.get("vendor_cause"), c["rule_id"])


if __name__ == "__main__":
    unittest.main()
