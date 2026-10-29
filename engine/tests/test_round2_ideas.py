"""2026-10-15 2차 아이디어 12건 시험 — 4 조치별 근거 ID · 5 조치 시각 짝 · 6 서식 원장 · 7 나눔 상한 · 9 서명 칸 · 10 격리 알림.
(1 링크 도메인·2 인라인 이벤트·3 화면 값 검토는 test_ui_api_list / test_ui_interp_review, 8 겹침은 test_render_layout,
 12 되돌리기 호환은 test_rollback_compat.) 실보고서는 쓰지 않는다 — 공식 서식 + 합성 샘플 로그 + 생성물만."""
import json
import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import report, report_custom as rc, report_style as rs  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

TPL = ENGINE / "report-template"
S = ENGINE / "samples"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                                {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                               rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.tdir = self.td / "tdir"
        self.tdir.mkdir()
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            if (TPL / f).exists():
                shutil.copyfile(TPL / f, self.tdir / f)


class ChecklistEvidence(Base):
    def test_each_action_points_to_kept_evidence(self):
        chk = self.inc["checklist"]
        self.assertTrue(chk and all(c.get("eid") for c in chk))
        eids = {t["eid"] for t in self.inc["timeline"]}
        for c in chk:
            self.assertIn(c["eid"], eids)
        r = report.generate(self.tdir / "template.yaml", self.inc, self.td / "o")
        html = Path(r["html"]).read_text(encoding="utf-8")
        self.assertIn("조치 방안별 근거", html)
        for c in chk:
            self.assertIn(c["eid"], html)


class ActionPairs(Base):
    def test_same_action_pairs_across_forms(self):
        r = report.generate(self.tdir / "template.yaml", self.inc, self.td / "o")
        by = {g["item"]: g for g in r["todo_summary"]}
        pairs = [k for k in by if k.startswith("시각 · 조치")]
        self.assertTrue(pairs)
        for k in pairs:
            self.assertEqual(by[k]["count"], 2, k)                 # 상황관리 1곳 + 사후관리 1곳
            self.assertFalse(by[k]["each"], k)                      # 같은 조치 = 같은 시각
            self.assertEqual(len(by[k]["forms"]), 2, k)
        self.assertNotIn("시각", by)                                 # 번호 없는 '시각' 묶음은 없어야 한다
        fixes = [k for k in by if k.startswith("수행 여부·일시 · 조치")]
        self.assertTrue(fixes)
        self.assertTrue({k.split(" · ")[-1] for k in fixes} <= {k.split(" · ")[-1] for k in pairs} | {"조치4"})


class FormLedger(Base):
    def test_export_and_check(self):
        d = rc.ledger_export(self.tdir)
        self.assertEqual({f["kind"] for f in d["forms"]}, {"builtin"})
        self.assertTrue(all(len(f["sha256"]) == 64 for f in d["forms"]))
        self.assertNotIn("fields", json.dumps([f for f in d["forms"] if f["kind"] == "builtin"]))
        self.assertEqual(rc.ledger_check(self.tdir, json.dumps(d))["counts"], {"same": 2, "changed": 0, "missing": 0, "local_only": 0})
        d["forms"][0]["sha256"] = "a" * 64
        d["forms"].append({"kind": "custom", "name": "본사 전용", "sha256": "b" * 64})
        c = rc.ledger_check(self.tdir, json.dumps(d))["counts"]
        self.assertEqual(c, {"same": 1, "changed": 1, "missing": 1, "local_only": 0})

    def test_hostile_ledger(self):
        for bad in ("", "[]", "x" * 10, json.dumps({"kind": "other", "forms": []}), json.dumps({"kind": rc.LEDGER_KIND, "forms": {}}),
                    json.dumps({"kind": rc.LEDGER_KIND, "forms": [{}] * 501}), "{" + " " * (rc.LEDGER_MAX + 1) + "}"):
            with self.subTest(bad=bad[:30]):
                with self.assertRaises(ValueError):
                    rc.ledger_check(self.tdir, bad)
        weird = {"kind": rc.LEDGER_KIND, "forms": [{"name": "<script>", "sha256": "../../x"}, {"name": "", "sha256": "c" * 64}, 5]}
        r = rc.ledger_check(self.tdir, json.dumps(weird))
        self.assertEqual(r["counts"]["missing"], 0)                  # 형식 안 맞는 줄은 버리되
        self.assertEqual(r["invalid"], 3)                            # 센다(GPT 33차)
        self.assertFalse(r["complete"])                              # 버린 줄이 있으면 '모두 같음' 아님
        good = rc.ledger_export(self.tdir)
        self.assertTrue(rc.ledger_check(self.tdir, json.dumps(good))["complete"])
        good["forms"].append({"name": "x", "sha256": "zz"})
        self.assertFalse(rc.ledger_check(self.tdir, json.dumps(good))["complete"])


class Ceiling(unittest.TestCase):
    def test_ceiling_only_ratios(self):
        labels = rs.form_labels(TPL)
        paras = rs.parse_hwpx((TPL / "form_status.hwpx").read_bytes())
        docs = [("status", paras, f"{i:064x}") for i in range(rs.CEIL_MIN_DOCS)]
        c = rs.ceiling(docs, labels)
        self.assertIsNotNone(c)
        self.assertEqual(c["groups"], 1)                         # 똑같은 문서는 한 묶음 — 한쪽에만 들어간다
        self.assertIsNone(rs.ceiling(docs[:3], labels))          # 문서가 적으면 재지 않는다
        self.assertFalse(rs._forbidden_check({"ceiling": c}, labels))

    def test_similar_groups(self):
        P = types.SimpleNamespace
        a = [P(text="가나다라마바사아자차카타파하" * 5)]
        b = [P(text="가나다라마바사아자차카타파하" * 5 + "끝")]
        c = [P(text="완전히 다른 내용의 보고서 문장들이 여기에 있습니다" * 3)]
        g = sorted(sorted(x) for x in rs.similar_groups([a, b, c]))
        self.assertEqual(g, [[0, 1], [2]])


class FitEndings(unittest.TestCase):
    """아이디어 11 + GPT 33차: 높임 끝만, 인용문·[기재]·시간대별(로그 원문이 섞이는 줄)은 그대로."""
    def test_rules(self):
        from logtriage.report_forms import StyleProfile
        sp = StyleProfile({"fields": {"장애원인": {"ending": {"noun": 9}}, "조치내용": {"ending": {"noun": 9}}}})
        self.assertEqual(sp.fit_endings("장애원인", ["서비스를 재기동하십시오.", "DB 포함", "오류 '연결이 끊어졌습니다'", "확인 [기재: 시각]"]),
                         ["서비스를 재기동", "DB 포함", "오류 '연결이 끊어졌습니다'", "확인 [기재: 시각]"])
        self.assertEqual(sp.fit_endings("조치내용", ["재기동하십시오"]), ["재기동하십시오"])
        self.assertEqual(sp.fit_endings("장애원인", ["재기동하십시오"], kind="timeline"), ["재기동하십시오"])


class LedgerSignature(unittest.TestCase):
    def test_label(self):
        sys.path.insert(0, str(ENGINE / "tools" / "build"))
        import build_ledger as bl
        self.assertEqual(bl.sig_label({"status": "NotSigned"}), "서명 없음")
        self.assertIn("ABCDEF0123456789", bl.sig_label({"status": "Valid", "thumbprint": "ABCDEF0123456789FFFF"}))
        self.assertIn("깨짐", bl.sig_label({"status": "HashMismatch"}))
        self.assertEqual(bl.signature(Path(tempfile.gettempdir()) / "없는파일.exe")["status"], "없음")


class QuarantineNotice(unittest.TestCase):
    def test_notice_once_a_day(self):
        from logtriage import safe_backup
        from logtriage.automation import Automation
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        a = Automation(types.SimpleNamespace(_base=base))
        self.assertIsNone(a.check_tmp_backups())
        q = base / ".backup-QZ_abc"
        (q / "stage").mkdir(parents=True)
        (q / "stage" / "x").write_text("x", encoding="utf-8")
        (q / safe_backup.QZ_MARK).write_text(json.dumps({"at": time.time() - 2 * 86400, "from": ".backup-abc"}), encoding="utf-8")
        msg = a.check_tmp_backups()
        self.assertIn("격리한 폴더 1개", msg)
        self.assertNotIn(str(base), msg)                          # 경로는 알림에 없다
        self.assertIsNone(a.check_tmp_backups())                  # 하루 한 번
        self.assertTrue(q.exists())                               # 알리기만 — 지우지 않는다
        n = a.notices()
        self.assertEqual(n["notices"][0]["category"], "tmp_backup")


if __name__ == "__main__":
    unittest.main()
