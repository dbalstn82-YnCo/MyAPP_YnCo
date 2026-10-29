"""룰·코드 YAML 안전 읽기(2026-10-14, GPT 교차 검토 6차 반박으로 실측 → 결함 2건 확인·수정).

- C 안전 파서(CSafeLoader)는 아주 깊은 중첩('[' 5,000개)에서 예외가 아니라 프로세스가 죽는다 → 읽기 전에 이벤트 단계로 깊이를 센다
- 파일 하나가 깨지면 load_rules·load_codes 전체가 멈춰 분석이 안 됐다 → 그 파일만 건너뛴다
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import yamlsafe  # noqa: E402
from logtriage.codes import load_aliases, load_codes  # noqa: E402
from logtriage.rules import load_rules  # noqa: E402

DEEP = "rules: " + "[" * 20000 + "]" * 20000 + "\n"
ALIAS = "a: &a [x]\nrules: [" + ",".join(["*a"] * 300) + "]\n"
BROKEN = "rules:\n  - id: [unclosed\n    : : :\n"


class YamlSafe(unittest.TestCase):
    def test_limits_reject_without_crashing(self):
        with self.assertRaises(yamlsafe.YamlRejected):
            yamlsafe.load(DEEP)                    # 이 줄이 프로세스를 죽이면 시험 전체가 실패한다
        with self.assertRaises(yamlsafe.YamlRejected):
            yamlsafe.load(ALIAS)
        with self.assertRaises(yamlsafe.YamlRejected):
            yamlsafe.load("x: " + "a" * (yamlsafe.MAX_BYTES + 1))
        self.assertEqual(yamlsafe.load("rules:\n- id: A\n"), {"rules": [{"id": "A"}]})

    def test_one_bad_file_does_not_stop_the_rest(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        (td / "rules").mkdir()
        (td / "codes").mkdir()
        good_rule = next((ENGINE / "rules").rglob("*.yaml"))
        shutil.copy(good_rule, td / "rules" / "good.yaml")
        shutil.copy(next((ENGINE / "errorcodes").glob("*.yaml")), td / "codes" / "good.yaml")
        n_rules = len(load_rules(td / "rules"))
        n_codes = len(load_codes(td / "codes"))
        self.assertGreater(n_rules, 0)
        self.assertGreater(n_codes, 0)
        for name, text in (("deep.yaml", DEEP), ("alias.yaml", ALIAS), ("broken.yaml", BROKEN), ("list.yaml", "- 1\n- 2\n")):
            (td / "rules" / name).write_text(text, encoding="utf-8")
            (td / "codes" / name).write_text(text, encoding="utf-8")
        self.assertEqual(len(load_rules(td / "rules")), n_rules)
        self.assertEqual(len(load_codes(td / "codes")), n_codes)
        (td / "codes" / "_aliases.yaml").write_text(DEEP, encoding="utf-8")
        self.assertEqual(load_aliases(td / "codes"), [])

    def test_skipped_files_are_reported(self):
        """건너뛰기만 하면 조용한 누락 — 룰팩 화면에 이름·사유를 알린다."""
        from logtriage.codes import unreadable_files as uc
        from logtriage.rules import unreadable_files as ur
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        (td / "rules").mkdir()
        (td / "errorcodes").mkdir()
        (td / "rules" / "deep.yaml").write_text(DEEP, encoding="utf-8")
        (td / "errorcodes" / "broken.yaml").write_text(BROKEN, encoding="utf-8")
        self.assertEqual([x["file"].replace("\\", "/") for x in ur(td / "rules")], ["rules/deep.yaml"])
        self.assertEqual([x["file"].replace("\\", "/") for x in uc(td / "errorcodes")], ["errorcodes/broken.yaml"])
        self.assertEqual(ur(ENGINE / "rules", ENGINE / "rules-local"), [])
        self.assertEqual(uc(ENGINE / "errorcodes"), [])

    def test_analysis_records_limited_scope(self):
        """룰 일부를 못 읽은 채 분석했으면 결과에 남긴다 — 화면은 '이상 미검출' 대신 '판정 범위 제한'(GPT 7차)."""
        from logtriage.service import run_analysis
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        for d in ("rules", "rules-local", "errorcodes"):
            shutil.copytree(ENGINE / d, td / d)
        S = ENGINE / "samples"
        args = ([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"}], None)
        kw = dict(rules_dir=td / "rules", local_dir=td / "rules-local", codes_dir=td / "errorcodes")
        self.assertEqual(run_analysis(*args, **kw)["kb_skipped"], [])
        (td / "rules" / "zz_bad.yaml").write_text(DEEP, encoding="utf-8")
        (td / "errorcodes" / "zz_bad.yaml").write_text(BROKEN, encoding="utf-8")
        r = run_analysis(*args, **kw)
        self.assertEqual(r["kb_skipped"], ["errorcodes/zz_bad.yaml", "rules/zz_bad.yaml"])
        self.assertTrue(r["first"])                                    # 나머지 룰로 판정은 계속된다

    def test_damage_log_survives_restart(self):
        """손상 기록(2026-10-15): 바뀔 때만 한 줄 · 새 프로세스(재시작)에서도 보임 · 고치면 '복구됨' · 내용은 남기지 않음."""
        from logtriage import server
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        for d in ("rules", "rules-local", "errorcodes"):
            shutil.copytree(ENGINE / d, td / d)
        bad = td / "rules" / "zz_bad.yaml"
        bad.write_text("rules:\n  - id: [SECRET-TEXT\n", encoding="utf-8")
        p1 = server.ServerApi(td, [], None).pack_info()
        p1b = server.ServerApi(td, [], None).pack_info()                      # 같은 상태로 다시 열어도 줄이 늘지 않는다
        self.assertEqual([(x["event"], x["file"].replace("\\", "/")) for x in p1b["damage_log"]], [("손상 발견", "rules/zz_bad.yaml")])
        self.assertTrue(p1["damage_log"][0]["sha"])
        self.assertNotIn("SECRET-TEXT", (td / "data" / "kb_damage.jsonl").read_text(encoding="utf-8"))
        logtxt = (td / "data" / "kb_damage.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("Error", logtxt); self.assertNotIn("line", logtxt)    # GPT UI 19차: 예외 글 대신 유형 코드만
        self.assertEqual(p1["damage_log"][0]["code"], "YAML_SYNTAX")
        self.assertEqual(p1["damage_log"][0]["why"], "YAML 문법 오류")
        bad.unlink()
        p2 = server.ServerApi(td, [], None).pack_info()                       # 재시작 = 새 인스턴스
        self.assertEqual([x["event"] for x in p2["damage_log"]], ["복구됨", "손상 발견"])

    def test_real_knowledge_base_is_unchanged(self):
        self.assertGreaterEqual(len(load_rules(ENGINE / "rules", ENGINE / "rules-local")), 400)
        self.assertGreaterEqual(len({k for k in load_codes(ENGINE / "errorcodes") if ":" in k}), 1400)


if __name__ == "__main__":
    unittest.main()
