"""2026-10-16 아이디어 12건 — 검증 축·표본 대기열·전용 절차 승급·문법/실행 검사·현장 피드백·판 추정·1차 명령 모음·결과 해석·
근거 보관·지식 지문·제조사 요청서·사후 원인. GPT 55차 조건(문법 통과 ≠ 실행 성공 ≠ 진단 정확성, 판정 불가, 사람 검토 후 룰 수정)을 시험으로 묶는다."""
import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "tools" / "build"))
from logtriage import knowledge_quality as KQ  # noqa: E402
from logtriage import storage  # noqa: E402
from logtriage.codes import load_codes  # noqa: E402
from logtriage.procedures import load_procedures, match_procedures  # noqa: E402
from logtriage.yamlsafe import load as yload  # noqa: E402


def _rule_ids():
    out = set()
    for f in (ENGINE / "rules").rglob("*.yaml"):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                out.add(str(r["id"]).upper())
    return out


class Records(unittest.TestCase):
    """⑨ 근거 보관·① 교차 검증 기록은 실제 판정을 가리키고, 발췌 해시가 맞아야 한다."""

    def test_evidence_hash_and_claims(self):
        ev = yload((ENGINE / "errorcodes" / "_evidence.yaml").read_text(encoding="utf-8"))["evidence"]
        keys = {k.upper() for k in load_codes(ENGINE / "errorcodes") if ":" in k} | _rule_ids()
        self.assertTrue(ev)
        for x in ev:
            for f in ("claim", "title", "url", "excerpt", "sha256", "versions", "checked", "by"):
                self.assertTrue(x.get(f), f"{x.get('claim')} {f} 없음")
            self.assertEqual(hashlib.sha256(x["excerpt"].encode("utf-8")).hexdigest(), x["sha256"], x["claim"])
            self.assertIn(str(x["claim"]).upper(), keys)
            self.assertTrue(x["url"].startswith("https://"))

    def test_verification_lists_point_to_real_verdicts(self):
        v = yload((ENGINE / "errorcodes" / "_verification.yaml").read_text(encoding="utf-8"))
        keys = {k.upper() for k in load_codes(ENGINE / "errorcodes") if ":" in k} | _rule_ids()
        for lst in ("gpt", "syntax_pass", "syntax_fail", "exec_pass", "exec_fail"):
            bad = [k for k in (v.get(lst) or []) if str(k).upper() not in keys]
            self.assertEqual(bad, [], lst)
        self.assertFalse(set(v.get("syntax_pass") or []) & set(v.get("syntax_fail") or []))

    def test_axes_are_independent(self):
        ver = KQ.load_verification(ENGINE / "errorcodes")
        a = KQ.axes("CUBRID:-3", ver=ver)
        self.assertEqual(a["source"], "공식 근거 보관")
        self.assertEqual(a["cross"], "GPT 표본 실검증")
        self.assertIn(a["syntax"], ("통과", "실패", "미실행"))
        b = KQ.axes("NOPE:X", verify_note="확인 못 함", ver=ver)
        self.assertEqual((b["source"], b["unverified"], b["cross"], b["syntax"], b["exec"]), ("분석기 지식", True, "", "미실행", "미실행"))


class Interpret(unittest.TestCase):
    """⑧ 기계로 못 읽으면 '판정 불가'·'사람 판단' — 명령 오류 출력을 '기준 충족'으로 읽지 않는다."""

    def test_command_failure_is_undecidable(self):
        for out in ("bash: errpt: command not found", "grep: /var/log/x: No such file or directory", "ERROR:  permission denied for view",
                    "SP2-0306: Invalid option.", "'wevtutil'은(는) 내부 또는 외부 명령, 실행할 수 있는 프로그램, 또는 배치 파일이 아닙니다."):
            self.assertEqual(KQ.interpret("결과가 있으면 확정", out)["verdict"], "판정 불가", out)

    def test_threshold_and_rows(self):
        r = KQ.interpret("사용률 90% 이상이면 확정", "Filesystem Use%\n/u01  95% /u01\n/ 10% /")
        # GPT 59차: 기계는 충족·미충족을 정하지 않는다 — '사람 판단' + 참고 수치(측정값·기준값·위아래)
        self.assertEqual((r["verdict"], r["measured"], r["threshold"], r["above"]), ("사람 판단", 95.0, 90.0, True))
        self.assertIn("참고 수치", r["why"])
        self.assertIn("/u01  95% /u01", r["why"])            # 측정값이 나온 줄을 보여 준다
        self.assertEqual(KQ.interpret("90% 이상", "1234%")["verdict"], "판정 불가")
        # GPT 58차: 한 줄에 % 지표가 여럿이면(sar -u: %user %system %idle) 어느 것과 비교할지 모른다 → 판정 불가
        self.assertEqual(KQ.interpret("CPU 90% 이상이면 확정", "12:00 all 5.0% 2.0% 93.0%")["verdict"], "판정 불가")
        # GPT 56차: '있으면' 기준을 결과 줄 유무로 판정하지 않는다(머리글·0 도 줄이다)
        self.assertEqual(KQ.interpret("ORA-00060 이 있으면 확정", "COUNT\n-----\n0")["verdict"], "사람 판단")
        r = KQ.interpret("사용률 90% 이상이면 확정", "/u01  40%")
        self.assertEqual((r["verdict"], r["above"]), ("사람 판단", False))
        for crit in ("90% 이상", "사용률 90% 이상이면 확정"):   # 어떤 출력에서도 '기준 충족'·'기준 미충족'을 내지 않는다
            for out in ("/u01 95% /u01", "/u01 40%", "x 100% y"):
                self.assertNotIn(KQ.interpret(crit, out)["verdict"], ("기준 충족", "기준 미충족"))
        self.assertEqual(KQ.interpret("사용률 90% 이상이면 확정", "used 12G")["verdict"], "판정 불가")
        self.assertEqual(KQ.interpret("ORA-00060 이 있으면 확정", "")["verdict"], "판정 불가")
        self.assertEqual(KQ.interpret("같은 SQL 쌍이 반복되는지 본다", "a\nb")["verdict"], "사람 판단")

    def test_server_api_does_not_store_and_limits_size(self):
        from logtriage.server import ServerApi

        class St:
            def get(self, _):
                return {"checklist": [{"rule_id": "R1", "cmds": [{"cmd": "df -h", "criterion": "90% 이상이면 확정"}]}]}
        fake = type("F", (), {"store": St()})()
        r = ServerApi.interpret_output(fake, "I", "R1", 0, "/a 97% /a")
        self.assertEqual((r["verdict"], r["above"]), ("사람 판단", True))
        self.assertIn("진단이 맞았다는 것은 다릅니다", r["note"])
        self.assertIn("error", ServerApi.interpret_output(fake, "I", "R1", 0, "x" * (KQ.MAX_INTERPRET + 1)))
        self.assertIn("error", ServerApi.interpret_output(fake, "I", "R1", 5, "x"))


class Commands(unittest.TestCase):
    """⑦ 1차 명령은 한 줄씩 복사만 — 위험 명령·비밀번호 명령은 복사하지 않는다. ⑥ 판이 어긋난다고 추정되면 복사 막음."""

    def test_risky_or_password_not_copyable(self):
        cs = KQ.first_commands(["`df -h` 확인 — 90% 이상이면 확정", "`systemctl restart httpd` (2차·승인 후)", "`mysql -u root -p<pw>`"])
        self.assertEqual([c["safe"] for c in cs], [True, False, False])
        self.assertEqual(cs[0]["criterion"], "90% 이상이면 확정")
        self.assertEqual(len(cs[0]["hash"]), 16)

    def test_service_marks_copy(self):
        from logtriage.service import run_analysis
        inc = run_analysis([{"path": str(ENGINE / "samples" / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                           rules_dir=ENGINE / "rules", codes_dir=ENGINE / "errorcodes", manuals_dir=ENGINE / "manuals")
        cl = inc["checklist"]
        self.assertTrue(cl)
        for c in cl:
            self.assertIn("axes", c)
            for m in c.get("cmds") or []:
                self.assertEqual(m["copy"], m["safe"] and m["fit"] != "어긋남")
        self.assertTrue(inc.get("kb_fingerprint"))
        self.assertIn("versions_detected", inc)


class Manifest(unittest.TestCase):
    """⑩ 지식 파일 추가·삭제·변경을 해시로 잡는다 — 정당한 교체(룰팩) 뒤에는 새로 쓴다."""

    def test_add_delete_change(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "errorcodes", "manuals"):
            (td / d).mkdir()
        (td / "rules" / "a.yaml").write_text("rules: []\n", encoding="utf-8")
        (td / "manuals" / "m_procedures.yaml").write_text("procedures: []\n", encoding="utf-8")
        self.assertIsNone(KQ.compare_manifest(td))
        KQ.write_manifest(td, {"rules": 0})
        self.assertEqual(KQ.compare_manifest(td)["changed"], [])
        (td / "rules" / "a.yaml").write_text("rules: [] # x\n", encoding="utf-8")
        (td / "manuals" / "m_procedures.yaml").unlink()
        (td / "errorcodes" / "n.yaml").write_text("codes: []\n", encoding="utf-8")
        c = KQ.compare_manifest(td)
        self.assertEqual((c["changed"], c["deleted"], c["added"]), (["rules/a.yaml"], ["manuals/m_procedures.yaml"], ["errorcodes/n.yaml"]))
        from logtriage.rulepack import _refresh_manifest
        _refresh_manifest(td)
        c = KQ.compare_manifest(td)
        self.assertEqual((c["changed"], c["deleted"], c["added"]), ([], [], []))
        self.assertEqual(json.loads((td / "knowledge-manifest.json").read_text(encoding="utf-8"))["rules"], 0)

    def test_dist_check_covers_manuals(self):
        import check_dist_knowledge as cdk
        self.assertIn("manuals", cdk.KNOW)


class FeedbackAndPostmortem(unittest.TestCase):
    """⑤ 현장 피드백(지문·결과·판만) ⑫ 사후 원인(확정/추정/미확정) — 룰 자동 수정 없음, 검토 목록은 관리자만."""

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.st = storage.Storage("sqlite:///" + (self.td / "t.db").as_posix())
        self.st.save_incident({"id": "I1", "analyzed_at": "2026-10-16 10:00", "first": {"verdict": "데드락", "rule_id": "R1"}})
        self.st.save_incident({"id": "I2", "analyzed_at": "2026-10-16 11:00", "first": {"verdict": "데드락", "rule_id": "R1"}})

    def test_feedback(self):
        h = "0123456789abcdef"
        for _ in range(5):   # GPT 56차: 같은 사람·같은 건·같은 명령은 한 표 — 연타로 부풀지 않는다
            self.st.add_feedback("R1", h, "ok", "19c", {"login": "a"}, incident_id="I1")
        self.st.add_feedback("R1", h, "fail", "", {"login": "b"}, incident_id="I1")
        self.st.add_feedback("R1", h, "ok", "", {"login": "a"}, incident_id="I2")
        self.assertEqual(self.st.feedback_summary(["R1"]), {"R1": {h: {"ok": 2, "fail": 1, "version": 0}}})
        self.st.add_feedback("R1", h, "version", "", {"login": "a"}, incident_id="I1")   # 마음을 바꾸면 마지막 표
        self.assertEqual(self.st.feedback_summary(["R1"]), {"R1": {h: {"ok": 1, "fail": 1, "version": 1}}})
        with self.assertRaises(ValueError):
            self.st.add_feedback("R1", h, "ok", "", {"login": "a"}, incident_id="NOPE")
        for bad in (("R1", "zz", "ok"), ("R1", h, "great"), ("", h, "ok"), ("R1", h.upper(), "ok")):
            with self.assertRaises(ValueError):
                self.st.add_feedback(*bad)

    def test_postmortem(self):
        with self.assertRaises(ValueError):
            self.st.set_postmortem("I1", "원인", "sure", "yes")
        with self.assertRaises(ValueError):
            self.st.set_postmortem("I1", " ", "confirmed", "yes")
        with self.assertRaises(ValueError):
            self.st.set_postmortem("NOPE", "원인", "confirmed", "yes")
        with self.assertRaises(ValueError):   # GPT 56차: '확정'은 근거 없이 받지 않는다
            self.st.set_postmortem("I1", "스토리지 캐시 배터리", "confirmed", "no", "", {"login": "b"})
        pm = self.st.set_postmortem("I1", "스토리지 캐시 배터리", "confirmed", "no", "제조사 RCA-123", {"login": "b"})
        self.assertEqual((pm["first_rule"], pm["certainty"], pm["actor"], pm["revisions"]), ("R1", "confirmed", "b", 1))
        pm = self.st.set_postmortem("I1", "스토리지 캐시 배터리", "probable", "partial")   # 다시 쓰면 이력 + 마지막 것이 보임
        self.assertEqual((pm["certainty"], pm["revisions"]), ("probable", 2))
        self.st.set_postmortem("I2", "데드락 맞음", "confirmed", "yes", "AWR 로 확인")
        rv = self.st.postmortem_review()
        self.assertEqual(len(rv), 1)
        self.assertEqual((rv[0]["total"], rv[0]["miss_confirmed"], rv[0]["miss_probable"], rv[0]["hit"], rv[0]["hit_confirmed"]),
                         (2, 0, 1, 1, 1))

    def test_permissions(self):
        from logtriage import server
        for n in ("kb_feedback", "kb_feedback_summary", "interpret_output", "postmortem_get", "postmortem_set", "postmortem_review"):
            self.assertIn(n, server.API_NAMES)
        self.assertIn("postmortem_review", server.ADMIN_APIS)
        self.assertNotIn("kb_feedback", server.READ_APIS)
        self.assertNotIn("postmortem_set", server.READ_APIS)
        self.assertIn("interpret_output", server.READ_APIS)
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        for n in ("kb_feedback", "interpret_output", "postmortem_set", "postmortem_review"):
            self.assertIn(f'"{n}"', ui)


class Procedures(unittest.TestCase):
    """③ 전용 절차 승급 — proclinks 는 있는 절차에만, scope: id 절차는 이름 붙인 판정에만."""

    def test_proclinks_merge_and_bad_link_reported(self):
        from logtriage import procedures as P
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        (td / "a_procedures.yaml").write_text(
            "procedures:\n- id: P1\n  products: [x]\n  category: c\n  title: t\n  stages: [{stage: 1, steps: [{do: d, cmd: 'df -h'}]}]\n"
            "- id: P2\n  scope: id\n  products: [x]\n  category: c\n  match: [ONLY]\n  title: t2\n  stages: [{stage: 1, steps: [{do: d, cmd: 'df -h'}]}]\n",
            encoding="utf-8")
        (td / "a_proclinks.yaml").write_text("links:\n- procedure: P1\n  match: [K1]\n- procedure: NOPE\n  match: [K2]\n", encoding="utf-8")
        ps = load_procedures(td)
        self.assertTrue(any("없는 절차" in s for s in P.SKIPPED.files))
        m = match_procedures(ps, "x", "os", "c", ["K1"])
        self.assertEqual((m[0]["id"], m[0]["link"]), ("P1", "이 판정 전용"))
        self.assertEqual([p["id"] for p in match_procedures(ps, "x", "os", "c", ["OTHER"])], ["P1"])   # P2 는 끼어들지 않는다
        self.assertEqual(match_procedures(ps, "x", "os", "c", ["ONLY"])[0]["id"], "P2")

    def test_id_match_needs_same_product(self):
        """GPT 56차: ID 가 같아도 제품이 다르면 전용이 아니다 — GOLDILOCKS ERR-11030 에 Altibase 절차가 붙던 결함."""
        ps = load_procedures(ENGINE / "manuals")
        m = match_procedures(ps, "goldilocks", "db", "memory", ["ERR-11030"], limit=1)[0]
        self.assertTrue(m["id"].startswith("GD-"), m["id"])
        m = match_procedures(ps, "altibase", "db", "storage", ["ERR-11030"], limit=1)[0]
        self.assertTrue(m["id"].startswith("ALT-"), m["id"])
        self.assertEqual(match_procedures(ps, "jeus", "was", "memory", ["WAS-JVM-001"], limit=1)[0]["id"], "JEUS-PROC-MEMORY")
        self.assertEqual(match_procedures(ps, "weblogic", "was", "memory", ["WAS-JVM-001"], limit=1)[0]["link"], "이 판정 전용")

    def test_tie_is_marked_ambiguous_unless_primary(self):
        """GPT 58차: 같은 순위의 전용 절차가 둘이면 임의로 '전용'이라 하지 않는다 — 사람이 고른 primary 가 있으면 그것."""
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        st = "stages: [{stage: 1, steps: [{do: d, cmd: 'df -h'}]}]"
        doc = ["procedures:"]
        for pid, mt in (("A", "[K]"), ("B", "[K, K2]")):
            doc += [f"- id: {pid}", "  products: [x]", "  category: c", f"  match: {mt}", f"  title: {pid}", f"  {st}"]
        (td / "a_procedures.yaml").write_text("\n".join(doc) + "\n", encoding="utf-8")
        m = match_procedures(load_procedures(td), "x", "os", "c", ["K"])
        self.assertIn("매칭 모호", m[0]["link"])
        self.assertNotEqual(m[0]["link"], "이 판정 전용")          # 화면은 '참고 절차' 경고를 붙인다
        (td / "a_proclinks.yaml").write_text("\n".join(["links:", "- procedure: B", "  match: [K]", "  primary: true", "  reviewed: r"]) + "\n",
                                            encoding="utf-8")
        m = match_procedures(load_procedures(td), "x", "os", "c", ["K"])
        self.assertEqual((m[0]["id"], m[0]["link"]), ("B", "이 판정 전용"))
        self.assertEqual(match_procedures(load_procedures(td), "x", "os", "c", ["K2"])[0]["link"], "이 판정 전용")

    def test_real_ties_resolved(self):
        ps = load_procedures(ENGINE / "manuals")
        for pr, lay, cat, i, want in (("java", "sw", "thread", "JAVA.UTIL.CONCURRENT.REJECTEDEXECUTIONEXCEPTION", "JAVA-PROC-THREAD"),
                                      ("iis", "web", "capacity", "503.2", "IIS-PROC-CAPACITY"),
                                      ("tomcat", "was", "connection", "WAS-POOL-002", "TOMCAT-PROC-CONNECTION")):
            m = match_procedures(ps, pr, lay, cat, [i], limit=1)[0]
            self.assertEqual((m["id"], m["link"]), (want, "이 판정 전용"), i)

    def test_r6_procedures_are_id_scoped(self):
        bad = []
        for f in sorted((ENGINE / "manuals").glob("r6*_procedures.yaml")):
            for p in yload(f.read_text(encoding="utf-8"))["procedures"]:
                if p.get("scope") != "id" or not p.get("match"):
                    bad.append(f"{f.name}:{p.get('id')}")
        self.assertEqual(bad, [])


class SafeBackupOwner(unittest.TestCase):
    """10-16 화면 점검 중 발견: 주인 표식(.owner)이 JSON 사전이 아니면 관리자 목록 API 가 끊기고 백업 시작 때 정리도 멈췄다."""

    def test_malformed_owner_does_not_crash(self):
        from logtriage import safe_backup as sb
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for name, own in ((".backup-a1", "12345"), (".backup-a2", "[1,2]"), (".backup-a3", "not json"), (".backup-a4", '{"pid": 999999}')):
            (td / name).mkdir()
            (td / name / ".owner").write_text(own, encoding="utf-8")
        rows = {r["name"]: r["state"] for r in sb.list_backups(td)}
        self.assertEqual((rows[".backup-a1"], rows[".backup-a2"], rows[".backup-a3"]), ("unowned", "unowned", "unowned"))
        self.assertEqual(rows[".backup-a4"], "orphan")
        from unittest import mock
        with mock.patch.object(sb, "_shared_writable", lambda *a: False):   # 임시 폴더는 넓은 쓰기 권한이라 자동 정리 자체를 안 한다 — 그 관문만 끈다
            sb._sweep_stale(td)                               # 손상 표식은 건너뛰고(멈추지 않음) 주인이 끝난 것만 정리
        self.assertTrue((td / ".backup-a1").exists())
        self.assertFalse((td / ".backup-a4").exists())

    def test_malformed_owner_cannot_bypass_quarantine(self):
        """GPT 58차: 손상·위조 표식으로 바로 지우기를 얻지 못한다 — 주인 모름은 격리(이름 바꾸기)만, 지우기는 격리 10분 뒤 관리자가 다시."""
        import os
        import time as _t
        from logtriage import safe_backup as sb
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        d = td / ".backup-forged"
        d.mkdir()
        (d / "data.bin").write_text("x", encoding="utf-8")
        (d / ".owner").write_text("[0]", encoding="utf-8")
        old = _t.time() - 3600
        for f in (d / "data.bin", d / ".owner", d):
            os.utime(f, (old, old))
        r = sb.delete_backup(td, ".backup-forged")
        self.assertTrue(r.get("ok") and r.get("quarantined"), r)
        self.assertFalse(d.exists())
        qz = [p for p in td.iterdir() if p.name.startswith(sb.QZ)]
        self.assertEqual(len(qz), 1)
        self.assertTrue((qz[0] / "data.bin").exists())                   # 자료는 아직 지워지지 않았다
        r2 = sb.delete_backup(td, qz[0].name)                              # 격리 직후 다시 지우기 → 거절
        self.assertFalse(r2.get("ok"), r2)


class Tools(unittest.TestCase):
    def test_sample_record_needs_two_people(self):
        import knowledge_sample_queue as q
        q.QDIR = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, q.QDIR, True)
        self.assertEqual(q.main(["record", "--round", "r", "--key", "a:b", "--verdict", "정확", "--reviewer", "A", "--approver", "A"]), 2)
        self.assertEqual(q.main(["record", "--round", "r", "--key", "a:b", "--verdict", "맞음", "--reviewer", "A", "--approver", "B"]), 2)
        self.assertEqual(q.main(["record", "--round", "r", "--key", "a:b", "--verdict", "정확", "--reviewer", "A", "--approver", "B"]), 0)
        self.assertEqual(len((q.QDIR / "결과.jsonl").read_text(encoding="utf-8").splitlines()), 1)

    def test_pg_allowlist(self):
        import knowledge_exec_check as x
        self.assertEqual(x.pg_allowed("SELECT count(*) FROM pg_stat_activity"), "")
        self.assertEqual(x.pg_allowed("SHOW max_connections;"), "")
        for q in ("SELECT pg_terminate_backend(1) FROM pg_stat_activity", "SELECT * FROM orders", "SELECT 1; DROP TABLE x",
                  "SELECT * FROM pg_stat_activity WHERE datname='<db>'", "SELECT set_config('a','b',false)", "SELECT * FROM pg_read_file('x')"):
            self.assertTrue(x.pg_allowed(q), q)

    def test_vendor_requests_no_customer_data(self):
        import make_vendor_requests as v
        items = v.collect()
        self.assertTrue(items)
        for it in items:
            self.assertTrue(it["claim"] and it["vendor"] and it["where"])


if __name__ == "__main__":
    unittest.main()
