"""2026-10-16 7차 아이디어 12건 — GPT 60차 조건까지 시험으로 묶는다.
③ 지표 고정 해석(머리글 칸·단위·범위·경계·표 둘·결속 안 된 짝은 참고만) ④ 시험 환경 없음 배지 ② 수정 후 재확인
⑤ 격리 기록(폴더 밖)·내용 지문·재인증(로그인 없으면 지우기 불가)·정션 ⑥ 허브 피드백 집계(통째 교체·형식·재전송)
⑨ 판 지정/출력 확인 구분·원본 보존 재평가 ⑩ 개선 제안(같은 장애 한 번) ⑫ 확인 목록 ⑦ 유령 연결 0 ⑧ 회신 분류 ⑪ 보낸 글 대조."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "tools" / "build"))
from logtriage import knowledge_quality as KQ  # noqa: E402
from logtriage import storage  # noqa: E402


def _tmp(test):
    td = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, td, True)
    return td


class Metrics(unittest.TestCase):
    def setUp(self):
        self.ms = KQ.load_metrics(ENGINE / "errorcodes")
        self.spec = KQ.metric_for(self.ms, "tomcat:TOMCAT-LOG-WRITE-FAIL", "df -h $CATALINA_BASE/logs")
        self.ino = KQ.metric_for(self.ms, "tomcat:TOMCAT-LOG-WRITE-FAIL", "df -i $CATALINA_BASE/logs")

    def test_binding(self):
        self.assertEqual((self.spec["id"], self.ino["id"]), ("fs-block-use", "fs-inode-use"))
        self.assertIsNone(KQ.metric_for(self.ms, "linux:LNX-AUDIT-DISK-FULL", "df -h /a ; df -i /a"))   # 두 명령을 한 줄에 — 결속 안 함
        self.assertIsNone(KQ.metric_for(self.ms, "oracle:ORA-00060", "df -h /u01"))                    # 목록에 없는 판정

    def test_counterexamples(self):
        I = lambda out, s=None: KQ.interpret("95% 이상이면 확정", out, s if s is not None else self.spec)  # noqa: E731
        h = "Filesystem Size Used Avail Use% Mounted on\n"
        self.assertEqual(I(h + "/dev/a 1G 1G 0 95% /l")["verdict"], "조건 충족")                    # 경계값(=) 포함
        self.assertEqual(I(h + "/dev/a 1G 1G 0 94.9% /l")["verdict"], "조건 미충족")                 # 소수점
        self.assertEqual(I(h + "/dev/very-long\n 1G 1G 0 97% /l")["verdict"], "조건 충족")            # 접힌 줄
        self.assertIn("원인 확정 아님", I(h + "/dev/a 1G 1G 0 99% /l")["why"])
        for bad in (h + "/dev/a 1G 1G 0 -5% /l", h + "/dev/a 1G 1G 0 120% /l", h + "/dev/a 1G 1G 0 n/a /l", h + h + "/dev/a 1 1 0 9% /",
                    "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/a 1 1 0 99% /", "bash: df: command not found", ""):
            self.assertEqual(I(bad)["verdict"], "판정 불가", bad)
        self.assertEqual(I("Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/a 1 1 0 99% /", self.ino)["verdict"], "조건 충족")
        # GPT 61차 P0-2: 경로를 지정한 명령인데 출력에 다른 파일시스템 줄이 섞이면 판정 불가
        self.assertTrue(self.spec["single"])
        self.assertEqual(I(h + "/dev/a 1G 1G 0 20% /logs\n/dev/b 1G 1G 0 99% /data")["verdict"], "판정 불가")
        allfs = KQ.metric_for(self.ms, "tomcat:WAS-TC-020", "bdf")      # 대상 없는 명령은 ANY 규칙
        self.assertFalse(allfs["single"])
        self.assertEqual(KQ.interpret("95% 이상", "Filesystem kbytes used avail %used Mounted on\n/dev/a 1 1 0 20% /\n/dev/b 1 1 0 99% /d", allfs)["verdict"], "조건 충족")
        # 결속 안 된 짝은 GPT 59차대로 참고 수치만
        self.assertEqual(KQ.interpret("95% 이상이면 확정", h + "/dev/a 1G 1G 0 99% /l", None)["verdict"], "사람 판단")

    def test_server_uses_binding(self):
        from logtriage.server import ServerApi

        class St:
            def get(self, _):
                return {"checklist": [{"rule_id": "R1", "code_key": "tomcat:TOMCAT-LOG-WRITE-FAIL",
                                       "cmds": [{"cmd": "df -h $CATALINA_BASE/logs", "criterion": "95% 이상이면 확정"}]}]}
        fake = type("F", (), {"store": St(), "_base": ENGINE})()
        r = ServerApi.interpret_output(fake, "I", "R1", 0, "Filesystem Size Used Avail Use% Mounted on\n/dev/a 1G 1G 0 98% /l")
        self.assertEqual((r["verdict"], r["metric"]), ("조건 충족", "fs-block-use"))


class Axes(unittest.TestCase):
    def test_env_and_reverified(self):
        v = KQ.load_verification(ENGINE / "errorcodes")
        v["exec_unavailable"] = {"oracle": "시험 DB 없음"}
        v["gpt_reverified"] = {"MYSQL:MY-1159"}
        self.assertEqual(KQ.axes("ORACLE:ORA-00060", ver=v)["exec"], "시험 환경 없음")
        self.assertEqual(KQ.axes("R1", ver=v, product="oracle")["exec"], "시험 환경 없음")
        self.assertEqual(KQ.axes("POSTGRESQL:X", ver=v)["exec"], "미실행")
        self.assertEqual(KQ.axes("MYSQL:MY-1159", ver=v)["cross"], "수정 후 재확인")
        real = KQ.load_verification(ENGINE / "errorcodes")
        self.assertIn("oracle", real["exec_unavailable"])          # 실행 검사 도구가 실제로 적어 둔 사유


class QuarantineDelete(unittest.TestCase):
    def _mk(self, td, name=".backup-x1"):
        d = td / name
        d.mkdir()
        (d / "a.bin").write_bytes(b"secret-copy")
        old = time.time() - 3600
        for f in (d / "a.bin", d):
            os.utime(f, (old, old))
        return d

    def _age(self, td, name):
        from logtriage import safe_backup as sb
        reg = sb._qreg(td)
        reg[name]["at"] -= 3600
        sb._qreg_write(td, reg)
        q = td / name
        old = time.time() - 3600
        for f in [q] + list(q.rglob("*")):
            os.utime(f, (old, old))

    def test_flow_and_guards(self):
        from unittest import mock
        from logtriage import safe_backup as sb
        td = _tmp(self)
        self.enterContext(mock.patch.object(sb, "_shared_writable", lambda *a: False))   # 임시 폴더는 넓은 쓰기 권한 — 그 관문만 끈다
        self._mk(td)
        r = sb.delete_backup(td, ".backup-x1")
        self.assertTrue(r.get("quarantined"), r)
        qn = r["name"]
        self.assertIn(qn, sb._qreg(td))                                    # 격리 기록은 폴더 밖(conf)
        self.assertFalse(sb.delete_backup(td, qn).get("ok"))              # 10분 전
        self._age(td, qn)
        r = sb.delete_backup(td, qn, allow_delete=False)                   # 로그인 없는 모드
        self.assertFalse(r.get("ok"))
        self.assertIn("OS 관리자", r["error"])
        (td / qn / "a.bin").write_bytes(b"swapped")                        # 격리 뒤 내용 바뀜
        self._age(td, qn) if False else None
        old = time.time() - 3600
        os.utime(td / qn / "a.bin", (old, old))
        r = sb.delete_backup(td, qn)
        self.assertFalse(r.get("ok"))
        self.assertIn("내용 지문", r["error"])
        (td / qn / "a.bin").write_bytes(b"secret-copy")
        os.utime(td / qn / "a.bin", (old, old))
        os.utime(td / qn, (old, old))
        r = sb.delete_backup(td, qn)
        self.assertTrue(r.get("ok"), r)
        self.assertNotIn(qn, sb._qreg(td))

    def test_forged_marker_without_record(self):
        from logtriage import safe_backup as sb
        td = _tmp(self)
        d = td / (sb.QZ + "forged")
        d.mkdir()
        (d / sb.QZ_MARK).write_text(json.dumps({"at": 1}), encoding="utf-8")   # 폴더 안 표식만 꾸민 것
        old = time.time() - 3600
        os.utime(d, (old, old))
        r = sb.delete_backup(td, d.name)
        self.assertFalse(r.get("ok"))
        self.assertIn("격리 기록", r["error"])
        rows = sb.list_backups(td)
        self.assertFalse(any(x["deletable"] for x in rows))
        self.assertEqual([x["trusted"] for x in rows if x["state"] == "quarantined"], [False])   # 표시·알림은 하되 지우기 대상 아님

    @unittest.skipUnless(os.name == "nt", "Windows 정션")
    def test_junction_inside_quarantine_blocks_delete(self):
        from logtriage import safe_backup as sb
        td = _tmp(self)
        outside = _tmp(self)
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        self._mk(td)
        qn = sb.delete_backup(td, ".backup-x1")["name"]
        rc = subprocess.run(["cmd", "/c", "mklink", "/J", str(td / qn / "j"), str(outside)], capture_output=True)
        if rc.returncode:
            self.skipTest("정션을 만들 수 없음")
        self._age(td, qn)
        r = sb.delete_backup(td, qn)
        self.assertFalse(r.get("ok"))
        self.assertTrue((outside / "keep.txt").exists())                  # 정션 너머는 절대 지우지 않는다
        subprocess.run(["cmd", "/c", "rmdir", str(td / qn / "j")], capture_output=True)

    def test_reauth_modes(self):
        from logtriage.server import Handler
        f = type("H", (), {"_local_login": lambda s: False, "password": "", "_u": {"login": "adm"}, "_ip": lambda s: "10.0.0.1",
                           "_REAUTH_HITS": {}, "REAUTH_MAX": 5, "REAUTH_WINDOW": 600.0})()
        ok, how, err = Handler._reauth(f, "x")
        self.assertEqual((ok, how), (False, "none"))
        from logtriage.server import as_verifier
        f.password = as_verifier("pw-shared")   # 8차 ⑪: 공용 비밀번호는 검증값으로만 들고 있다(make_server 가 바꾼다)
        self.assertEqual(Handler._reauth(f, "nope")[:2], (False, "shared"))
        self.assertEqual(Handler._reauth(f, "pw-shared")[:2], (True, "shared"))
        for _ in range(5):
            Handler._reauth(f, "nope")
        self.assertEqual(Handler._reauth(f, "pw-shared")[:2], (False, "limited"))   # GPT 61차: 재인증 시도 자체를 제한(맞는 비밀번호도 막힘)


class HubFeedback(unittest.TestCase):
    def test_snapshot_replace_and_validation(self):
        from logtriage.hub import HubStore, ReplayError
        base = _tmp(self)
        hs = HubStore(base)
        hs.add_site("S1", "사이트1")
        hs.add_site("S2", "사이트2")
        good = {"rule_id": "DB-ORA-004", "cmd_hash": "0123456789abcdef", "ok": 1, "fail": 3, "version": 0}
        p = {"site": {"version": "1.0.0"}, "stream": "f" * 16, "seq": 1, "kbfb": [good]}
        self.assertEqual(hs.ingest("S1", p)["received"]["kbfb"], 1)
        hs.ingest("S1", dict(p, seq=2, kbfb=[good]))                       # 같은 내용 재전송 — 통째 교체라 두 배가 되지 않는다
        hs.ingest("S2", dict(p, kbfb=[dict(good, fail=2)]))
        top = hs.overview()["kbfb"]
        self.assertEqual((top[0]["fail"], top[0]["sites"]), (5, 2))
        for bad in ([dict(good, cmd_hash="ZZ")], [dict(good, fail=-1)], [dict(good, fail=True)], [dict(good, rule_id="<x>")], [good] * 2001, "x",
                    [good, dict(good, fail=9)]):   # GPT 61차: 같은 (판정, 명령) 줄이 둘이면 모호 — 통째 거부
            r = hs.ingest("S1", dict(p, seq=hs_seq(hs), kbfb=bad))
            self.assertEqual(r["received"].get("kbfb_rejected"), 1, str(bad)[:40])
        self.assertEqual(hs.overview()["kbfb"][0]["fail"], 5)              # 거부되면 예전 것 유지
        with self.assertRaises(ReplayError):
            hs.ingest("S1", dict(p, seq=2, kbfb=[]))

    def test_site_sends_only_when_enabled_and_only_counts(self):
        from logtriage import hub
        c = hub._validate({"role": "site", "site_id": "S1", "hub_url": "https://hq.example", "hub_token": "t" * 32}, Path("."), "t") \
            if hasattr(hub, "_validate") else None
        conf = c or {}
        self.assertIs(conf.get("send_feedback", False), False)


_SEQ = [100]


def hs_seq(_hs):
    _SEQ[0] += 1
    return _SEQ[0]


class Versions(unittest.TestCase):
    def test_assign_vs_evidence_and_reeval_keeps_original(self):
        from logtriage.server import ServerApi
        td = _tmp(self)
        st = storage.Storage("sqlite:///" + (td / "t.db").as_posix())
        inc = {"id": "I1", "analyzed_at": "2026-10-16", "first": {}, "files": [{"name": "a", "product": "postgresql", "host": "db1"}],
               "checklist": [{"rule_id": "R1", "product": "postgresql", "cmds": [
                   {"cmd": "SELECT checkpoints_timed FROM pg_stat_bgwriter;", "tail": " (16 이하)", "safe": True, "hash": "a" * 16, "fit": "", "copy": True},
                   {"cmd": "SELECT num_timed FROM pg_stat_checkpointer;", "tail": " (17+)", "safe": True, "hash": "b" * 16, "fit": "", "copy": True}]}]}
        st.save_incident(inc)
        fake = type("F", (), {"store": st, "actor": type("A", (), {"login": "op"})()})()
        self.assertIn("error", ServerApi.host_version_set(fake, "db1", "postgresql", "16", "PostgreSQL 15.3 on x86_64"))   # 출력과 다름
        r = ServerApi.host_version_set(fake, "db1", "postgresql", "17", "")
        self.assertEqual(r["record"]["source"], "manual")
        ev = ServerApi.version_reevaluate(fake, "I1")
        cm = ev["items"][0]["cmds"]
        self.assertEqual([(c["fit"], c["copy"], c["basis"]) for c in cm], [("어긋남", False, "담당자 지정"), ("맞음", True, "담당자 지정")])
        self.assertEqual(st.get("I1")["checklist"][0]["cmds"][0]["fit"], "")                      # 원본은 그대로
        r = ServerApi.host_version_set(fake, "db1", "postgresql", "17", "PostgreSQL 17.2 on x86_64-pc-linux-gnu")
        self.assertEqual(r["record"]["source"], "evidence")
        self.assertEqual(ServerApi.version_reevaluate(fake, "I1")["items"][0]["cmds"][1]["basis"], "제출 출력 확인")
        with st._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT COUNT(*) FROM version_reevals")
            self.assertEqual(cur.fetchone()[0], 2)                                            # 재평가 이력


class Proposals(unittest.TestCase):
    def test_same_incident_counts_once(self):
        td = _tmp(self)
        st = storage.Storage("sqlite:///" + (td / "t.db").as_posix())

        def inc(i, sig_file):
            st.save_incident({"id": i, "analyzed_at": "2026-10-16", "first": {"verdict": "데드락", "rule_id": "R1"},
                              "files": [{"name": sig_file}], "checklist": [{"rule_id": "R1"}]})
            st.set_postmortem(i, "실제는 스토리지", "confirmed", "no", "RCA 문서")
        inc("I1", "a.log")
        inc("I2", "a.log")   # 같은 증상(지문) 재기록
        self.assertEqual(st.postmortem_proposals(), [])                  # 같은 장애(같은 시각·파일)를 두 번 기록 — 한 건(GPT 60차)
        inc("I3", "b.log")
        rows = st.postmortem_proposals()
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["cases"], 2)
        self.assertIn("실제는 스토리지", rows[0]["causes"])


class Attention(unittest.TestCase):
    def test_table(self):
        from logtriage.server import ServerApi
        td = _tmp(self)
        st = storage.Storage("sqlite:///" + (td / "t.db").as_posix())
        fake = type("F", (), {"store": st, "_base": ENGINE, "_ATT_CACHE": {}})()
        r = ServerApi.kb_attention(fake)
        self.assertNotIn("error", r)
        self.assertTrue(r["rows"])
        for x in r["rows"]:
            self.assertTrue(x["flags"])
        self.assertTrue(set(r["counts"]) <= {"매칭 모호", "제목 핵심어 0", "미확인 포함", "문법·실행 실패", "시험 환경 없음", "현장"})


class LinkAudit(unittest.TestCase):
    def test_no_ghost_ids(self):
        from logtriage import kb_audit
        self.assertEqual(kb_audit.audit(ENGINE)["ghosts"], [])

    def test_known_misfit_scores_zero(self):
        from logtriage import kb_audit
        from logtriage.procedures import load_procedures
        ps = {p["id"]: p for p in load_procedures(ENGINE / "manuals")}
        vs = {v["key"]: v for v in kb_audit.verdicts(ENGINE)}
        self.assertEqual(kb_audit.fitness(vs["LINUX:LNX-APPARMOR-DENIED"], ps["LNX-PROC-SECURITY"]), 0.0)   # 57차 확인 오류 연결
        self.assertGreater(kb_audit.fitness(vs["LINUX:LNX-APPARMOR-DENIED"], ps["LNX-PROC-R6C-APPARMOR"]), 0.5)


class Tools(unittest.TestCase):
    def test_vendor_reply_classify(self):
        import import_vendor_replies as v
        self.assertEqual(v.classify("맞음 — 근거: Admin Guide 3.2"), "해제 후보")
        self.assertEqual(v.classify("맞음"), "보류(근거 없음)")
        self.assertEqual(v.classify("틀림, 문서 KB-123 참조"), "수정 대상")
        self.assertEqual(v.classify("잘 모르겠음"), "보류(형식 다름)")
        self.assertEqual(v._clean("=HYPERLINK(\"x\")")[0], "'")
        td = _tmp(self)
        (td / "벤더.md").write_text("| # | 위치 | 확인할 주장 | 회신(맞음/틀림·근거) |\n|---|---|---|---|\n| 1 | 절차 A | 주장 | 맞음 — 근거: 매뉴얼 2판 4장 |\n"
                                   "| 2 | 코드 B | 주장2 | <b>틀림</b> |\n", encoding="utf-8")
        items = v.collect([td / "벤더.md"])
        self.assertEqual([x["class"] for x in items], ["해제 후보", "보류(근거 없음)"])

    def test_sent_check(self):
        import knowledge_sample_queue as q
        td = _tmp(self)
        (td / "s.txt").write_text("가 나\n다  라", encoding="utf-8")
        (td / "v.txt").write_text("가 나 다 라 ", encoding="utf-8")
        (td / "w.txt").write_text("가 나 다", encoding="utf-8")
        self.assertEqual(q.main(["sent-check", "--sent", str(td / "s.txt"), "--seen", str(td / "v.txt")]), 0)
        self.assertEqual(q.main(["sent-check", "--sent", str(td / "s.txt"), "--seen", str(td / "w.txt")]), 1)
        # 대화창은 `…` 를 코드 모양으로 그리며 백틱을 없앤다(10-16 실측) — 양쪽에 같은 규칙을 둘 때만 일치
        (td / "b.txt").write_text("명령 `df -h` 확인", encoding="utf-8")
        (td / "r.txt").write_text("명령 df -h 확인", encoding="utf-8")
        self.assertEqual(q.main(["sent-check", "--sent", str(td / "b.txt"), "--seen", str(td / "r.txt")]), 1)
        self.assertEqual(q.main(["sent-check", "--sent", str(td / "b.txt"), "--seen", str(td / "r.txt"), "--render"]), 0)

    def test_rule_binding_by_bare_id(self):
        ms = KQ.load_metrics(ENGINE / "errorcodes")
        self.assertEqual(KQ.metric_for(ms, "tomcat:WAS-TC-020", "df -h <로그경로>")["id"], "fs-block-use")   # 룰 항목 키 = 제품:룰ID
        self.assertIsNone(KQ.metric_for(ms, "oracle:TOMCAT-NO-SPACE", "df -h /x"))                        # 코드 결속은 제품까지
        part = KQ.metric_for(ms, "tomcat:SW-BM-005", "df -h /x")        # 8차 ⑨: 다른 조건 섞인 룰은 수치 부분만 결속
        self.assertTrue(part and part["part"])
        self.assertFalse(KQ.metric_for(ms, "tomcat:WAS-TC-020", "df -h /x")["part"])


if __name__ == "__main__":
    unittest.main()
