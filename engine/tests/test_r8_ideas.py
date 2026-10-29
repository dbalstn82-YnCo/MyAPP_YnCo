"""2026-10-19 8차 아이디어 12건 — 재검증 대기열·연결 승인·점검 격리·지식 출시·원문 반입함·현장 실행 결과·판 다름 신호·
다중 인스턴스 판·혼합 기준 지표 분할·장애 묶음·공용 비밀번호 KDF·위험 가중 표본."""
import json
import os
import shutil
import sqlite3
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

VERIFY_TOOLS = ENGINE.parent / "검증도구"


def _tmp(test):
    td = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, td, True)
    return td


def _kbase(test) -> Path:
    """지식(manuals·errorcodes·rules)만 복사한 자료 폴더 — 결정 기록이 엔진 폴더에 쓰이지 않게."""
    td = _tmp(test)
    for d in ("manuals", "errorcodes", "rules"):
        shutil.copytree(ENGINE / d, td / d)
    return td


def _st(test):
    td = _tmp(test)
    return storage.Storage("sqlite:///" + (td / "t.db").as_posix())


class ReverifyQueue(unittest.TestCase):
    """① 고침 표시 뒤 다시 보지 않은 항목 — 다음 회차 이름, 원문 그대로면 경고·보내지 않음."""

    def setUp(self):
        import knowledge_sample_queue as q
        self.q = q
        self.old = q.QDIR
        q.QDIR = _tmp(self)
        self.addCleanup(setattr, q, "QDIR", self.old)
        by = {x["key"]: x for x in q.entries()}
        from logtriage.procedures import load_procedures
        procs = load_procedures(ENGINE / "manuals")
        self.k1, self.k2, self.k3 = sorted(by)[:3]
        self.cur1 = q._current_item(self.k1, by, procs)

    def _rows(self, rows):
        (self.q.QDIR / "결과.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")

    def test_next_round(self):
        self.assertEqual([self.q.next_round(x) for x in ("R", "R-re", "R-re2", "R-re9")], ["R-re", "R-re2", "R-re3", "R-re10"])

    def test_pending_states(self):
        self._rows([{"round": "R", "key": self.k1, "verdict": "부분", "fixed": True, "sent_sha": self.cur1["sha"]},   # 원문 그대로
                    {"round": "R", "key": self.k2, "verdict": "오류", "fixed": True, "sent_sha": "0" * 64},           # 바뀜
                    {"round": "R", "key": self.k3, "verdict": "부분", "fixed": True, "sent_sha": "1" * 64},
                    {"round": "R-re", "key": self.k3, "verdict": "정확", "fixed": False}])                           # 다음 회차에서 봄
        st = {x["key"]: x["state"] for x in self.q.pending_items()}
        self.assertTrue(st[self.k1].startswith("원문 그대로"))
        self.assertTrue(st[self.k2].startswith("바뀜"))
        self.assertNotIn(self.k3, st)
        self.assertEqual(self.q.main(["pending"]), 1)                    # 원문 그대로가 있으면 1
        self.q.main(["reverify"])
        sent = json.loads((self.q.QDIR / "재검증-R-re.json").read_text(encoding="utf-8"))
        self.assertEqual([x["key"] for x in sent["items"]], [self.k2])   # 원문 그대로는 보내지 않는다


class WeightedSample(unittest.TestCase):
    """⑫ 무작위 층을 먼저 모집단에서, 가중 층은 위험도 가중 — 결과 줄에 층이 남고 장부가 층별로 적는다."""

    def test_strata(self):
        import knowledge_sample_queue as q
        old = q.QDIR
        q.QDIR = _tmp(self)
        self.addCleanup(setattr, q, "QDIR", old)
        q.main(["make", "--n", "10", "--seed", "t8"])
        d = json.loads((q.QDIR / "대기열.json").read_text(encoding="utf-8"))
        sts = [x["stratum"] for x in d["items"]]
        self.assertGreaterEqual(sts.count("무작위"), 3)
        self.assertIn("가중", sts)
        self.assertTrue((q.QDIR / f"대기열-{d['round']}.json").exists())
        k = next(x["key"] for x in d["items"] if x["stratum"] == "무작위")
        q.main(["record", "--round", d["round"], "--key", k, "--verdict", "정확", "--reviewer", "GPT", "--approver", "Claude"])
        row = json.loads((q.QDIR / "결과.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(row["stratum"], "무작위")
        import build_ledger as bl
        oq = bl.QDIR
        bl.QDIR = q.QDIR
        self.addCleanup(setattr, bl, "QDIR", oq)
        self.assertIn("무작위(미검증 집합) 1/0/0", bl.sample_result())

    def test_danger_kinds(self):
        from logtriage.kb_audit import danger_kinds_text
        self.assertEqual(danger_kinds_text("SQL> alter system kill session '1,2';"), ["세션·프로세스 종료", "설정·권한 변경"])
        self.assertEqual(danger_kinds_text("df -h /tmp"), [])
        self.assertEqual(danger_kinds_text("kill -9 1; kill -9 2"), ["세션·프로세스 종료"])   # 종류 수 — 같은 동작은 한 번


class LinkReview(unittest.TestCase):
    """② 검토 ≠ 승인 — 반려는 대기열로, 한 건 승인은 상세를 연 뒤·개정 번호가 맞을 때만,
    묶음은 서버가 고른 표본 3건을 연 뒤에만이고 결과는 '묶음 승인'(개별 검토 아님), 위험·불일치 연결은 묶음 불가(GPT 64차 P0)."""

    def setUp(self):
        from logtriage import link_review as LR
        self.LR = LR
        self.base = _kbase(self)
        self.its = LR.items(self.base)
        LR._SAMPLES.clear()
        LR._OPENED.clear()
        self.easy = [x for x in self.its if not x["individual"]]
        self.hard = [x for x in self.its if x["individual"]]

    def test_individual_reasons_exist(self):
        self.assertTrue(self.easy and self.hard)
        self.assertTrue(any("2차 위험 명령" in r for x in self.hard for r in x["individual"]))

    def test_product_mismatch_cannot_be_approved(self):
        """GPT 65차: 판정 제품과 절차 제품이 다른 연결은 승인 금지(반려·지식 수정만)."""
        bad = [x for x in self.its if any(r.startswith("판정 제품과 절차 제품이 다름") for r in x["individual"])]
        self.assertTrue(bad)
        x = bad[0]
        self.LR.detail(self.base, x["procedure"], x["id"], "adm")
        with self.assertRaises(ValueError):
            self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm", rev=0)
        self.LR.decide(self.base, x["procedure"], x["id"], "반려", "adm", "제품이 달라 진단 대상이 아님", rev=0)

    def test_reject_returns_to_queue_and_rev(self):
        from logtriage import kb_audit
        x = self.its[0]
        with self.assertRaises(ValueError):
            self.LR.decide(self.base, x["procedure"], x["id"], "반려", "adm", "짧음", rev=0)   # 사유 5자 미만
        with self.assertRaises(ValueError):
            self.LR.decide(self.base, x["procedure"], x["id"], "반려", "adm", "1차가 이 증상을 진단하지 않음")   # rev 없음
        before = len(kb_audit.audit(self.base)["low_fit"])
        self.LR.decide(self.base, x["procedure"], x["id"], "반려", "adm", "1차가 이 증상을 진단하지 않음", rev=0)
        self.assertIn((x["procedure"], x["id"]), self.LR.rejected(self.base))
        self.assertGreater(len(kb_audit.audit(self.base)["low_fit"]), before)   # 반려 → 다시 적합성 대기열(출시 멈춤)
        with self.assertRaises(ValueError):
            self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm2", rev=1)   # 상세를 안 열었다
        self.LR.detail(self.base, x["procedure"], x["id"], "adm2")
        with self.assertRaises(ValueError) as cm:
            self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm2", rev=0)   # 그사이 결정됨(지금 rev 1)
        self.assertIn("그사이", str(cm.exception))
        self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm2", rev=1, answers={"symptom": "예", "version": "예", "rollback": "예"})   # 9차 ①: 근거 세 질문
        self.assertEqual(self.LR.counts(self.base)["승인"], 1)
        self.assertEqual(len((self.base / self.LR.LOCAL_FILE).read_text(encoding="utf-8").splitlines()), 2)   # 이력은 남는다

    def test_batch_is_not_approval(self):
        pick = [{"procedure": x["procedure"], "id": x["id"]} for x in self.easy[:6]]
        mixed = pick[:5] + [{"procedure": self.hard[0]["procedure"], "id": self.hard[0]["id"]}]
        with self.assertRaises(ValueError):
            self.LR.sample(self.base, mixed, "adm")                       # 한 건씩 볼 연결이 섞이면 묶음 불가
        with self.assertRaises(ValueError):
            self.LR.batch(self.base, pick, "adm")                         # 표본 없이
        with self.assertRaises(ValueError):
            self.LR.sample(self.base, pick[:3], "adm")                    # 3건 이하는 한 건씩
        s = self.LR.sample(self.base, pick, "adm")["sample"]
        self.assertEqual(len(s), 3)
        self.LR.detail(self.base, s[0]["procedure"], s[0]["id"], "adm")
        with self.assertRaises(ValueError):
            self.LR.batch(self.base, pick, "adm")                         # 2건 안 열었다
        for x in s[1:]:
            self.LR.detail(self.base, x["procedure"], x["id"], "other")    # 다른 사람이 연 것은 세지 않는다
        with self.assertRaises(ValueError):
            self.LR.batch(self.base, pick, "adm")
        for x in s[1:]:
            self.LR.detail(self.base, x["procedure"], x["id"], "adm")
        with self.assertRaises(ValueError):
            self.LR.batch(self.base, pick[:5], "adm")                     # 묶음이 바뀌면 표본도 다시
        self.LR.sample(self.base, pick, "adm")
        for k in self.LR._SAMPLES["adm"]["sample"]:
            self.LR.detail(self.base, *k.split("|", 1), "adm")
        self.assertEqual(self.LR.batch(self.base, pick, "adm")["approved"], 6)
        c = self.LR.counts(self.base)
        self.assertEqual((c["묶음 승인"], c["승인"]), (6, 0))             # '승인'으로 세지 않는다
        rows = [json.loads(l) for l in (self.base / self.LR.LOCAL_FILE).read_text(encoding="utf-8").splitlines()]
        self.assertTrue(all(r["decision"] == "묶음 승인" and "개별 검토 아님" in r["note"] for r in rows))
        with self.assertRaises(ValueError):
            self.LR.decide(self.base, pick[0]["procedure"], pick[0]["id"], "묶음 승인", "adm", rev=1)   # 한 건 결정으로 묶음 승인을 못 만든다

    def test_import_into_engine_file(self):
        import knowledge_link_audit as kla
        x = self.its[0]
        self.LR.detail(self.base, x["procedure"], x["id"], "adm")
        self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm", rev=0, answers={"symptom": "예", "version": "예", "rollback": "예"})
        old = kla.ENGINE
        kla.ENGINE = self.base
        self.addCleanup(setattr, kla, "ENGINE", old)
        self.assertEqual(kla.import_approvals(self.base / self.LR.LOCAL_FILE), 1)
        self.assertEqual(kla.import_approvals(self.base / self.LR.LOCAL_FILE), 0)   # 두 번 들여와도 한 번
        self.assertEqual(self.LR.decisions(self.base)[f"{x['procedure']}|{x['id']}"]["rev"], 1)   # 병합본·이력 겹침은 한 번
        (self.base / self.LR.LOCAL_FILE).unlink()
        self.assertEqual(self.LR.counts(self.base)["승인"], 1)            # 엔진 병합본만으로도 같은 결정


@unittest.skipUnless((VERIFY_TOOLS / "exe_guard.py").exists(), "검증도구 폴더 없음")
class ExeGuard(unittest.TestCase):
    """③ 설치 폴더 점검 — 점검이 바꾼 자료를 되돌리고 전후 해시가 같아야 통과, 실행 파일은 건드리지 않는다."""

    def test_refuse_installed_and_clone(self):
        """GPT 64차 P0: 설치 폴더 점검·되돌리기를 없앴다 — 설치 폴더는 거절, 자료는 빌드 폴더로 일관된 복제(SQLite 는 backup API)."""
        sys.path.insert(0, str(VERIFY_TOOLS))
        import exe_guard as g
        src, build = _tmp(self), _tmp(self)
        old = g.INSTALLED
        g.INSTALLED = src.resolve()
        self.addCleanup(setattr, g, "INSTALLED", old)
        with self.assertRaises(SystemExit) as cm:
            g.protect(src)
        self.assertEqual(cm.exception.code, 2)
        (src / "data").mkdir()
        c = sqlite3.connect(src / "data" / "logtriage.db")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("CREATE TABLE t(x)")
        c.execute("INSERT INTO t VALUES(1)")
        c.commit()
        c.execute("PRAGMA wal_autocheckpoint=0")
        c.execute("INSERT INTO t VALUES(2)")   # WAL 에만 있는 줄
        c.commit()
        (src / "LogTriage.exe").write_bytes(b"MZsrc")
        (src / "conf.json").write_text("{}", encoding="utf-8")
        (build / "LogTriage.exe").write_bytes(b"MZbuild")
        (build / "data").mkdir()
        (build / "data" / "logtriage.db-wal").write_bytes(b"stale")
        fp = g.fingerprint(src)
        r = g.clone_data(build, src)
        self.assertEqual(g.fingerprint(src), fp)                        # 원본은 그대로(복제는 읽기 전용)
        c.close()
        self.assertEqual(r["sqlite"], 1)
        self.assertEqual((build / "LogTriage.exe").read_bytes(), b"MZbuild")   # 실행 파일은 복사하지 않는다
        self.assertFalse((build / "data" / "logtriage.db-wal").exists())
        d = sqlite3.connect(build / "data" / "logtriage.db")
        self.assertEqual([x[0] for x in d.execute("SELECT x FROM t ORDER BY x")], [1, 2])   # WAL 의 줄까지 한 시점으로
        d.close()
        self.assertTrue((build / "conf.json").exists())


class KnowledgeRelease(unittest.TestCase):
    """④ 한 단계라도 실패하면 배포 폴더는 손대지 않는다 · 넘겨받는 시험 결과는 엔진 지문이 같을 때만."""

    def test_stop_before_copy(self):
        import knowledge_release as kr
        dist = _tmp(self)
        (dist / "rules").mkdir()
        calls = []
        orig = (kr.step_exec, kr.step_audit, kr.step_tests, kr.step_dist)
        self.addCleanup(lambda: [setattr(kr, n, f) for n, f in zip(("step_exec", "step_audit", "step_tests", "step_dist"), orig)])
        kr.step_exec = lambda: (calls.append("exec"), (True, ""))[1]
        kr.step_audit = lambda: (calls.append("audit"), (False, "유령 1"))[1]
        kr.step_tests = lambda p: (calls.append("tests"), (True, ""))[1]
        kr.step_dist = lambda d, ph: (calls.append(ph), (True, ""))[1]
        self.assertEqual(kr.main(["--note", "t", "--dist", str(dist)]), 1)
        self.assertEqual(calls, ["exec", "audit"])
        self.assertEqual(list((dist / "rules").iterdir()), [])

    def test_copy_only_knowledge(self):
        import knowledge_release as kr
        dist = _tmp(self)
        n = kr.copy_knowledge(dist)
        self.assertGreater(n, 100)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        self.assertEqual(kr.copy_knowledge(dist), 0)                     # 같으면 바꾸지 않는다
        self.assertFalse(any(p.suffix.lower() in (".py", ".exe") for p in dist.rglob("*")))

    def test_swap_is_whole_and_recoverable(self):
        """GPT 64차 P0-④: 신구 지식이 섞이지 않는다 — 전환 도중 멈춘 흔적이 있으면 구판 전체로, 지식 아닌 파일은 잃지 않는다."""
        import knowledge_release as kr
        dist = _tmp(self)
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        (dist / "manuals" / "그림.png").write_bytes(b"png")          # 배포 폴더에만 있는 지식 아닌 파일
        marker = dist / "rules" / "os" / "linux.yaml"
        marker.write_text(marker.read_text(encoding="utf-8") + "\n# 구판 표식\n", encoding="utf-8")
        self.assertEqual(kr.copy_knowledge(dist), 1)
        self.assertTrue((dist / kr.OLD / "rules").is_dir())              # 사후 검사 전까지 구판 보관
        self.assertNotIn("# 구판 표식", marker.read_text(encoding="utf-8"))
        self.assertEqual((dist / "manuals" / "그림.png").read_bytes(), b"png")
        self.assertIn("되돌림", kr.recover(dist))                       # 사후 검사 실패·중간 멈춤 → 구판 전체로
        self.assertIn("# 구판 표식", marker.read_text(encoding="utf-8"))
        self.assertFalse((dist / kr.OLD).exists())
        (dist / kr.NEW).mkdir()
        with self.assertRaises(RuntimeError):
            kr.copy_knowledge(dist)                                      # 남은 준비 폴더가 있으면 먼저 recover
        kr.recover(dist)
        orig = kr.ENGINE
        bad = _tmp(self)
        for d in kr.KNOW:
            shutil.copytree(orig / d, bad / d)
        kr.ENGINE = bad
        self.addCleanup(setattr, kr, "ENGINE", orig)
        real = shutil.copyfile

        def flaky(a, b, *x, **k):
            real(a, b, *x, **k)
            if str(a).endswith("_metrics.yaml"):
                Path(b).write_text("깨진 사본", encoding="utf-8")       # 준비본이 엔진과 다르면 전환하지 않는다
        shutil.copyfile = flaky
        self.addCleanup(setattr, shutil, "copyfile", real)
        with self.assertRaises(RuntimeError):
            kr.copy_knowledge(dist)
        self.assertFalse((dist / kr.NEW).exists())
        self.assertIn("# 구판 표식", marker.read_text(encoding="utf-8"))   # 배포 폴더는 그대로

    def test_crash_points_and_app_refuses(self):
        """GPT 65차: 첫·둘째 rename 직후 멈춤, 복구 도중 다시 멈춤 — 어느 경우에도 recover 가 구판 전체로 되돌리고, 그 전에는 앱이 뜨지 않는다."""
        import knowledge_release as kr
        from logtriage import server as S
        dist = _tmp(self)
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        orig = {d: kr._tree(dist / d) for d in kr.KNOW}
        for stop_after in (1, 2, 3):                                   # rename 몇 번 뒤 멈췄나
            (dist / kr.NEW).mkdir()
            (dist / kr.OLD).mkdir()
            for d in kr.KNOW:
                shutil.copytree(dist / d, dist / kr.NEW / d)
                (dist / kr.NEW / d / "새판.yaml").write_text("x: 1\n", encoding="utf-8")
            done = 0
            for d in kr.KNOW:
                if done >= stop_after:
                    break
                os.replace(dist / d, dist / kr.OLD / d)                  # 구판 치우기
                done += 1
                if done >= stop_after:
                    break
                os.replace(dist / kr.NEW / d, dist / d)                  # 새판 넣기
                done += 1
            self.assertIn("전환 도중", S.release_leftover(dist))
            with self.assertRaises(SystemExit):
                S.make_server("127.0.0.1", 0, dist, None)                # 혼합 지식으로 뜨지 않는다
            # 복구 도중 다시 멈춤: 첫 폴더만 되돌리고 멈춘 것처럼
            first = next((d for d in kr.KNOW if (dist / kr.OLD / d).is_dir()), None)
            if first and stop_after == 3:
                if (dist / first).exists():
                    shutil.rmtree(dist / first)
                os.replace(dist / kr.OLD / first, dist / first)
            kr.recover(dist)
            self.assertEqual(S.release_leftover(dist), "")
            self.assertEqual({d: kr._tree(dist / d) for d in kr.KNOW}, orig, f"rename {stop_after}번 뒤 멈춤")

    def test_tests_from_fingerprint(self):
        import build_ledger as bl
        p = _tmp(self) / "r.json"
        p.write_text(json.dumps({"label": "통과 9건", "ok": True, "ts": time.time(), "engine_fp": bl.engine_fp()}), encoding="utf-8")
        self.assertEqual(bl.tests_from(p), ("통과 9건", True))
        p.write_text(json.dumps({"label": "통과 9건", "ok": True, "ts": time.time(), "engine_fp": "0" * 64}), encoding="utf-8")
        self.assertFalse(bl.tests_from(p)[1])
        p.write_text(json.dumps({"label": "통과 9건", "ok": True, "ts": time.time() - 9000, "engine_fp": bl.engine_fp()}), encoding="utf-8")
        self.assertFalse(bl.tests_from(p)[1])


class VendorDocs(unittest.TestCase):
    """⑤ 반입 문서에서 확인 위치 후보만 — 맞다고 판정하지 않고, confirm 은 그 쪽에 발췌가 있을 때만."""

    def test_candidates_and_confirm(self):
        import vendor_doc_match as vd
        docs = _tmp(self)
        (docs / "tibero_ref.txt").write_text("\n" * 70 + "V$LOCK 의 칼럼: TYPE ID1 ID2 SESS_ID LMODE REQUESTED\nWLOCK_DD_OBJ 는 DDL 객체 잠금\n",
                                             encoding="utf-8")
        (docs / "skip.bin").write_bytes(b"\0")
        idx, skipped = vd.index(docs)
        keys, hits = vd.candidates("미검증 — Tibero V$LOCK/GV$LOCK 컬럼 SESS_ID·LMODE 의미, WLOCK_DD_OBJ", idx)
        self.assertIn("v$lock", keys)
        self.assertEqual((hits[0]["doc"], hits[0]["page"]), ("tibero_ref.txt", 2))
        self.assertEqual(vd.candidates("식별어 없는 주장", idx), ([], []))
        ev = _tmp(self) / "_evidence_local.yaml"
        old = vd.EVID
        vd.EVID = ev
        self.addCleanup(setattr, vd, "EVID", old)
        base = ["confirm", "--claim", "tibero:TBR-12033", "--doc", "tibero_ref.txt", "--verdict", "맞음", "--by", "DBA", "--docs", str(docs)]
        self.assertEqual(vd.main(base + ["--page", "1", "--excerpt", "WLOCK_DD_OBJ 는 DDL 객체 잠금"]), 1)   # 그 쪽에 없음
        self.assertEqual(vd.main(base + ["--page", "2", "--excerpt", "WLOCK_DD_OBJ 는 DDL 객체 잠금"]), 0)
        ver = {"evidence": {}, "evidence_local": {}}
        import yaml
        for x in yaml.safe_load(ev.read_text(encoding="utf-8"))["evidence"]:
            ver["evidence_local"][x["claim"]] = x
        self.assertEqual(KQ.axes("TIBERO:TBR-12033", ver=ver)["source"], "반입 원문 대조")
        ver["evidence_local"]["TIBERO:TBR-12033"]["verdict"] = "틀림"
        self.assertTrue(KQ.axes("TIBERO:TBR-12033", ver=ver)["source"].startswith("반입 원문과 다름"))


class FieldExec(unittest.TestCase):
    """⑥ 성공·오류·코드·머리글 이름만(머리글은 이 PC 에만) — 값·여러 줄은 거절, 허브는 머리글 없이·하나라도 틀리면 통째 거부, 엔진은 '현장 보고'로·멱등."""

    def setUp(self):
        self.st = _st(self)
        self.st.save_incident({"id": "I1", "analyzed_at": "2026-10-19", "files": [{"name": "a", "product": "tibero", "host": "db1"}],
                               "checklist": [{"rule_id": "R1", "code_key": "TIBERO:TBR-12033", "product": "tibero", "cmds": [
                                   {"cmd": "select * from v$lock;", "safe": True, "hash": "a" * 16},
                                   {"cmd": "alter system kill session (1,2);", "safe": False, "hash": "b" * 16}]}]})
        from logtriage.server import ServerApi
        self.f = type("F", (), {"store": self.st, "actor": type("A", (), {"login": "op"})()})()
        self.S = ServerApi

    def test_server_validation(self):
        S, f = self.S, self.f
        self.assertIn("error", S.exec_report(f, "I1", "R1", 1, "성공", "", "SID"))                 # 위험 명령은 받지 않음
        self.assertIn("error", S.exec_report(f, "I1", "R1", 0, "성공", "", "TYPE ID1\n 12 34"))     # 값 줄
        self.assertIn("error", S.exec_report(f, "I1", "R1", 0, "성공", "", "TYPE 12"))              # 숫자 = 값
        self.assertIn("error", S.exec_report(f, "I1", "R1", 0, "오류", "ORA-00942: table does not exist", ""))   # 문장
        r = S.exec_report(f, "I1", "R1", 0, "성공", "", "TYPE | ID1 | ID2 | SESS_ID\n")
        self.assertEqual(r["summary"]["a" * 16]["headers"], {"TYPE ID1 ID2 SESS_ID": 1})
        self.assertTrue(S.exec_report(f, "I1", "R1", 0, "성공", "", "Filesystem Size Used Avail Use% Mounted on").get("ok"))   # 실제 df 머리글(%) — 포장본 점검(10-19)이 잡은 결함
        for bad in ("TYPE %%%%", "TYPE _%", "TYPE ___", "TYPE A%%%"):                                                   # GPT 66차: 이름 아닌 낱말
            self.assertIn("error", S.exec_report(f, "I1", "R1", 0, "성공", "", bad), bad)
        S.exec_report(f, "I1", "R1", 0, "오류", "TBR-17004", "")                                   # 같은 사람·건·명령 — 마지막 한 줄
        s = self.st.exec_report_summary()["TIBERO:TBR-12033"]["a" * 16]
        self.assertEqual((s["ok"], s["error"], s["codes"]), (0, 1, {"TBR-17004": 1}))

    def test_value_like_headers(self):
        """GPT 64차 P0: 글자 제한은 유출 방지가 아니다 — 숫자 4개 이상 이어진 이름은 값일 수 있어 거절, 머리글은 이 PC 에만."""
        self.assertIn("error", self.S.exec_report(self.f, "I1", "R1", 0, "성공", "", "TYPE ACCT_20261019"))
        self.assertIn("error", self.S.exec_report(self.f, "I1", "R1", 0, "성공", "", "TYPE " + "A" * 42))

    def test_hub_rows(self):
        from logtriage.hub import _xrep_rows
        g = {"vkey": "TIBERO:TBR-12033", "cmd_hash": "a" * 16, "ok": 2, "error": 1, "codes": {"TBR-17004": 1}}
        self.assertEqual(len(_xrep_rows("S1", [g], 0.0)), 1)
        for bad in ([dict(g, headers="TYPE ID1")], [dict(g, extra=1)],          # 머리글·모르는 칸은 허브가 받지 않는다(GPT 64차 P0)
                    [dict(g, codes={"a b": 1})], [dict(g, ok=True)], [g, g], [dict(g, cmd_hash="x")],
                    [dict(g, codes={str(i): 1 for i in range(6)})], "x"):
            self.assertIsNone(_xrep_rows("S1", bad, 0.0), str(bad)[:50])

    def test_site_payload_has_no_headers(self):
        from logtriage import hub
        self.S.exec_report(self.f, "I1", "R1", 0, "성공", "", "TYPE ID1 ID2")
        rows = hub.xrep_payload(self.st)
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]), {"vkey", "cmd_hash", "ok", "error", "codes"})   # 머리글은 보내지 않는다
        self.assertIsNotNone(hub._xrep_rows("S1", rows, 0.0))             # 보내는 꼴 그대로 본사가 받는다

    def test_hub_ingest_and_engine_import_idempotent(self):
        from logtriage.hub import HubStore
        hs = HubStore(_tmp(self))
        hs.add_site("S1", "사이트1")
        g = {"vkey": "TIBERO:TBR-12033", "cmd_hash": "a" * 16, "ok": 2, "error": 1, "codes": {"TBR-17004": 1}}
        r = hs.ingest("S1", {"site": {"version": "1.0.0"}, "stream": "e" * 16, "seq": 1, "xrep": [g]})
        self.assertEqual(r["received"]["xrep"], 1)
        top = hs.overview()["xrep"][0]
        self.assertEqual((top["ok"], top["error"], top["codes"]), (2, 1, {"TBR-17004": 1}))
        self.assertNotIn("headers", top)
        self.S.exec_report(self.f, "I1", "R1", 0, "성공", "", "TYPE ID1 ID2")
        import import_field_exec as ife
        vp = _tmp(self) / "_verification.yaml"
        shutil.copy(ENGINE / "errorcodes" / "_verification.yaml", vp)
        old = ife.VP, ife.OUT
        ife.VP, ife.OUT = vp, vp.with_name("현장실행.md")
        self.addCleanup(lambda: (setattr(ife, "VP", old[0]), setattr(ife, "OUT", old[1])))
        ife.main(["--db", str(self.st.path)])                             # 출처(사이트 ID)를 모름 — 합산하지 않는다(GPT 65차)
        ver = KQ.load_verification(vp.parent)
        self.assertNotIn("TIBERO:TBR-12033", ver["field_exec"])
        ife.main(["--db", str(self.st.path), "--site", "S9"])
        ife.main(["--db", str(self.st.path), "--site", "S9"])             # 같은 DB 두 번 — 두 번 세지 않는다
        ver = KQ.load_verification(vp.parent)
        self.assertEqual(ver["field_exec"]["TIBERO:TBR-12033"]["ok"], 1)
        self.assertEqual(KQ.axes("TIBERO:TBR-12033", ver=ver, product="tibero")["exec"], "현장 보고 성공 1")
        self.S.exec_report(type("F", (), {"store": self.st, "actor": type("A", (), {"login": "op2"})()})(), "I1", "R1", 0, "성공", "", "")
        cp = _tmp(self) / "copy.db"                                       # 담당자가 DB 를 다른 곳에 복사해 와도 같은 출처
        shutil.copy(self.st.path, cp)
        ife.main(["--db", str(cp), "--site", "S9"])
        ver = KQ.load_verification(vp.parent)
        self.assertEqual(ver["field_exec"]["TIBERO:TBR-12033"]["ok"], 2)   # 보고 1건 늘어난 DB — 교체라 2(3 아님)
        ife.main(["--db", str(hs.path)])
        ife.main(["--db", str(hs.path)])
        ver = KQ.load_verification(vp.parent)
        self.assertEqual(ver["field_exec"]["TIBERO:TBR-12033"]["ok"], 4)   # 사이트 DB 2 + 허브 S1 2, 허브 두 번 넣어도 그대로
        self.assertEqual(ver["field_exec"]["TIBERO:TBR-12033"]["sources"], 2)


class VersionSignals(unittest.TestCase):
    """⑦ '판 다름'이 서로 다른 분석 건 2건 이상에서 같은 호스트·제품 — 판 지정 제안."""

    def test_signal(self):
        st = _st(self)
        for i, at in (("I1", "2026-10-19T10"), ("I2", "2026-10-18T09"), ("I3", "2026-10-19T10"), ("I1b", "2026-10-19T10")):
            st.save_incident({"id": i, "analyzed_at": at, "files": [{"name": "a", "product": "postgresql", "host": "db2" if i == "I3" else "db1"}],
                              "checklist": [{"rule_id": "R1", "product": "postgresql"}]})
        st.add_feedback("R1", "a" * 16, "version", "", {"login": "op2"}, "I1b")   # I1 과 같은 장애(같은 시각·파일)의 재분석 — 한 번만
        self.assertEqual(st.version_signals(), [])
        st.add_feedback("R1", "a" * 16, "version", "", {"login": "op"}, "I1")
        self.assertEqual(st.version_signals(), [])
        st.add_feedback("R1", "a" * 16, "version", "", {"login": "op"}, "I3")   # 다른 호스트
        self.assertEqual(st.version_signals(), [])
        st.add_feedback("R1", "a" * 16, "version", "", {"login": "op"}, "I2")
        rows = st.version_signals()
        self.assertEqual([(r["host"], r["product"], r["incidents"], r["current"]) for r in rows], [("db1", "postgresql", 2, None)])
        st.set_host_version("db1", "postgresql", "16", actor={"login": "op"})
        self.assertEqual(st.version_signals()[0]["current"]["version"], "16")


class Instances(unittest.TestCase):
    """⑧ 같은 호스트에 판이 다른 인스턴스 — 인스턴스를 모르면 한 판으로 다시 보지 않는다."""

    def setUp(self):
        self.st = _st(self)
        from logtriage.server import ServerApi
        self.S = ServerApi
        self.f = type("F", (), {"store": self.st, "actor": type("A", (), {"login": "op"})()})()

    def _inc(self, i, instance=""):
        self.st.save_incident({"id": i, "analyzed_at": "2026-10-19", "first": {},
                               "files": [{"name": "a", "product": "postgresql", "host": "db1", "instance": instance}],
                               "checklist": [{"rule_id": "R1", "product": "postgresql", "cmds": [
                                   {"cmd": "SELECT checkpoints_timed FROM pg_stat_bgwriter;", "tail": " (16 이하)", "safe": True, "hash": "a" * 16, "fit": ""}]}]})

    def test_mixed_and_pick(self):
        self.assertIn("error", self.S.host_version_set(self.f, "db1", "postgresql", "16", "", "bad name!"))
        self.S.host_version_set(self.f, "db1", "postgresql", "16", "", "pg16")
        self.S.host_version_set(self.f, "db1", "postgresql", "17", "", "pg17")
        self._inc("I1")
        r = self.S.version_reevaluate(self.f, "I1")
        self.assertEqual(r["basis"], {})
        self.assertIn("postgresql", r["mixed"])
        self.assertEqual(r["items"][0]["cmds"][0]["basis"], "판 혼재 가능(인스턴스 미지정)")
        self._inc("I2", "pg17")
        r = self.S.version_reevaluate(self.f, "I2")
        self.assertEqual((r["basis"]["postgresql"]["version"], r["items"][0]["cmds"][0]["fit"]), ("17", "어긋남"))
        self._inc("I3", "pg16")
        self.assertEqual(self.S.version_reevaluate(self.f, "I3")["items"][0]["cmds"][0]["fit"], "맞음")
        self.S.host_version_set(self.f, "db1", "postgresql", "17", "", "")       # 호스트 전체 기록
        self._inc("I4", "pg-other")                                           # 기록 없는 인스턴스 — 호스트 전체 판을 물려받지 않는다(GPT 64차)
        r = self.S.version_reevaluate(self.f, "I4")
        self.assertEqual((r["basis"], r["items"][0]["cmds"][0]["basis"]), ({}, "추정"))

    def test_old_db_gets_column(self):
        td = _tmp(self)
        p = td / "old.db"
        c = sqlite3.connect(p)
        c.execute("CREATE TABLE host_versions(id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, host TEXT NOT NULL, "
                  "product TEXT NOT NULL, version TEXT NOT NULL, source TEXT NOT NULL, evidence_sha TEXT, expires REAL NOT NULL)")
        c.commit()
        c.close()
        st = storage.Storage("sqlite:///" + p.as_posix())
        st.set_host_version("h", "oracle", "19", instance="ORCL1")
        self.assertEqual(list(st.host_versions(["h"])), [("h", "oracle", "ORCL1")])


class PartMetrics(unittest.TestCase):
    """⑨ 섞인 기준은 수치 부분만 — '수치 조건 충족/미충족'과 나머지 조건 안내, 다른 비교(여유 < 사용량)는 결속하지 않는다."""

    def test_part(self):
        ms = KQ.load_metrics(ENGINE / "errorcodes")
        s = KQ.metric_for(ms, "bizmaster-adapter:SW-BM-005", "df -h <msg_dir>")
        self.assertTrue(s["part"])
        out = "Filesystem Size Used Avail Use% Mounted on\n/dev/a 50G 9G 41G 18% /m"
        r = KQ.interpret("사용률 95% 이상이거나 실행 계정 쓰기 권한이 없으면 확정", out, s)
        self.assertEqual(r["verdict"], "수치 조건 미충족")
        self.assertIn("실행 계정 쓰기 권한", r["note"])
        r = KQ.interpret("사용률 95% 이상이거나 실행 계정 쓰기 권한이 없으면 확정", out.replace("18%", "97%"), s)
        self.assertEqual(r["verdict"], "수치 조건 충족")
        self.assertIsNone(KQ.metric_for(ms, "aix:LEG-AIX-BACKUP", "df -g <백업경로>"))
        self.assertEqual(KQ.metric_for(ms, "aix:LEG-AIX-BACKUP", "df -g /tmp")["id"], "aix-tmp-use")
        self.assertIsNone(KQ.metric_for(ms, "linux:OS-LNX-011", "df -hT ; df -i"))


class IncidentGroups(unittest.TestCase):
    """⑩ 자동 식별이 틀리면 관리자가 나누거나 합친다 — 사유 필수, 이력 보존, 자동으로 되돌리기."""

    def test_split_merge(self):
        st = _st(self)

        def inc(i, f):
            st.save_incident({"id": i, "analyzed_at": "2026-10-19", "first": {"verdict": "데드락", "rule_id": "R1"},
                              "files": [{"name": f}], "checklist": [{"rule_id": "R1"}]})
            st.set_postmortem(i, "실제는 스토리지", "confirmed", "no", "RCA 문서")
        inc("I1", "a.log")
        inc("I2", "a.log")
        self.assertEqual(st.postmortem_proposals(), [])
        near = st.postmortem_proposals(include_near=True)
        self.assertTrue(near and near[0]["near"])                         # 나누기 후보로만 보인다
        with self.assertRaises(ValueError):
            st.set_incident_group(["I1"], "I1", "짧음")
        st.set_incident_group(["I1"], "I1", "다른 날 같은 시각 — 별개 장애")
        st.set_incident_group(["I2"], "I2", "다른 날 같은 시각 — 별개 장애")
        rows = st.postmortem_proposals()
        self.assertEqual((len(rows), rows[0]["cases"]), (1, 2))
        st.set_incident_group(["I1", "I2"], "G-1", "같은 스토리지 장애를 두 번 분석")
        self.assertEqual(st.postmortem_proposals(), [])
        st.set_incident_group(["I1", "I2"], None, "자동 식별로 되돌림")
        self.assertEqual(st.postmortem_proposals(), [])
        self.assertEqual(len(st.incident_group_history("I1")), 3)


class SharedPasswordKdf(unittest.TestCase):
    """⑪ 공용 비밀번호는 scrypt 검증값으로만 — 평문을 들고 있지 않고, 파일은 제자리 변환."""

    def test_verifier(self):
        from logtriage import server as S
        v = S.pw_verifier("s3cret-Pass")
        self.assertTrue(v.startswith("lt-scrypt$17$8$1$"))   # GPT 64차: OWASP 권장 최소 N=2^17
        self.assertNotIn("s3cret", v)
        self.assertTrue(S.pw_ok("s3cret-Pass", v))
        self.assertFalse(S.pw_ok("s3cret-pass", v))
        self.assertFalse(S.pw_ok("s3cret-Pass", "s3cret-Pass"))          # 평문을 검증값으로 받지 않는다
        self.assertEqual(S.as_verifier(v), v)
        self.assertNotEqual(S.pw_verifier("a"), S.pw_verifier("a"))       # 소금
        self.assertFalse(S.pw_ok("x", "lt-scrypt$40$8$1$00$00"))          # 터무니없는 비용 값은 거절
        import hashlib as _h
        weak_salt = b"s" * 16
        weak = "lt-scrypt$15$1$1$" + weak_salt.hex() + "$" + _h.scrypt(b"pw", salt=weak_salt, n=1 << 15, r=1, p=1, maxmem=256 << 20, dklen=32).hex()
        self.assertFalse(S.pw_ok("pw", weak))                                # 맞는 비밀번호라도 약한 비용(r=1)으로 만든 검증값은 받지 않는다
        old = S._scrypt

        def boom(*a, **k):
            raise MemoryError("memory limit exceeded")
        S._scrypt = boom
        self.addCleanup(setattr, S, "_scrypt", old)
        self.assertIsNone(S.pw_ok("s3cret-Pass", v))                      # 확인 못 함 = None(틀림과 구별 — 실패로 세지 않게)
        S._scrypt = old
        from logtriage.server import Handler
        f = type("H", (), {"_local_login": lambda s: False, "password": v, "_u": {"login": "adm"}, "_ip": lambda s: "10.0.0.2",
                           "_REAUTH_HITS": {}, "REAUTH_MAX": 5, "REAUTH_WINDOW": 600.0})()
        S._scrypt = boom
        self.assertEqual(Handler._reauth(f, "s3cret-Pass")[:2], (False, "error"))
        S._scrypt = old
        with self.assertRaises(SystemExit):
            S.make_server("127.0.0.1", 0, _tmp(self), "lt-scrypt$40$8$1$00$00")   # 깨진 검증값을 평문으로 받지 않는다

    def test_file_and_server(self):
        from logtriage import server as S
        td = _tmp(self)
        p = td / "pw.txt"
        p.write_text("plain-pass-1\n", encoding="utf-8")
        self.assertEqual(S.hash_password_file(p), 0)
        v = p.read_text(encoding="utf-8").strip()
        self.assertTrue(S.pw_ok("plain-pass-1", v))
        self.assertEqual(S.hash_password_file(p), 0)
        self.assertEqual(p.read_text(encoding="utf-8").strip(), v)       # 두 번 바꾸지 않는다
        self.assertFalse((td / "pw.txt.lt-new").exists())
        d = td / "dir"
        d.mkdir()
        self.assertEqual(S.hash_password_file(d), 2)                       # 일반 파일이 아니면 거절

    @unittest.skipUnless(os.name == "nt", "Windows ACL")
    def test_file_acl_kept(self):
        """GPT 65차: os.replace 는 원본 NTFS ACL 을 잃는다 — ReplaceFileW 로 바꿔 원본 ACL 이 그대로인지 Get-Acl 로 대조."""
        import subprocess
        from logtriage import server as S
        td = _tmp(self)
        p = td / "server.conf.pw"
        p.write_text("plain-pass-acl\n", encoding="utf-8")
        user = os.environ.get("USERNAME", "")
        subprocess.run(["icacls", str(p), "/inheritance:r", "/grant:r", f"{user}:F"], capture_output=True)
        sd = lambda: subprocess.run(["powershell", "-NoProfile", "-Command", f"(Get-Acl -LiteralPath '{p}').Sddl"],  # noqa: E731
                                    capture_output=True, text=True).stdout.strip()
        before = sd()
        self.assertTrue(before)
        self.assertEqual(S.hash_password_file(p), 0)
        self.assertEqual(sd(), before)
        self.assertTrue(S.pw_ok("plain-pass-acl", p.read_text(encoding="utf-8").strip()))
        srv, h = S.make_server("127.0.0.1", 0, td, "plain-pass-2")
        try:
            self.assertTrue(h.password.startswith("lt-scrypt$"))
            self.assertTrue(S.pw_ok("plain-pass-2", h.password))
        finally:
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
