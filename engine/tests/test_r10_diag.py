"""10차(2026-10-19 마스터 보고 "어떤 로그도 분석이 안 되고 장애 이력이 없다") — 화면의 '없음'을 증거로 가르는 장치.

① 지식(룰) 0개면 분석을 거부한다(예전엔 '알려진 장애 패턴 미검출' 0건 리포트 — 거짓 음성)
② 이력 읽기 오류를 삼키지 않는다(진단에 싣는다)
③ 이력 위치·보관 건수를 진단에 싣는다
④ 이관 파일(incidents.json.migrated)에만 남은 예전 분석을 알리고, 관리자가 가져올 수 있다(이미 있는 id 는 건너뜀)
⑤ 앱 밖에서 이력이 줄면 다음 기동이 알린다
⑥ 합성 로그 자가 점검 — 지금 지식으로 판정이 실제로 나는지(이력에 남기지 않음)
⑦⑧ 기동 자기진단·분석 결과를 실행 기록에 한 줄
⑨ 점검 도구가 띄운 창은 '시험 실행' 표시
"""
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from logtriage.server import make_server  # noqa: E402
from logtriage.service import NoKnowledgeError, run_analysis  # noqa: E402

SAMPLE = ENGINE / "samples" / "catalina.out"


def _tmp(test):
    td = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, td, True)
    return td


def _base(test, knowledge=True):
    td = _tmp(test)
    for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
        if knowledge:
            shutil.copytree(ENGINE / d, td / d)
        else:
            (td / d).mkdir()
    return td


def _api(test, base):
    httpd, handler = make_server("127.0.0.1", 0, base, None, [ENGINE / "samples"], desktop=True, native=False)
    test.addCleanup(httpd.server_close)
    return handler.api


class NoKnowledge(unittest.TestCase):
    def test_service_refuses_zero_rules(self):
        b = _base(self, knowledge=False)
        with self.assertRaises(NoKnowledgeError) as cm:
            run_analysis([{"path": str(SAMPLE), "product": "tomcat", "host": "h"}], None, 30, 10, b / "rules", b / "rules-local", b / "errorcodes")
        self.assertIn("룰)이 0개", str(cm.exception))
        with self.assertRaises(NoKnowledgeError) as cm:                     # 폴더 자체가 없음
            run_analysis([{"path": str(SAMPLE), "product": "tomcat", "host": "h"}], None, 30, 10, b / "없음", b / "rules-local", b / "errorcodes")
        self.assertIn("룰 폴더가 없습니다", str(cm.exception))

    def test_site_rules_alone_refused(self):
        """기본 룰이 없고 사이트 룰만 있으면 — 합계는 0이 아니어도 거의 다 놓친다 → 거부(GPT 76차)."""
        b = _base(self, knowledge=False)
        (b / "rules-local" / "site.yaml").write_text('rules:\n- id: SITE-1\n  layer: was\n  product: [tomcat]\n'
                                                     '  match: {regex: "OutOfMemoryError"}\n  verdict: site\n', encoding="utf-8")
        with self.assertRaises(NoKnowledgeError):
            run_analysis([{"path": str(SAMPLE), "product": "tomcat", "host": "h"}], None, 30, 10, b / "rules", b / "rules-local", b / "errorcodes")

    def test_window_analyze_returns_error_not_empty_report(self):
        b = _base(self, knowledge=False)
        api = _api(self, b)
        r = api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertIn("error", r)
        self.assertIn("믿을 수 없습니다", r["error"])
        self.assertEqual(api.history(), [])                                   # 0건 리포트를 이력에 남기지 않음

    def test_cli_refuses(self):
        t = _tmp(self)
        for d in ("rules", "rules-local", "errorcodes"):
            (t / d).mkdir()
        r = subprocess.run([sys.executable, "-m", "logtriage.cli", "--input", f"{SAMPLE}:tomcat:h", "--rules", str(t / "rules"),
                            "--rules-local", str(t / "rules-local"), "--codes", str(t / "errorcodes")],
                           cwd=str(ENGINE), capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        self.assertNotEqual(r.returncode, 0, r.stdout[-300:])
        self.assertIn("0개", r.stderr + r.stdout)

    def test_normal_knowledge_still_analyzes(self):
        b = _base(self)
        r = run_analysis([{"path": str(SAMPLE), "product": "tomcat", "host": "h"}], None, 30, 10, b / "rules", b / "rules-local", b / "errorcodes")
        self.assertGreater(r["findings_total"], 0)


class Diag(unittest.TestCase):
    def test_self_check_ok_and_fail(self):
        api = _api(self, _base(self))
        d = api.diag()
        self.assertEqual(d["self_check"]["state"], "ok", d["self_check"])
        self.assertGreater(d["self_check"]["findings"], 0)
        self.assertEqual(api.history(), [])                                   # 자가 점검은 이력에 남지 않는다
        self.assertFalse(any("자가 점검 실패" in w for w in d["warnings"]))
        b2 = _base(self, knowledge=False)
        d2 = _api(self, b2).diag()
        self.assertEqual(d2["self_check"]["state"], "fail")
        self.assertTrue(any("자가 점검 실패" in w for w in d2["warnings"]))

    def test_self_check_fails_when_rules_do_not_fire(self):
        """룰은 있는데(0개 아님) 견본에 하나도 안 걸리면 — 지식이 바뀌었거나 일부만 읽힌 것 → 자가 점검 실패."""
        b = _base(self)
        shutil.rmtree(b / "rules")
        (b / "rules").mkdir()
        (b / "rules" / "only.yaml").write_text('rules:\n- id: NEVER-1\n  layer: was\n  product: [tomcat]\n'
                                               '  match: {regex: "ZZZ_NEVER_MATCHES"}\n  verdict: never\n', encoding="utf-8")
        d = _api(self, b).diag()
        self.assertEqual(d["rules"], 1)
        self.assertEqual(d["self_check"]["state"], "fail", d["self_check"])
        self.assertIn("시그니처 룰 판정 0건", d["self_check"]["note"])   # 벤더 에러코드 발견만으로는 통과하지 않는다

    def test_history_read_error_is_reported(self):
        api = _api(self, _base(self))

        def boom(*a, **k):
            raise RuntimeError("DB 잠김 시험")
        api.store.history = boom
        with self.assertRaises(ValueError) as cm:                             # GPT 76차 P0-02: 200 + [] 로 위장하지 않는다
            api.history()
        self.assertIn("'이력 없음'이 아닙니다", str(cm.exception))
        self.assertNotIn("DB 잠김 시험", str(cm.exception))                   # 자세한 글은 진단·기록에만
        d = api.diag()
        self.assertIn("DB 잠김 시험", d["history"]["error"])
        self.assertTrue(any("이력을 읽지 못했습니다" in w for w in d["warnings"]))

    def test_history_where_and_count(self):
        b = _base(self)
        api = _api(self, b)
        r = api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertNotIn("error", r)
        d = api.diag()
        self.assertEqual(d["history"]["count"], 1)
        self.assertTrue(d["history"]["where"].endswith("logtriage.db"), d["history"]["where"])

    def test_history_drop_detected_once(self):
        b = _base(self)
        api = _api(self, b)
        for _ in range(2):
            api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api.history()                                                         # 앱이 본 건수 = 2
        self.assertEqual(json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))["high"], 2)
        ids = [h["id"] for h in api.history()]
        api.store.delete_incident(ids[0])                                     # 앱 밖에서 줄어든 것처럼(표시 갱신 없이)
        api2 = _api(self, b)                                                  # 다음 기동
        self.assertEqual(len(api2.history()), 1)                              # 화면 init 처럼 이력부터 — 그래도 감소 판정이 지워지면 안 된다
        d = api2.diag()
        self.assertTrue(d["drop"]["dropped"], d["drop"])
        self.assertEqual((d["drop"]["prev"], d["drop"]["now"]), (2, 1))
        self.assertTrue(any("2건 → 지금 1건" in w for w in d["warnings"]))
        api3 = _api(self, b)                                                  # GPT 76차: 다음 기동에도 남는다 — 저절로 기준을 내리지 않음
        api3.history()
        self.assertTrue(api3.diag()["drop"]["dropped"])
        r = api3.ack_history_change()                                         # 관리자 확인 → 지금이 새 기준
        self.assertFalse(r["drop"]["dropped"])
        api4 = _api(self, b)
        self.assertFalse(api4.diag()["drop"]["dropped"])
        api4.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api4.history()                                                        # 앱 안에서 늘어난 것은 기준을 올린다
        self.assertEqual(json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))["high"], 2)

    def test_same_count_replacement_and_db_change(self):
        b = _base(self)
        api = _api(self, b)
        for _ in range(2):
            api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api.history()
        ids = [h["id"] for h in api.history()]
        api.store.delete_incident(ids[0])                                     # 앱 밖에서 한 건 빼고 다른 한 건 넣음 — 건수는 같음
        api.store.save_incident({"id": "INC-OUTSIDE-1", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": []})
        d = _api(self, b).diag()
        self.assertTrue(d["drop"]["replaced"], d["drop"])
        self.assertFalse(d["drop"]["dropped"])
        self.assertTrue(any("구성이 바뀌었습니다" in w for w in d["warnings"]))
        m = json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))
        m["db"], m["db_rel"] = "다른 위치.db", ""     # 13차: 상대 위치까지 다른 DB(폴더째 이동은 같은 DB로 본다)
        (b / "data" / "history-mark.json").write_text(json.dumps(m), encoding="utf-8")
        d = _api(self, b).diag()
        self.assertTrue(d["drop"]["db_changed"], d["drop"])
        self.assertTrue(any("DB 위치가 지난번과 다릅니다" in w for w in d["warnings"]))

    def test_read_error_does_not_move_mark(self):
        b = _base(self)
        api = _api(self, b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api.history()
        before = (b / "data" / "history-mark.json").read_bytes()
        api2 = _api(self, b)

        def boom(*a, **k):
            raise RuntimeError("읽기 실패")
        api2.store.incident_count = boom
        api2.diag()
        self.assertEqual((b / "data" / "history-mark.json").read_bytes(), before)
        # 건수는 읽히지만 이력 읽기가 실패한 상태 — 그때 본 건수로 기준을 올리면 안 된다
        api.store.save_incident({"id": "INC-OUTSIDE-2", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": []})
        api3 = _api(self, b)
        api3._hist_error = "RuntimeError: 읽기 실패"
        api3.diag()
        self.assertEqual(json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))["high"], 1)

    def test_self_check_timeout(self):
        from logtriage.gui import app as A
        api = _api(self, _base(self))
        old_run, old_sec = A.run_analysis, A.Api.SELF_CHECK_SEC
        self.addCleanup(lambda: (setattr(A, "run_analysis", old_run), setattr(A.Api, "SELF_CHECK_SEC", old_sec)))
        import time as _t
        A.run_analysis = lambda *a, **k: _t.sleep(3)
        A.Api.SELF_CHECK_SEC = 0.5
        t0 = _t.monotonic()
        sc = api.diag()["self_check"]
        self.assertLess(_t.monotonic() - t0, 2.5)                             # 화면을 막지 않는다
        self.assertEqual(sc["state"], "timeout", sc)

    def test_concurrent_diag_single_drop_verdict(self):
        """화면 init 과 기동 기록 스레드가 동시에 불러도 감소 판정이 둘로 갈리지 않는다(잠금)."""
        import threading
        b = _base(self)
        api = _api(self, b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api.history()
        api.store.delete_incident(api.history()[0]["id"])
        api2 = _api(self, b)
        out = []
        ts = [threading.Thread(target=lambda: out.append(api2.diag()["drop"]["dropped"])) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(out, [True] * 4)


class HistoryUi(unittest.TestCase):
    def test_ui_never_treats_error_as_empty(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        import re
        raw = re.findall(r"history=await api\(\)\.history\(\)", ui)
        self.assertEqual(raw, [], "이력 응답은 asHist() 로 — 오류 객체를 빈 이력으로 그리지 않는다")
        self.assertEqual(ui.count("asHist(await api().history())"), 3)
        self.assertIn("HIST_ERR||hs.error", ui)


class Legacy(unittest.TestCase):
    def _mig(self, b, rows):
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")

    def test_notice_and_restore(self):
        b = _base(self)
        api = _api(self, b)
        r = api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        rows = [{"id": "INC-20260910-000001", "analyzed_at": "2026-09-10 10:00:00", "files": [], "checklist": [], "name": ""},
                {"id": "INC-20260910-000002", "analyzed_at": "2026-09-10 11:00:00", "files": [], "checklist": [], "name": "옛 분석"},
                {"id": r["id"], "analyzed_at": "2026-09-10 12:00:00", "files": [], "checklist": []},   # 이미 있음 → 건너뜀
                {"analyzed_at": "2026-09-10"}, "깨진 줄"]
        self._mig(b, rows)
        d = api.diag()
        self.assertEqual((d["legacy"]["total"], d["legacy"]["missing"]), (3, 2))
        self.assertTrue(any("예전 분석 2건" in w for w in d["warnings"]))
        res = api.restore_legacy_history()
        self.assertEqual((res["restored"], res["skipped"]), (2, 3))
        bk = b / "backups" / res["backup"]                                    # GPT 76차 P1-03: 가져오기 전 DB 백업
        self.assertTrue(bk.is_file())
        self.assertEqual(sum(1 for l in bk.read_text(encoding="utf-8").splitlines() if '"table": "incidents"' in l), 1)
        ids = {h["id"] for h in api.history()}
        self.assertTrue({"INC-20260910-000001", "INC-20260910-000002", r["id"]} <= ids)
        again = api.restore_legacy_history()
        self.assertEqual((again["restored"], again["skipped"]), (0, 5))                 # 두 번 해도 늘지 않음
        self.assertTrue((b / "incidents.json.migrated").exists())                       # 이관 파일은 그대로
        api.__dict__.pop("_drop_cache", None)
        self.assertEqual(api.diag()["legacy"]["missing"], 0)

    def test_restore_is_admin_only(self):
        from logtriage.server import ADMIN_APIS, API_NAMES
        self.assertIn("restore_legacy_history", ADMIN_APIS)
        self.assertIn("restore_legacy_history", API_NAMES)
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn('"restore_legacy_history"', ui)
        self.assertIn("confirm(", ui[ui.index("restoreLegacy:async"):ui.index("restoreLegacy:async") + 400])

    def test_bad_file(self):
        b = _base(self)
        (b / "incidents.json.migrated").write_text("{깨짐", encoding="utf-8")
        api = _api(self, b)
        self.assertIn("error", api.diag()["legacy"])
        self.assertIn("error", api.restore_legacy_history())


class Seed(unittest.TestCase):
    """단독 exe(마스터 보고의 진짜 원인) — exe 옆에 지식이 없으면 내장 지식을 펼친다. 내장 위치 대신 엔진 폴더를 원본으로 시험."""

    def test_empty_folder_gets_knowledge_and_analyzes(self):
        from logtriage.knowledge_seed import KNOW, FORMS, STAGE, seed
        from logtriage.knowledge_gen import FILE
        from logtriage.server import release_leftover
        b = _tmp(self)
        r = seed(b, ENGINE)
        self.assertEqual(r["seeded"], list(KNOW) + [FORMS])
        self.assertTrue((b / FILE).exists())
        self.assertFalse((b / STAGE).exists())
        self.assertTrue((b / "rules-local").is_dir())
        self.assertEqual(release_leftover(b), "")
        res = run_analysis([{"path": str(SAMPLE), "product": "tomcat", "host": "h"}], None, 30, 10, b / "rules", b / "rules-local", b / "errorcodes")
        self.assertGreater(res["findings_total"], 0)
        self.assertEqual(seed(b, ENGINE)["seeded"], [])                       # 두 번째는 아무것도 안 함
        self.assertIn("내장 지식", (b / FILE).read_text(encoding="utf-8"))

    def test_existing_knowledge_untouched(self):
        from logtriage.knowledge_seed import seed
        b = _base(self)
        f = next((b / "rules").rglob("*.yaml"))
        f.write_text(f.read_text(encoding="utf-8") + "\n# 사이트 룰팩으로 갱신된 판\n", encoding="utf-8")
        self.assertEqual(seed(b, ENGINE)["seeded"], [])
        self.assertIn("사이트 룰팩으로 갱신된 판", f.read_text(encoding="utf-8"))

    def test_partial_not_seeded(self):
        from logtriage.knowledge_seed import seed
        b = _tmp(self)
        shutil.copytree(ENGINE / "rules", b / "rules")                       # rules 만 있음 — 섞지 않는다
        r = seed(b, ENGINE)
        self.assertNotIn("errorcodes", r["seeded"])
        self.assertFalse((b / "errorcodes").exists())
        self.assertIn("일부만 있습니다", r.get("error", ""))                 # GPT 78차: 세대 기록 없는 일부 지식으로는 뜨지 않는다
        from logtriage import knowledge_seed as KS
        from logtriage.server import prepare_base
        old = KS.bundled_root
        KS.bundled_root = lambda: ENGINE
        self.addCleanup(lambda: setattr(KS, "bundled_root", old))
        self.assertIn("일부만 있습니다", prepare_base(b))
        shutil.rmtree(b / "rules")                                            # 안내대로 지우면 — 다시 펼친다
        self.assertEqual(prepare_base(b), "")
        self.assertTrue((b / "errorcodes").is_dir())

    def _lockfile(self, b, rec):
        from logtriage.knowledge_seed import LOCK
        (b / LOCK).write_text(json.dumps(rec) if isinstance(rec, dict) else rec, encoding="utf-8")

    def test_lock_owner_rules(self):
        """GPT 78차 잠재 P0-02·P1: 주인이 끝났다는 것이 입증될 때만 잠금을 치운다 — 죽은 pid·재사용된 pid(생성 시각 다름)는 치우고,
        살아 있는 주인·읽을 수 없는 잠금은 빼앗지 않는다(기다리다 안내)."""
        from logtriage import knowledge_seed as KS
        old = KS.LOCK_WAIT
        KS.LOCK_WAIT = 1.5
        self.addCleanup(lambda: setattr(KS, "LOCK_WAIT", old))
        dead = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True).stdout.strip()
        b = _tmp(self)
        self._lockfile(b, {"pid": int(dead), "start": 1})
        self.assertNotIn("error", KS.seed(b, ENGINE))                         # 죽은 주인 — 치우고 펼침
        live = os.getppid() or os.getpid()
        b2 = _tmp(self)
        self._lockfile(b2, {"pid": os.getpid(), "start": KS._proc_start(os.getpid())})
        r = KS.seed(b2, ENGINE)
        self.assertIn("주인을 확인할 수 없는 잠금", r.get("error", ""))       # 살아 있는 주인 — 빼앗지 않음
        self.assertFalse((b2 / "rules").exists())
        if KS._proc_start(os.getpid()) is not None:
            b3 = _tmp(self)
            self._lockfile(b3, {"pid": os.getpid(), "start": 12345})          # 같은 pid, 다른 생성 시각 = 재사용 → 주인은 끝났다
            self.assertNotIn("error", KS.seed(b3, ENGINE))
        b4 = _tmp(self)
        self._lockfile(b4, "")                                                # 읽을 수 없음 — 빼앗지 않음
        self.assertIn("error", KS.seed(b4, ENGINE))
        self.assertTrue(live)

    _KILL = ("import sys, os; sys.path.insert(0, %r); from pathlib import Path\n"
             "from logtriage import knowledge_seed as KS, knowledge_gen as KG\n"
             "k = %d; n = [0]; _r = os.replace; _w = KG.write_gen\n"
             "def rep(a, b):\n    _r(a, b)\n    if Path(b).name not in KS.KNOW: return\n    n[0] += 1\n    if n[0] == k: os._exit(9)\n"
             "def wg(*a, **kw):\n    if k == 4: os._exit(9)\n    r = _w(*a, **kw)\n    if k == 5: os._exit(9)\n    return r\n"
             "os.replace = rep; KG.write_gen = wg\n"
             "KS.seed(Path(%r), Path(%r))\n")

    def test_killed_seed_recovers(self):
        """GPT 77차 P0-02: 세 폴더 이동 각각 직후(1~3), 세대 기록 직전(4)·직후(5)에 프로세스를 죽인 뒤 다시 기동 — 내장본 한 세대로 끝난다."""
        from logtriage.knowledge_seed import KNOW, LOCK, STAGE, seed
        from logtriage.knowledge_gen import check_gen, dir_hash
        for k in (1, 2, 3, 4, 5):
            with self.subTest(k=k):
                b = _tmp(self)
                subprocess.run([sys.executable, "-c", self._KILL % (str(ENGINE), k, str(b), str(ENGINE))], capture_output=True, timeout=120)
                self.assertTrue((b / STAGE).exists(), k)                     # 끊긴 흔적
                t0 = __import__("time").monotonic()
                r = seed(b, ENGINE)                                           # 다음 기동
                self.assertLess(__import__("time").monotonic() - t0, 30)       # 죽은 프로세스의 잠금을 기다리지 않는다
                self.assertNotIn("error", r, r)
                self.assertFalse((b / STAGE).exists())
                self.assertFalse((b / LOCK).exists())
                self.assertEqual(check_gen(b), "")
                for d in KNOW:
                    self.assertEqual(dir_hash(b / d), dir_hash(ENGINE / d), (k, d))

    def test_interrupted_seed_does_not_overwrite_site_knowledge(self):
        """끊긴 펼침 뒤 누가 지식을 넣었으면(펼치기 전·내장본 어느 것과도 다름) 덮어쓰지 않고 멈춘다."""
        from logtriage.knowledge_seed import STAGE, seed
        b = _tmp(self)
        subprocess.run([sys.executable, "-c", self._KILL % (str(ENGINE), 1, str(b), str(ENGINE))], capture_output=True, timeout=120)
        f = next((b / "rules").rglob("*.yaml"))
        f.write_text(f.read_text(encoding="utf-8") + "\n# 사이트에서 넣은 판\n", encoding="utf-8")
        r = seed(b, ENGINE)
        self.assertIn("덮어쓰지 않습니다", r.get("error", ""))
        self.assertIn("사이트에서 넣은 판", f.read_text(encoding="utf-8"))
        self.assertTrue((b / STAGE).exists())
        (b / STAGE / "plan.json").unlink()                                   # 일지가 없으면 — 역시 덮어쓰지 않음
        self.assertIn("plan.json", seed(b, ENGINE).get("error", ""))
        self.assertIn("사이트에서 넣은 판", f.read_text(encoding="utf-8"))

    def test_concurrent_first_start(self):
        """GPT 77차 P0-03: 두 프로세스가 같은 빈 폴더에서 동시에 처음 뜸 — 둘 다 오류 없이, 결과는 한 세대."""
        from logtriage.knowledge_seed import KNOW, LOCK, STAGE
        from logtriage.knowledge_gen import check_gen, dir_hash
        b = _tmp(self)
        code = ("import sys, json; sys.path.insert(0, %r); from pathlib import Path; from logtriage import knowledge_seed as KS\n"
                "print(json.dumps(KS.seed(Path(%r), Path(%r)), ensure_ascii=False))\n") % (str(ENGINE), str(b), str(ENGINE))
        ps = [subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(3)]
        outs = [json.loads(p.communicate(timeout=180)[0].decode("utf-8").strip().splitlines()[-1]) for p in ps]
        self.assertFalse(any("error" in o for o in outs), outs)
        self.assertEqual(sum(1 for o in outs if "rules" in o["seeded"]), 1, outs)   # 하나만 펼쳤다
        self.assertEqual(check_gen(b), "")
        self.assertFalse((b / STAGE).exists() or (b / LOCK).exists())
        for d in KNOW:
            self.assertEqual(dir_hash(b / d), dir_hash(ENGINE / d))

    def test_link_folder_refused(self):
        from logtriage.knowledge_seed import seed
        b = _tmp(self)
        tgt = _tmp(self)
        try:
            os.symlink(tgt, b / "rules", target_is_directory=True)
        except OSError:
            self.skipTest("심볼릭 링크 권한 없음")
        r = seed(b, ENGINE)
        self.assertIn("링크", r.get("error", ""))
        self.assertEqual(list(tgt.iterdir()), [])

    def test_not_frozen_no_bundle(self):
        from logtriage.knowledge_seed import bundled_root, seed
        self.assertIsNone(bundled_root())
        b = _tmp(self)
        self.assertEqual(seed(b)["seeded"], [])                               # 개발 실행은 펼칠 것이 없다

    def test_specs_bundle_knowledge(self):
        if not (ENGINE / "deploy" / "local" / "logtriage.spec").is_file():
            self.skipTest("PC 빌드 spec 이 없는 곳(리눅스 묶음) — PC exe 전용 확인")
        for spec in ("logtriage.spec", "logtriage-cli.spec"):
            s = (ENGINE / "deploy" / "local" / spec).read_text(encoding="utf-8")
            for d in ("rules", "errorcodes", "manuals", "report-template"):
                self.assertIn(f"('../../{d}', 'knowledge/{d}')", s, spec)

    def test_prepare_base_seeds_then_checks(self):
        """기동 준비가 실제로 펼친다(내장 위치를 엔진 폴더로 바꿔 끼움) — 펼친 뒤 make_server 가 뜨고 분석이 판정을 낸다."""
        from logtriage import knowledge_seed as KS
        from logtriage.server import prepare_base
        old = KS.bundled_root
        KS.bundled_root = lambda: ENGINE
        self.addCleanup(lambda: setattr(KS, "bundled_root", old))
        b = _tmp(self)
        self.assertEqual(prepare_base(b), "")
        self.assertTrue(any((b / "rules").rglob("*.yaml")))
        api = _api(self, b)
        r = api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertGreater(r.get("findings_total", 0), 0, r.get("error"))

    def test_prepare_base_used_everywhere(self):
        app = (ENGINE / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")
        srv = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertEqual(app.count("prepare_base("), 2)
        self.assertNotIn("release_leftover(base", app)
        self.assertIn("left = prepare_base(base)", srv)
        self.assertIn("seed(ENGINE_DIR)", (ENGINE / "logtriage" / "cli.py").read_text(encoding="utf-8"))


class StandaloneBand(unittest.TestCase):
    def test_standalone_no_stamp_is_not_a_warning(self):
        """단독 실행(내장 지식 펼침)은 설치 기록이 없는 게 정상 — 'no_stamp' 띠 대신 'standalone'. 설치 폴더 같은 곳은 그대로 no_stamp."""
        from logtriage.knowledge_seed import seed
        from logtriage.server import ServerApi
        b = _tmp(self)
        seed(b, ENGINE)
        (b / "LogTriage.exe").write_bytes(b"MZ")
        old = (getattr(sys, "frozen", None), sys.executable)
        sys.frozen, sys.executable = True, str(b / "LogTriage.exe")
        self.addCleanup(lambda: (setattr(sys, "executable", old[1]), delattr(sys, "frozen") if old[0] is None else setattr(sys, "frozen", old[0])))
        ServerApi._INSTALL.clear()
        self.addCleanup(ServerApi._INSTALL.clear)
        api = _api(self, b)
        self.assertEqual(api.install_check()["state"], "standalone")
        b2 = _base(self)                                                      # 세대 기록 없는 설치 폴더 — 기록 없음은 알린다
        (b2 / "LogTriage.exe").write_bytes(b"MZ")
        sys.executable = str(b2 / "LogTriage.exe")
        self.assertEqual(_api(self, b2).install_check()["state"], "no_stamp")
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn('["mismatch","broken","no_stamp"].includes(r.state)', ui)   # standalone 은 띠 목록에 없다


class SampleLogs(unittest.TestCase):
    def test_sample_logs_listed_and_analyzable(self):
        """10차 UX(GPT 79차 첫 5분): 견본 로그 넣기 — 4종 자동 판별, 그대로 분석하면 판정이 나온다."""
        api = _api(self, _base(self))
        s = api.sample_logs()
        self.assertEqual([x["name"] for x in s], ["catalina.out", "alert_orcl.log", "SystemOut.log", "listener.log"])
        self.assertTrue(all(x["product"] for x in s), s)
        r = api.analyze({"inputs": [{"path": x["path"], "product": x["product"], "host": "sample"} for x in s]})
        self.assertGreater(r.get("findings_total", 0), 0, r.get("error"))

    def test_not_offered_outside_allowed_paths(self):
        httpd, handler = make_server("127.0.0.1", 0, _base(self), None, [_tmp(self)], desktop=False, native=False)
        self.addCleanup(httpd.server_close)
        # 12차(리눅스 서버도 30초 체험): 서버형은 '엔진과 함께 온 합성 견본 4종'만 내준다 — 견본 폴더 바로 아래·정해진 이름.
        # 그 밖의 경로는 여전히 허용 경로(업로드·--allow-dir) 밖이면 내주지 않는다(분석도 거절 — test_r12_linux_parity)
        s = handler.api.sample_logs()
        root = handler.api._samples_root().resolve()
        self.assertEqual(sorted(x["name"] for x in s), sorted(handler.api.SAMPLE_PICK))
        self.assertTrue(all(Path(x["path"]).resolve().parent == root for x in s), s)
        self.assertFalse(handler.api._allowed(root / "nginx_error.log"))
        self.assertFalse(handler.api._allowed(Path(_tmp(self)).parent / "outside.log"))

    def test_kb_line_single_writer(self):
        """지식 줄은 kbLine 한 곳에서만 그린다 — 분석 뒤 다시 그릴 때 자가 점검 표시가 지워지던 것(exe24 화면 점검에서 발견)."""
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertNotIn('$("#metaline").textContent=', ui)
        self.assertNotIn('$("#rulechip").textContent=', ui)
        self.assertGreaterEqual(ui.count("kbLine(m)"), 5)
        self.assertIn("if(LAST_META) kbLine(LAST_META)", ui)

    def test_ui_and_spec(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertIn('id="samplebtn"', ui)
        self.assertIn("api().sample_logs()", ui)
        spec = ENGINE / "deploy" / "local" / "logtriage.spec"
        if spec.is_file():                         # PC 빌드 spec 은 개발 트리에만(리눅스 묶음에는 samples 폴더를 그대로 싣는다 — test_r12_linux_parity)
            self.assertIn("('../../samples', 'samples')", spec.read_text(encoding="utf-8"))
        else:
            self.assertTrue((ENGINE / "samples" / "SHA256SUMS.json").is_file())


class LogLines(unittest.TestCase):
    def test_analysis_and_failure_logged_without_content(self):
        b = _base(self)
        api = _api(self, b)
        with self.assertLogs(level=logging.INFO) as cm:
            api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        line = next(l for l in cm.output if "analysis " in l and " files=" in l)   # 11차: 견본 그대로면 DEMO- 이므로 접두어에 매이지 않음
        self.assertIn("products=tomcat", line)
        self.assertIn("findings=", line)
        self.assertNotIn("HikariPool", line)                                  # 로그 내용은 남기지 않는다
        b2 = _base(self, knowledge=False)
        with self.assertLogs(level=logging.WARNING) as cm:
            _api(self, b2).analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertTrue(any("analysis failed: NoKnowledgeError" in l for l in cm.output))

    def test_startup_diag_line(self):
        from logtriage.gui.app import _diag_log
        api = _api(self, _base(self))
        with self.assertLogs(level=logging.INFO) as cm:
            _diag_log(api)
        line = next(l for l in cm.output if "self-diagnosis" in l)
        for k in ("rules=", "history=", "self_check=ok/", "install=dev"):
            self.assertIn(k, line)


class TestRunMark(unittest.TestCase):
    def test_title_and_warning(self):
        from logtriage.gui import app as A
        old = os.environ.pop("LOGTRIAGE_TEST_RUN", None)
        self.addCleanup(lambda: os.environ.__setitem__("LOGTRIAGE_TEST_RUN", old) if old is not None else os.environ.pop("LOGTRIAGE_TEST_RUN", None))
        self.assertFalse(A.window_title().startswith("[시험"))
        api = _api(self, _base(self))
        self.assertFalse(api.diag()["test_run"])
        os.environ["LOGTRIAGE_TEST_RUN"] = "1"
        self.assertTrue(A.window_title().startswith("[시험 실행 · 업무 사용 금지]"))
        d = api.diag()
        self.assertTrue(d["test_run"])
        self.assertIn("시험 실행", d["warnings"][0])


if __name__ == "__main__":
    unittest.main()
