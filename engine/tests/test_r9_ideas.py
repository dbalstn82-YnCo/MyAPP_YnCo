"""2026-10-19 9차 아이디어 12건 — 승인 도우미·수렴 상한·반입 우선순위·현장 시범·머리글 대조·포장본 점검 관문·출시 강제 종료·
되돌리기 DB 예행·GPT 지적 장부·설치본 무결성·되돌리기 칸 관문·결정 감사."""
import csv
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "tools" / "build"))
from logtriage import storage  # noqa: E402


def _tmp(test):
    td = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, td, True)
    return td


def _kbase(test) -> Path:
    td = _tmp(test)
    for d in ("manuals", "errorcodes", "rules"):
        shutil.copytree(ENGINE / d, td / d)
    return td


class ApprovalAssist(unittest.TestCase):
    """① 한 건 승인은 세 질문 모두 '예' — 답은 근거로 남는다. 위험 명령이 있으면 되돌리기 '해당 없음' 불가."""

    def setUp(self):
        from logtriage import link_review as LR
        self.LR = LR
        self.base = _kbase(self)
        LR._OPENED.clear()
        its = LR.items(self.base)
        self.risky = next(x for x in its if x["danger"] and not any(r.startswith("판정 제품") for r in x["individual"]))
        self.safe = next(x for x in its if not x["danger"] and not any(r.startswith("판정 제품") for r in x["individual"]))

    def _ok(self, x, ans):
        self.LR.detail(self.base, x["procedure"], x["id"], "adm")
        return self.LR.decide(self.base, x["procedure"], x["id"], "승인", "adm", rev=0, answers=ans)

    def test_answers_required(self):
        yes = {"symptom": "예", "version": "예", "rollback": "예"}
        for bad in (None, {}, dict(yes, symptom="아니오"), dict(yes, version=""), dict(yes, rollback="해당 없음")):
            with self.assertRaises(ValueError, msg=str(bad)):
                self._ok(self.risky, bad)
        r = self._ok(self.risky, yes)
        self.assertEqual(r["answers"], yes)
        r2 = self._ok(self.safe, dict(yes, rollback="해당 없음"))          # 위험 명령 없으면 '해당 없음' 가능
        self.assertEqual(r2["answers"]["rollback"], "해당 없음")
        rows = [json.loads(l) for l in (self.base / self.LR.LOCAL_FILE).read_text(encoding="utf-8").splitlines()]
        self.assertTrue(all("answers" in r for r in rows if r["decision"] == "승인"))

    def test_assist_groups(self):
        a = self.LR.assist(self.base)
        self.assertEqual(set(a["questions"]), {"symptom", "version", "rollback"})
        self.assertEqual(sum(g["individual"] + g["batchable"] for g in a["groups"]), self.LR.counts(self.base)["대기"])


class Convergence(unittest.TestCase):
    """② 같은 사슬에서 연속 3회 부분·오류면 수렴 실패 — 재검증에서 빠지고 제조사 요청서 맨 앞."""

    def test_streak(self):
        import knowledge_sample_queue as q
        old = q.QDIR
        q.QDIR = _tmp(self)
        self.addCleanup(setattr, q, "QDIR", old)
        by = {x["key"]: x for x in q.entries()}
        from logtriage.procedures import load_procedures
        k1, k2 = sorted(by)[:2]
        rows = [{"round": "R", "key": k1, "verdict": "부분", "fixed": True, "sent_sha": "0" * 64},
                {"round": "R-re", "key": k1, "verdict": "오류", "fixed": True, "sent_sha": "0" * 64},
                {"round": "R-re2", "key": k1, "verdict": "부분", "fixed": True, "sent_sha": "0" * 64},
                {"round": "R", "key": k2, "verdict": "부분", "fixed": True, "sent_sha": "0" * 64},
                {"round": "R-re", "key": k2, "verdict": "정확", "fixed": False},
                {"round": "R-re2", "key": k2, "verdict": "부분", "fixed": True, "sent_sha": "0" * 64}]
        (q.QDIR / "결과.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
        st = {x["key"]: x for x in q.pending_items()}
        self.assertTrue(st[k1]["state"].startswith("수렴 실패"))
        self.assertEqual(st[k1]["streak"], 3)
        self.assertEqual(st[k2]["streak"], 1)                             # 사이에 '정확'이 있으면 다시 센다
        q.main(["pending"])
        self.assertEqual([x["key"] for x in json.loads((q.QDIR / "수렴실패.json").read_text(encoding="utf-8"))], [k1])
        q.main(["reverify"])
        sent = json.loads((q.QDIR / "재검증-R-re3.json").read_text(encoding="utf-8"))
        self.assertNotIn(k1, [x["key"] for x in sent["items"]])
        self.assertIn(k2, [x["key"] for x in sent["items"]])


class DocPlan(unittest.TestCase):
    """③ 식별어 꼴 → 문서 종류, 문서 주소 제외, 수렴 실패 묶음이 맨 앞."""

    def test_kinds_and_order(self):
        import vendor_doc_match as vd
        self.assertEqual(vd.doc_kind("v$lock", "tibero"), "참조 안내서(동적 뷰·데이터 사전)")
        self.assertEqual(vd.doc_kind("sess_id", "tibero"), "참조 안내서(동적 뷰·데이터 사전)")
        self.assertEqual(vd.doc_kind("error_lockfail_in_nowait", "tibero"), "오류 메시지 안내서")
        self.assertEqual(vd.doc_kind("--parallel", "linux"), "명령어 안내서(man·CLI 옵션)")
        self.assertIsNone(vd.doc_kind("docs.tmaxsoft", "tibero"))
        old = vd.OUT
        vd.OUT = _tmp(self)
        self.addCleanup(setattr, vd, "OUT", old)
        (vd.OUT / "수렴실패.json").write_text(json.dumps([{"key": "TIBERO:TBR-12033", "round": "R", "streak": 5}]), encoding="utf-8")
        vd.main(["plan"])
        first = (vd.OUT / "반입요청우선순위.md").read_text(encoding="utf-8").split("| 1 |", 1)[1].split("\n", 1)[0]
        self.assertIn("수렴 실패 포함", first)


class Pilot(unittest.TestCase):
    """④⑤ 시범 묶음 → 담당자 양식 → 같은 검사로 줄마다 → 현장 보고, 미확인 칼럼과 머리글 대조."""

    def test_make_import_and_columns(self):
        import field_pilot as fp
        import import_field_exec as ife
        out = _tmp(self)
        old = fp.OUT
        fp.OUT = out
        self.addCleanup(setattr, fp, "OUT", old)
        self.assertEqual(fp.main(["make", "--product", "tibero", "--n", "20"]), 0)
        f = out / "tibero-시범-보고양식.csv"
        rows = list(csv.reader(f.read_text(encoding="utf-8-sig").splitlines()))
        self.assertEqual(rows[0], fp.COLS)
        self.assertGreaterEqual(len(rows) - 1, 10)
        tbr = next((r for r in rows[1:] if r[1] == "TIBERO:TBR-12033"), None)
        rows[1][4:7] = ["성공", "", "TYPE ID1 ID2 SESS_ID LMODE"]
        rows[2][4:7] = ["성공", "", "TYPE 20261019"]                      # 값 같은 머리글 — 그 줄만 거절
        if tbr is not None and tbr is not rows[1] and tbr is not rows[2]:
            tbr[4:7] = ["성공", "", "TYPE ID1 ID2 SESS_ID LMODE REQUESTED"]
        with f.open("w", encoding="utf-8-sig", newline="") as fh:
            csv.writer(fh).writerows(rows)
        vp = _tmp(self) / "_verification.yaml"
        shutil.copy(ENGINE / "errorcodes" / "_verification.yaml", vp)
        o2 = ife.VP, ife.OUT
        ife.VP, ife.OUT = vp, vp.with_name("현장실행.md")
        self.addCleanup(lambda: (setattr(ife, "VP", o2[0]), setattr(ife, "OUT", o2[1])))
        self.assertEqual(fp.main(["import", str(f), "--site", "PILOT"]), 1)       # 거절 줄이 있으면 1
        import yaml
        v = yaml.safe_load(vp.read_text(encoding="utf-8"))
        self.assertEqual(v["field_exec"][rows[1][1].upper()]["ok"], 1)
        self.assertNotIn(rows[2][1].upper(), v["field_exec"])
        fp.main(["import", str(f), "--site", "PILOT"])                          # 다시 넣어도 두 번 안 셈
        v = yaml.safe_load(vp.read_text(encoding="utf-8"))
        self.assertEqual(v["field_exec"][rows[1][1].upper()]["ok"], 1)
        cc = ife.column_check({"TIBERO:TBR-12033": {"headers": ["TYPE ID1 ID2 SESS_ID LMODE"]}})
        self.assertIn("SESS_ID", cc["TIBERO:TBR-12033"]["seen"])
        self.assertIn("REQUESTED", cc["TIBERO:TBR-12033"]["missing"])


class InstallGate(unittest.TestCase):
    """⑥⑩ 포장본 점검이 그 exe 해시로 전부 통과해야 이동 설치 · 설치 기록과 실행 exe 대조."""

    def setUp(self):
        import install_move as im
        self.im = im
        self.td = _tmp(self)
        self.run_ = self.td / "run"
        self.dist = self.td / "dist"
        self.bk = self.td / "backup"
        for d in (self.run_, self.dist, self.bk):
            d.mkdir()
        (self.run_ / "LogTriage.exe").write_bytes(b"MZnew")
        (self.run_ / "logtriage-cli.exe").write_bytes(b"MZcli-new")
        (self.dist / "LogTriage.exe").write_bytes(b"MZcur")
        (self.dist / "LogTriage.exe.이전판").write_bytes(b"MZprev")
        (self.dist / "logtriage-cli.exe").write_bytes(b"MZcli-cur")
        self.checks = self.td / "exe_checks.json"
        o = (im.CHECKS, im.LOCAL)
        im.CHECKS = self.checks
        im.LOCAL = self.td
        self.addCleanup(lambda: (setattr(im, "CHECKS", o[0]), setattr(im, "LOCAL", o[1])))

    def _w(self, ok=True, gui=None):
        self.checks.write_text(json.dumps({"at": "t", "ok": ok, "gui_sha": gui or self.im.sha(self.run_ / "LogTriage.exe"),
                                           "cli_sha": self.im.sha(self.run_ / "logtriage-cli.exe"), "results": {"a": {"ok": ok}}}), encoding="utf-8")

    def test_gate_and_move(self):
        args = [str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]
        self.assertEqual(self.im.main(args), 1)                        # 기록 없음
        self._w(ok=False)
        self.assertEqual(self.im.main(args), 1)                        # 점검 실패
        self._w(gui="0" * 64)
        self.assertEqual(self.im.main(args), 1)                        # 다른 판의 점검
        self._w()
        self.assertEqual(self.im.main(args), 0)
        self.assertEqual((self.dist / "LogTriage.exe").read_bytes(), b"MZnew")
        self.assertEqual((self.dist / "LogTriage.exe.이전판").read_bytes(), b"MZcur")
        self.assertEqual((self.bk / "LogTriage.exe.7").read_bytes(), b"MZprev")
        self.assertEqual((self.bk / "logtriage-cli.exe.8").read_bytes(), b"MZcli-cur")
        self.assertFalse((self.run_ / "LogTriage.exe").exists())          # 복사가 아니라 이동
        st = json.loads((self.dist / "install-stamp.json").read_text(encoding="utf-8"))
        self.assertEqual(st["gui_sha"], self.im.sha(self.dist / "LogTriage.exe"))

    def test_mid_move_failure_rolls_back(self):
        """GPT 70차 P0: 세 번째 이동에서 실패 → 앞의 두 이동을 되돌려 배포 폴더가 설치 전 그대로."""
        self._w()
        before = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        real = self.im.os.replace
        n = [0]

        def flaky(a, b):
            n[0] += 1
            if n[0] == 3:
                raise OSError("디스크 오류(시험)")
            return real(a, b)
        self.im.os.replace = flaky
        self.addCleanup(setattr, self.im.os, "replace", real)
        self.assertEqual(self.im.main([str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]), 1)
        self.im.os.replace = real
        self.assertEqual({p.name: p.read_bytes() for p in self.dist.iterdir()}, before)
        self.assertTrue((self.run_ / "LogTriage.exe").exists())
        self.assertEqual(list(self.bk.iterdir()), [])

    def test_killed_mid_install(self):
        """GPT 71차 P0: 이동 1~4번째 직후 프로세스가 죽으면(예외 처리 못 돎) — 앱은 뜨지 않고, 다음 실행이 일지로 되돌린 뒤 다시 하면 설치된다."""
        import subprocess
        from logtriage.server import release_leftover
        self._w()
        (self.dist / self.im.STAMP).write_text('{"gui_sha": "OLD"}', encoding="utf-8")
        before = {p.name: p.read_bytes() for p in self.dist.iterdir()}
        code = ("import sys, os; sys.path.insert(0, %r); import install_move as im; from pathlib import Path; "
                "im.CHECKS = Path(%r); im.LOCAL = Path(%r); _r = os.replace; n = [0]\n"
                "def rep(a, b):\n    _r(a, b); n[0] += 1\n    if n[0] == %%d: os._exit(9)\n"
                "im.os.replace = rep\nif %%d == 6: im.Path.unlink = lambda *a, **k: os._exit(9)\nim.main([%r, '--retire', '7', '--cli-retire', '8', '--dist', %r])\n"
                % (str(ENGINE / "tools" / "build"), str(self.checks), str(self.td), str(self.run_), str(self.dist)))
        for k in (1, 2, 3, 4, 5, 6):   # 72차: 5 = 이동 다 끝나고 도장 전, 6 = 도장 쓴 뒤 흔적 지우기 전
            subprocess.run([sys.executable, "-c", code % (k, k)], capture_output=True, timeout=60)
            self.assertTrue((self.dist / self.im.PENDING).exists(), k)
            self.assertIn("이동 설치가 중간에 멈춘", release_leftover(self.dist))
            self.assertEqual(self.im.main([str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]), 1)   # 먼저 되돌림
            self.assertFalse((self.dist / self.im.PENDING).exists())
            self.assertEqual({p.name: p.read_bytes() for p in self.dist.iterdir()}, before, k)
            self.assertEqual(list(self.bk.iterdir()), [], k)
        self.assertEqual(self.im.main([str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]), 0)
        self.assertEqual((self.dist / "LogTriage.exe").read_bytes(), b"MZnew")
        self.assertEqual(release_leftover(self.dist), "")

    def _kill_at(self, k):
        import subprocess
        code = ("import sys, os; sys.path.insert(0, %r); import install_move as im; from pathlib import Path; "
                "im.CHECKS = Path(%r); im.LOCAL = Path(%r); _r = os.replace; n = [0]\n"
                "def rep(a, b):\n    _r(a, b); n[0] += 1\n    if n[0] == %d: os._exit(9)\n"
                "im.os.replace = rep\nim.main([%r, '--retire', '7', '--cli-retire', '8', '--dist', %r])\n"
                % (str(ENGINE / "tools" / "build"), str(self.checks), str(self.td), k, str(self.run_), str(self.dist)))
        subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=60)
        self.assertTrue((self.dist / self.im.PENDING).exists())

    def _snap(self):
        return {str(p.relative_to(self.td)): p.read_bytes() for p in self.td.rglob("*") if p.is_file() and p.name != self.im.PENDING}

    def test_undo_refuses_ambiguous_states(self):
        """GPT 72차 P0-02·03: 손댄 백업 · 양쪽 다 있음 · 양쪽 다 없음 · 일지 경로 조작 — 아무것도 옮기지 않고 흔적 유지, 앱도 계속 거부."""
        from logtriage.server import release_leftover
        args = [str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]
        self._w()
        pend = self.dist / self.im.PENDING
        (self.td / "other").mkdir()

        def add_move(src, dst):                                                # 일지에 실재 파일을 가리키는 이동을 끼워 넣음(sha 까지 맞춤)
            dst.write_bytes(b"victim")
            j = json.loads(pend.read_text(encoding="utf-8"))
            j["moves"].append([str(src), str(dst), self.im.sha(dst)])
            pend.write_text(json.dumps(j, ensure_ascii=False), encoding="utf-8")

        cases = {   # 사례 → (망가뜨리기, 막아야 할 관문의 글)
            "손댄 백업": (lambda: (self.bk / "LogTriage.exe.7").write_bytes(b"MZevil"), "상태가 일지와 다릅니다"),
            "양쪽 다 있음": (lambda: (self.dist / "LogTriage.exe.이전판").write_bytes(b"MZother"), "상태가 일지와 다릅니다"),
            "양쪽 다 없음": (lambda: (self.bk / "LogTriage.exe.7").unlink(), "상태가 일지와 다릅니다"),
            "일지 경로 조작": (lambda: add_move(self.td / "other" / "LogTriage.exe.s", self.td / "other" / "LogTriage.exe.v"), "설치 계획 밖"),
            "일지 이름 조작": (lambda: add_move(self.dist / "data2.db", self.dist / "data.db"), "설치 계획 밖"),
            "되돌린 뒤 낯선 exe": (lambda: (self.dist / "LogTriage.exe.손").write_bytes(b"MZhand"), "계획대로 되돌려도 배포 폴더 exe 가 설치 전과 다릅니다"),
            # GPT 73차 P0: 아직 안 옮긴 이동(cli → backup)의 목적지에 낯선 파일 — 출발지 sha 만 보면 '안 옮김'으로 넘어가 복구 완료가 됐다
            "안 옮긴 이동의 목적지에 낯선 파일": (lambda: (self.bk / "logtriage-cli.exe.8").write_bytes(b"MZstray"), "계획대로 되돌려도 설치 전과 다릅니다"),
        }
        for name, (spoil, gate_msg) in cases.items():
            with self.subTest(name):
                self._kill_at(1)                                               # 이전판 → backup/…7 만 옮기고 죽음
                spoil()
                snap = self._snap()
                self.assertIn(gate_msg, self.im.undo_pending(pend), name)      # 어느 관문이 막았는지까지 확인
                self.assertTrue(pend.exists(), name)                           # 흔적 유지
                self.assertEqual(self._snap(), snap, name)                     # 아무것도 옮기지 않음(73차: 대조를 옮기기 전에)
                self.assertEqual(self.im.main(args), 1)
                self.assertTrue(pend.exists(), name)
                self.assertIn("이동 설치가 중간에 멈춘", release_leftover(self.dist))
                for q in (self.td / "other").iterdir():
                    q.unlink()
                for q in ("data.db", "LogTriage.exe.손"):
                    (self.dist / q).unlink(missing_ok=True)
                # 다음 사례를 위해 원상태로
                pend.unlink()
                for q in list(self.bk.iterdir()):
                    q.unlink()
                (self.dist / "LogTriage.exe.이전판").write_bytes(b"MZprev")
        self.assertEqual(sorted(p.name for p in self.dist.iterdir()), ["LogTriage.exe", "LogTriage.exe.이전판", "logtriage-cli.exe"])

    def test_undo_plain_files_only(self):
        """링크(재분석 지점)는 일지가 가리켜도 옮기지 않는다 — 심볼릭 링크를 만들 권한이 없는 PC 에서는 건너뜀."""
        import install_move as im
        f = self.td / "real.exe"
        f.write_bytes(b"x")
        link = self.td / "LogTriage.exe.link"
        try:
            os.symlink(f, link)
        except OSError:
            self.skipTest("심볼릭 링크 권한 없음")
        self.assertFalse(im._plain(link))
        self.assertTrue(im._plain(f))
        self.assertTrue(im._plain(self.td / "없음.exe"))

    def test_install_refuses_while_running(self):
        self._w()
        before = self._snap()
        o = self.im.running_from
        self.im.running_from = lambda root: ["4242"]
        self.addCleanup(lambda: setattr(self.im, "running_from", o))
        self.assertEqual(self.im.main([str(self.run_), "--retire", "7", "--cli-retire", "8", "--dist", str(self.dist)]), 1)
        self.assertEqual(self._snap(), before)
        self.assertFalse((self.dist / self.im.PENDING).exists())

    def test_runtime_check(self):
        from logtriage.server import ServerApi
        f = type("F", (), {"_base": self.td, "_INSTALL": {}})()
        self.assertEqual(ServerApi.install_check(f)["state"], "dev")   # 개발 실행은 대조 안 함
        exe = self.dist / "LogTriage.exe"
        (self.dist / "install-stamp.json").write_text(json.dumps({"gui_sha": self.im.sha(exe), "cli_sha": ""}), encoding="utf-8")
        o = (getattr(sys, "frozen", None), sys.executable)
        sys.frozen, sys.executable = True, str(exe)
        try:
            f._INSTALL = {}
            self.assertEqual(ServerApi.install_check(f)["state"], "ok")
            exe.write_bytes(b"MZswapped")
            f._INSTALL = {}
            self.assertEqual(ServerApi.install_check(f)["state"], "mismatch")
        finally:
            if o[0] is None:
                del sys.frozen
            else:
                sys.frozen = o[0]
            sys.executable = o[1]

    def test_ledger_label(self):
        import build_ledger as bl
        o = bl.LOCAL
        bl.LOCAL = self.td
        self.addCleanup(setattr, bl, "LOCAL", o)
        (self.td / "build").mkdir()
        self._w()
        shutil.copy(self.checks, self.td / "build" / "exe_checks.json")
        h = {"gui": self.im.sha(self.run_ / "LogTriage.exe"), "cli": self.im.sha(self.run_ / "logtriage-cli.exe")}
        self.assertTrue(bl.exe_checks_label(h).startswith("통과 1/1"))
        self.assertTrue(bl.exe_checks_label({"gui": "x", "cli": "y"}).startswith("기록 없음"))


class CrashFuzz(unittest.TestCase):
    """⑦ 이름 바꾸기 1~6번째 직후 종료(주입) + 무작위 종료 — 섞임 0, 흔적 있으면 앱 거부, recover 뒤 구판."""

    def test_fuzz(self):
        import release_crash_fuzz as rf
        s = rf.run(2, seed=7, max_delay=1.5)
        self.assertEqual((s["injected"], s["recover_injected"]), (6, 3))
        self.assertEqual(s["violations"], [])
        self.assertIn(".lt-know-new+.lt-know-old", s["phases"])          # 주입이 실제로 바꿔치기 한가운데를 맞혔다

    def test_mixed_without_trace_refused(self):
        """GPT 70·71차: 흔적 없이 한 폴더만 바뀌면(세대 기록의 내용 지문과 일부만 다름) 기동 거부.
        룰팩처럼 한 폴더만 바꾸고 세대 기록을 갱신하면 거부하지 않는다(폴더 안 표식은 룰팩이 지워 거짓 '섞임'이 됐다 — 설계 변경)."""
        import knowledge_release as kr
        from logtriage import knowledge_gen as KG
        from logtriage.server import release_leftover, make_server
        dist = _tmp(self)
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        self.assertTrue((dist / KG.FILE).exists())
        self.assertEqual(release_leftover(dist), "")
        f = next((dist / "rules").rglob("*.yaml"))
        f.write_text(f.read_text(encoding="utf-8") + "\n# 손으로 바꿈\n", encoding="utf-8")
        self.assertIn("지식 폴더 rules 이(가)", release_leftover(dist))
        with self.assertRaises(SystemExit):
            make_server("127.0.0.1", 0, dist, None)
        KG.write_gen(dist, "rulepack 시험")                                   # 룰팩 적용은 세대 기록을 갱신한다
        self.assertEqual(release_leftover(dist), "")
        for d in KG.DIRS:                                                      # 72차 P0-01: 셋 다 바뀌어도 거부(한 폴더 신판+한 폴더 손 수정 = 셋 다 다름)
            g = next((dist / d).rglob("*.yaml"))
            g.write_text(g.read_text(encoding="utf-8") + "\n# x\n", encoding="utf-8")
        self.assertIn("rules, errorcodes, manuals", release_leftover(dist))
        KG.write_gen(dist, "재출시")
        self.assertEqual(release_leftover(dist), "")
        (dist / KG.FILE).write_text("{깨짐", encoding="utf-8")
        self.assertIn("깨져", release_leftover(dist))
        (dist / KG.FILE).unlink()
        self.assertEqual(release_leftover(dist), "")                           # 기록 없음 = 옛 설치
        (dist / "knowledge-manifest.json").write_text('{"files": {}, "gen_era": true}', encoding="utf-8")
        self.assertIn("기록이 사라져", release_leftover(dist))                  # 71차: 세대 기록 시대 설치에서 기록이 사라짐 → 거부
        (dist / "knowledge-manifest.json").write_text('{"files": {}}', encoding="utf-8")
        self.assertEqual(release_leftover(dist), "")

    def test_after_check_marks_gen_era(self):
        """71차: 출시 사후 검사가 매니페스트에 gen_era 를 남긴다 — 뒤에 기록이 지워지면 기동 거부."""
        import knowledge_release as kr
        import check_dist_knowledge as cdk
        from logtriage import knowledge_gen as KG
        from logtriage.server import release_leftover
        dist = _tmp(self)
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        self.assertEqual(cdk.main(["--after", "--dist", str(dist)]), 0)
        self.assertTrue(json.loads((dist / "knowledge-manifest.json").read_text(encoding="utf-8"))["gen_era"])
        self.assertEqual(release_leftover(dist), "")
        (dist / KG.FILE).unlink()
        self.assertIn("기록이 사라져", release_leftover(dist))

    def test_release_refuses_while_running(self):
        """72차 P1-02 부분 수용의 근거: 앱이 배포 폴더에서 돌면 지식 출시는 바꿔치기 전에 멈춘다(지식 읽기와 겹치지 않게)."""
        import knowledge_release as kr
        dist = _tmp(self)
        saved = {k: getattr(kr, k) for k in ("step_exec", "step_audit", "step_tests", "step_dist", "running_from")}
        self.addCleanup(lambda: [setattr(kr, k, v) for k, v in saved.items()])
        kr.step_exec = kr.step_audit = lambda: (True, "")
        kr.step_tests = lambda res: (True, "")
        kr.step_dist = lambda d, ph: (True, "")
        kr.running_from = lambda root: ["4242"]
        self.assertEqual(kr.main(["--note", "시험", "--dist", str(dist)]), 1)
        self.assertEqual(list(dist.iterdir()), [])                             # 아무것도 바꾸지 않음

    def test_recover_restores_gen(self):
        import knowledge_release as kr
        from logtriage import knowledge_gen as KG
        from logtriage.server import release_leftover
        dist = _tmp(self)
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        before = (dist / KG.FILE).read_text(encoding="utf-8")
        f = next(p for p in sorted((dist / "rules").rglob("*.yaml")))
        f.write_text(f.read_text(encoding="utf-8") + "\n# 구판\n", encoding="utf-8")
        KG.write_gen(dist, "구판")
        before = (dist / KG.FILE).read_text(encoding="utf-8")
        kr.copy_knowledge(dist)                                                # 전환 뒤 사후 검사 전에 멈춘 것처럼
        self.assertNotEqual((dist / KG.FILE).read_text(encoding="utf-8"), before)
        kr.recover(dist)
        self.assertEqual((dist / KG.FILE).read_text(encoding="utf-8"), before)  # 세대 기록도 구판으로
        self.assertEqual(release_leftover(dist), "")


class RulepackGen(unittest.TestCase):
    """GPT 71차 P1 · 설계 변경 근거: 룰팩은 rules 만 통째로 바꾼다 — 적용 뒤 세대 기록을 갱신하지 않으면 다음 기동이 '한 폴더만 바뀜'으로 거부된다."""

    def test_apply_updates_gen(self):
        from logtriage import rulepack, knowledge_gen as KG
        from logtriage.server import release_leftover
        td = _tmp(self)
        src = td / "src"; src.mkdir()
        (src / "r.yaml").write_text('rules:\n- id: GEN-1\n  layer: was\n  product: [tomcat]\n  match: {regex: "OutOfMemoryError"}\n  verdict: Memory failure\n', encoding="utf-8")
        sig = rulepack.load_signing_key(td / "sign.pem", create=True)
        pub = rulepack.public_bytes(sig)
        base = td / "site"
        for d in KG.DIRS:
            (base / d).mkdir(parents=True)
            (base / d / "a.yaml").write_text("x: 1\n", encoding="utf-8")
        KG.write_gen(base, "설치")
        old = (base / KG.FILE).read_text(encoding="utf-8")
        pk = td / "p.rpk"
        rulepack.build(src, pk, None, signer=sig)
        rulepack.apply(pk, base / "rules", pub, confirm_fp=rulepack.fingerprint(pub))
        self.assertNotEqual((base / KG.FILE).read_text(encoding="utf-8"), old)
        self.assertIn("rulepack", (base / KG.FILE).read_text(encoding="utf-8"))
        self.assertEqual(release_leftover(base), "")


class RollbackRehearsal(unittest.TestCase):
    """⑧ 이전판 소스로 새 판 분석 DB 를 열고 읽는다 + 잃는 것·섞여 읽히는 것 목록."""

    def test_rehearsal(self):
        import rollback_compat as rbc
        import rollback_rehearsal as rbr
        exe = rbc.LOCAL / "dist" / "LogTriage.exe.이전판"
        snap = rbc.SRC / f"src-{rbc.sha16(exe)}.zip" if exe.is_file() else None
        if not snap or not snap.is_file():
            self.skipTest("이전판 소스 스냅숏 없음")
        r = rbr.run(snap)
        self.assertEqual(r["result"], "pass", r["steps"])
        self.assertTrue(r["steps"]["write_incident"]["ok"] and r["steps"]["reread_by_new"]["ok"])   # GPT 70차: 쓰기 뒤 새 판으로 다시 읽기
        self.assertGreaterEqual(r["losses"]["exec_reports"], 1)
        self.assertEqual(r["losses"]["instance_conflicts"], 1)
        self.assertIn("섞여 읽힘", r["note"])


class Findings(unittest.TestCase):
    """⑨ 수용은 지키는 시험 이름 필수·실제 있는 시험이어야, 되풀이 지적 찾기."""

    def test_ledger(self):
        import gpt_findings as gf
        old = gf.LEDGER
        gf.LEDGER = _tmp(self) / "GPT지적장부.jsonl"
        self.addCleanup(setattr, gf, "LEDGER", old)
        base = ["add", "--round", "1", "--area", "③", "--reason", "근거", "--where", "x"]
        self.assertEqual(gf.main(base + ["--id", "1-a", "--finding", "설치 폴더 되돌리기 위험", "--decision", "수용"]), 2)   # 시험 없음
        self.assertEqual(gf.main(base + ["--id", "1-a", "--finding", "설치 폴더 되돌리기 위험", "--decision", "수용", "--test", "test_ledger"]), 0)
        self.assertEqual(gf.main(base + ["--id", "1-a", "--finding", "중복", "--decision", "수용", "--test", "test_ledger"]), 2)   # 같은 id
        gf.main(["add", "--round", "2", "--area", "③", "--reason", "근거", "--where", "x", "--id", "2-a", "--finding", "설치 폴더 되돌리기 위험 여전",
                 "--decision", "수용", "--test", "test_no_such_test_xyz"])
        r = gf.check()
        self.assertIn("2-a", r["missing_test"])
        self.assertIn(("1-a", "2-a"), r["repeat"])


class RollbackGate(unittest.TestCase):
    """⑪ 2차 위험 명령에 되돌리기 칸이 없으면 지식 출시 2단계가 멈춘다."""

    def test_gaps(self):
        from logtriage.kb_audit import rollback_gaps
        self.assertEqual(rollback_gaps(ENGINE), [])
        base = _kbase(self)
        (base / "manuals" / "zz_test_procedures.yaml").write_text(
            "procedures:\n- id: ZZ-PROC-1\n  products: [linux]\n  category: disk\n  match: [ZZ-1]\n  title: 시험\n  stages:\n"
            "  - stage: 1\n    steps:\n    - do: 확인\n      cmd: df -h\n      check: 보기\n"
            "  - stage: 2\n    steps:\n    - do: 지우기\n      cmd: rm -rf /tmp/x\n      check: 없어짐\n      note: '사전조건: 승인 · 영향: 파일 삭제'\n",
            encoding="utf-8")
        gaps = rollback_gaps(base)
        self.assertEqual([g["procedure"] for g in gaps], ["ZZ-PROC-1"])
        f = base / "manuals" / "zz_test_procedures.yaml"
        t = f.read_text(encoding="utf-8")
        for note, bad in (("사전조건: 승인 · 백업/롤백: 없음", True), ("사전조건: 승인 · 백업/롤백: 추후 확인", True),   # GPT 70차: 글자만 채운 계획
                          ("백업/롤백: 되돌릴 수 없음", True),                                                       # 되돌릴 수 없는데 승인 조건 없음
                          ("승인: 운영 책임자 · 백업/롤백: 되돌릴 수 없음 — 지우기 전 /tmp/x 목록 보관", False),
                          ("사전조건: 승인 · 백업/롤백: 지우기 전 tar 로 /backup 에 보관, 되돌릴 때 tar 로 풀기", False)):
            f.write_text(t.replace("'사전조건: 승인 · 영향: 파일 삭제'", repr(note).replace('"', "'")), encoding="utf-8")
            self.assertEqual(bool(rollback_gaps(base)), bad, note)


class Governance(unittest.TestCase):
    """⑫ 한 달 동안의 관리자 결정 — 결정자별·장애 묶음·판 지정·현장 보고."""

    def test_report(self):
        from logtriage import link_review as LR
        from logtriage.server import ServerApi
        base = _kbase(self)
        st = storage.Storage("sqlite:///" + (base / "t.db").as_posix())
        st.save_incident({"id": "I1", "analyzed_at": "2026-10-19", "files": [], "checklist": []})
        st.set_incident_group(["I1"], "G-1", "같은 장애 두 번 분석", {"login": "adm"})
        st.set_host_version("db1", "postgresql", "16", actor={"login": "adm"}, instance="pg16")
        x = LR.items(base)[0]
        LR.decide(base, x["procedure"], x["id"], "반려", "adm", "진단 대상이 다름", rev=0)
        f = type("F", (), {"_base": base, "store": st})()
        r = ServerApi.governance_report(f, time.strftime("%Y-%m"))
        self.assertEqual((r["link"].get("반려"), r["groups"], r["versions"]), (1, 1, 1))
        self.assertIn("adm", r["markdown"])
        self.assertIn("error", ServerApi.governance_report(f, "2026/10"))


class Round70P1(unittest.TestCase):
    """GPT 70차 P1 — CSV 수식 주입·반입 기록, 월보 이스케이프, 수렴 실패 재진입, 설치 기록 깨짐, 장부 시험 실제 실행."""

    def test_csv_cells(self):
        import field_pilot as fp
        self.assertEqual(fp.cell("=cmd|' /C calc'!A0"), "'=cmd|' /C calc'!A0")
        self.assertEqual(fp.cell("-rf"), "'-rf")
        self.assertEqual(fp.cell("grep x"), "grep x")
        self.assertEqual(fp.uncell("'=SUM(1)"), "=SUM(1)")
        self.assertEqual(fp.uncell("'abc"), "'abc")                          # 우리가 붙인 것만 뗀다
        for v in ["'-rf", "'=x", "''=x", "=x", "'abc", "abc", "'", "", "@a", "\t1", "''", "'+1"]:   # 72차: 손대지 않은 칸은 정확히 왕복
            self.assertEqual(fp.uncell(fp.cell(v)), v, v)
            self.assertFalse(fp.cell(v).lstrip("'")[:1] in fp._FORMULA and not fp.cell(v).startswith("'"), v)

    def test_governance_escape(self):
        from logtriage.server import ServerApi
        base = _kbase(self)
        st = storage.Storage("sqlite:///" + (base / "t.db").as_posix())
        st.save_incident({"id": "I1", "analyzed_at": "2026-10-19", "files": [], "checklist": []})
        st.set_incident_group(["I1"], "G-1", "표|깨기 `코드`\n줄바꿈 사유", {"login": "a|b"})
        r = ServerApi.governance_report(type("F", (), {"_base": base, "store": st})(), time.strftime("%Y-%m"))
        row = next(l for l in r["markdown"].splitlines() if "I1" in l)
        self.assertEqual(row.count(" | "), 4)                               # 칸 수가 그대로(| 이스케이프)
        self.assertIn("표\\|깨기 \\`코드\\` 줄바꿈 사유", row)

    def test_stuck_reentry(self):
        import knowledge_sample_queue as q
        old = q.QDIR
        q.QDIR = _tmp(self)
        self.addCleanup(setattr, q, "QDIR", old)
        k = sorted({x["key"] for x in q.entries()})[0]
        rows = [{"round": r, "key": k, "verdict": "부분", "fixed": True, "sent_sha": "0" * 64} for r in ("R", "R-re", "R-re2")]
        (q.QDIR / "결과.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
        q.main(["reverify"])
        self.assertFalse((q.QDIR / "재검증-R-re3.json").exists())             # 수렴 실패는 빠짐
        q.main(["reverify", "--include-stuck", k])
        self.assertEqual([x["key"] for x in json.loads((q.QDIR / "재검증-R-re3.json").read_text(encoding="utf-8"))["items"]], [k])

    def test_broken_stamp(self):
        from logtriage.server import ServerApi
        td = _tmp(self)
        exe = td / "LogTriage.exe"
        exe.write_bytes(b"MZ")
        o = (getattr(sys, "frozen", None), sys.executable)
        sys.frozen, sys.executable = True, str(exe)
        try:
            f = type("F", (), {"_base": td, "_INSTALL": {}})()
            self.assertEqual(ServerApi.install_check(f)["state"], "no_stamp")
            (td / "install-stamp.json").write_text("{깨짐", encoding="utf-8")
            f._INSTALL = {}
            self.assertEqual(ServerApi.install_check(f)["state"], "broken")
        finally:
            if o[0] is None:
                del sys.frozen
            else:
                sys.frozen = o[0]
            sys.executable = o[1]

    def test_findings_run(self):
        import gpt_findings as gf
        old = gf.LEDGER
        gf.LEDGER = _tmp(self) / "GPT지적장부.jsonl"
        self.addCleanup(setattr, gf, "LEDGER", old)
        gf.main(["add", "--round", "1", "--area", "x", "--reason", "r", "--id", "1", "--finding", "f", "--decision", "수용", "--test", "test_csv_cells"])
        self.assertEqual(gf.run_tests(), [])


if __name__ == "__main__":
    unittest.main()
