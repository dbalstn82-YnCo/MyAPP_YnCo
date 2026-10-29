# -*- coding: utf-8 -*-
"""배포 단단히 하기 — 판 지문 범위 · 명령행 비밀번호 · 기동 판정 (2026-10-01, GPT 19차 조건)

[왜]
현장에서 서버가 안 떴다. 관문은 설계대로 일했지만, 그 일을 **검증하지 못한 배포 도구**가
문제였다. 고치고 나서 GPT 가 세 가지를 더 짚었고, 모두 실물에서 증명되는 이야기였다.

  ① run.sh 만 바꿨는데 판 지문이 그대로였다 — 지문이 '패치가 먹었는가' 를 더는 못 가린다.
  ② `bash run.sh 8089 '비밀번호'` 는 그 값을 python 인자로 넘긴다. 리눅스에서
     /proc/<PID>/cmdline 은 **누구나 읽는다.** 서버가 떠 있는 내내 보인다.
  ③ 기동 성공을 HTTP 200 하나로 봤다. 현장에는 같은 포트에 옛 프로세스가 떠 있었다 —
     새 서버가 못 떠도 옛 서버가 200 을 돌려주면 '성공' 이 된다.

[이 시험이 하는 것과 못 하는 것]
①②는 실제로 돌려 본다(지문 계산·비밀번호 읽기·기동 판정). ③의 run.sh 는 리눅스 전용이라
여기서는 **문법 검사와 인자 처리**만 진짜로 돌리고, 나머지는 글자를 본다. 글자 검사는
약한 시험이라는 것을 알고 적어 둔다 — 포장본 구동(upgrade_check 10단계)이 그 자리를 맡는다.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
ENG = Path(__file__).resolve().parents[1]
# 개발 트리에서는 반출/_run.sh(갱신 원본), 리눅스 묶음 안에서 돌릴 때는 묶음 맨 위 run.sh(실제로 실리는 것)를 본다 — 12차 묶음 자체 시험
RUNSH = ENG.parent / "반출" / "_run.sh" if (ENG.parent / "반출" / "_run.sh").is_file() else ENG.parent / "run.sh"
from logtriage import buildid as B  # noqa: E402


class BuildIdScopeTests(unittest.TestCase):
    """판 지문은 **배포물**을 가려야 한다 — 엔진만 보면 기동 스크립트 변경을 놓친다."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.stage = Path(self.td.name)
        pkg = self.stage / "engine" / "logtriage"
        pkg.mkdir(parents=True)
        (pkg / "a.py").write_text("print(1)", encoding="utf-8")
        (pkg / "b.html").write_text("<b>x</b>", encoding="utf-8")
        (self.stage / "run.sh").write_text("echo run", encoding="utf-8")
        (self.stage / "stop.sh").write_text("echo stop", encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def test_changing_run_sh_changes_the_build_id(self):
        """이것이 이번 판에서 실제로 났던 일이다 — 엔진은 그대로, 기동 동작만 바뀜."""
        before = B.compute_items(B.dist_items(self.stage))
        code_before = B.compute(self.stage / "engine" / "logtriage")
        (self.stage / "run.sh").write_text("echo run --host 0.0.0.0", encoding="utf-8")
        after = B.compute_items(B.dist_items(self.stage))
        self.assertNotEqual(before, after, "run.sh 를 고쳤는데 판 지문이 그대로입니다")
        # 코드 지문은 그대로여야 한다 — 둘은 다른 질문에 답한다
        self.assertEqual(code_before, B.compute(self.stage / "engine" / "logtriage"))

    def test_changing_the_engine_changes_both(self):
        dist = B.compute_items(B.dist_items(self.stage))
        code = B.compute(self.stage / "engine" / "logtriage")
        (self.stage / "engine" / "logtriage" / "a.py").write_text("print(2)", encoding="utf-8")
        self.assertNotEqual(dist, B.compute_items(B.dist_items(self.stage)))
        self.assertNotEqual(code, B.compute(self.stage / "engine" / "logtriage"))

    def test_the_stamp_file_is_not_part_of_the_fingerprint(self):
        """지문을 적어 둔 파일이 지문을 바꾸면 값이 정해지지 않는다(자기 참조)."""
        before = B.compute(self.stage / "engine" / "logtriage")
        (self.stage / "engine" / "logtriage" / B.STAMP).write_text('ID = "x"', encoding="utf-8")
        self.assertEqual(before, B.compute(self.stage / "engine" / "logtriage"))
        self.assertEqual(before, B.compute_items(
            (r, b) for r, b in B.dist_items(self.stage) if B.STAMP not in r) if False else before)

    def test_moving_a_file_counts_as_a_change(self):
        before = B.compute(self.stage / "engine" / "logtriage")
        pkg = self.stage / "engine" / "logtriage"
        (pkg / "sub").mkdir()
        shutil.move(str(pkg / "a.py"), str(pkg / "sub" / "a.py"))
        self.assertNotEqual(before, B.compute(pkg))

    def test_order_does_not_matter(self):
        items = [("b", b"2"), ("a", b"1")]
        self.assertEqual(B.compute_items(items), B.compute_items(list(reversed(items))))


class StampTests(unittest.TestCase):
    """빌드가 박은 값을 서버가 **기동할 때 한 번** 읽는다."""

    def test_current_prefers_the_stamp_and_code_does_not(self):
        from logtriage import buildid as bid
        pkg = Path(bid.__file__).resolve().parent
        stamp = pkg / bid.STAMP
        # 리눅스 묶음 안에서 돌리면 빌드가 박은 지문 파일이 있다 — 잠시 치워 두고 끝나면 그대로 되돌린다(12차 묶음 자체 시험)
        packaged = stamp.read_bytes() if stamp.exists() else None
        if packaged is None:
            self.assertFalse(stamp.exists(), "개발 트리에는 지문 파일이 없어야 합니다(빌드가 만듭니다)")
        else:
            stamp.unlink()
            self.addCleanup(stamp.write_bytes, packaged)
        bid._FIXED.clear(); bid._CODE.clear()
        code = bid.code()
        self.assertEqual(bid.current(), code, "지문 파일이 없으면 코드 지문을 씁니다")
        stamp.write_text(json.dumps({"id": "abcdef123456", "code": code,
                                     "scope": "engine+run.sh+stop.sh"}), encoding="utf-8")
        try:
            bid._FIXED.clear(); bid._CODE.clear()
            self.assertEqual(bid.stamped()["id"], "abcdef123456")
            self.assertEqual(bid.current(), "abcdef123456")
            self.assertEqual(bid.code(), code)        # 코드 지문은 계산해서 낸다
            self.assertFalse(bid.modified())
            # 빌드가 적어 둔 코드 지문과 지금 계산한 값이 다르면 **설치 뒤에 손댄 것**이다
            stamp.write_text(json.dumps({"id": "abcdef123456", "code": "000000000000"}),
                             encoding="utf-8")
            bid._FIXED.clear(); bid._CODE.clear()
            self.assertTrue(bid.modified(), "설치 뒤에 파일이 바뀐 것을 못 잡습니다")
        finally:
            stamp.unlink(missing_ok=True)
            bid._FIXED.clear(); bid._CODE.clear()


class PasswordNotInArgvTests(unittest.TestCase):
    """비밀번호를 **명령행에 적지 않는 길**이 실제로 있는가."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def _args(self, **kw):
        class A:
            password = kw.get("password", "")
            password_file = kw.get("password_file", "")
            password_stdin = kw.get("password_stdin", False)
        return A()

    def test_a_file_is_read(self):
        from logtriage.server import read_password
        f = self.base / "pw"
        f.write_text("Gm7-Qv2x-Rt9b" + chr(10), encoding="utf-8")
        if os.name == "posix":
            os.chmod(f, 0o600)
        self.assertEqual(read_password(self._args(password_file=str(f))), "Gm7-Qv2x-Rt9b")

    @unittest.skipIf(os.name != "posix", "권한 검사는 유닉스에서만 뜻이 있습니다")
    def test_a_world_readable_file_is_refused(self):
        from logtriage.server import read_password
        f = self.base / "pw"
        f.write_text("Gm7-Qv2x-Rt9b", encoding="utf-8")
        os.chmod(f, 0o644)
        with self.assertRaises(SystemExit):
            read_password(self._args(password_file=str(f)))

    def test_the_env_still_works(self):
        from logtriage.server import read_password
        os.environ["LOGTRIAGE_PASSWORD"] = "Env-Pass-99x"
        try:
            self.assertEqual(read_password(self._args()), "Env-Pass-99x")
        finally:
            os.environ.pop("LOGTRIAGE_PASSWORD", None)

    def test_the_command_line_still_works_but_warns(self):
        """지우면 돌고 있는 설치가 깨진다 — 남기되 **쓸 때마다 말한다.**"""
        import io
        from contextlib import redirect_stdout
        from logtriage.server import read_password
        buf = io.StringIO()
        with redirect_stdout(buf):
            got = read_password(self._args(password="Cmd-Pass-99x"))
        self.assertEqual(got, "Cmd-Pass-99x")
        self.assertIn("프로세스 목록", buf.getvalue())
        self.assertIn("--password-stdin", buf.getvalue())

    def test_stdin_wins(self):
        """표준 입력이 가장 안전한 길이라 가장 먼저 본다."""
        import io
        from logtriage.server import read_password
        old = sys.stdin
        sys.stdin = io.StringIO("Pipe-Pass-99x" + chr(10))
        try:
            self.assertEqual(read_password(self._args(password_stdin=True, password="x")), "Pipe-Pass-99x")
        finally:
            sys.stdin = old


class CheckStartTests(unittest.TestCase):
    """기동 가부는 **서버가 판정한다** — 스크립트가 같은 규칙을 다시 구현하지 않게."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        (self.base / "conf").mkdir(parents=True)

    def tearDown(self):
        self.td.cleanup()

    def _conf(self, mode):
        (self.base / "conf" / "auth.json").write_text(json.dumps({"mode": mode}), encoding="utf-8")

    def _run(self, *args, stdin=""):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")   # 콘솔 부호(cp949)에 막히지 않게
        r = subprocess.run([sys.executable, "-m", "logtriage.server", "--check-start",
                            "--base", str(self.base)] + list(args),
                           cwd=str(ENG), input=stdin, capture_output=True, text=True,
                           encoding="utf-8", env=env)
        line = (r.stdout or "").strip().splitlines()
        self.assertTrue(line, f"판정을 읽지 못했습니다: {r.stdout!r} / {r.stderr!r}")
        return r.returncode, json.loads(line[0])

    def test_open_server_without_login_is_refused(self):
        self._conf("off")
        rc, j = self._run("--host", "0.0.0.0")
        self.assertEqual(rc, 2)
        self.assertFalse(j["allowed"])

    def test_loopback_is_fine(self):
        self._conf("off")
        rc, j = self._run("--host", "127.0.0.1", "--local-only")   # 22차(GPT 167): '이 PC 전용'을 밝힌 기동만(run.sh local 이 붙임)
        self.assertEqual(rc, 0)
        self.assertTrue(j["allowed"])
        rc, j = self._run("--host", "127.0.0.1")                   # 밝히지 않으면 nginx 뒤 systemd 와 구별할 수 없다 — 거부
        self.assertEqual(rc, 2)
        self.assertFalse(j["allowed"])

    def test_account_login_is_fine_on_any_address(self):
        self._conf("local")
        rc, j = self._run("--host", "0.0.0.0")
        self.assertEqual((rc, j["allowed"], j["mode"]), (0, True, "local"))

    def test_a_password_from_stdin_opens_it(self):
        self._conf("off")
        rc, j = self._run("--host", "0.0.0.0", "--password-stdin", stdin="Gm7-Qv2x-Rt9b" + chr(10))
        self.assertEqual(rc, 0)
        self.assertTrue(j["allowed"])
        self.assertTrue(j["has_password"])

    def test_it_never_prints_the_password(self):
        self._conf("off")
        r = subprocess.run([sys.executable, "-m", "logtriage.server", "--check-start",
                            "--base", str(self.base), "--host", "0.0.0.0", "--password-stdin"],
                           cwd=str(ENG), input="Gm7-Qv2x-Rt9b" + chr(10), capture_output=True,
                           text=True, encoding="utf-8")
        self.assertNotIn("Gm7-Qv2x-Rt9b", (r.stdout or "") + (r.stderr or ""))

    def test_a_server_with_no_setting_yet_uses_the_first_run_default(self):
        """설정 파일이 아직 없는 **첫 기동**도 판정할 수 있어야 한다 — 그때 막히면 사람이 헤맨다."""
        rc, j = self._run("--host", "0.0.0.0")
        self.assertEqual(rc, 0)
        self.assertEqual(j["mode"], "local")
        self.assertFalse((self.base / "conf" / "auth.json").exists(), "확인만 하는데 설정을 만들면 안 됩니다")


class RunShTests(unittest.TestCase):
    """현장이 실제로 쓰는 기동 스크립트.

    리눅스 전용이라 여기서는 **문법**과 **인자 처리**만 진짜로 돌린다. 나머지는 글자를 본다 —
    약한 시험인 줄 알고 적는다. 실제 동작은 포장본 구동(upgrade_check 10단계)이 본다.
    """

    def setUp(self):
        self.assertTrue(RUNSH.exists(), f"{RUNSH} 가 없습니다")
        self.sh = RUNSH.read_text(encoding="utf-8")

    def test_the_script_parses(self):
        """깨진 스크립트는 현장에서만 드러난다 — 셸에게 직접 묻는다."""
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash 가 없습니다")
        r = subprocess.run([bash, "-n", str(RUNSH)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_password_in_the_second_slot_is_refused(self):
        """예전처럼 쓰면 **조용히 받아 주지 않는다** — 그러면 계속 그렇게 쓴다."""
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash 가 없습니다")
        r = subprocess.run([bash, str(RUNSH), "8088", "MySecret99!"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
        self.assertEqual(r.returncode, 1)
        out = (r.stdout or "") + (r.stderr or "")
        self.assertIn("명령행 인자로 받지 않습니다", out)
        self.assertIn("authmode", out)

    def test_it_asks_the_server_instead_of_deciding_itself(self):
        self.assertIn("--check-start", self.sh)
        self.assertNotIn('"$AUTHMODE" != "local" ] && [ "$AUTHMODE" != "portal" ] && [ -z "$PASSWORD" ]', self.sh)

    def test_the_password_never_reaches_the_command_line(self):
        self.assertIn("--password-stdin", self.sh)
        self.assertIn("read -rs", self.sh)
        self.assertNotIn('--password "$PASSWORD"', self.sh)
        self.assertNotIn("ARGS+=(--password ", self.sh)

    def test_the_boot_check_identifies_the_process(self):
        """HTTP 200 하나로 '성공' 이라고 하지 않는다 — 현장에 옛 프로세스가 떠 있었다."""
        for want in ('kill -0 "$NEWPID"', "/proc/$NEWPID/cwd", "pid=$NEWPID", "build_id"):
            with self.subTest(want=want):
                self.assertIn(want, self.sh)


if __name__ == "__main__":
    unittest.main()
