"""21차(2026-10-26 마스터): '로컬 단독 설치형에서 서버 모니터링을 위한 agent 파일이 없다'.
① PC 묶음(make_pc_zip)에 agent 폴더 · server.conf.example · LogTriage-server.cmd — 사용법의 '서버 모드' 절차가 쓰는 파일
② 같은 경로의 구멍: server.conf.example 의 PASSWORD='바꾸세요' 를 그대로 두면 누구나 아는 값으로 LAN 에 열렸다
   → 공통(make_server, 리눅스 포함): 예시 자리 값으로 LAN 수신 거부 / 윈도우 exe(창·상시): 10자 미만도 거부"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "tools" / "build"))

from logtriage.server import PW_KDF, as_verifier, make_server, weak_shared_password  # noqa: E402


class WeakSharedPasswordTest(unittest.TestCase):
    def test_placeholders_and_length(self):
        for pw in ("바꾸세요", "change-me", "CHANGEME", " password "):
            self.assertTrue(weak_shared_password(pw), pw)
        self.assertEqual(weak_shared_password("short9char"[:9]), "")             # 공통 규칙은 자리 값만
        self.assertEqual(weak_shared_password("short9cha", strict=True), "10자 미만")   # exe 는 길이도
        self.assertEqual(weak_shared_password("Lt-Strong-Pass-26", strict=True), "")
        self.assertEqual(weak_shared_password(None, strict=True), "")
        v = as_verifier("바꾸세요")                                               # 검증값은 원문을 모른다 — 판단하지 않음
        self.assertTrue(str(v).startswith(PW_KDF + "$"))
        self.assertEqual(weak_shared_password(v, strict=True), "")

    def test_make_server_refuses_placeholder_on_lan_only(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as cm:
                make_server("0.0.0.0", 0, Path(td), "바꾸세요")
            self.assertIn("LAN", str(cm.exception))
        with tempfile.TemporaryDirectory() as td:                                # 이 PC 안(루프백)은 그대로 — 기존 동작 유지
            httpd, _ = make_server("127.0.0.1", 0, Path(td), "바꾸세요")
            httpd.server_close()

    def test_exe_paths_use_strict_check(self):
        src = (ENGINE / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")
        self.assertEqual(src.count("weak_shared_password(password, strict=True)"), 2)   # 상시 모드 · 창 모드
        self.assertIn('listen, port, password, _down = "127.0.0.1", 0, None,', src)       # 창 모드는 이 PC 안에서만으로 내림(22차: 까닭도 남김)


class PcZipAgentTest(unittest.TestCase):
    def setUp(self):
        import make_pc_zip
        self.m = make_pc_zip

    def test_agent_files_listed(self):
        names = self.m.agent_files()
        for n in ("lt-agent.sh", "lt-agent.py", "lt-agent.ps1", "lt-agent.cmd", "lt-agent-ctl.sh", "lt-agent-install.sh", "lt_procs.py", "README.txt"):
            self.assertIn(n, names)
        self.assertNotIn("lt-agent-setup.sh", names)          # 서버가 해시를 채워 주는 틀 — 그대로는 못 씀
        self.assertFalse([n for n in names if n.endswith(".pyc") or n.startswith(("_", "."))])

    def test_agent_line_endings(self):
        for n in self.m.agent_files():
            b = self.m.agent_bytes(n)
            if n.endswith((".cmd", ".ps1")):
                self.assertEqual(b.count(b"\r\n"), b.count(b"\n"), n)
            else:
                self.assertNotIn(b"\r", b, n)               # 리눅스에서 그대로 돌아야 한다(CRLF 면 셸이 깨짐)

    def test_agent_has_no_secret_values(self):
        for n in self.m.agent_files():
            t = self.m.agent_bytes(n).decode("utf-8", "ignore")
            if not n.endswith(".cmd"):                          # .cmd 의 %TOKEN% 은 배치 변수(설정에서 읽음)
                self.assertNotIn("%TOKEN%", t)
            self.assertNotRegex(t, r"(?m)^TOKEN=[A-Za-z0-9_\-]{12,}")   # 실제 토큰이 박힌 설정은 없어야

    def test_serve_files_exist_and_usage_points_to_them(self):
        if not (self.m.DOCS / "LogTriage-server.cmd").is_file():   # 리눅스 묶음 안: 윈도우 서버 모드 파일(deploy/local 의 PC 배포 파일)은 들어가지 않는다
            self.skipTest("PC 배포 문서 없음(리눅스 묶음)")
        for n in self.m.SERVE + self.m.TEXTS:
            self.assertTrue((self.m.DOCS / n).is_file(), n)
        u = (self.m.DOCS / "사용법.txt").read_text(encoding="utf-8")
        self.assertNotIn("tools\\agent\\", u)                  # 묶음에 없는 경로를 안내하지 않는다
        self.assertIn("agent 폴더", u)
        self.assertIn("10자 이상", u)


if __name__ == "__main__":
    unittest.main()
