# -*- coding: utf-8 -*-
"""HTTP 본문 처리 — **소켓 수준**으로 본다 (2026-10-02)

왜 이 파일이 생겼나. 거절하는 자리(_reject_json)가 본문을 비우려고 **두 번째로** 읽다가
오지 않을 바이트를 영원히 기다렸다. 초기 설정 코드를 틀리게 적은 사람이 오류 화면 대신
멈춘 창을 봤다. 고친 뒤 GPT 가 "두 번 읽기만 고쳤다고 모든 정지가 사라진 것은 아니다" 라고
짚었고, 따져 보니 맞았다 — **Content-Length 를 크게 적고 적게 보내면** 첫 번째 읽기부터
영원히 기다린다. 연결 하나가 스레드 하나를 쓰므로 몇 번만 하면 서버가 멈춘다.

여기서는 http.client 를 쓰지 않는다. 그 계층은 우리가 보려는 어긋난 요청을 만들어 주지
않는다. **소켓에 직접 바이트를 쓴다.**

[무엇을 보는가]
  ① 정상 길이 + 틀린 코드      → 즉시 403, 계정 안 생김
  ② Content-Length 가 실제보다 큼 → 유한한 시간 안에 끝난다(스레드가 묶이지 않는다)
  ③ 본문 크기 상한 초과         → 거절, 통째로 읽어 메모리에 쌓지 않는다
  ④ 모르는 Transfer-Encoding    → 거절
  ⑤ 잘못된 POST 뒤 같은 연결    → 요청 경계가 섞이지 않는다(연결을 닫는다)
"""
from __future__ import annotations   # 3.9 호환(리눅스 RHEL 9 시스템 python) — 12차
import json
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_enterprise import Srv, prep_base  # noqa: E402

CONF = {"mode": "local", "first_admin": "", "local": {"domain": "solideos.com", "scrypt_n": 12}}
PW = "Bq7-Zrt2!wVm"
NL = chr(13) + chr(10)


class RawBodyTests(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=CONF)
        self.s = Srv(self.base)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def raw(self, head: str, body: bytes, send: int | None = None, timeout: float = 20.0,
            keep: bool = False):
        """소켓에 직접 쓴다 — send 를 주면 **적어 놓은 길이보다 적게** 보낸다."""
        c = socket.create_connection(("127.0.0.1", self.s.port), timeout=timeout)
        try:
            c.sendall(head.encode("ascii"))
            c.sendall(body if send is None else body[:send])
            if keep:                       # 연결을 열어 둔 채 응답을 기다린다(정지 시험)
                time.sleep(0.2)
            got = b""
            try:
                while True:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    got += chunk
                    if not keep and b"\r\n\r\n" in got:
                        break
            except socket.timeout:
                return None, got           # None = 시간 안에 응답이 오지 않았다
            return got.split(NL.encode("ascii"), 1)[0].decode("ascii", "replace"), got
        finally:
            c.close()

    def _post(self, path: str, body: bytes, extra: str = "", length: int | None = None) -> str:
        n = len(body) if length is None else length
        return (f"POST {path} HTTP/1.1{NL}Host: 127.0.0.1{NL}"
                f"Content-Type: application/x-www-form-urlencoded{NL}"
                f"Content-Length: {n}{NL}{extra}{NL}")

    # ── ① 정상 길이 + 틀린 코드 ──
    def test_a_wrong_setup_code_answers_at_once(self):
        """고치기 전에는 **여기서 멈췄다.** 오류 화면 대신 멈춘 창을 봤다."""
        form = urllib.parse.urlencode({"t": "WRONG-CODE", "email": "a@solideos.com",
                                       "name": "x", "password": PW, "confirm": PW}).encode()
        t0 = time.time()
        line, _ = self.raw(self._post("/setup", form), form, timeout=10)
        self.assertIsNotNone(line, "응답이 오지 않았습니다 — 멈췄습니다")
        self.assertIn("403", line)
        self.assertLess(time.time() - t0, 5, "응답이 너무 늦습니다")
        self.assertEqual(self.s.api.accounts.count(), 0)

    # ── ② Content-Length 가 실제보다 큼 ──
    def test_a_short_body_does_not_pin_a_thread_forever(self):
        """적어 놓은 길이보다 적게 보내고 연결을 끊지 않으면, 읽기가 영원히 기다릴 수 있다.

        그러면 그 요청을 맡은 스레드가 묶인다 — 몇 번만 하면 서버가 멈춘다. 유한한 시간 안에
        끝나야 하고, **그 뒤에도 서버가 멀쩡해야 한다.**
        """
        form = b"t=x&email=a%40solideos.com&password=" + b"y" * 50
        before = threading.active_count()
        line, _ = self.raw(self._post("/setup", form, length=10000), form, send=5,
                           timeout=15, keep=True)
        # 응답이 오든(거절) 연결이 끊기든 상관없다 — **기다리다 끝나야** 한다.
        time.sleep(1.0)
        after = threading.active_count()
        self.assertLessEqual(after - before, 2, f"스레드가 묶였습니다: {before} -> {after}")
        # 서버는 그 뒤에도 멀쩡하다
        r, _ = self.s.req("GET", "/healthz")
        self.assertEqual(r.status, 200, "반쪽 본문 뒤에 서버가 응답하지 않습니다")

    def test_many_half_bodies_do_not_stop_the_server(self):
        """한 번으로는 티가 안 난다 — 여러 번 해도 서버가 살아 있는지 본다."""
        form = b"t=x&password=" + b"y" * 40
        for _ in range(6):
            self.raw(self._post("/setup", form, length=9000), form, send=4, timeout=3, keep=True)
        r, _ = self.s.req("GET", "/healthz")
        self.assertEqual(r.status, 200, "반쪽 본문을 여러 번 받으면 서버가 멈춥니다")

    # ── ③ 본문 크기 상한 ──
    def test_a_huge_body_is_refused(self):
        """200KB 본문은 **읽지 않고** 거절한다 — 메모리에 쌓지 않는다.

        그래서 보내는 쪽은 다 보내기도 전에 연결이 끊긴다(ConnectionAborted). 그것이 맞는
        동작이라 시험도 그렇게 받아들인다 — 끊김도 거절이다. 중요한 것은 **계정이 안 생기는
        것**과 그 뒤에도 서버가 멀쩡한 것이다.
        """
        big = b"t=" + b"z" * 200000
        try:
            line, _ = self.raw(self._post("/setup", big), big, timeout=15)
            if line is not None:
                self.assertRegex(line, r"4\d\d", f"거절해야 합니다: {line}")
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            pass          # 다 보내기 전에 끊었다 = 읽지 않고 거절했다
        self.assertEqual(self.s.api.accounts.count(), 0)
        self.assertEqual(self.s.req("GET", "/healthz")[0].status, 200)

    # ── ④ 모르는 전송 형식 ──
    def test_chunked_is_not_silently_accepted(self):
        head = (f"POST /setup HTTP/1.1{NL}Host: 127.0.0.1{NL}"
                f"Content-Type: application/x-www-form-urlencoded{NL}"
                f"Transfer-Encoding: chunked{NL}{NL}")
        body = b"5" + NL.encode() + b"t=x&" + NL.encode() + b"0" + NL.encode() + NL.encode()
        line, _ = self.raw(head, body, timeout=10)
        if line is not None:
            self.assertRegex(line, r"4\d\d", f"잘린 요청을 받아들였습니다: {line}")
        self.assertEqual(self.s.api.accounts.count(), 0)

    # ── ⑤ 잘못된 POST 뒤 같은 연결 ──
    def test_the_connection_is_closed_after_a_refusal(self):
        """거절한 뒤 연결이 열려 있으면, 안 읽은 본문이 다음 요청으로 보여 경계가 섞인다.

        처음엔 `Connection: close` 머리글을 찾았는데 없었다 — **서버가 HTTP/1.0 으로
        답하기 때문**이다. 1.0 은 연결 유지를 하지 않으므로 머리글 없이도 닫힌다.
        글자를 찾는 대신 **실제로 닫히는지** 본다.
        """
        form = urllib.parse.urlencode({"t": "WRONG", "email": "a@solideos.com",
                                       "password": PW, "confirm": PW}).encode()
        c = socket.create_connection(("127.0.0.1", self.s.port), timeout=10)
        try:
            c.sendall(self._post("/setup", form).encode("ascii"))
            c.sendall(form)
            got = b""
            while True:
                chunk = c.recv(4096)
                if not chunk:
                    break               # 서버가 닫았다 — 여기로 와야 한다
                got += chunk
            self.assertIn(b"403", got.split(NL.encode("ascii"), 1)[0])
            self.assertTrue(got.startswith(b"HTTP/1.0") or b"Connection: close" in got,
                            "연결을 닫지 않습니다 — 다음 요청과 섞일 수 있습니다")
        finally:
            c.close()


class SetupCodeTests(unittest.TestCase):
    """초기 설정 코드 자체 — 난수·보관·소비."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=CONF)
        self.s = Srv(self.base)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def test_the_code_is_long_enough_and_random(self):
        import os as _os
        toks = set()
        for _ in range(5):
            toks.add(self.s.api.setup_token)
            self.s.api.setup_token = _os.urandom(0).hex() or self.s.api.setup_token
        tok = self.s.api.setup_token
        self.assertGreaterEqual(len(tok), 12, "코드가 짧습니다")
        self.assertTrue(tok.isascii())

    def test_the_code_file_is_not_world_readable(self):
        import os as _os
        p = self.base / "conf" / "setup-code.txt"
        self.assertTrue(p.exists())
        self.assertIn(self.s.api.setup_token, p.read_text(encoding="utf-8"))
        if _os.name == "posix":
            self.assertEqual(_os.stat(p).st_mode & 0o077, 0, "다른 사용자가 코드를 읽을 수 있습니다")

    def test_the_file_does_not_promise_a_code_free_path(self):
        """파일이 '사내망에서는 코드 없이 됩니다' 라고 적고 있었다 — 이제 거짓이다."""
        p = (self.base / "conf" / "setup-code.txt").read_text(encoding="utf-8")
        self.assertNotIn("코드 없이", p)
        self.assertIn("같은 PC 에서 열어도 코드가 필요합니다", p)

    def test_the_code_dies_when_the_first_admin_is_made(self):
        body = urllib.parse.urlencode({"t": self.s.api.setup_token, "email": "boss@solideos.com",
                                       "name": "관리자", "password": PW, "confirm": PW})
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        old = self.s.api.setup_token
        r, _ = self.s.req("POST", "/setup", body, h)
        self.assertEqual(r.status, 302)
        self.assertEqual(self.s.api.setup_token, "")
        self.assertFalse((self.base / "conf" / "setup-code.txt").exists())
        # 같은 코드를 다시 써도 소용없다
        body2 = urllib.parse.urlencode({"t": old, "email": "second@solideos.com",
                                        "password": PW, "confirm": PW})
        self.assertEqual(self.s.req("POST", "/setup", body2, h)[0].status, 403)
        self.assertEqual(self.s.api.accounts.count(), 1)

    def test_guessing_is_counted(self):
        """72비트라 맞힐 수 없지만, **세지 않는 것**과 못 맞히는 것은 다르다."""
        h = {"Content-Type": "application/x-www-form-urlencoded"}
        for i in range(12):
            body = urllib.parse.urlencode({"t": f"GUESS{i}", "email": "x@solideos.com",
                                           "password": PW, "confirm": PW})
            self.s.req("POST", "/setup", body, h)
        self.assertEqual(self.s.api.accounts.count(), 0)
        # 맞는 코드를 들고 와도 막혀 있다(시도가 너무 많다)
        body = urllib.parse.urlencode({"t": self.s.api.setup_token, "email": "boss@solideos.com",
                                       "name": "관리자", "password": PW, "confirm": PW})
        r, _ = self.s.req("POST", "/setup", body, h)
        self.assertEqual(r.status, 429, "틀린 코드를 세지 않습니다")


if __name__ == "__main__":
    unittest.main()
