"""이 PC 전용 창 모드(2026-10-13 마스터 결정 "이 PC 전용이면 로그인 없이").

- 창(부트스트랩 토큰)은 계정 없이 바로 분석 화면 — 첫 관리자 만들기·로그인 화면을 거치지 않는다
- 토큰 없는 요청은 같은 PC(루프백)여도 막힌다 — 전에는 창 모드에서 토큰 없이도 '이 PC 사용자' 로 들여보냈다
- 다른 PC 가 붙을 수 있는 조건(LAN 수신·서버 비밀번호·창이 아닌 서버)에서는 켜지지 않는다
"""
import http.client
import json
import re
import tempfile
import threading
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # 엔진 경로
from logtriage.auth import ensure_conf
from logtriage.server import make_server


class LocalOnlyWindow(unittest.TestCase):
    def _srv(self, **kw):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        base = Path(td.name)
        ensure_conf(base)                         # 처음 기동: 회사 이메일 계정 로그인(mode=local) 설정이 생긴다
        httpd, h = make_server("127.0.0.1", 0, base, kw.pop("password", None), desktop=kw.pop("desktop", True), **kw)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (httpd.shutdown(), httpd.server_close(), t.join()))
        return httpd, h

    def _get(self, port, path, cookie=""):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{port}", **({"Cookie": cookie} if cookie else {})})
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        c.close()
        return r, body

    def test_window_gets_in_without_account(self):
        httpd, h = self._srv(local_only=True)
        self.assertTrue(h.local_only)
        port = httpd.server_address[1]
        r, _ = self._get(port, f"/auth/bootstrap?t={h.boot_token}")
        self.assertEqual(r.status, 302)
        self.assertEqual(r.getheader("Location"), "/")              # /setup·/login 이 아니다
        m = re.search(r"lt_session=([0-9a-f]{32})", r.getheader("Set-Cookie") or "")
        self.assertTrue(m)
        ck = f"lt_session={m.group(1)}"
        r, body = self._get(port, "/api/me", ck)
        self.assertEqual(r.status, 200)
        me = json.loads(body)
        self.assertEqual(me["login"], "(이 PC)")
        self.assertFalse(me["logout"])                              # 로그아웃할 계정이 없다
        r, body = self._get(port, "/", ck)
        self.assertEqual(r.status, 200)
        self.assertNotIn("관리자 계정 만들기", body)

    def test_no_token_no_entry_even_from_same_pc(self):
        httpd, h = self._srv(local_only=True)
        port = httpd.server_address[1]
        r, _ = self._get(port, "/api/me")
        self.assertIn(r.status, (401, 403))
        tok = h.boot_token
        r, _ = self._get(port, f"/auth/bootstrap?t={tok}")
        self.assertEqual(r.status, 302)
        self.assertIn("no-store", r.getheader("Cache-Control") or "")
        self.assertIn("no-referrer", r.getheader("Referrer-Policy") or "")
        r, _ = self._get(port, f"/auth/bootstrap?t={tok}")              # 같은 토큰 두 번째 — 한 번만 쓴다
        self.assertEqual(r.status, 403)
        r, _ = self._get(port, "/auth/bootstrap?t=" + "0" * 32)       # 틀린 토큰
        self.assertEqual(r.status, 403)
        r, _ = self._get(port, "/api/me", "lt_session=" + "a" * 32)    # 지어낸 세션
        self.assertIn(r.status, (401, 403))

    def test_not_enabled_when_others_can_connect(self):
        _, h = self._srv(local_only=True, password="pw-for-lan")       # 서버 비밀번호를 쓰는 설정
        self.assertFalse(h.local_only)
        _, h = self._srv(local_only=True, desktop=False)                # 창이 아닌 서버
        self.assertFalse(h.local_only)
        _, h = self._srv()                                              # 지정하지 않으면 꺼짐
        self.assertFalse(h.local_only)

    def test_desktop_without_local_only_keeps_account_login(self):
        httpd, h = self._srv()                                          # 창 모드라도 local_only 아니면 계정 로그인 그대로
        port = httpd.server_address[1]
        r, _ = self._get(port, f"/auth/bootstrap?t={h.boot_token}")
        self.assertEqual(r.status, 302)
        self.assertIn(r.getheader("Location"), ("/setup", "/login"))
        r, _ = self._get(port, "/api/me")
        self.assertIn(r.status, (401, 403))


if __name__ == "__main__":
    unittest.main()
