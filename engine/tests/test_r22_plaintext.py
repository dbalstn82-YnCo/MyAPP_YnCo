"""22차(2026-10-27 마스터: '메뉴에 마우스를 올리면 왼쪽 아래에 IP · 주소가 보인다 — 보안 문제?').
링크 주소 표시는 브라우저 기능이고 주소창과 같은 값 — 새로 드러나는 것은 없다. 대신 주소에 **비밀**이 실리지 않는지,
그리고 같은 화면의 진짜 문제(주소창 '안전하지 않음' = 평문 HTTP)를 사용자에게 알리는지 본다.
① 평문 사내망 접속: 로그인 화면(비밀번호 넣기 전) · 앱 환경 점검 띠 맨 위에 경고. 같은 PC 직접 · HTTPS 는 경고 없음
② 화면 링크 주소에 세션 · 토큰 · 비밀번호가 실리지 않는다(내려받기 표는 5분 1회용, 설정 코드는 주소창에서 지운다)"""
from __future__ import annotations

import json
import re
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from logtriage.server import make_server  # noqa: E402

PW = "k3Vq9TzpX2mA"
LAN_HTTP = {"X-Forwarded-Proto": "http", "X-Forwarded-For": "10.1.2.3"}
LAN_HTTPS = {"X-Forwarded-Proto": "https", "X-Forwarded-For": "10.1.2.3"}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class PlaintextWarnTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.httpd, _ = make_server("127.0.0.1", 0, Path(self.td.name), PW)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.u = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.td.cleanup()

    def _get(self, path, hdr):
        try:
            return urllib.request.urlopen(urllib.request.Request(self.u + path, headers=hdr)).read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8")

    def test_login_page_warns_only_on_plaintext_lan(self):
        self.assertIn('id="ltplain"', self._get("/login", LAN_HTTP))
        self.assertNotIn('id="ltplain"', self._get("/login", {}))           # 같은 PC 직접 — 망을 지나지 않음
        self.assertNotIn('id="ltplain"', self._get("/login", LAN_HTTPS))

    def _session(self, hdr):
        op = urllib.request.build_opener(_NoRedirect)
        req = urllib.request.Request(self.u + "/login", data=("password=" + PW).encode(), headers=dict(hdr, **{"Content-Type": "application/x-www-form-urlencoded"}))
        try:
            op.open(req)
            self.fail("로그인 뒤 이동이 없음")
        except urllib.error.HTTPError as e:
            m = re.search(r"lt_session=([0-9a-f]{32})", e.headers.get("Set-Cookie", ""))
            self.assertTrue(m, e.headers)
            return m.group(1)

    def _diag(self, hdr):
        sid = self._session(hdr)
        req = urllib.request.Request(self.u + "/api/diag", data=b"[]", headers=dict(hdr, **{
            "Content-Type": "application/json", "X-NMS-Request": "1", "Cookie": "lt_session=" + sid}))
        return json.loads(urllib.request.urlopen(req).read().decode("utf-8"))

    def test_app_band_on_top_only_on_plaintext_lan(self):
        d = self._diag(LAN_HTTP)
        self.assertEqual(d["warn_items"][0]["code"], "plaintext_http")
        self.assertNotIn("plaintext_http", [i["code"] for i in self._diag(LAN_HTTPS)["warn_items"]])


class NoSecretInLinksTest(unittest.TestCase):
    def test_no_secret_query_in_screens(self):
        """화면이 만드는 링크 · 이동 주소에 세션 · 비밀번호 · 토큰 이름의 매개변수가 없다(내려받기 1회용 표 ticket 만 예외)."""
        bad = re.compile(r"[?&](sid|session|lt_session|token|password|pw|secret|key)=", re.I)
        for f in (ENGINE / "logtriage" / "gui").glob("*.html"):
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                self.assertIsNone(bad.search(line), f"{f.name}:{n}")

    def test_ticket_is_short_and_single_use(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn("DL_TICKET_TTL", src)
        self.assertIn("got = cls._dl_tickets.pop(t, None)", src)       # 한 번 쓰면 사라진다

    def test_setup_code_removed_from_address_bar(self):
        page = (ENGINE / "logtriage" / "gui" / "login.html").read_text(encoding="utf-8")
        self.assertIn("history.replaceState(null,'',location.pathname)", page)

    def test_access_log_redacts_one_time_secrets(self):
        """GPT 172: 1회용 비밀이 실린 주소가 서버 접속 기록에 그대로 남지 않는다."""
        import io
        import contextlib
        from logtriage.server import Handler
        h = Handler.__new__(Handler)
        h.client_address = ("127.0.0.1", 1)
        h.address_string = lambda: "127.0.0.1"
        for line, secret in (('"GET /auth/bootstrap?t=abcdef0123 HTTP/1.1" 302 -', "abcdef0123"),
                             ('"GET /setup?t=SETUPCODE99 HTTP/1.1" 200 -', "SETUPCODE99"),
                             ('"GET /static/lt-agent.zip?ticket=TKT123456&x=1 HTTP/1.1" 200 -', "TKT123456")):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                h.log_message("%s", line)
            self.assertNotIn(secret, buf.getvalue(), line)
            self.assertIn("[redacted]", buf.getvalue())

    def test_server_header_hides_versions(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn('server_version = "LogTriage"', src)
        self.assertIn('sys_version = ""', src)


if __name__ == "__main__":
    unittest.main()
