# -*- coding: utf-8 -*-
"""보안 진단 대비 보강 시험 (2026-09-22)

· 화면 응답에 보안 헤더(CSP·프레임 차단·Referrer·Permissions)가 붙는다 — 평문 구간에는 HSTS 를 걸지 않는다
· 관리자 화면을 정해진 대역에서만 열 수 있다(conf 의 admin_allow, 비우면 제한 없음)
· SNMP community 는 DB 에 평문으로 남지 않는다
· 평문(HTTP)은 당분간 그대로 쓸 수 있다 — 차단 예정임을 설정 파일이 알린다
"""
import json
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import auth as A  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

CONF = {"mode": "local", "local": {"domain": "solideos.com", "scrypt_n": 12}}
PW = "Hdr-9fQr!42w"


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class HeaderTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        prep_base(self.base, auth=CONF)
        self.s = Srv(self.base)
        self.s.api.accounts.create("a@solideos.com", PW, role="admin", sites=["*"],
                                   asset_sites=["LOCAL"], must_change=False)
        body, h = form(email="a@solideos.com", password=PW)
        self.ck = cookie_of(self.s.req("POST", "/login", body, h)[0])

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def test_html_pages_carry_security_headers(self):
        for path in ("/login", "/", "/board", "/nms"):
            with self.subTest(page=path):
                r, _ = self.s.req("GET", path, cookie=self.ck)
                self.assertIn(r.status, (200, 302))
                if r.status != 200:
                    continue
                csp = r.getheader("Content-Security-Policy") or ""
                self.assertIn("frame-ancestors 'none'", csp)      # 클릭재킹
                self.assertIn("object-src 'none'", csp)
                self.assertIn("base-uri 'none'", csp)
                self.assertIn("form-action 'self'", csp)
                self.assertEqual(r.getheader("X-Frame-Options"), "DENY")
                self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
                self.assertEqual(r.getheader("Referrer-Policy"), "no-referrer")
                self.assertTrue(r.getheader("Permissions-Policy"))

    def test_no_hsts_on_plain_connection(self):
        """평문 구간에 HSTS 를 걸면 그 뒤로 접속이 막힌다 — 암호화 구간에서만 붙여야 한다."""
        r, _ = self.s.req("GET", "/login")
        self.assertIsNone(r.getheader("Strict-Transport-Security"))

    def test_json_responses_are_not_sniffable_or_framable(self):
        r, _ = self.s.req("GET", "/api/me", cookie=self.ck)
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.getheader("X-Frame-Options"), "DENY")

    def test_pages_still_work_under_csp(self):
        """CSP 를 걸어도 화면이 쓰는 자원(문서 안 대본·스타일·data: 이미지)은 허용돼야 한다."""
        r, body = self.s.req("GET", "/login", cookie=self.ck)
        csp = r.getheader("Content-Security-Policy")
        # 2026-10-15 아이디어 2: 대본은 nonce 로만 — 'unsafe-inline' 이 다시 들어오면 화면 XSS 한 곳이 곧 실행이 된다
        import re as _re
        m = _re.search(r"script-src 'self' 'nonce-([A-Za-z0-9_\-]+)';", csp)
        self.assertIsNotNone(m, csp)
        self.assertNotRegex(csp.split("style-src")[0], "unsafe-inline")
        page = body.decode("utf-8")
        tags = _re.findall(r"<script\b[^>]*>", page)
        self.assertTrue(tags)
        for t in tags:                                        # 이 응답의 대본은 모두 같은 표를 달고 있다
            self.assertIn(f'nonce="{m.group(1)}"', t)
        r2 = self.s.req("GET", "/login", cookie=self.ck)[0]   # 표는 응답마다 새로
        self.assertNotIn(m.group(1), r2.getheader("Content-Security-Policy"))
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)
        # 3차 아이디어 1: <style> 요소도 같은 nonce 로만, style= 속성만 unsafe-inline
        self.assertIn(f"style-src-elem 'self' 'nonce-{m.group(1)}'", csp)
        self.assertIn("style-src-attr 'unsafe-inline'", csp)
        self.assertIn("require-trusted-types-for 'script'", csp)        # 3차 아이디어 2
        self.assertLess(page.index("trustedTypes.createPolicy"), page.index("<script", page.index("trustedTypes.createPolicy")) if page.count("<script") > 1 else 10**9)
        for t in _re.findall(r"<style\b[^>]*>", page):
            self.assertIn(f'nonce="{m.group(1)}"', t)
        self.assertIn("img-src 'self' data: blob:", csp)   # 모니터링 화면이 아이콘을 blob 으로 만들어 쓴다
        self.assertNotIn("img-src *", csp)
        self.assertNotIn("user-select:none", page)          # 브라우저 화면은 글자 선택 그대로(창 전용 규칙은 아래)


class DesktopWindowStyle(unittest.TestCase):
    """포장본 점검(2026-10-16): 창(pywebview)이 넣던 nonce 없는 <style>(글자 선택 끔)이 style-src-elem 에 막혔다 —
    창 주입은 끄고(text_select=True) 같은 규칙을 서버가 nonce 를 달아 넣는다. 데스크톱 창에만."""

    def test_rule_has_nonce_and_window_injection_off(self):
        import http.client
        import re as _re
        import threading
        from logtriage.server import make_server
        src = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")
        self.assertIn("text_select=True", src)
        with tempfile.TemporaryDirectory() as td:
            prep_base(Path(td))
            httpd, h = make_server("127.0.0.1", 0, Path(td), None, desktop=True)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                port = httpd.server_address[1]
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                c.request("GET", f"/auth/bootstrap?t={h.boot_token}")
                r = c.getresponse(); r.read()
                ck = (r.getheader("Set-Cookie") or "").split(";")[0]
                c.request("GET", "/", headers={"Cookie": ck})
                r = c.getresponse(); page = r.read().decode("utf-8")
                csp = r.getheader("Content-Security-Policy") or ""
                n = _re.search(r"'nonce-([A-Za-z0-9_\-]+)'", csp).group(1)
                m = _re.search(r'<style nonce="([^"]+)">body\{-webkit-user-select:none;user-select:none;cursor:default\}</style></head>', page)
                self.assertIsNotNone(m, "창 전용 글자 선택 규칙이 없다")
                self.assertEqual(m.group(1), n)
            finally:
                httpd.shutdown()


class AdminNetworkTests(unittest.TestCase):
    """관리자 화면 접근 대역 제한."""

    def _start(self, allow):
        self.td = tempfile.TemporaryDirectory()
        base = Path(self.td.name)
        conf = dict(CONF)
        if allow is not None:
            conf["admin_allow"] = allow
        prep_base(base, auth=conf)
        self.s = Srv(base)
        self.s.api.accounts.create("a@solideos.com", PW, role="admin", sites=["*"],
                                   asset_sites=["LOCAL"], must_change=False)
        body, h = form(email="a@solideos.com", password=PW)
        self.ck = cookie_of(self.s.req("POST", "/login", body, h)[0])

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def test_no_restriction_by_default(self):
        self._start(None)
        self.assertEqual(self.s.req("GET", "/admin", cookie=self.ck)[0].status, 200)

    def test_allowed_range_passes(self):
        self._start(["127.0.0.0/8"])
        self.assertEqual(self.s.req("GET", "/admin", cookie=self.ck)[0].status, 200)
        self.assertEqual(self.s.req("GET", "/api/admin/accounts", cookie=self.ck)[0].status, 200)

    def test_other_range_is_refused(self):
        self._start(["10.9.9.0/24"])
        r, b = self.s.req("GET", "/admin", cookie=self.ck)
        self.assertEqual(r.status, 403)
        self.assertIn("접속", b.decode("utf-8"))
        self.assertEqual(self.s.req("GET", "/api/admin/accounts", cookie=self.ck)[0].status, 403)
        self.assertEqual(self.s.req("GET", "/", cookie=self.ck)[0].status, 200)   # 다른 화면은 그대로


class SnmpSecretTests(unittest.TestCase):
    def test_community_is_not_stored_in_clear(self):
        from logtriage.nms import Store
        d = tempfile.TemporaryDirectory()
        base = Path(d.name)
        n = Store(base / "data" / "nms" / "nms.sqlite3")
        tid = n.save({"name": "sw01", "address": "10.0.0.7", "kind": "network", "method": "icmp",
                      "metrics": "snmp", "snmp_community": "s3cr3t-comm", "enabled": True})["id"]
        raw = (base / "data" / "nms" / "nms.sqlite3").read_bytes()
        self.assertNotIn(b"s3cr3t-comm", raw)
        with n.db() as db:
            stored = db.execute("SELECT snmp_community FROM targets").fetchone()[0]
        self.assertTrue(stored.startswith("enc1:"))
        self.assertEqual(n._sc_dec(stored, tid), "s3cr3t-comm")
        self.assertEqual(n._sc_dec(stored, "other-target"), "")              # 다른 대상 행으로 옮겨 붙일 수 없다
        self.assertEqual(n.snapshot()["targets"][0]["snmp_community"], "")   # 화면에는 안 나간다
        self.assertEqual(n._sc_dec("old-plain-value"), "old-plain-value")    # 예전 DB 호환

    def test_plaintext_is_migrated_when_read(self):
        """예전 평문으로 남아 있던 값은 읽는 김에 암호문으로 바꿔 둔다(평문이 계속 남지 않게)."""
        from logtriage.nms import Store
        d = tempfile.TemporaryDirectory()
        base = Path(d.name)
        n = Store(base / "data" / "nms" / "nms.sqlite3")
        tid = n.save({"name": "sw02", "address": "10.0.0.8", "kind": "network", "method": "icmp",
                      "metrics": "snmp", "snmp_community": "will-move", "enabled": True})["id"]
        with n.db() as db:      # 예전 판처럼 평문으로 되돌려 놓는다
            db.execute("UPDATE targets SET snmp_community='legacy-plain' WHERE id=?", (tid,))
        self.assertEqual(n._sc_dec("legacy-plain", tid), "legacy-plain")     # 읽히고
        with n.db() as db:
            now = db.execute("SELECT snmp_community FROM targets WHERE id=?", (tid,)).fetchone()[0]
        self.assertTrue(now.startswith("enc1:"))                             # 그 자리에서 암호문으로 바뀐다
        self.assertEqual(n._sc_dec(now, tid), "legacy-plain")
        d.cleanup()

    def test_refuses_to_store_plaintext_when_key_is_missing(self):
        """암호화할 수 없으면 평문으로 후퇴하지 않고 거절한다(fail-closed)."""
        from logtriage.nms import Store
        d = tempfile.TemporaryDirectory()
        n = Store(Path(d.name) / "data" / "nms" / "nms.sqlite3")
        n._ckey = None
        with self.assertRaises(ValueError):
            n._sc_enc("secret", "t1")
        d.cleanup()
        d.cleanup()


class HttpStillAllowedTests(unittest.TestCase):
    """평문은 당분간 허용 — 다만 차단 예정임을 설정이 알려야 한다."""

    def test_default_still_allows_plain_on_internal(self):
        d = tempfile.TemporaryDirectory()
        conf = A.ensure_conf(Path(d.name))
        self.assertEqual(conf["require_https"], "auto")     # 사내망·VPN 평문 허용 유지
        saved = (Path(d.name) / "conf" / "auth.json").read_text(encoding="utf-8")
        self.assertIn("차단될 예정", saved)                   # 설정 파일에 예고가 적힌다
        self.assertEqual(conf["admin_allow"], [])           # 기본은 대역 제한 없음
        d.cleanup()


class InfoLeakTests(unittest.TestCase):
    """응답 헤더로 제품·언어 버전을 알려 주지 않는다(정보 노출)."""

    def test_server_header_has_no_versions(self):
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        prep_base(base, auth=CONF)
        s = Srv(base)
        try:
            srv = s.req("GET", "/login")[0].getheader("Server") or ""
            self.assertNotIn("Python", srv)
            self.assertNotRegex(srv, r"\d+\.\d+")     # 버전 숫자가 없어야 한다
        finally:
            s.close(); td.cleanup()


class AgentDownloadCacheTests(unittest.TestCase):
    """토큰이 든 배포물은 캐시에 남기지 않는다."""

    def test_no_store_on_agent_artifacts(self):
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        prep_base(base, auth=CONF)
        s = Srv(base)
        try:
            s.api.accounts.create("a@solideos.com", PW, role="operator", sites=["*"],
                                  asset_sites=["LOCAL"], must_change=False)
            body, h = form(email="a@solideos.com", password=PW)
            ck = cookie_of(s.req("POST", "/login", body, h)[0])
            for path in ("/static/lt-agent.sh", "/static/lt-agent.zip"):
                with self.subTest(path=path):
                    r, _ = s.req("GET", path, cookie=ck)
                    self.assertEqual(r.status, 200)
                    self.assertIn("no-store", r.getheader("Cache-Control") or "")
                    self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        finally:
            s.close(); td.cleanup()


class ObjectPermissionTests(unittest.TestCase):
    """로그인만으로는 남의 사이트 물건을 못 가져간다(IDOR/BOLA)."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        base = Path(self.td.name)
        prep_base(base, auth=CONF)
        self.s = Srv(base)
        acc = self.s.api.accounts
        acc.create("own@solideos.com", PW, role="operator", sites=["*"], asset_sites=["LOCAL"], must_change=False)
        acc.create("no@solideos.com", "Noa-3xPt!91k", role="operator", sites=["*"], must_change=False)
        self.ck = self._login("own@solideos.com", PW)
        self.ck_no = self._login("no@solideos.com", "Noa-3xPt!91k")

    def tearDown(self):
        self.s.close(); self.td.cleanup()

    def _login(self, email, pw):
        body, h = form(email=email, password=pw)
        return cookie_of(self.s.req("POST", "/login", body, h)[0])

    def test_asset_gated_endpoints_refuse_without_permission(self):
        """장비 IP 가 들어 있는 것들은 자산 조회 권한이 있어야 한다 — 권한 없으면 식별자를 알아도 못 본다."""
        for path in ("/resources",
                     "/api/inventory/docs",
                     "/api/automation/download?area=out&name=x.html",
                     "/static/lt-agent.sh",
                     "/api/nms/agent_tokens"):
            with self.subTest(path=path):
                self.assertEqual(self.s.req("GET", path, cookie=self.ck_no)[0].status, 403)

    def test_same_endpoints_open_to_the_owner(self):
        for path in ("/resources", "/api/inventory/docs", "/api/nms/agent_tokens"):
            with self.subTest(path=path):
                self.assertEqual(self.s.req("GET", path, cookie=self.ck)[0].status, 200)

    def test_unauthenticated_gets_nothing(self):
        for path in ("/api/nms/status", "/api/inventory/docs", "/static/lt-agent.sh", "/api/board/list", "/admin"):
            with self.subTest(path=path):
                r, _ = self.s.req("GET", path)
                self.assertIn(r.status, (302, 401, 403), f"{path} 가 로그인 없이 열립니다")


if __name__ == "__main__":
    unittest.main()
