# -*- coding: utf-8 -*-
"""전사 배포(r4): 통합 계정 인증(ldap·oidc·header·link)·비상 관리자·권한·사이트 범위·감사·본사 허브 수집 — 실제 HTTP 서버로 검증."""
import base64
import hashlib
import http.client
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logtriage import auth as A  # noqa: E402
from logtriage import hub as H  # noqa: E402
from logtriage.server import make_server  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
LINK_SECRET = "s3cret-for-tests-0123456789abcdef"


def prep_base(td: Path, auth=None, hub=None):
    (td / "conf").mkdir(parents=True, exist_ok=True)
    if auth is not None:
        (td / "conf" / "auth.json").write_text(json.dumps(auth), encoding="utf-8")
    if hub is not None:
        (td / "conf" / "hub.json").write_text(json.dumps(hub), encoding="utf-8")
    return td


class Srv:
    def __init__(self, base, password=None):
        self.httpd, self.h = make_server("127.0.0.1", 0, base, password)
        self.api = self.h.api
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def req(self, method, path, body=None, headers=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = dict(headers or {})
        if cookie:
            h["Cookie"] = cookie
        if isinstance(body, (dict, list)):
            body = json.dumps(body); h.setdefault("Content-Type", "application/json")
        if method == "POST" and path.startswith("/api/"):
            h.setdefault("X-NMS-Request", "1")      # 우리 화면과 같은 표시(CSRF 관문)
        c.request(method, path, body, h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r, data

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()
        if self.api.hub_client:
            self.api.hub_client.stop()


def cookie_of(r, name="lt_sid"):
    for k, v in r.getheaders():
        if k.lower() == "set-cookie" and v.startswith(name + "="):
            return v.split(";")[0]
    return None


# ── 가짜 LDAP 서버: 요청 바이트를 ldap3 기준 부호와 비교하고, 고정 응답을 돌려준다 ──
BIND_OK = bytes.fromhex("300c02010161070a010004000400")
BIND_BAD = bytes.fromhex("300c02010161070a013104000400")
ENTRY = bytes.fromhex("30818a0201026481840416434e3d75312c44433d636f72702c44433d6c6f63616c306a301a040b646973706c61794e616d65310b0409ed998deab8b8eb8f99301b040a6465706172746d656e74310d040b4954ec9ab4ec9881ed8c80302f04086d656d6265724f6631230411434e3d49542d4f70732c44433d636f7270040e434e3d416c6c2c44433d636f7270")
DONE = bytes.fromhex("300c02010265070a010004000400")
BIND_REQ_OK = bytes.fromhex("301c0201016017020103040d753140636f72702e6c6f63616c8003707721")   # u1@corp.local / pw!  (ldap3 부호)
SEARCH_REQ = bytes.fromhex("30670201026362041044433d636f72702c44433d6c6f63616c0a01020a0100020102020105010100a314040e73414d4163636f756e744e616d65040275313029040b646973706c61794e616d65040a6465706172746d656e7404046d61696c04086d656d6265724f66")


class FakeLdap(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(); self.sock.bind(("127.0.0.1", 0)); self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.seen = []

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            c.settimeout(5)
            try:
                buf = b""
                while True:
                    try:
                        chunk = c.recv(4096)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 2 and len(buf) >= 2 + buf[1]:
                        msg, buf = buf[:2 + buf[1]], buf[2 + buf[1]:]
                        self.seen.append(msg)
                        op = msg[5] if msg[1] < 0x80 else None
                        if op == 0x60:
                            c.sendall(BIND_OK if msg == BIND_REQ_OK else BIND_BAD)
                        elif op == 0x63:
                            c.sendall((ENTRY if msg == SEARCH_REQ else b"") + DONE)
                        elif op == 0x42:
                            raise ConnectionAbortedError
            except (ConnectionAbortedError, OSError):
                pass
            finally:
                c.close()


class AuthUnitTests(unittest.TestCase):
    def test_password_hash_and_rs256(self):
        h = A.hash_pw("correct horse battery")
        self.assertTrue(A.check_pw("correct horse battery", h))
        self.assertFalse(A.check_pw("wrong", h))
        self.assertFalse(A.check_pw("x", "garbage"))

    def test_link_signature_replay_and_expiry(self):
        with tempfile.TemporaryDirectory() as td:
            st = A.AuthStore(Path(td) / "a.sqlite3")
            conf = {"portal": {"method": "link", "link": {"secret": LINK_SECRET, "max_skew_sec": 120}}}
            ts, n = int(time.time()), "nonce12345678"
            q = {"u": ["kim"], "t": [str(ts)], "n": [n], "sig": [A.link_sign(LINK_SECRET, "kim", ts, n)]}
            self.assertEqual(A.link_login(conf, q, st)["login"], "kim")
            with self.assertRaises(A.AuthError):   # 재사용
                A.link_login(conf, q, st)
            q2 = dict(q, n=["nonceABCDEFGH"], sig=["00" * 32])
            with self.assertRaises(A.AuthError):   # 서명 불일치
                A.link_login(conf, q2, st)
            old = ts - 600
            q3 = {"u": ["kim"], "t": [str(old)], "n": ["nonceOLD12345"], "sig": [A.link_sign(LINK_SECRET, "kim", old, "nonceOLD12345")]}
            with self.assertRaises(A.AuthError):   # 만료
                A.link_login(conf, q3, st)

    def test_last_admin_and_self_protection(self):
        with tempfile.TemporaryDirectory() as td:
            st = A.AuthStore(Path(td) / "a.sqlite3")
            st.set_local("admin", "0123456789ab")
            with self.assertRaises(ValueError):
                st.update_user("admin", {"role": "viewer"}, actor="other")   # 마지막 관리자
            with self.assertRaises(ValueError):
                st.update_user("admin", {"disabled": True}, actor="admin")   # 자기 자신
            with self.assertRaises(ValueError):
                st.update_user("admin", {"sites": ["../x"]}, actor="other")
            with self.assertRaises(ValueError):
                st.set_local("admin", "short")

    def test_group_map(self):
        conf = {"default_role": "viewer", "portal": {"group_map": [{"group": "cn=it-ops", "role": "operator", "sites": ["S1"]},
                                                                    {"group": "cn=sec", "role": "admin", "sites": ["*"]}]}}
        self.assertEqual(A._map_groups(conf, ["CN=IT-Ops,DC=corp"])["role"], "operator")
        self.assertEqual(A._map_groups(conf, ["CN=IT-Ops,DC=corp", "CN=Sec,DC=corp"])["role"], "admin")
        self.assertIsNone(A._map_groups(conf, ["CN=Other"]))

    def test_ldap_bind_and_search_against_reference_encoding(self):
        srv = FakeLdap(); srv.start()
        conf = {"portal": {"method": "ldap", "ldap": {"url": f"ldap://127.0.0.1:{srv.port}", "bind_dn_format": "{login}@corp.local",
                                                       "search_base": "DC=corp,DC=local", "timeout": 3}}}
        info = A.ldap_login(conf, "u1", "pw!")
        self.assertEqual(info["name"], "홍길동"); self.assertEqual(info["dept"], "IT운영팀")
        self.assertIn("CN=IT-Ops,DC=corp", info["groups"])
        self.assertIn(BIND_REQ_OK, srv.seen); self.assertIn(SEARCH_REQ, srv.seen)
        with self.assertRaises(A.AuthError) as cm:
            A.ldap_login(conf, "u1", "wrong")
        self.assertIn("맞지 않습니다", str(cm.exception))
        with self.assertRaises(A.AuthError):   # 빈 비밀번호 = 익명 바인드 → 반드시 거절(서버에 보내지도 않음)
            A.ldap_login(conf, "u1", "")
        with self.assertRaises(A.AuthError):   # DN 주입 문자
            A.ldap_login(conf, "u1,cn=admin", "pw!")
        srv.sock.close()

    @unittest.skipUnless(__import__("importlib").util.find_spec("cryptography"), "cryptography 없음(개발 PC 전용 검증)")
    def test_oidc_rs256(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = key.public_key().public_numbers()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        jwks = {"keys": [{"kty": "RSA", "kid": "k1", "n": b64(pub.n.to_bytes(256, "big")), "e": b64(pub.e.to_bytes(3, "big"))}]}
        state = {}

        class IdP(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                body = json.dumps(jwks).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                head = b64(json.dumps({"alg": "RS256", "kid": "k1"}).encode())
                claims = {"iss": "https://idp", "aud": "lt", "exp": time.time() + 300, "nonce": state["nonce"],
                          "preferred_username": "park", "name": "박운영", "groups": ["CN=Sec"]}
                p = b64(json.dumps(claims).encode())
                sig = state.get("key", key).sign(f"{head}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
                body = json.dumps({"id_token": f"{head}.{p}.{b64(sig)}"}).encode()
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        idp = ThreadingHTTPServer(("127.0.0.1", 0), IdP)
        threading.Thread(target=idp.serve_forever, daemon=True).start()
        u = f"http://127.0.0.1:{idp.server_address[1]}"
        conf = {"portal": {"method": "oidc", "oidc": {"authorize_url": u + "/auth", "token_url": u + "/token", "jwks_url": u + "/jwks",
                                                       "issuer": "https://idp", "client_id": "lt", "redirect_uri": "http://x/cb"}}}
        o = A.Oidc(conf)
        url = o.authorize_url()
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        state["nonce"] = q["nonce"][0]
        info = o.callback({"state": q["state"], "code": ["c1"]})
        self.assertEqual((info["login"], info["name"]), ("park", "박운영"))
        with self.assertRaises(A.AuthError):   # state 재사용
            o.callback({"state": q["state"], "code": ["c1"]})
        # 서명 위조
        url = o.authorize_url(); q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query); state["nonce"] = q["nonce"][0]
        state["key"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)   # 다른 키로 서명
        with self.assertRaises(A.AuthError):
            o.callback({"state": q["state"], "code": ["c2"]})
        idp.shutdown(); idp.server_close()


class EnterpriseHttpTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_portal_link_roles_site_scope_audit(self):
        auth = {"mode": "portal", "default_role": "viewer", "default_sites": [], "portal": {"method": "link", "link": {"secret": LINK_SECRET}}}
        prep_base(self.base, auth=auth, hub={"role": "central", "site_id": "HQ", "site_name": "본사"})
        A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3").set_local("admin", "0123456789ab")
        s = Srv(self.base)
        try:
            r, _ = s.req("GET", "/")
            self.assertEqual((r.status, r.getheader("Location")), (302, "/login"))
            r, b = s.req("GET", "/login")
            self.assertIn("<b>LogTriage</b> 메뉴", b.decode()); self.assertNotIn("사내 포털", b.decode())
            r, _ = s.req("POST", "/api/stats", [])
            self.assertEqual(r.status, 401)
            # 포털 링크 로그인 → 조회 권한·사이트 없음
            ts, n = int(time.time()), "abcdefgh1234"
            q = urllib.parse.urlencode({"u": "kim", "t": ts, "n": n, "sig": A.link_sign(LINK_SECRET, "kim", ts, n)})
            r, _ = s.req("GET", "/sso/link?" + q)
            ck = cookie_of(r); self.assertTrue(ck)
            # 다른 사이트에서 넘어온 요청에는 세션을 실어 보내지 않는다(Strict).
            # 바깥 링크로 들어오면 한 번 더 눌러야 하는 불편이 있지만 보안을 앞세운다(GPT 11차)
            self.assertIn("SameSite=Strict", r.getheader("Set-Cookie"))
            self.assertIn("HttpOnly", r.getheader("Set-Cookie"))
            r, b = s.req("GET", "/api/me", cookie=ck); me = json.loads(b)
            self.assertEqual((me["login"], me["role"], me["can_operate"]), ("kim", "viewer", False))
            r, _ = s.req("GET", "/", cookie=ck)   # 본사 서버 자체 사이트 권한 없음 → 전사 현황으로
            self.assertEqual((r.status, r.getheader("Location")), (302, "/hub"))
            r, b = s.req("GET", "/api/hub/overview", cookie=ck)
            self.assertEqual(json.loads(b)["sites"], [])   # 볼 수 있는 사이트 없음
            r, _ = s.req("GET", "/admin", cookie=ck); self.assertEqual(r.status, 403)
            r, _ = s.req("GET", "/sso/link?" + q); self.assertEqual(r.status, 401)   # 링크 재사용 차단
            # 비상 관리자 로그인 → 권한 부여
            r, _ = s.req("POST", "/login", "local=1&login=admin&password=bad", {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(r.status, 401)
            r, _ = s.req("POST", "/login", "local=1&login=admin&password=0123456789ab", {"Content-Type": "application/x-www-form-urlencoded"})
            ack = cookie_of(r); self.assertTrue(ack)
            r, b = s.req("GET", "/api/admin/users", cookie=ack)
            self.assertEqual(r.status, 200); self.assertEqual({u["login"] for u in json.loads(b)["users"]}, {"admin", "kim"})
            r, b = s.req("POST", "/api/admin/user_update", {"login": "kim", "role": "viewer", "sites": ["HQ"]}, cookie=ack)
            self.assertEqual(r.status, 200, b)
            r, _ = s.req("GET", "/api/me", cookie=ck); self.assertEqual(r.status, 401)   # 권한 변경 → 기존 세션 종료
            ts, n = int(time.time()), "abcdefgh5678"
            q = urllib.parse.urlencode({"u": "kim", "t": ts, "n": n, "sig": A.link_sign(LINK_SECRET, "kim", ts, n)})
            ck = cookie_of(s.req("GET", "/sso/link?" + q)[0])
            r, _ = s.req("GET", "/", cookie=ck); self.assertEqual(r.status, 200)
            r, b = s.req("POST", "/api/stats", [], cookie=ck); self.assertEqual(r.status, 200)          # 조회 API 허용
            r, b = s.req("POST", "/api/analyze", [{}], cookie=ck); self.assertEqual(r.status, 403)    # 분석 실행은 운영 권한
            self.assertIn("운영 권한", json.loads(b)["error"])
            r, _ = s.req("PUT", "/api/upload?name=a.log", "x", cookie=ck); self.assertEqual(r.status, 403)
            r, _ = s.req("GET", "/api/nms/agent", cookie=ck); self.assertEqual(r.status, 403)       # 에이전트 토큰 노출 금지
            r, _ = s.req("POST", "/api/automation/run", {"id": "x"}, cookie=ck); self.assertEqual(r.status, 403)
            r, _ = s.req("POST", "/api/admin/user_update", {"login": "kim", "role": "admin"}, cookie=ck); self.assertEqual(r.status, 403)
            # 교차 출처 POST 차단
            r, _ = s.req("POST", "/api/stats", [], {"Origin": "http://evil.example"}, cookie=ck); self.assertEqual(r.status, 403)
            # 감사 기록
            r, b = s.req("GET", "/api/admin/audit?days=1", cookie=ack)
            acts = [(x["login"], x["action"], x["ok"]) for x in json.loads(b)["rows"]]
            self.assertIn(("kim", "login", 1), acts); self.assertIn(("admin", "login.fail", 0), acts)
            self.assertIn(("kim", "denied", 0), acts); self.assertIn(("admin", "admin.user_update", 1), acts)
            # 로그아웃
            r, _ = s.req("GET", "/logout", cookie=ck); self.assertEqual(r.status, 302)
            r, _ = s.req("GET", "/api/me", cookie=ck); self.assertEqual(r.status, 401)
            # 무차별 대입 차단(5분 10회)
            for _ in range(10):
                s.req("POST", "/login", "local=1&login=admin&password=nope", {"Content-Type": "application/x-www-form-urlencoded"})
            r, _ = s.req("POST", "/login", "local=1&login=admin&password=0123456789ab", {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(r.status, 429)
        finally:
            s.close()

    def test_header_sso_trusted_proxy_only(self):
        auth = {"mode": "portal", "default_role": "operator", "default_sites": ["*"],
                "portal": {"method": "header", "header": {"trusted_proxies": ["127.0.0.1"]}}}
        prep_base(self.base, auth=auth)
        s = Srv(self.base)
        try:
            r, b = s.req("GET", "/api/me", headers={"X-Portal-User": "lee", "X-Portal-Name": urllib.parse.quote("이운영")})
            me = json.loads(b); self.assertEqual((r.status, me["login"], me["name"], me["role"]), (200, "lee", "이운영", "operator"))
            r, _ = s.req("GET", "/api/me"); self.assertEqual(r.status, 401)
            s.api.auth_conf["portal"]["header"]["trusted_proxies"] = ["10.9.9.9"]   # 앞단이 아닌 곳에서 온 헤더는 무시
            s.h._hdr_cache.clear()
            r, _ = s.req("GET", "/api/me", headers={"X-Portal-User": "lee"}); self.assertEqual(r.status, 401)
        finally:
            s.close()

    def test_review_fixes_legacy_session_https_header_secret(self):
        auth = {"mode": "portal", "default_role": "admin", "default_sites": ["*"], "portal": {"method": "link", "link": {"secret": "short-secret-1234"}}}
        prep_base(self.base, auth=auth)
        s = Srv(self.base, password="pw12345")
        try:
            s.h._sessions.add("a" * 32)   # 예전 단일 비밀번호 세션이 메모리에 남아 있어도 통합 로그인 모드에서는 무효
            r, _ = s.req("GET", "/api/me", cookie="lt_session=" + "a" * 32); self.assertEqual(r.status, 401)
            r, _ = s.req("POST", "/login", "password=pw12345", {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertIsNone(cookie_of(r, "lt_session"))
            ts, n = int(time.time()), "weaksecret01"
            q = urllib.parse.urlencode({"u": "kim", "t": ts, "n": n, "sig": A.link_sign("short-secret-1234", "kim", ts, n)})
            r, b = s.req("GET", "/sso/link?" + q); self.assertEqual(r.status, 401); self.assertIn("약합니다", b.decode())   # 약한 비밀키 거절
            r, b = s.req("GET", "/api/me", headers={"X-Forwarded-Proto": "http"}); self.assertEqual(r.status, 403)   # 평문 HTTP 앞단 거절
            self.assertIn("HTTPS", json.loads(b)["error"])
            r, _ = s.req("GET", "/healthz", headers={"X-Forwarded-Proto": "http"}); self.assertEqual(r.status, 200)
        finally:
            s.close()
        self.assertTrue(A.secret_ok(__import__("secrets").token_urlsafe(36))); self.assertFalse(A.secret_ok("a" * 40))
        # header: trusted_proxies 명시 필수 + proxy_secret
        with self.assertRaises(A.AuthError):
            A.header_login({"portal": {"header": {}}}, "127.0.0.1", {"X-Portal-User": "x"})
        hc = {"portal": {"header": {"trusted_proxies": ["127.0.0.1"], "proxy_secret": "p" * 8 + "Q1w2e3r4t5y6"}}}
        with self.assertRaises(A.AuthError):
            A.header_login(hc, "127.0.0.1", {"X-Portal-User": "x", "X-Proxy-Secret": "nope"})
        self.assertEqual(A.header_login(hc, "127.0.0.1", {"X-Portal-User": "x", "X-Proxy-Secret": "p" * 8 + "Q1w2e3r4t5y6"})["login"], "x")

    def test_nms_addresses_masked_without_asset_permission(self):
        auth = {"mode": "portal", "default_role": "operator", "default_sites": ["*"], "portal": {"method": "link", "link": {"secret": LINK_SECRET}}}
        prep_base(self.base, auth=auth)
        s = Srv(self.base)
        try:
            s.api.nms.save({"name": "web01", "address": "10.9.8.7", "kind": "server", "method": "icmp", "interval": 30})
            ts, n = int(time.time()), "maskmask0001"
            ck = cookie_of(s.req("GET", "/sso/link?" + urllib.parse.urlencode({"u": "kim", "t": ts, "n": n, "sig": A.link_sign(LINK_SECRET, "kim", ts, n)}))[0])
            r, b = s.req("GET", "/api/nms/status", cookie=ck)
            self.assertNotIn("10.9.8.7", b.decode()); self.assertIn("(자산 권한 필요)", b.decode())
            r, _ = s.req("POST", "/api/nms/save", {"name": "x", "address": "10.1.1.1", "kind": "server", "method": "icmp"},
                         {"X-NMS-Request": "1"}, cookie=ck)
            self.assertEqual(r.status, 403)   # 장비 등록·변경은 자산 권한 필요
            s.api.auth.update_user("kim", {"asset_sites": ["LOCAL"]}, actor="admin")
            ts, n = int(time.time()), "maskmask0002"
            ck = cookie_of(s.req("GET", "/sso/link?" + urllib.parse.urlencode({"u": "kim", "t": ts, "n": n, "sig": A.link_sign(LINK_SECRET, "kim", ts, n)}))[0])
            self.assertIn("10.9.8.7", s.req("GET", "/api/nms/status", cookie=ck)[1].decode())
        finally:
            s.close()

    def test_ldap_login_form(self):
        srv = FakeLdap(); srv.start()
        auth = {"mode": "portal", "default_role": "viewer", "default_sites": ["*"],
                "portal": {"method": "ldap", "ldap": {"url": f"ldap://127.0.0.1:{srv.port}", "bind_dn_format": "{login}@corp.local",
                                                       "search_base": "DC=corp,DC=local"},
                           "group_map": [{"group": "CN=IT-Ops", "role": "operator", "sites": ["*"]}]}}
        prep_base(self.base, auth=auth)
        s = Srv(self.base)
        try:
            r, b = s.req("GET", "/login"); self.assertIn("계정 ID", b.decode()); self.assertNotIn("사내 포털", b.decode())
            r, b = s.req("POST", "/login", "login=u1&password=wrong", {"Content-Type": "application/x-www-form-urlencoded"})
            self.assertEqual(r.status, 401); self.assertIn("맞지 않습니다", b.decode())
            r, _ = s.req("POST", "/login", "login=u1&password=pw%21", {"Content-Type": "application/x-www-form-urlencoded"})
            ck = cookie_of(r); self.assertTrue(ck)
            me = json.loads(s.req("GET", "/api/me", cookie=ck)[1])
            self.assertEqual((me["name"], me["dept"], me["role"]), ("홍길동", "IT운영팀", "operator"))   # 그룹 매핑
        finally:
            s.close(); srv.sock.close()

    def test_legacy_modes_unchanged(self):
        prep_base(self.base)
        s = Srv(self.base)   # auth.json 없음 + 비밀번호 없음 = 기존처럼 인증 없음
        try:
            r, b = s.req("GET", "/api/me"); self.assertEqual(json.loads(b)["role"], "admin")
        finally:
            s.close()
        s = Srv(self.base, password="pw12345")
        try:
            r, _ = s.req("GET", "/api/me"); self.assertEqual(r.status, 401)
            r, _ = s.req("POST", "/login", "password=pw12345", {"Content-Type": "application/x-www-form-urlencoded"})
            ck = cookie_of(r, "lt_session"); self.assertTrue(ck)
            self.assertEqual(json.loads(s.req("GET", "/api/me", cookie=ck)[1])["role"], "admin")
        finally:
            s.close()

    def test_site_to_central_collection(self):
        H.INGEST_MIN_GAP = 0   # 시험에서는 연속 전송 허용(운영 기본 5초)
        cbase = self.base / "central"; sbase = self.base / "site"
        cbase.mkdir(); sbase.mkdir()
        prep_base(cbase, hub={"role": "central", "site_id": "HQ", "site_name": "본사"})
        c = Srv(cbase)
        try:
            r, b = c.req("POST", "/api/hub/admin/site_add", {"id": "BUSAN", "name": "부산 IDC"})
            j = json.loads(b); self.assertEqual(r.status, 200, b); tok = j["token"]
            self.assertEqual(j["hub_json"]["site_id"], "BUSAN")
            r, _ = c.req("POST", "/api/hub/ingest", {"site": {}}, {"X-Site-Token": "bad"}); self.assertEqual(r.status, 401)
            prep_base(sbase, hub={"role": "site", "site_id": "BUSAN", "site_name": "부산 IDC", "hub_url": f"http://127.0.0.1:{c.port}",
                                  "hub_token": tok, "interval_sec": 15})
            s = Srv(sbase)
            try:
                s.api.nms.save({"name": "web01", "address": "127.0.0.1", "kind": "server", "method": "icmp", "interval": 30})
                (sbase / "reports").mkdir(exist_ok=True)
                rep = sbase / "reports" / "periodic-20260918.html"
                rep.write_text("<h1>보고서</h1>", encoding="utf-8")
                os.utime(rep, (time.time() - 60, time.time() - 60))
                res = s.api.hub_client.cycle()
                self.assertTrue(res["ok"]); self.assertEqual(res["received"]["targets"], 1)
                st = s.api.hub_client.status(); self.assertTrue(st["healthy"]); self.assertEqual(st["sent"]["reports"], 1)
                s.api.hub_client.cycle()   # 두 번째 주기: 같은 보고서를 다시 보내지 않음
                self.assertEqual(s.api.hub_client.status()["sent"]["reports"], 1)
                c.api.hub_client.cycle()   # 본사 자체 사이트
                ov = json.loads(c.req("GET", "/api/hub/overview")[1])
                ids = {x["id"]: x for x in ov["sites"]}
                self.assertEqual(set(ids), {"HQ", "BUSAN"}); self.assertEqual(ids["BUSAN"]["state"], "online")
                self.assertEqual(ids["BUSAN"]["targets"], 1)
                self.assertEqual(ov["reports"][0]["name"], "periodic-20260918.html")
                r, b = c.req("GET", "/api/hub/file?site=BUSAN&name=periodic-20260918.html")
                self.assertEqual((r.status, b.decode("utf-8")), (200, "<h1>보고서</h1>"))
                r, _ = c.req("GET", "/api/hub/file?site=BUSAN&name=../../conf/hub.json"); self.assertEqual(r.status, 404)
                # 사이트에서 항목 삭제 → 본사에서도 사라짐
                tid = s.api.nms.snapshot()["targets"][0]["id"]
                s.api.nms.delete(tid); s.api.hub_client.cycle()
                ov = json.loads(c.req("GET", "/api/hub/overview")[1])
                self.assertEqual({x["id"]: x["targets"] for x in ov["sites"]}["BUSAN"], 0)
                # 사이트 중지 → 수신 거절 → 사이트 쪽 오류 상태
                c.req("POST", "/api/hub/admin/site_update", {"id": "BUSAN", "disabled": True})
                with self.assertRaises(RuntimeError):
                    s.api.hub_client.cycle()
                # 잘못된 자료는 400 (서버 오류 아님)
                c.req("POST", "/api/hub/admin/site_update", {"id": "BUSAN", "disabled": False})
                r, _ = c.req("POST", "/api/hub/ingest", {"targets": "x"}, {"X-Site-Token": tok}); self.assertEqual(r.status, 400)
                r, _ = c.req("POST", "/api/hub/ingest", {"targets": []}, {"X-Site-Token": tok}); self.assertEqual(r.status, 400)   # 순번 없는 전송 거절
                st = s.api.hub_client.state
                body = {"stream": st["stream"], "seq": st["seq"] + 1, "targets": [{"id": "a", "usage": {"cpu": "NaN"}, "latency": 1e99}]}
                r, _ = c.req("POST", "/api/hub/ingest", body, {"X-Site-Token": tok}); self.assertEqual(r.status, 200)
                r, b = c.req("POST", "/api/hub/ingest", body, {"X-Site-Token": tok}); self.assertEqual(r.status, 409)   # 같은 전송 재생 거절
                r, _ = c.req("POST", "/api/hub/ingest", dict(body, stream="ab" * 16, seq=1), {"X-Site-Token": tok}); self.assertEqual(r.status, 409)   # 동작 중인 흐름이 있으면 새 흐름 거절
                import sqlite3 as _sq   # 기존 흐름이 2분 이상 멈춘 상황 → 새 흐름 수락, 이전 흐름은 영구 폐기
                db = _sq.connect(str(c.api.hub.path))
                db.execute("UPDATE sites SET stream_seen=stream_seen-200 WHERE id='BUSAN'"); db.commit(); db.close()
                r, _ = c.req("POST", "/api/hub/ingest", dict(body, stream="ab" * 16, seq=1), {"X-Site-Token": tok}); self.assertEqual(r.status, 200)
                r, b = c.req("POST", "/api/hub/ingest", dict(body, seq=body["seq"] + 5), {"X-Site-Token": tok}); self.assertEqual(r.status, 409)
                self.assertIn("폐기", json.loads(b)["error"])
                # 보고서 사본: 같은 내용 재전송 → 성공(중복), 같은 이름·다른 내용 → 덮어쓰지 않고 새 판(~r2)으로 보관
                q = "/api/hub/file?name=periodic-20260918.html&mtime=1"
                r, b = c.req("PUT", q, "<h1>보고서</h1>".encode("utf-8"), {"X-Site-Token": tok}); self.assertTrue(json.loads(b).get("duplicate"))
                r, b = c.req("PUT", q, b"regenerated", {"X-Site-Token": tok}); self.assertEqual(json.loads(b)["stored_as"], "periodic-20260918~r2.html")
                self.assertEqual(c.req("GET", "/api/hub/file?site=BUSAN&name=periodic-20260918.html")[1].decode("utf-8"), "<h1>보고서</h1>")
                self.assertEqual(c.req("GET", "/api/hub/file?site=BUSAN&name=periodic-20260918~r2.html")[1], b"regenerated")
            finally:
                s.close()
        finally:
            c.close()


if __name__ == "__main__":
    unittest.main()
