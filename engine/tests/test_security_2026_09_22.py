# -*- coding: utf-8 -*-
"""2026-09-22 보안 개편 시험
  · 첫 기동: 설정이 없으면 이메일 로그인으로 만들어지고, 계정이 없으면 /setup(관리자 계정 만들기)으로 보낸다
  · 비밀번호 분실: 관리자 발급 1회용 코드로 재설정(만료·횟수 제한·재사용 금지)
  · 저장 암호화: DB 에 ID(이메일)·이름·비밀번호·코드가 평문으로 남지 않는다
  · 분석 이력: 등록한 계정 외에는 IP·호스트명을 ** 로 가린다
"""
from __future__ import annotations   # 3.9 호환(리눅스 RHEL 9 시스템 python) — 12차
import json
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import accounts as AC  # noqa: E402
from logtriage import auth as A  # noqa: E402
from logtriage import privacy as P  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

CONF = {"mode": "local", "local": {"domain": "solideos.com", "scrypt_n": 12}}
PW1 = "Tmx-9fQr!42w"
PW2 = "Pv7#kLm2$eZq"
PW3 = "Qh4@wZr7!nT2"


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class FirstRunTests(unittest.TestCase):
    """설정 없이 기동해도 로그인(첫 계정 만들기) 화면이 보여야 한다."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)

    def tearDown(self):
        self.td.cleanup()

    def test_ensure_conf_makes_a_usable_setting(self):
        """2026-10-01 사용자 지시로 처음 기동 기본값이 **계정 로그인**으로 돌아왔다.

        "페이지를 열고 계정 로그인" — 설정이 없으면 local 로 만들고, 계정이 없으면
        [관리자 계정 만들기] 로 간다. 이미 있는 설정을 덮어쓰지 않는 규칙은 그대로다.
        """
        conf = A.ensure_conf(self.base)
        self.assertEqual(conf["mode"], "local")
        self.assertEqual(conf["require_https"], "auto")            # 사내망·VPN 은 평문 허용, 인터넷 구간은 HTTPS
        self.assertEqual(conf["local"]["domain"], "solideos.com")
        saved = json.loads((self.base / "conf" / "auth.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["mode"], "local")
        saved["mode"] = "off"                                      # 이미 있는 설정은 덮어쓰지 않는다
        (self.base / "conf" / "auth.json").write_text(json.dumps(saved), encoding="utf-8")
        self.assertEqual(A.ensure_conf(self.base)["mode"], "off")

    def _email_login(self, first_admin: str | None = None):
        """이메일 계정 로그인을 **켜고** 본다.

        2026-09-30 부터 처음 기동 기본값은 '로그인 없음' 이다. 이메일 로그인은 끈 것이지
        지운 것이 아니므로, 이 갈래가 아직 살아 있는지는 계속 확인해야 한다 — 그래야
        "추후 도입" 이 말이 된다.
        """
        A.ensure_conf(self.base)
        p = self.base / "conf" / "auth.json"
        c = json.loads(p.read_text(encoding="utf-8"))
        c["mode"] = "local"
        if first_admin is not None:
            c["first_admin"] = first_admin
        p.write_text(json.dumps(c, ensure_ascii=False), encoding="utf-8")

    def _free_conf(self):
        """예약된 첫 관리자를 비운 설정 — ID 를 직접 정해 만드는 경우."""
        self._email_login(first_admin="")

    def test_setup_screen_then_login(self):
        self._free_conf()
        s = Srv(self.base)
        try:
            r, _ = s.req("GET", "/")
            self.assertEqual((r.status, r.getheader("Location")), (302, "/setup"))
            # 코드 없이 열면 **코드 넣는 화면**이 나온다(기본값 token, 2026-10-01)
            r, b = s.req("GET", "/setup")
            self.assertEqual(r.status, 403)
            self.assertIn("초기 설정 코드", b.decode("utf-8"))
            r, b = s.req("GET", "/setup?t=" + s.api.setup_token)
            page = b.decode("utf-8")
            self.assertEqual(r.status, 200)
            for want in ("관리자 계정 만들기", "#C12554", "hong123@solideos.com"):
                self.assertIn(want, page)
            r, _ = s.req("GET", "/login")                          # 계정이 없으면 로그인 화면도 설정으로 유도
            self.assertEqual((r.status, r.getheader("Location")), (302, "/setup"))
            # 첫 계정 만들기에는 1회용 코드가 필요하다(2026-10-01, setup_scope 기본값 token)
            body, h = form(email="boss@solideos.com", name="관리자", password=PW1, confirm=PW1,
                           t=s.api.setup_token)
            r, _ = s.req("POST", "/setup", body, h)
            ck = cookie_of(r)
            self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
            me = json.loads(s.req("GET", "/api/me", cookie=ck)[1])
            self.assertEqual((me["login"], me["role"], me["must_change"]), ("boss@solideos.com", "admin", False))
            self.assertEqual(me["asset_sites"], ["LOCAL"])         # 첫 관리자는 이 서버 자산 조회 권한도 갖는다
            r, _ = s.req("GET", "/setup")                          # 두 번째부터는 닫힌다
            self.assertEqual((r.status, r.getheader("Location")), (302, "/login"))
            body, h = form(email="another@solideos.com", password=PW2, confirm=PW2)
            r, _ = s.req("POST", "/setup", body, h)   # 코드가 있어도 두 번째는 없다(화면이 닫혔다)
            self.assertEqual(r.status, 403)
        finally:
            s.close()

    def test_default_first_admin_is_empty(self):
        """2026-10-22 마스터: 첫 관리자가 개발자 개인 계정으로 박혀 있으면 배포한 곳에서 관리자를 못 만든다 — 기본값은 빈 값,
        1회용 코드를 넣은 사람이 ID 를 직접 적는다."""
        A.ensure_conf(self.base)
        self.assertEqual(A.load_conf(self.base)["first_admin"], "")
        self.assertEqual(A.FIRST_RUN_CONF["first_admin"], "")
        for f in (ROOT / "logtriage").rglob("*.py"):              # 개인 계정이 코드에 글자로 남지 않는다(지움 판정은 해시)
            self.assertNotIn("dbals" + "tn82", f.read_text(encoding="utf-8"), f)
        ex = ROOT / "deploy" / "server" / "conf-examples" / "auth.json.local.example"
        self.assertEqual(json.loads(ex.read_text(encoding="utf-8"))["first_admin"], "")

    def test_old_auto_first_admin_is_unpinned(self):
        """옛 판이 자동으로 적은 개인 계정 first_admin(자동 생성 설명 · 예시 복사본)은 기동 때 비운다. 사람이 적은 다른 ID 는 그대로."""
        p = self.base / "conf" / "auth.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        old = "dbals" + "tn82@solideos.com"                       # 이 시험 파일도 위 글자 검사에 걸리지 않게 나눠 쓴다
        for desc in (A.FIRST_RUN_CONF["_설명"], "사내 이메일 계정 로그인. 이 파일을 <설치경로>/conf/auth.json 으로 복사하고"):
            p.write_text(json.dumps({"_설명": desc, "mode": "local", "first_admin": old.upper()}, ensure_ascii=False), encoding="utf-8")
            self.assertEqual(A.ensure_conf(self.base)["first_admin"], "", desc)
            self.assertEqual(json.loads(p.read_text(encoding="utf-8"))["first_admin"], "")   # 파일에도 비워 남긴다(사람이 보는 값)
            bak = p.with_name("auth.json.before-first-admin-unpin")
            self.assertEqual(json.loads(bak.read_text(encoding="utf-8"))["first_admin"], old.upper())   # GPT 102차 P1-01: 원본 보관
            bak.unlink()
        p.write_text(json.dumps({"_설명": A.FIRST_RUN_CONF["_설명"], "mode": "local", "first_admin": "boss@solideos.com"}), encoding="utf-8")
        self.assertEqual(A.ensure_conf(self.base)["first_admin"], "boss@solideos.com")     # 사람이 고른 ID 는 유지
        p.write_text(json.dumps({"_설명": "운영팀이 직접 쓴 설정", "mode": "local", "first_admin": old}), encoding="utf-8")
        self.assertEqual(A.ensure_conf(self.base)["first_admin"], old)                      # 손으로 쓴 설정은 유지

    def test_setup_without_reserved_id_types_any_id(self):
        """기본값(빈 first_admin): 코드를 넣으면 ID 칸이 열려 있고, 적은 ID 로 첫 관리자가 만들어진다."""
        A.ensure_conf(self.base)
        self._email_login()
        s = Srv(self.base)
        try:
            code = (self.base / "conf" / "setup-code.txt").read_text(encoding="utf-8")
            self.assertNotIn("첫 관리자 :", code)
            page = s.req("GET", "/setup?t=" + s.api.setup_token)[1].decode("utf-8")
            self.assertIn('name="email"', page)
            self.assertNotIn("비밀번호만", page)
            body, h = form(email="newadmin@solideos.com", name="관리자", password=PW1, confirm=PW1, t=s.api.setup_token)
            r, _ = s.req("POST", "/setup", body, h)
            self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
            me = json.loads(s.req("GET", "/api/me", cookie=cookie_of(r))[1])
            self.assertEqual((me["login"], me["role"]), ("newadmin@solideos.com", "admin"))
        finally:
            s.close()

    def test_first_admin_is_reserved(self):
        """설정에 **사람이** 예약해 둔 ID 가 첫 관리자가 된다 — 화면에서는 비밀번호만 정하고, 다른 ID 를 보내도 예약된 ID 로 만들어진다."""
        self._email_login(first_admin="boss@solideos.com")   # 기본값은 비어 있다(2026-10-22) — 예약은 사람이 적었을 때만
        conf = A.load_conf(self.base)
        fa = conf["first_admin"]
        self.assertTrue(fa.endswith("@solideos.com"))
        self.assertTrue((self.base / "conf" / "setup-code.txt").exists() is False)   # 서버를 열기 전에는 없다
        s = Srv(self.base)
        try:
            code = (self.base / "conf" / "setup-code.txt").read_text(encoding="utf-8")
            self.assertIn(s.api.setup_token, code)                 # 코드는 파일로도 남는다
            self.assertIn(fa, code)
            self.assertEqual(s.req("GET", "/setup")[0].status, 403)      # 코드 없이는 안 열린다
            page = s.req("GET", "/setup?t=" + s.api.setup_token)[1].decode("utf-8")
            self.assertIn(fa, page)
            self.assertIn("비밀번호만", page)
            self.assertNotIn('name="email"', page)                 # ID 칸은 고정(읽기 전용)
            body, h = form(email="somebody@solideos.com", name="관리자", password=PW1, confirm=PW1,
                           t=s.api.setup_token)
            r, _ = s.req("POST", "/setup", body, h)
            self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
            me = json.loads(s.req("GET", "/api/me", cookie=cookie_of(r))[1])
            self.assertEqual((me["login"], me["role"]), (fa, "admin"))
            self.assertFalse((self.base / "conf" / "setup-code.txt").exists())       # 만들고 나면 코드 파일도 지운다
            self.assertEqual(s.api.setup_token, "")
        finally:
            s.close()

    def test_setup_scope_no_longer_opens_anything(self):
        """**웹으로 첫 계정을 만드는 길에는 예외가 없다**(2026-10-02).

        전에는 접속 자리로 갈랐다 — loopback(이 서버만) / private(사내망까지) / token(코드).
        같은 PC 에 리버스 프록시가 있으면 밖에서 온 사람도 127.0.0.1 로 보이므로 그 판단이
        서지 않는다. 기본값만 고치고 옛 값을 그대로 두면 **그 설정이 적힌 설치는 뚫린 채
        남는다** — 현장 설치가 그렇다. 그래서 설정과 무관하게 코드를 받는다.
        setup_scope 는 남겨 두되(옛 파일을 읽기 위해) 아무것도 열지 않는다.
        """
        from logtriage.server import Handler

        class Fake:
            path = "/setup"
            headers = {}
            api = type("A", (), {"auth_conf": {"setup_scope": "private"}, "setup_token": "TOK"})()

            def __init__(self, ip):
                self.client_address = (ip, 5000)

        for m in ("_setup_ok", "_private_peer", "_loopback_peer", "_proxied"):
            setattr(Fake, m, getattr(Handler, m))

        for scope in ("loopback", "private", "token"):
            Fake.api.auth_conf["setup_scope"] = scope
            for ip in ("127.0.0.1", "10.20.30.41", "8.8.8.8"):
                with self.subTest(scope=scope, ip=ip):
                    self.assertFalse(Fake(ip)._setup_ok(), "코드 없이 첫 계정을 만들 수 있습니다")
                    self.assertTrue(Fake(ip)._setup_ok("TOK"))
                    self.assertFalse(Fake(ip)._setup_ok("wrong"))
        # 주소에 붙인 코드도 받는다
        f = Fake("8.8.8.8")
        f.path = "/setup?t=TOK"
        self.assertTrue(f._setup_ok())
        # 한글을 붙여 넣어도 터지지 않는다(compare_digest 는 비-ASCII 를 비교하지 못한다)
        self.assertFalse(Fake("8.8.8.8")._setup_ok("코드아님"))

    def test_setup_behind_proxy_needs_code(self):
        """앞단(nginx 등)을 거쳐 온 요청은 주소로 자리를 가릴 수 없다 — 그래서 코드를 받는다.

        같은 PC 의 프록시 뒤에서는 인터넷 접속도 127.0.0.1 로 보인다. 프록시가 X-Forwarded-*
        를 안 붙이는 경우까지 있어서, 이제는 프록시 여부와 무관하게 코드를 받는다.
        """
        from logtriage.server import Handler

        class Fake:
            client_address = ("127.0.0.1", 5000)                   # 프록시가 같은 PC 에 있다
            path = "/setup"
            headers = {"X-Forwarded-For": "203.0.113.9"}
            api = type("A", (), {"auth_conf": {"setup_scope": "private"}, "setup_token": "TOK"})()

        for m in ("_setup_ok", "_private_peer", "_loopback_peer", "_proxied"):
            setattr(Fake, m, getattr(Handler, m))
        f = Fake()
        self.assertTrue(f._proxied())
        self.assertFalse(f._setup_ok())                            # 루프백처럼 보여도 그냥 통과시키지 않는다
        self.assertTrue(f._setup_ok("TOK"))                        # 코드가 있으면 허용
        f.headers = {}
        self.assertFalse(f._setup_ok(), "앞단 머리글이 없으면 다시 열립니다 — 그 자리가 구멍이었습니다")
        self.assertTrue(f._setup_ok("TOK"))

    def test_setup_closes_when_account_made_by_cli(self):
        self._free_conf()
        s = Srv(self.base)
        try:
            self.assertEqual(s.req("GET", "/")[0].getheader("Location"), "/setup")
            s.api.accounts.create("cli@solideos.com", PW1, role="admin", must_change=False)   # 기동 뒤 명령줄로 발급
            r, _ = s.req("GET", "/")
            self.assertEqual((r.status, r.getheader("Location")), (302, "/login"))
        finally:
            s.close()


class RecoveryCodeTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.store = A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3")
        self.acc = AC.Accounts(self.store, self.base, CONF)
        self.acc.create("user1@solideos.com", PW1, role="operator", must_change=False)

    def tearDown(self):
        self.td.cleanup()

    def test_issue_and_use(self):
        c = self.acc.issue_code("user1@solideos.com", actor="admin1@solideos.com")
        self.assertRegex(c["code"], r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertTrue(self.acc.code_status("user1@solideos.com")["valid"])
        with self.assertRaises(A.AuthError):                       # 틀린 코드
            self.acc.reset_with_code("user1@solideos.com", "AAAA-BBBB-CCCC", PW2)
        self.acc.reset_with_code("user1@solideos.com", c["code"].lower().replace("-", " "), PW2)   # 대소문자·붙임표 무시
        self.assertTrue(self.acc.verify("user1@solideos.com", PW2))
        self.assertIsNone(self.acc.code_status("user1@solideos.com"))   # 1회용
        with self.assertRaises(A.AuthError):
            self.acc.reset_with_code("user1@solideos.com", c["code"], PW3)

    def test_expiry_and_tries(self):
        c = self.acc.issue_code("user1@solideos.com")
        db = sqlite3.connect(str(self.base / "data" / "auth" / "auth.sqlite3"))
        db.execute("UPDATE recovery SET expires=?", (time.time() - 1,)); db.commit(); db.close()
        with self.assertRaises(A.AuthError) as cm:
            self.acc.reset_with_code("user1@solideos.com", c["code"], PW2)
        self.assertIn("만료", str(cm.exception))
        c = self.acc.issue_code("user1@solideos.com")
        for _ in range(AC.Accounts.CODE_TRIES):
            with self.assertRaises(A.AuthError):
                self.acc.reset_with_code("user1@solideos.com", "ZZZZ-ZZZZ-ZZZZ", PW2)
        with self.assertRaises(A.AuthError) as cm:                 # 횟수 초과 후에는 맞는 코드도 거부
            self.acc.reset_with_code("user1@solideos.com", c["code"], PW2)
        self.assertIn("만료", str(cm.exception) + "초과")
        self.assertFalse(self.acc.verify("user1@solideos.com", PW1)["must_change"])   # 원래 비밀번호는 그대로

    def test_policy_applies_to_new_password(self):
        c = self.acc.issue_code("user1@solideos.com")
        with self.assertRaises(A.AuthError):                       # 정책 미달 비밀번호는 거부
            self.acc.reset_with_code("user1@solideos.com", c["code"], "1234")
        self.assertTrue(self.acc.code_status("user1@solideos.com")["valid"])   # 코드는 아직 살아 있다
        self.acc.reset_with_code("user1@solideos.com", c["code"], PW2)


class StorageEncryptionTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.dbfile = self.base / "data" / "auth" / "auth.sqlite3"
        self.store = A.AuthStore(self.dbfile)
        self.acc = AC.Accounts(self.store, self.base, CONF)

    def tearDown(self):
        self.td.cleanup()

    def test_no_plaintext_identity_or_secret(self):
        self.acc.create("hong123@solideos.com", PW1, role="admin", name="홍길동", dept="인프라운영팀", must_change=False)
        tok = self.store.new_session("hong123@solideos.com", "10.1.2.3")
        self.store.audit("hong123@solideos.com", "10.1.2.3", "login", "email")
        code = self.acc.issue_code("hong123@solideos.com")["code"]
        raw = self.dbfile.read_bytes()
        for secret in (b"hong123@solideos.com", "홍길동".encode("utf-8"), "인프라운영팀".encode("utf-8"),
                       PW1.encode(), code.encode(), code.replace("-", "").encode(), tok.encode()):
            self.assertNotIn(secret, raw, f"평문 노출: {secret[:24]!r}")
        self.assertNotIn(b"scrypt", raw)                           # 저장 방식 이름조차 남지 않는다
        u = self.store.get_user("hong123@solideos.com")            # 화면에는 예전과 같은 모양으로 보인다
        self.assertEqual((u["login"], u["name"], u["dept"]), ("hong123@solideos.com", "홍길동", "인프라운영팀"))
        self.assertEqual(self.store.session_user(tok, 60, 12)["login"], "hong123@solideos.com")
        rows = self.store.audit_list(login="hong123@solideos.com")
        self.assertTrue(rows and rows[0]["login"] == "hong123@solideos.com" and rows[0]["target"] == "email")

    def test_old_pepper_still_verifies(self):
        """예전(v1) 검증값 — 페퍼 SHA-256 — 도 그대로 로그인된다."""
        self.acc.create("legacy@solideos.com", PW1, must_change=False)
        v1 = self.acc._verifier("legacy@solideos.com", PW1, {"v": 1, "algo": "scrypt", "n": 2 ** 12, "r": 8, "p": 1,
                                                             "salt": "00112233445566778899aabbccddeeff"})
        with self.store.db() as db:
            db.execute("UPDATE accounts SET verifier=? WHERE idx=?", (v1, self.acc._idx("legacy@solideos.com")))
        self.assertTrue(self.acc.verify("legacy@solideos.com", PW1))
        self.acc.set_password("legacy@solideos.com", PW2, old=PW1)   # 바꾸면 새 방식(v2)으로 저장
        with self.store.db() as db:
            row = db.execute("SELECT verifier FROM accounts WHERE idx=?", (self.acc._idx("legacy@solideos.com"),)).fetchone()
        self.assertEqual(self.acc._params("legacy@solideos.com", row["verifier"])["pep"], "sha512")

    def test_migration_from_plaintext_db(self):
        """예전 판에서 만든 DB(평문 이메일·이름)를 열면 암호화 방식으로 옮긴다."""
        p = self.base / "old" / "data" / "auth" / "auth.sqlite3"
        p.parent.mkdir(parents=True)
        db = sqlite3.connect(str(p))
        db.executescript("""
        CREATE TABLE users(login TEXT PRIMARY KEY, name TEXT DEFAULT '', dept TEXT DEFAULT '', email TEXT DEFAULT '',
          role TEXT DEFAULT 'viewer', sites TEXT DEFAULT '[]', source TEXT DEFAULT 'portal', pw_hash TEXT,
          created REAL, last_login REAL, disabled INTEGER DEFAULT 0, managed INTEGER DEFAULT 0, asset_sites TEXT DEFAULT '[]');
        CREATE TABLE sessions(th TEXT PRIMARY KEY, login TEXT, created REAL, seen REAL, ip TEXT);
        CREATE TABLE audit(id INTEGER PRIMARY KEY, at REAL, login TEXT, ip TEXT, action TEXT, target TEXT, detail TEXT, ok INTEGER);
        CREATE TABLE nonces(nonce TEXT PRIMARY KEY, at REAL);
        INSERT INTO users(login,name,role,sites,source,created) VALUES('old@solideos.com','옛사용자','admin','["*"]','email',1);
        INSERT INTO audit(at,login,ip,action,target,detail,ok) VALUES(%f,'old@solideos.com','10.0.0.1','login','email','',1);
        """ % time.time())
        db.commit(); db.close()
        store = A.AuthStore(p, base=self.base / "old")
        u = store.get_user("old@solideos.com")
        self.assertEqual((u["login"], u["name"], u["role"]), ("old@solideos.com", "옛사용자", "admin"))
        self.assertNotIn(b"old@solideos.com", p.read_bytes())
        self.assertEqual(store.audit_list()[0]["login"], "old@solideos.com")


class HistoryMaskTests(unittest.TestCase):
    """등록한 계정 외에는 IP·호스트명이 ** 로 보여야 한다."""

    INC = {"id": "INC-TEST-1", "analyzed_at": "2026-09-22 09:00:00", "name": "wasprd01", "owner": "a@solideos.com",
           "first": {"layer_ko": "WAS", "verdict": "연결 실패", "host": "wasprd01.solideos.com",
                     "message": "12:34:56 connect to 10.20.30.41:1521 from wasprd01 failed (mac 00:1A:2B:3C:4D:5E)"},
           "events": [{"host": "dbprd02", "message": "catalina.out rotate, version 8.0.32"}]}

    def test_unit_masking(self):
        hosts = P.hosts_of(self.INC)
        self.assertIn("wasprd01", hosts)
        self.assertIn("dbprd02", hosts)
        m = P.mask_result(self.INC)
        self.assertEqual(m["first"]["host"], "**")
        self.assertNotIn("10.20.30.41", json.dumps(m, ensure_ascii=False))
        self.assertNotIn("wasprd01", json.dumps(m, ensure_ascii=False))
        self.assertIn("12:34:56", m["first"]["message"])            # 시각은 IPv6 로 오해하지 않는다
        self.assertIn("catalina.out", m["events"][0]["message"])    # 파일명·버전은 그대로
        self.assertIn("8.0.32", m["events"][0]["message"])
        self.assertEqual(m["id"], "INC-TEST-1")                     # 식별자·시각은 남긴다
        self.assertEqual(P.mask_for_viewer(self.INC, "a@solideos.com")["first"]["host"], "wasprd01.solideos.com")
        self.assertEqual(P.mask_for_viewer(self.INC, "b@solideos.com")["first"]["host"], "**")

    def test_http_history_masked_for_others(self):
        td = tempfile.TemporaryDirectory()
        base = Path(td.name)
        prep_base(base, auth=CONF)
        s = Srv(base)
        try:
            acc = s.api.accounts
            acc.create("a@solideos.com", PW1, role="operator", sites=["*"], must_change=False)
            acc.create("b@solideos.com", PW2, role="operator", sites=["*"], must_change=False)
            s.api.store.save_incident(dict(self.INC))
            body, h = form(email="a@solideos.com", password=PW1)
            ck_a = cookie_of(s.req("POST", "/login", body, h)[0])
            body, h = form(email="b@solideos.com", password=PW2)
            ck_b = cookie_of(s.req("POST", "/login", body, h)[0])

            own = json.loads(s.req("POST", "/api/history", "[]", {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=ck_a)[1])
            other = json.loads(s.req("POST", "/api/history", "[]", {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=ck_b)[1])
            self.assertEqual(own[0]["first"]["host"], "wasprd01.solideos.com")
            self.assertEqual(other[0]["first"]["host"], "**")
            self.assertTrue(other[0].get("masked"))
            self.assertNotIn("10.20.30.41", json.dumps(other, ensure_ascii=False))

            # Ctrl+K 찾기(GPT UI 19차): 가린 뒤에 거른다 — 남의 분석은 가려진 호스트명으로 걸리지 않고, 본문도 나가지 않는다
            qf = lambda ck, q: json.loads(s.req("POST", "/api/quickfind", json.dumps([q]), {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=ck)[1])
            self.assertEqual([x["id"] for x in qf(ck_a, "wasprd01")], ["INC-TEST-1"])
            self.assertEqual(qf(ck_b, "wasprd01"), [])
            self.assertEqual(qf(ck_b, "10.20.30"), [])
            hit = qf(ck_b, "INC-TEST-1")
            self.assertEqual([x["id"] for x in hit], ["INC-TEST-1"])
            self.assertNotIn("wasprd01", json.dumps(hit, ensure_ascii=False))
            self.assertEqual(set(hit[0]), {"id", "name", "verdict", "severity", "at"})
            # GPT 19차 후속 필수 01: 새 API 가 기존 이력 API 보다 더 알려 주지 않는다 — 찾기 결과는 그 사람이 받는 이력의 부분 집합,
            # 칸은 이력(가린 것)의 칸 값 그대로. 결과를 골라도 보고서 생성 같은 상세 권한은 그대로 막힌다(아래 403)
            hist_b = {h["id"]: h for h in other}
            for q in ("INC", "연결", "WAS", "INC-TEST-1"):
                for x in qf(ck_b, q):
                    self.assertIn(x["id"], hist_b)
                    self.assertEqual(x["name"], hist_b[x["id"]].get("name", ""))
                    self.assertEqual(x["verdict"], (hist_b[x["id"]].get("first") or {}).get("verdict", ""))
            # 직접 호출로 서버를 두드리지 못하게 — 계정마다 10초에 30번
            from logtriage import server as _srv
            _srv._QF_HITS.clear()
            got = [qf(ck_a, "wasprd01") for _ in range(_srv.QF_MAX)]
            self.assertTrue(all(isinstance(x, list) for x in got))
            r, body = s.req("POST", "/api/quickfind", json.dumps(["wasprd01"]), {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=ck_a)
            self.assertEqual(r.status, 429)                                     # GPT 20차: 빈 결과와 구분 — '없음' 이 아니라 '잦음'
            self.assertIn("너무 잦습니다", json.loads(body)["error"])
            self.assertIsInstance(qf(ck_b, "wasprd01"), list)                  # 다른 계정은 따로 센다
            _srv._QF_HITS.clear()

            r, b = s.req("POST", "/api/generate_report", json.dumps(["INC-TEST-1"]),
                         {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=ck_b)
            self.assertEqual(r.status, 403)
            self.assertIn("등록한 담당자와 같은 부서만", b.decode("utf-8"))   # 15차: 같은 부서 공유 — 다른 부서는 여전히 403
        finally:
            s.close(); td.cleanup()


class BoardTests(unittest.TestCase):
    """게시판 — 질문·답글·채택, 분석 이력 첨부와 가림 규칙."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        prep_base(self.base, auth=CONF)
        self.s = Srv(self.base)
        acc = self.s.api.accounts
        acc.create("a@solideos.com", PW1, role="operator", sites=["*"], must_change=False, name="김분석")
        acc.create("b@solideos.com", PW2, role="viewer", sites=["*"], must_change=False, name="이조회")
        self.s.api.store.save_incident({"id": "INC-B1", "analyzed_at": "2026-09-22 10:00:00", "name": "wasprd01",
                                        "owner": "a@solideos.com",
                                        "first": {"host": "wasprd01", "verdict": "커넥션 풀 고갈", "layer_ko": "WAS",
                                                  "message": "pool exhausted at 10.20.30.41"}})
        self.ca = self._login("a@solideos.com", PW1)
        self.cb = self._login("b@solideos.com", PW2)

    def tearDown(self):
        self.s.close(); self.td.cleanup()

    def _login(self, email, pw):
        body, h = form(email=email, password=pw)
        return cookie_of(self.s.req("POST", "/login", body, h)[0])

    def _post(self, path, obj, cookie):
        r, b = self.s.req("POST", path, json.dumps(obj), {"Content-Type": "application/json", "X-NMS-Request": "1"}, cookie=cookie)
        return r, json.loads(b or b"{}")

    def test_post_reply_accept_and_attachment_masking(self):
        r, d = self._post("/api/board/create", {"kind": "question", "title": "WAS 커넥션 풀 고갈",
                                                "body": "10시경 발생", "incidents": ["INC-B1"]}, self.ca)
        self.assertEqual(r.status, 200)
        pid = d["id"]
        lst = json.loads(self.s.req("GET", "/api/board/list", cookie=self.cb)[1])
        self.assertEqual(lst["posts"][0]["title"], "WAS 커넥션 풀 고갈")
        self.assertEqual(lst["posts"][0]["author_name"], "김분석")
        r, _ = self._post("/api/board/reply", {"id": pid, "body": "어제 같은 증상이었습니다"}, self.cb)
        self.assertEqual(r.status, 200)
        det = json.loads(self.s.req("GET", f"/api/board/post?id={pid}", cookie=self.cb)[1])
        self.assertEqual(len(det["replies"]), 1)

        other = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.cb)[1])
        own = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.ca)[1])
        self.assertEqual(other["incident"]["first"]["host"], "**")
        self.assertNotIn("10.20.30.41", json.dumps(other, ensure_ascii=False))
        self.assertEqual(own["incident"]["first"]["host"], "wasprd01")
        self.assertTrue(own["can_open"])

        self._post("/api/board/update", {"id": pid, "share_raw": True}, self.ca)   # 글쓴이가 원문 공개
        shared = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.cb)[1])
        self.assertEqual(shared["incident"]["first"]["host"], "wasprd01")
        self.assertTrue(shared["shared"])

        r, _ = self._post("/api/board/accept", {"id": pid, "reply": det["replies"][0]["id"]}, self.ca)
        self.assertEqual(r.status, 200)
        self.assertTrue(json.loads(self.s.req("GET", f"/api/board/post?id={pid}", cookie=self.ca)[1])["solved"])

    def test_board_page_layout_and_widgets(self):
        """화면 뼈대 — 본문이 class="main" 이라야 폭이 늘어난다(2026-09-22 2차: 쪼그라들던 문제)."""
        page = self.s.req("GET", "/board", cookie=self.ca)[1].decode("utf-8")
        self.assertIn('<div class="main">', page)          # 사이드바 옆 본문이 남은 폭을 차지한다
        self.assertIn('class="topbar"', page)
        self.assertIn('class="content"', page)
        self.assertIn("/static/_srv_common.css", page)     # 다른 서버형 화면과 같은 팔레트·부품
        self.assertIn(".ck input{appearance:none", page)   # 체크상자는 직접 그린다
        self.assertIn(".sw input{appearance:none", page)   # 원문 공개는 전환 단추
        self.assertNotIn(".hero{", page)                   # 다른 화면에서 따라온 규칙이 남아 있지 않다
        self.assertNotIn("사건", page)

    def test_list_stats_and_attached_info(self):
        """목록 요약(전체·미해결·답글)과 글에 붙은 분석의 이름·시각 — 이름도 같은 가림 규칙을 따른다."""
        _, d = self._post("/api/board/create", {"kind": "question", "title": "붙임 확인",
                                                "body": "본문", "incidents": ["INC-B1"]}, self.ca)
        pid = d["id"]
        lst = json.loads(self.s.req("GET", "/api/board/list", cookie=self.ca)[1])
        self.assertEqual(lst["stats"], {"posts": 1, "open": 1, "replies": 0})
        self._post("/api/board/create", {"kind": "share", "title": "공유 글", "body": "본문"}, self.ca)   # 분석 공유는 미해결로 세지 않는다(10-14)
        lst = json.loads(self.s.req("GET", "/api/board/list", cookie=self.ca)[1])
        self.assertEqual(lst["stats"], {"posts": 2, "open": 1, "replies": 0})
        own = json.loads(self.s.req("GET", f"/api/board/post?id={pid}", cookie=self.ca)[1])
        self.assertEqual(own["attached"][0]["id"], "INC-B1")
        self.assertEqual(own["attached"][0]["name"], "wasprd01")      # 등록한 담당자에게는 원문
        self.assertFalse(own["attached"][0]["masked"])
        self.assertTrue(own["attached"][0]["mine"])
        other = json.loads(self.s.req("GET", f"/api/board/post?id={pid}", cookie=self.cb)[1])
        self.assertEqual(other["attached"][0]["name"], "**")          # 이름에 섞인 호스트명도 가린다
        self.assertTrue(other["attached"][0]["masked"])
        self.assertFalse(other["attached"][0]["mine"])

    def test_incident_events_are_a_list(self):
        """붙인 분석의 이벤트는 언제나 목록으로 준다 — 원본 보관이 끝난 건은 빈 목록 + 안내문(2026-09-22 2차)."""
        _, d = self._post("/api/board/create", {"kind": "question", "title": "이벤트 확인",
                                                "body": "본문", "incidents": ["INC-B1"]}, self.ca)
        pid = d["id"]
        v = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.ca)[1])
        self.assertIsInstance(v["events"], list)          # dict 를 그대로 넘기면 화면이 비어 버린다
        self.assertEqual(v["events"], [])
        self.assertIn("이벤트", v["note"])                 # 왜 비었는지 알려 준다

        import tempfile as _t
        jl = Path(_t.mkstemp(suffix=".jsonl")[1])
        jl.write_text(json.dumps({"ts": "2026-09-22 10:00:01", "host": "wasprd01", "layer": "WAS",
                                  "product": "JEUS", "severity": "ERROR", "code": "JEUS-3021",
                                  "message": "pool exhausted at 10.20.30.41"}, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(self.s.api.store.import_events("INC-B1", jl), 1)
        own = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.ca)[1])
        self.assertEqual(own["events"][0]["code"], "JEUS-3021")
        self.assertEqual(own["events"][0]["host"], "wasprd01")
        self.assertEqual(own["note"], "")
        other = json.loads(self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.cb)[1])
        self.assertEqual(other["events"][0]["host"], "**")            # 다른 계정에는 이벤트 줄도 가린다
        self.assertEqual(other["events"][0]["code"], "JEUS-3021")     # 코드·시각은 그대로
        self.assertNotIn("10.20.30.41", json.dumps(other, ensure_ascii=False))

    def test_reply_delete(self):
        _, d = self._post("/api/board/create", {"kind": "question", "title": "답글 삭제", "body": "본문"}, self.ca)
        pid = d["id"]
        _, r = self._post("/api/board/reply", {"id": pid, "body": "답글"}, self.cb)
        rid = r["id"]
        st, _ = self._post("/api/board/reply_delete", {"reply": rid}, self.ca)   # 남의 답글은 못 지운다
        self.assertEqual(st.status, 400)
        st, ok = self._post("/api/board/reply_delete", {"reply": rid}, self.cb)
        self.assertEqual((st.status, ok.get("ok")), (200, True))
        self.assertEqual(json.loads(self.s.req("GET", f"/api/board/post?id={pid}", cookie=self.ca)[1])["replies"], [])

    def test_only_author_edits_and_attachment_must_belong(self):
        _, d = self._post("/api/board/create", {"kind": "share", "title": "공유합니다", "body": "내용"}, self.ca)
        pid = d["id"]
        r, e = self._post("/api/board/update", {"id": pid, "title": "남의 글 고치기"}, self.cb)
        self.assertEqual(r.status, 400); self.assertIn("글쓴이만", e["error"])
        r, e = self._post("/api/board/delete", {"id": pid}, self.cb)
        self.assertEqual(r.status, 400)
        r, b = self.s.req("GET", f"/api/board/incident?post={pid}&id=INC-B1", cookie=self.ca)
        self.assertEqual(r.status, 400)
        self.assertIn("붙어 있지 않은", json.loads(b)["error"])

    def test_board_page_and_menu(self):
        r, b = self.s.req("GET", "/board", cookie=self.cb)
        page = b.decode("utf-8")
        self.assertEqual(r.status, 200)
        for want in ("게시판", "글쓰기", "분석 이력"):
            self.assertIn(want, page)
        self.assertNotIn("폐쇄망", page)


class TransportTests(unittest.TestCase):
    """접속 구간 — 사내망·VPN 은 평문 허용, 인터넷 구간은 HTTPS 필요(require_https=auto)."""

    def test_auto_policy(self):
        """auto: 같은 PC·사내망·VPN(사설 대역)은 평문 허용, 그 밖(인터넷)은 HTTPS 필요."""
        from logtriage.server import Handler

        class Fake:
            client_address = ("10.20.30.41", 5000)      # 사내망·VPN 대역
            headers = {}
            server = type("S", (), {"tls": False})()
            api = type("A", (), {"auth_conf": {"mode": "local", "require_https": "auto"}})()

        Fake._private_peer = Handler._private_peer      # 판단에 쓰는 보조 메서드도 그대로 붙인다
        Fake._need_https = Handler._need_https
        Fake._https_ok = Handler._https_ok
        Fake._loopback_peer = Handler._loopback_peer
        f = Fake()
        need, priv = f._need_https, f._private_peer
        self.assertTrue(priv())
        self.assertFalse(need())                        # 사내망: 평문 허용
        f.client_address = ("8.8.8.8", 5000)            # 인터넷 주소(공인 IP)
        self.assertFalse(priv())
        self.assertTrue(need())                         # 인터넷: HTTPS 필요
        f.api.auth_conf["require_https"] = False
        self.assertFalse(need())
        f.api.auth_conf["require_https"] = True
        f.client_address = ("10.20.30.41", 5000)
        self.assertTrue(need())                         # true 면 사내망에서도 HTTPS 요구
        f.server.tls = True
        self.assertTrue(f._https_ok())                           # 서버가 직접 TLS 로 받은 요청


if __name__ == "__main__":
    unittest.main()
