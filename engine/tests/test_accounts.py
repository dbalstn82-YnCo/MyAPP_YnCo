# -*- coding: utf-8 -*-
"""사내 이메일 계정 로그인(2026-09-21): 도메인 제한, 비밀번호 3중 저장(페퍼+scrypt+ChaCha20-Poly1305),
정책·이력·잠금·기간 만료, 첫 로그인 강제 변경, 계정 관리 API, 표준 암호 시험값(RFC 8439·5869)."""
import json
import sqlite3
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import accounts as AC  # noqa: E402
from logtriage import auth as A  # noqa: E402
from logtriage import crypto as C  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

CONF = {"mode": "local", "local": {"domain": "solideos.com", "scrypt_n": 12}}
GOOD = "Tmx-9fQr!42w"          # 정책을 만족하는 시험용 비밀번호
GOOD2 = "Pv7#kLm2$eZq"


class CryptoVectorTests(unittest.TestCase):
    def test_rfc8439_chacha20(self):
        ct = C.chacha20(bytes(range(32)), 1, bytes.fromhex("000000000000004a00000000"),
                        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
        self.assertEqual(ct[:16].hex(), "6e2e359a2568f98041ba0728dd0d6981")

    def test_rfc8439_poly1305_and_aead(self):
        self.assertEqual(C.poly1305(bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                                    b"Cryptographic Forum Research Group").hex(), "a8061dc1305136c6c22b8baf0c0127a9")
        k = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        n, aad = bytes.fromhex("070000004041424344454647"), bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        out = C.chacha20_poly1305_encrypt(k, n, pt, aad)
        self.assertEqual(out[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(C.chacha20_poly1305_decrypt(k, n, out, aad), pt)
        with self.assertRaises(C.AeadError):
            C.chacha20_poly1305_decrypt(k, n, out[:-1] + bytes([out[-1] ^ 1]), aad)
        with self.assertRaises(C.AeadError):   # 추가 데이터(이메일)가 다르면 실패
            C.chacha20_poly1305_decrypt(k, n, out, b"other")

    def test_rfc5869_hkdf_and_keyfile(self):
        self.assertEqual(C.hkdf(bytes([0x0b] * 22), bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42,
                                bytes.fromhex("000102030405060708090a0b0c")).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        with tempfile.TemporaryDirectory() as td:
            k1, k2 = C.server_key(Path(td)), C.server_key(Path(td))
            self.assertEqual(k1, k2); self.assertEqual(len(k1), 32)
            self.assertNotEqual(C.derive(Path(td), "password-pepper"), C.derive(Path(td), "verifier-enc"))


class AccountUnitTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.store = A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3")
        self.acc = AC.Accounts(self.store, self.base, CONF)

    def tearDown(self):
        self.td.cleanup()

    def test_only_company_domain(self):
        for bad in ("hong@gmail.com", "hong@solideos.co.kr", "hong@sub.solideos.com", "hong", "hong@", "@solideos.com",
                    "hong@@solideos.com", "한글@solideos.com", "hong solideos.com"):
            with self.assertRaises(A.AuthError, msg=bad):
                AC.normalize_email(bad, "solideos.com")
        self.assertEqual(AC.normalize_email("  ADF123@Solideos.COM ", "solideos.com"), "adf123@solideos.com")
        self.assertEqual(AC.normalize_email("kim.min-su_1@solideos.com", "solideos.com"), "kim.min-su_1@solideos.com")
        with self.assertRaises(A.AuthError) as cm:
            self.acc.create("user@naver.com")
        self.assertIn("@solideos.com 계정만", str(cm.exception))

    def test_password_policy(self):
        e = "adf123@solideos.com"
        for bad, why in (("Short1!", "짧음"), ("alllowercase123", "종류 부족"), ("adf123Aa!xxxx", "ID 포함"),
                         ("Solideos12!x", "회사명"), ("Aa!qwerty1234", "연속"), ("Aaaa!11112222", "반복"), ("  Tmx-9fQr!42w", "공백")):
            with self.assertRaises(A.AuthError, msg=why):
                AC.check_policy(bad, e, self.acc.conf)
        AC.check_policy(GOOD, e, self.acc.conf)
        for _ in range(20):   # 임시 비밀번호는 언제나 정책을 통과해야 한다
            AC.check_policy(AC.temp_password(), e, self.acc.conf)

    def test_storage_is_triple_protected(self):
        r = self.acc.create("adf123@solideos.com", GOOD)
        self.assertIsNone(r["password"])
        raw = Path(self.base / "data" / "auth" / "auth.sqlite3").read_bytes()
        self.assertNotIn(GOOD.encode(), raw)
        self.assertNotIn(b"scrypt", raw)          # 검증값이 통째로 암호화되어 알고리즘 이름조차 평문으로 없다
        with self.store.db() as db:
            v1 = bytes(db.execute("SELECT verifier FROM accounts").fetchone()[0])
        self.assertGreater(len(v1), 40)
        self.assertTrue(self.acc._matches("adf123@solideos.com", GOOD, v1))
        v2 = self.acc._make("adf123@solideos.com", GOOD)
        self.assertNotEqual(v1, v2)               # 소금·nonce 가 달라 같은 비밀번호도 저장값이 다르다
        p = self.acc._params("adf123@solideos.com", v1)
        self.assertEqual((p["algo"], p["n"]), ("scrypt", 2 ** 12))
        # 서버 키 파일이 없거나 바뀌면 검증 자체가 불가능(=DB 만 유출돼도 대입 불가)
        (self.base / "conf" / "secret.key").write_bytes(b"\x00" * 32)
        other = AC.Accounts(A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3"), self.base, CONF)
        with self.assertRaises(A.AuthError):
            other.verify("adf123@solideos.com", GOOD)

    def test_login_lock_history_expiry(self):
        e = "adf123@solideos.com"
        self.acc.create(e, GOOD)
        u = self.acc.verify(e, GOOD)
        self.assertEqual((u["login"], u["must_change"]), (e, False))
        for i in range(4):
            with self.assertRaises(A.AuthError):
                self.acc.verify(e, "Wrong-pass-9!")
        with self.assertRaises(A.AuthError) as cm:
            self.acc.verify(e, "Wrong-pass-9!")
        self.assertIn("잠갔습니다", str(cm.exception))
        with self.assertRaises(A.AuthError) as cm:
            self.acc.verify(e, GOOD)          # 잠긴 동안은 올바른 비밀번호도 거절
        self.assertIn("잠긴 계정", str(cm.exception))
        self.acc.unlock(e)
        self.assertTrue(self.acc.verify(e, GOOD))
        with self.assertRaises(A.AuthError):   # 현재 비밀번호 확인 필요
            self.acc.set_password(e, GOOD2, old="nope")
        self.acc.set_password(e, GOOD2, old=GOOD)
        with self.assertRaises(A.AuthError) as cm:
            self.acc.set_password(e, GOOD, old=GOOD2)   # 최근 사용 비밀번호 재사용 금지
        self.assertIn("최근에 쓴", str(cm.exception))
        self.assertTrue(self.acc.verify(e, GOOD2))
        db = sqlite3.connect(str(self.base / "data" / "auth" / "auth.sqlite3"))
        db.execute("UPDATE accounts SET pw_changed=?", (time.time() - 91 * 86400,)); db.commit(); db.close()
        self.assertTrue(self.acc.verify(e, GOOD2)["must_change"])   # 90일 지나면 변경 요구
        pw = self.acc.reset(e)
        self.assertTrue(self.acc.verify(e, pw)["must_change"])
        self.store.update_user(e, {"disabled": True}, actor="admin")
        with self.assertRaises(A.AuthError) as cm:
            self.acc.verify(e, pw)
        self.assertIn("중지", str(cm.exception))


class LoginHttpTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        prep_base(self.base, auth=CONF)
        self.s = Srv(self.base)
        self.acc = self.s.api.accounts
        self.acc.create("admin1@solideos.com", GOOD, role="admin", asset_sites=["LOCAL"])
        self.acc.create("user1@solideos.com", GOOD2, role="operator", sites=["*"])

    def tearDown(self):
        self.s.close(); self.td.cleanup()

    def form(self, **kw):
        return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}

    def pwform(self, cookie, **kw):
        """비밀번호 변경 폼 — **화면이 준 증표**를 함께 보낸다(쿠키만으로는 안 받는다).

        증표를 여기서 지어내면 화면이 증표를 안 주기 시작해도 시험이 모른다. 화면에서 읽는다.
        """
        import re as _re
        page = self.s.req("GET", "/password", cookie=cookie)[1].decode("utf-8")
        m = _re.search(r'name="t" value="([0-9a-f]{32})"', page)
        assert m, "비밀번호 변경 화면이 증표를 주지 않습니다"
        return self.form(t=m.group(1), **kw)

    def login(self, email, pw):
        body, h = self.form(email=email, password=pw)
        return self.s.req("POST", "/login", body, h)

    def test_login_page_and_flow(self):
        r, b = self.s.req("GET", "/login")
        page = b.decode("utf-8")
        self.assertEqual(r.status, 200)
        for want in ("solideo", "(주)솔리데오", "#C12554", "회사 이메일", "hong123@solideos.com", "data:image/jpeg;base64,"):
            self.assertIn(want, page)
        self.assertNotIn("사내 포털", page)
        r, b = self.login("user1@gmail.com", GOOD2)
        self.assertEqual(r.status, 401); self.assertIn("@solideos.com 계정만", b.decode())
        r, b = self.login("user1@solideos.com", "nope-12345!A")
        self.assertEqual(r.status, 401); self.assertIn("남은 시도", b.decode())
        r, _ = self.login("user1@solideos.com", GOOD2)
        ck = cookie_of(r)
        self.assertEqual((r.status, r.getheader("Location")), (302, "/")); self.assertTrue(ck)
        me = json.loads(self.s.req("GET", "/api/me", cookie=ck)[1])
        self.assertEqual((me["login"], me["auth"], me["role"], me["email_domain"], me["must_change"]),
                         ("user1@solideos.com", "email", "operator", "solideos.com", False))
        self.assertEqual(self.s.req("GET", "/", cookie=ck)[0].status, 200)
        r, _ = self.s.req("GET", "/logout", cookie=ck)
        self.assertEqual(self.s.req("GET", "/api/me", cookie=ck)[0].status, 401)

    def test_forced_change_on_first_login(self):
        pw = self.acc.reset("user1@solideos.com")
        r, _ = self.login("user1@solideos.com", pw)
        ck = cookie_of(r)
        self.assertEqual(r.getheader("Location"), "/password")
        r, _ = self.s.req("GET", "/", cookie=ck)
        self.assertEqual((r.status, r.getheader("Location")), (302, "/password"))
        r, b = self.s.req("POST", "/api/stats", [], cookie=ck)
        self.assertEqual(r.status, 403); self.assertTrue(json.loads(b)["password_change"])
        r, b = self.s.req("GET", "/password", cookie=ck)
        self.assertIn("처음 로그인", b.decode())
        body, h = self.pwform(ck, current=pw, new=GOOD, confirm="different")
        r, b = self.s.req("POST", "/password", body, h, cookie=ck)
        self.assertEqual(r.status, 400); self.assertIn("서로 다릅니다", b.decode())
        body, h = self.pwform(ck, current=pw, new="weak", confirm="weak")
        r, b = self.s.req("POST", "/password", body, h, cookie=ck)
        self.assertEqual(r.status, 400); self.assertIn("10자 이상", b.decode())
        body, h = self.pwform(ck, current=pw, new=GOOD, confirm=GOOD)
        r, _ = self.s.req("POST", "/password", body, h, cookie=ck)
        self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
        new_ck = cookie_of(r)
        self.assertEqual(self.s.req("GET", "/", cookie=new_ck)[0].status, 200)
        self.assertEqual(self.s.req("GET", "/api/me", cookie=ck)[0].status, 401)   # 변경 전 세션은 끊긴다

    def test_admin_account_api(self):
        r, _ = self.login("admin1@solideos.com", GOOD)
        ad = cookie_of(r)
        r, b = self.s.req("GET", "/api/admin/accounts", cookie=ad)
        self.assertEqual(r.status, 200)
        j = json.loads(b)
        self.assertEqual(j["domain"], "solideos.com")
        self.assertEqual({a["email"] for a in j["accounts"]}, {"admin1@solideos.com", "user1@solideos.com"})
        r, b = self.s.req("POST", "/api/admin/account_add", {"email": "new9@solideos.com", "role": "viewer"}, cookie=ad)
        self.assertEqual(r.status, 200)
        pw = json.loads(b)["password"]
        self.assertTrue(pw and len(pw) >= 12)
        r, b = self.s.req("POST", "/api/admin/account_add", {"email": "x@daum.net"}, cookie=ad)
        self.assertEqual(r.status, 400); self.assertIn("@solideos.com", json.loads(b)["error"])
        r, _ = self.login("new9@solideos.com", pw)
        self.assertEqual(r.getheader("Location"), "/password")
        for _ in range(5):
            self.login("user1@solideos.com", "Bad-pass-12!")
        r, b = self.login("user1@solideos.com", GOOD2)
        self.assertIn("잠", b.decode())
        r, _ = self.s.req("POST", "/api/admin/account_unlock", {"email": "user1@solideos.com"}, cookie=ad)
        self.assertEqual(r.status, 200)
        self.s.h._fail.clear()
        r, _ = self.login("user1@solideos.com", GOOD2)
        self.assertEqual(r.status, 302)
        r, _ = self.s.req("POST", "/api/admin/account_delete", {"email": "new9@solideos.com"}, cookie=ad)
        self.assertEqual(r.status, 200)
        self.assertEqual(len(json.loads(self.s.req("GET", "/api/admin/accounts", cookie=ad)[1])["accounts"]), 2)
        op = cookie_of(self.login("user1@solideos.com", GOOD2)[0])
        self.assertEqual(self.s.req("GET", "/api/admin/accounts", cookie=op)[0].status, 403)
        self.assertEqual(self.s.req("POST", "/api/admin/account_reset", {"email": "admin1@solideos.com"}, cookie=op)[0].status, 403)

    def test_audit_records(self):
        self.login("user1@solideos.com", "Bad-pass-12!")
        r, _ = self.login("admin1@solideos.com", GOOD)
        ad = cookie_of(r)
        rows = json.loads(self.s.req("GET", "/api/admin/audit?days=1", cookie=ad)[1])["rows"]
        acts = {(x["login"], x["action"], x["ok"]) for x in rows}
        self.assertIn(("user1@solideos.com", "login.fail", 0), acts)
        self.assertIn(("admin1@solideos.com", "login", 1), acts)
        self.assertTrue(any(x["action"] == "account.create" for x in rows))


if __name__ == "__main__":
    unittest.main()
