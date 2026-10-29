# -*- coding: utf-8 -*-
"""직접 가입 · 관리자 승인 · 막힌 명령의 승인 요청 (2026-10-01)

사용자 지시
  "페이지를 열고 계정 로그인 / 계정은 다수의 인원이 접속 할 수 있게 계정 생성을 직접 할 수
   있게하고 / 관리자 계정을 별도로 생성해서 관리자 페이지에서 계정관리가 이루어 질 수 있도록"
  "사용자 계정에 막혀 있는 명령어 승인 요청 할 수 있는 기능도 필요해"

[이 시험이 지키려는 것]
소스를 훑어 글자가 있는지 보지 않는다 — **실제 서버를 띄워 눌러 본다.** 이 제품에서 큰
결함은 모두 초록색 시험을 지나갔고(사이트 ID 잠금, 신원 승계, 토큰 승계, 깨진 화면 대본,
현장 기동 실패) 실물을 구동해서야 잡혔다.

막는 것만 보면 '늘 막힘' 도 통과한다. 그래서 **되는 쪽(양성 대조)** 을 반드시 함께 본다 —
관리자는 되고 조회 권한은 안 되는지, 조회 권한도 '요청' 은 되는지.
"""
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
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

PWA = "Bq7-Zrt2!wVm"      # 관리자
PWU = "Hn4#kXc9$zRp"      # 가입하는 사람
PWV = "Ljr6@tWq3!yBn"


def conf(signup="approve"):
    return {"mode": "local", "first_admin": "",
            "local": {"domain": "solideos.com", "scrypt_n": 12, "signup": signup}}


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class Base(unittest.TestCase):
    SIGNUP = "approve"

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=conf(self.SIGNUP))
        self.s = Srv(self.base)
        self.admin = self._setup_admin()

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def _setup_admin(self, email="boss@solideos.com"):
        # 첫 계정 만들기에는 1회용 코드가 필요하다(setup_scope 기본값 token) — 현장 흐름 그대로.
        body, h = form(email=email, name="관리자", password=PWA, confirm=PWA, t=self.s.api.setup_token)
        r, _ = self.s.req("POST", "/setup", body, h)
        self.assertEqual(r.status, 302, "관리자 계정을 만들지 못했습니다 — 이 뒤 시험이 모두 뜻을 잃습니다")
        ck = cookie_of(r)
        self.assertTrue(ck)
        return ck

    def _join(self, email="hong@solideos.com", password=PWU, code="", name="홍길동", dept="인프라운영팀"):
        body, h = form(email=email, name=name, dept=dept, password=password, confirm=password, code=code)
        return self.s.req("POST", "/join", body, h)

    def _login(self, email="hong@solideos.com", password=PWU):
        body, h = form(email=email, password=password)
        return self.s.req("POST", "/login", body, h)


class JoinScreenTests(Base):
    """로그인 화면에서 [계정 만들기] 로 들어가는 길."""

    def test_the_login_page_offers_it(self):
        page = self.s.req("GET", "/login")[1].decode("utf-8")
        self.assertIn('href="/join"', page)
        self.assertIn("계정 만들기", page)

    def test_the_form_has_no_role_field(self):
        """신청하는 사람이 자기 권한을 적어 내면 그것은 권한 체계가 아니다."""
        page = self.s.req("GET", "/join")[1].decode("utf-8")
        self.assertIn('name="email"', page)
        self.assertIn('name="password"', page)
        self.assertNotIn('name="role"', page)
        self.assertIn("조회", page)                      # 어떤 권한으로 만들어지는지 적어 둔다

    def test_without_any_account_it_goes_to_setup_first(self):
        """계정이 하나도 없는 서버에서는 **첫 관리자**부터 만든다 — 가입으로 들어오지 못한다."""
        with tempfile.TemporaryDirectory() as td:
            s = Srv(prep_base(Path(td), auth=conf()))
            try:
                r, _ = s.req("GET", "/join")
                self.assertEqual((r.status, r.getheader("Location")), (302, "/setup"))
                body, h = form(email="x@solideos.com", name="x", password=PWU, confirm=PWU)
                r, _ = s.req("POST", "/join", body, h)   # 계정이 없는 서버에서는 가입이 막힌다
                self.assertEqual(r.status, 403)
                self.assertEqual(AC.Accounts(s.api.auth, Path(td), conf()).count(), 0)
            finally:
                s.close()

    def test_it_is_not_there_when_the_login_mode_has_no_accounts(self):
        """단일 비밀번호·로그인 없음 서버에는 '내 계정' 이 없다 — 가입 길도 없어야 한다."""
        with tempfile.TemporaryDirectory() as td:
            b = prep_base(Path(td), auth={"mode": "off"})
            s = Srv(b)
            try:
                self.assertEqual(s.req("GET", "/join")[0].status, 404)
                self.assertEqual(s.req("POST", "/join", *form(email="a@solideos.com"))[0].status, 404)
            finally:
                s.close()


class ApprovalFlowTests(Base):
    """기본값 — 누구나 신청하고 관리자가 승인한다."""

    def test_signup_then_wait_then_approved(self):
        r, b = self._join()
        self.assertEqual(r.status, 200)
        self.assertIn("접수", b.decode("utf-8"))

        # ① 승인 전에는 **맞는 비밀번호로도** 못 들어온다
        r, b = self._login()
        self.assertEqual(r.status, 401)
        page = b.decode("utf-8")
        self.assertIn("승인", page)
        self.assertNotIn("Set-Cookie", str(r.getheaders()))

        # ② 관리자 화면에 신청이 보인다 — 이름·부서까지
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        self.assertEqual([x["email"] for x in j["pending"]], ["hong@solideos.com"])
        self.assertEqual(j["pending"][0]["name"], "홍길동")
        self.assertEqual(j["pending"][0]["dept"], "인프라운영팀")
        self.assertEqual(j["signup"]["mode"], "approve")

        # ③ 승인하면 들어온다
        r, b = self.s.req("POST", "/api/admin/account_approve",
                          {"email": "hong@solideos.com", "role": "operator"}, cookie=self.admin)
        self.assertEqual(r.status, 200, b)
        r, _ = self._login()
        self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
        me = json.loads(self.s.req("GET", "/api/me", cookie=cookie_of(r))[1])
        self.assertEqual((me["login"], me["role"]), ("hong@solideos.com", "operator"))
        self.assertFalse(me["must_change"])      # 본인이 정한 비밀번호다 — 다시 바꾸게 하지 않는다

    def test_a_wrong_password_on_a_pending_account_says_nothing_about_approval(self):
        """남의 ID 로 '승인 대기인지' 를 떠볼 수 없다 — 비밀번호가 맞은 뒤에만 알려 준다."""
        self._join()
        r, b = self._login(password="Wrong-Pass!99x")
        self.assertEqual(r.status, 401)
        page = b.decode("utf-8")
        self.assertNotIn("승인", page)
        self.assertIn("맞지 않습니다", page)

    def test_reject_removes_the_request_and_allows_a_new_one(self):
        self._join()
        r, _ = self.s.req("POST", "/api/admin/account_reject", {"email": "hong@solideos.com"}, cookie=self.admin)
        self.assertEqual(r.status, 200)
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        self.assertEqual(j["pending"], [])
        self.assertNotIn("hong@solideos.com", [a["email"] for a in j["accounts"]])
        self.assertEqual(self._join()[0].status, 200)       # 같은 ID 로 다시 신청할 수 있다

    def test_an_approved_account_cannot_be_rejected(self):
        """쓰고 있는 계정을 '거절' 로 지우지 않는다 — 그 길은 [중지]·[삭제] 다."""
        self._join()
        self.s.req("POST", "/api/admin/account_approve", {"email": "hong@solideos.com"}, cookie=self.admin)
        r, b = self.s.req("POST", "/api/admin/account_reject", {"email": "hong@solideos.com"}, cookie=self.admin)
        self.assertEqual(r.status, 400)
        self.assertIn("이미 승인", json.loads(b)["error"])

    def test_a_viewer_cannot_approve(self):
        """승인은 관리자만 — 조회 권한으로 자기 신청을 통과시킬 수 없다."""
        self._join()
        self.s.req("POST", "/api/admin/account_approve", {"email": "hong@solideos.com"}, cookie=self.admin)
        ck = cookie_of(self._login()[0])
        self._join(email="other@solideos.com", password=PWV, name="다른사람")
        r, _ = self.s.req("POST", "/api/admin/account_approve", {"email": "other@solideos.com", "role": "admin"},
                          cookie=ck)
        self.assertEqual(r.status, 403)
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        self.assertEqual([x["email"] for x in j["pending"]], ["other@solideos.com"])


class OpenAndCodeTests(Base):
    """가입 방식 네 가지 — 즉시 사용 · 가입 코드 · 받지 않음."""

    def test_open_lets_them_in_at_once(self):
        """'즉시 사용' 은 **설정 파일로만** 켠다(화면에서는 못 켠다) — 켠 서버에서는 바로 들어온다."""
        with tempfile.TemporaryDirectory() as td:
            base = prep_base(Path(td), auth=conf("open"))
            s2 = Srv(base)
            try:
                body, h = form(email="boss2@solideos.com", name="관리자", password=PWA, confirm=PWA,
                               t=s2.api.setup_token)
                self.assertEqual(s2.req("POST", "/setup", body, h)[0].status, 302)
                body, h = form(email="hong@solideos.com", name="홍길동", dept="운영",
                               password=PWU, confirm=PWU)
                self.assertEqual(s2.req("POST", "/join", body, h)[0].status, 200)
                body, h = form(email="hong@solideos.com", password=PWU)
                r, _ = s2.req("POST", "/login", body, h)
                self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
                me = json.loads(s2.req("GET", "/api/me", cookie=cookie_of(r))[1])
                self.assertEqual(me["role"], "viewer")   # 직접 가입은 언제나 조회 권한이다
            finally:
                s2.close()

    def test_changing_the_mode_needs_no_restart(self):
        """설정 변경 때문에 서비스를 다시 띄우지 않는다(사용자 규칙) — **같은 프로세스**에서 바뀐다."""
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "off"}, cookie=self.admin)
        self.assertEqual(self.s.req("GET", "/join")[0].status, 403)
        self.assertEqual(self._join()[0].status, 403)
        self.assertNotIn('href="/join"', self.s.req("GET", "/login")[1].decode("utf-8"))
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "approve"}, cookie=self.admin)
        self.assertEqual(self.s.req("GET", "/join")[0].status, 200)
        self.assertEqual(self._join()[0].status, 200)
        # 파일에도 남는다(다음 기동에도 같은 값) — 그리고 로그인 방식은 손대지 않는다
        c = json.loads((self.base / "conf" / "auth.json").read_text(encoding="utf-8"))
        self.assertEqual(c["local"]["signup"], "approve")
        self.assertEqual(c["mode"], "local")

    def test_an_unknown_mode_is_refused(self):
        r, b = self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "전부열기"}, cookie=self.admin)
        self.assertEqual(r.status, 400)
        self.assertEqual(self.s.api.accounts.conf["signup"], "approve")

    def test_a_viewer_cannot_change_the_mode(self):
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {},
                                     cookie=self.admin)[1])["code"]
        self._join(code=code)
        ck = cookie_of(self._login()[0])
        r, _ = self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "off"}, cookie=ck)
        self.assertEqual(r.status, 403)
        self.assertEqual(self.s.api.accounts.conf["signup"], "code")

    def test_the_signup_code(self):
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        j = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {"max_uses": 1, "minutes": 60},
                                  cookie=self.admin)[1])
        code = j["code"]
        self.assertRegex(code, r"^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        self.assertIn("가입 코드", self.s.req("GET", "/join")[1].decode("utf-8"))

        r, b = self._join()                                   # 코드 없이
        self.assertEqual(r.status, 400)
        self.assertIn("가입 코드", b.decode("utf-8"))
        r, b = self._join(code="AAAA-BBBB-CCCC")              # 틀린 코드
        self.assertEqual(r.status, 400)
        r, _ = self._join(code=code.lower().replace("-", " "))  # 대소문자·붙임표는 무시한다
        self.assertEqual(r.status, 200)
        r, _ = self._login()                                  # 코드를 받은 사람은 승인을 기다리지 않는다
        self.assertEqual((r.status, r.getheader("Location")), (302, "/"))
        # 1회만 쓰게 발급했으므로 다음 사람은 막힌다
        r, b = self._join(email="two@solideos.com", password=PWV, code=code)
        self.assertEqual(r.status, 400)
        self.assertIn("기한이 지났", b.decode("utf-8"))

    def test_a_cancelled_code_stops_working(self):
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {}, cookie=self.admin)[1])["code"]
        self.s.req("POST", "/api/admin/account_signup_code_cancel", {}, cookie=self.admin)
        self.assertEqual(self._join(code=code)[0].status, 400)

    def test_the_code_is_not_stored_in_the_clear(self):
        """코드도 비밀번호와 같은 세 겹으로만 남는다 — DB 만 빠져나가도 되돌릴 수 없다."""
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {}, cookie=self.admin)[1])["code"]
        raw = (self.base / "data" / "auth" / "auth.sqlite3").read_bytes()
        self.assertNotIn(code.encode(), raw)
        self.assertNotIn(code.replace("-", "").encode(), raw)


class SignupRulesTests(Base):
    """가입에도 같은 규칙이 걸린다 — 도메인 · 비밀번호 · 중복."""

    def test_another_domain_cannot_join(self):
        r, b = self._join(email="hong@gmail.com")
        self.assertEqual(r.status, 400)
        self.assertIn("solideos.com", b.decode("utf-8"))

    def test_a_weak_password_is_refused(self):
        for pw in ("short1!A", "abcd1234abcd", "solideos2026!"):
            with self.subTest(pw=pw):
                r, _ = self._join(password=pw)
                self.assertEqual(r.status, 400)
        self.assertEqual(json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])["pending"], [])

    def test_two_passwords_must_match(self):
        body, h = form(email="hong@solideos.com", name="홍", password=PWU, confirm=PWV)
        r, b = self.s.req("POST", "/join", body, h)
        self.assertEqual(r.status, 400)
        self.assertIn("서로 다릅니다", b.decode("utf-8"))

    def test_an_existing_id_cannot_join_again(self):
        self._join()
        r, b = self._join()
        self.assertEqual(r.status, 400)
        self.assertIn("이미 등록된", b.decode("utf-8"))
        r, b = self._join(email="boss@solideos.com", password=PWV)     # 관리자 ID 를 덮어쓰려는 시도
        self.assertEqual(r.status, 400)
        me = json.loads(self.s.req("GET", "/api/me", cookie=self.admin)[1])
        self.assertEqual(me["role"], "admin")                          # 관리자는 그대로다

    def test_the_reason_and_name_are_not_stored_in_the_clear(self):
        self._join(name="홍길동", dept="인프라운영팀")
        raw = (self.base / "data" / "auth" / "auth.sqlite3").read_bytes()
        self.assertNotIn("hong@solideos.com".encode(), raw)
        self.assertNotIn("인프라운영팀".encode("utf-8"), raw)


class AccessRequestTests(Base):
    """막힌 명령의 승인 요청 — 막기만 하고 끝내지 않는다."""

    def _viewer(self, email="hong@solideos.com", password=PWU):
        """조회 권한 사용자 하나 — 관리자가 가입 코드를 주고 그 코드로 들어오는 길.

        '즉시 사용' 으로 만들던 것을 바꿨다. 그 방식은 화면에서 켤 수 없게 했으므로
        (닿을 수 있는 사람이 모두 들어오는 길), 시험도 현장이 쓸 길로 만든다.
        """
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {},
                                     cookie=self.admin)[1])["code"]
        self._join(email=email, password=password, code=code)
        r, _ = self._login(email, password)
        return cookie_of(r)

    def test_a_blocked_command_tells_how_to_ask(self):
        """운영 권한이 필요한 명령이 막히면 **요청할 길**을 함께 준다."""
        ck = self._viewer()
        r, b = self.s.req("POST", "/api/analyze", [], cookie=ck)
        self.assertEqual(r.status, 403)
        j = json.loads(b)
        self.assertEqual(j["request"], {"kind": "role", "want": "operator", "action": "POST /api/analyze"})

        # 양성 대조 — 관리자는 같은 길로 지나간다(모두 막혀서 통과하는 시험이 아니다)
        self.assertEqual(self.s.req("GET", "/api/admin/users", cookie=self.admin)[0].status, 200)

    def test_a_command_needing_admin_does_not_offer_a_request(self):
        """줄 수 없는 것을 내밀지 않는다 — 내밀어 놓고 거절하면 화면과 서버가 어긋난다."""
        ck = self._viewer()
        r, b = self.s.req("POST", "/api/admin/users", {}, cookie=ck)
        self.assertEqual(r.status, 403)
        j = json.loads(b)
        self.assertNotIn("request", j)
        self.assertIn("요청으로 드리지 않습니다", j["error"])
        page = self.s.req("GET", "/admin", cookie=ck)[1].decode("utf-8")
        self.assertNotIn('action="/access-request"', page)
        self.assertIn("계정 발급", page)

    def test_the_whole_round_trip(self):
        ck = self._viewer()
        self.s.req("POST", "/api/admin/users", {}, cookie=ck)
        r, b = self.s.req("POST", "/api/access/request",
                          {"kind": "role", "want": "operator", "action": "POST /api/analyze",
                           "reason": "부산 장애 1차 대응을 맡았습니다"}, cookie=ck)
        self.assertEqual(r.status, 200, b)

        j = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])
        self.assertEqual(len(j["requests"]), 1)
        q = j["requests"][0]
        self.assertEqual((q["login"], q["kind"], q["want"], q["status"]),
                         ("hong@solideos.com", "role", "operator", "pending"))
        self.assertEqual(q["action"], "POST /api/analyze")          # 무엇을 하려다 막혔는지
        self.assertIn("부산", q["reason"])                           # 왜 필요한지

        r, b = self.s.req("POST", "/api/admin/request_decide", {"id": q["id"], "approve": True}, cookie=self.admin)
        self.assertEqual(r.status, 200, b)
        # 권한이 **실제로** 올라갔다 — 표시만 바꾸면 그 사람은 또 막힌다
        users = {u["login"]: u for u in json.loads(self.s.req("GET", "/api/admin/users", cookie=self.admin)[1])["users"]}
        self.assertEqual(users["hong@solideos.com"]["role"], "operator")
        # 권한이 바뀌면 그 접속은 끊긴다(새 권한은 다시 로그인한 뒤부터)
        self.assertEqual(self.s.req("GET", "/api/me", cookie=ck)[0].status, 401)
        ck2 = cookie_of(self._login()[0])
        self.assertEqual(json.loads(self.s.req("GET", "/api/me", cookie=ck2)[1])["role"], "operator")

    def test_a_denied_request_changes_nothing(self):
        ck = self._viewer()
        self.s.req("POST", "/api/access/request", {"kind": "role", "want": "operator", "reason": "다 보고 싶습니다"},
                   cookie=ck)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"][0]
        r, _ = self.s.req("POST", "/api/admin/request_decide",
                          {"id": q["id"], "approve": False, "note": "담당이 아닙니다"}, cookie=self.admin)
        self.assertEqual(r.status, 200)
        users = {u["login"]: u for u in json.loads(self.s.req("GET", "/api/admin/users", cookie=self.admin)[1])["users"]}
        self.assertEqual(users["hong@solideos.com"]["role"], "viewer")
        mine = json.loads(self.s.req("GET", "/api/access/mine", cookie=ck)[1])["requests"]
        self.assertEqual((mine[0]["status"], mine[0]["note"]), ("denied", "담당이 아닙니다"))
        # 같은 요청을 두 번 처리하지 않는다
        self.assertEqual(self.s.req("POST", "/api/admin/request_decide", {"id": q["id"], "approve": True},
                                    cookie=self.admin)[0].status, 400)

    def test_a_request_cannot_be_made_for_someone_else(self):
        """요청자는 **세션에서** 온다 — 본문에 남의 ID 를 적어도 바뀌지 않는다."""
        ck = self._viewer()
        self.s.req("POST", "/api/access/request",
                   {"login": "boss@solideos.com", "kind": "role", "want": "operator", "reason": "x"}, cookie=ck)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"]
        self.assertEqual([x["login"] for x in q], ["hong@solideos.com"])

    def test_a_viewer_cannot_decide(self):
        ck = self._viewer()
        self.s.req("POST", "/api/access/request", {"kind": "role", "want": "operator", "reason": "x"}, cookie=ck)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"][0]
        self.assertEqual(self.s.req("POST", "/api/admin/request_decide", {"id": q["id"], "approve": True},
                                    cookie=ck)[0].status, 403)
        self.assertEqual(self.s.req("GET", "/api/admin/requests", cookie=ck)[0].status, 403)
        users = {u["login"]: u for u in json.loads(self.s.req("GET", "/api/admin/users", cookie=self.admin)[1])["users"]}
        self.assertEqual(users["hong@solideos.com"]["role"], "viewer")

    def test_the_same_request_does_not_pile_up(self):
        ck = self._viewer()
        for i in range(4):
            self.s.req("POST", "/api/access/request", {"kind": "role", "want": "operator", "reason": f"{i}번째"},
                       cookie=ck)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"]
        self.assertEqual(len(q), 1)
        self.assertIn("3번째", q[0]["reason"])      # 마지막 사유로 덮어쓴다

    def test_bad_requests_are_refused(self):
        ck = self._viewer()
        for v in ({"kind": "god", "want": "operator"}, {"kind": "role", "want": "superuser"},
                  {"kind": "role", "want": "admin"},        # 관리자는 요청으로 주지 않는다
                  {"kind": "site", "want": "../etc"}, {"kind": "asset", "want": ""}):
            with self.subTest(**v):
                r, _ = self.s.req("POST", "/api/access/request", v, cookie=ck)
                self.assertEqual(r.status, 400)
        self.assertEqual(json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"], [])

    def test_the_reason_is_not_stored_in_the_clear(self):
        ck = self._viewer()
        self.s.req("POST", "/api/access/request",
                   {"kind": "role", "want": "operator", "reason": "부산아이디씨담당입니다"}, cookie=ck)
        raw = (self.base / "data" / "auth" / "auth.sqlite3").read_bytes()
        self.assertNotIn("부산아이디씨담당입니다".encode("utf-8"), raw)

    def test_the_denial_note_is_not_stored_in_the_clear_either(self):
        """관리자가 적는 거절 사유도 요청자에게 보여 주는 글이다 — 같은 급으로 다룬다.

        처음에는 감사 기록의 평문 칸(detail)과 요청 줄의 평문 칸(note)에 그대로 넣었다.
        시험이 잡아 줬다 — 사유에는 장비 주소·호스트명이 섞일 수 있고, 분석 이력에서는
        그것을 가리고 있다. 가려 둔 것을 다른 표가 흘리면 가린 뜻이 없다.
        """
        ck = self._viewer()
        self.s.req("POST", "/api/access/request",
                   {"kind": "role", "want": "operator", "reason": "서버실 야간당번"}, cookie=ck)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"][0]
        self.s.req("POST", "/api/admin/request_decide",
                   {"id": q["id"], "approve": False, "note": "야간당번은 운영권한 대상이 아닙니다"},
                   cookie=self.admin)
        raw = (self.base / "data" / "auth" / "auth.sqlite3").read_bytes()
        self.assertNotIn("야간당번은 운영권한 대상이 아닙니다".encode("utf-8"), raw)
        self.assertNotIn("서버실 야간당번".encode("utf-8"), raw)
        # 그래도 요청자와 관리자에게는 보인다(암호화해 둔 것이지 버린 것이 아니다)
        mine = json.loads(self.s.req("GET", "/api/access/mine", cookie=ck)[1])["requests"][0]
        self.assertIn("야간당번", mine["note"])
        self.assertIn("야간당번", mine["reason"])

    def test_the_blocked_screen_has_a_form_not_a_script(self):
        """막힌 **화면**(GET)에서도 요청할 수 있다. 그 자리에 대본을 지어 넣지 않는다 —
        대본이 깨지면 화면이 통째로 죽는다(전에 겪었다).

        자산 조회로 본다. 화면 중 권한으로 막히는 것은 관리자 화면뿐인데, 관리자 권한은
        요청으로 주지 않기로 해서 그 자리에는 폼이 나오지 않는다(바로 위 시험).
        """
        ck = self._viewer()
        r, b = self.s.req("GET", "/resources", cookie=ck)
        page = b.decode("utf-8")
        self.assertEqual(r.status, 403)
        self.assertIn('action="/access-request"', page)
        self.assertIn('name="kind" value="asset"', page)
        self.assertIn('name="want" value="LOCAL"', page)
        self.assertIn('name="reason"', page)
        self.assertNotIn("fetch(", page)
        # 폼이 실제로 동작하고(대본 없이), 두 번째로 열면 '기다리고 있습니다' 가 된다
        import re as _re
        tok = _re.search(r'name="t" value="([0-9a-f]{32})"', page).group(1)
        body, h = form(kind="asset", want="LOCAL", action="GET /resources",
                       reason="부산 IDC 자산 담당입니다", t=tok)
        r, b = self.s.req("POST", "/access-request", body, h, cookie=ck)
        self.assertEqual(r.status, 200)
        self.assertIn("승인 요청을 보냈습니다", b.decode("utf-8"))
        page = self.s.req("GET", "/resources", cookie=ck)[1].decode("utf-8")
        self.assertIn("기다리고", page)
        self.assertNotIn('action="/access-request"', page)
        q = json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"][0]
        self.assertEqual((q["kind"], q["want"], q["action"]), ("asset", "LOCAL", "GET /resources"))
        # 승인하면 그 사이트 자산 조회 권한이 **실제로** 붙는다
        r, _ = self.s.req("POST", "/api/admin/request_decide", {"id": q["id"], "approve": True},
                          cookie=self.admin)
        self.assertEqual(r.status, 200)
        users = {u["login"]: u for u in json.loads(
            self.s.req("GET", "/api/admin/users", cookie=self.admin)[1])["users"]}
        self.assertIn("LOCAL", users["hong@solideos.com"]["asset_sites"])

    def test_asking_is_allowed_even_though_the_command_is_not(self):
        """양성 대조 — 조회 권한으로 '막힌 것' 과 '요청' 이 같이 막히면 기능이 없는 것과 같다."""
        ck = self._viewer()
        self.assertEqual(self.s.req("POST", "/api/admin/users", {}, cookie=ck)[0].status, 403)
        self.assertEqual(self.s.req("POST", "/api/access/request",
                                    {"kind": "role", "want": "operator", "reason": "x"}, cookie=ck)[0].status, 200)
        self.assertEqual(self.s.req("GET", "/api/access/mine", cookie=ck)[0].status, 200)

    def test_not_logged_in_cannot_ask(self):
        self.assertEqual(self.s.req("POST", "/api/access/request",
                                    {"kind": "role", "want": "operator"})[0].status, 401)
        # 폼 자리도 로그인부터 — 열어 둔 화면에서 세션이 끊긴 뒤 누르면 401 이다
        self.assertEqual(self.s.req("POST", "/access-request", *form(kind="role", want="operator"))[0].status, 401)


class AdminScreenTests(Base):
    """관리자 화면이 **그 일을 할 수 있는 화면**인지 — 길만 나 있고 화면이 없던 것을 고쳤다."""

    def test_the_account_tab_exists_and_calls_the_right_apis(self):
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        for want in ('data-t="acct"', "계정 · 가입", "권한 요청",
                     "/api/admin/accounts", "/api/admin/account_approve", "/api/admin/account_reject",
                     "/api/admin/account_reset", "/api/admin/account_signup_mode",
                     "/api/admin/account_signup_code", "/api/admin/requests", "/api/admin/request_decide"):
            with self.subTest(want=want):
                self.assertIn(want, page)

    def test_the_screen_says_what_open_signup_costs(self):
        """불편을 감수하더라도 대가는 조용히 두지 않는다."""
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("누구나", page)
        self.assertIn("다시 시작하지 않습니다", page)

    def test_the_screen_says_which_login_is_running(self):
        """머리 표시도 기동 배너와 같은 병을 앓고 있었다 — 계정 로그인으로 돌고 있는데
        '기존 방식(통합 로그인 미설정)' 에 빨간불이었다. 실물을 띄워 보고 잡았다.

        여기서는 화면 글자만 본다(대본이 채우는 자리라 서버 쪽에서 눌러 볼 수 없다).
        실제로 어떻게 보이는지는 브라우저로 열어 확인했다.
        """
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("계정 로그인(회사 이메일)", page)
        self.assertNotIn("기존 방식(통합 로그인 미설정)", page)

    def test_the_tab_counts_everything_that_waits(self):
        """가입 신청만 세면, 권한 요청이 밀려 있어도 탭이 조용하다."""
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("PEND.join", page)
        self.assertIn("PEND.req", page)
        self.assertIn("PEND.join+PEND.req", page)

    def test_no_password_is_ever_shown_in_a_list(self):
        """비밀번호는 아무도 볼 수 없다 — 목록 API 가 값을 내보내지 않는지 본다."""
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "open"}, cookie=self.admin)
        self._join()
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        for a in j["accounts"]:
            self.assertNotIn("password", a)
            self.assertNotIn("verifier", a)
        self.assertNotIn(PWU, json.dumps(j, ensure_ascii=False))


class BootBannerTests(unittest.TestCase):
    """기동 줄은 담당자가 '로그인이 걸렸는지' 보는 **유일한 자리**다 — 사실만 적는다.

    실물을 띄워 보고 잡았다. 계정 로그인으로 떠 있는 서버가 `auth=off` 라고 적고 있었다
    (배너가 portal 과 단일 비밀번호만 알았다). 기본값이 계정 로그인으로 바뀌면서 현장에서
    **매번** 틀린 줄을 읽게 될 자리였다.
    """

    def test_it_says_what_the_login_really_is(self):
        from logtriage.server import auth_banner
        self.assertEqual(auth_banner({"mode": "local"}, None), "local(계정)")
        self.assertEqual(auth_banner({"mode": "local"}, "pw"), "local(계정)+password")
        self.assertEqual(auth_banner({"mode": "portal", "portal": {"method": "ldap"}}, None), "portal:ldap")
        self.assertEqual(auth_banner({"mode": "password"}, "pw"), "password")
        self.assertEqual(auth_banner({"mode": "off"}, None), "off(로그인 없음)")
        self.assertEqual(auth_banner(None, None), "off(로그인 없음)")

    def test_it_never_calls_an_account_server_open(self):
        """계정 로그인인데 'off' 라고 적는 길이 하나도 없어야 한다."""
        from logtriage.server import auth_banner
        for pw in (None, "", "pw"):
            with self.subTest(password=pw):
                self.assertNotIn("off", auth_banner({"mode": "local"}, pw))
                self.assertNotIn("off", auth_banner({"mode": "portal", "portal": {"method": "oidc"}}, pw))


class GptGateTests(Base):
    """GPT 20차가 건 네 관문.

    ① 원격 계정 로그인이 HTTPS 로 보호되는가
    ② 첫 관리자 생성·승인 전 로그인 차단 — 위 ApprovalFlowTests 가 이미 왕복으로 본다
    ③ 일반 명령 승인으로 **관리자 권한이 나가지 않는가**
    ④ 가입 코드 동시 소비 · 폼의 CSRF · 관리자 화면의 사유 XSS
    """

    def _viewer(self, email="hong@solideos.com", password=PWU):
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {}, cookie=self.admin)[1])["code"]
        self._join(email=email, password=password, code=code)
        return cookie_of(self._login(email, password)[0])

    # ── ③ 관리자 권한은 요청으로 나가지 않는다 ──
    def test_an_admin_role_cannot_be_requested(self):
        ck = self._viewer()
        r, b = self.s.req("POST", "/api/access/request",
                          {"kind": "role", "want": "admin", "reason": "다 하고 싶습니다"}, cookie=ck)
        self.assertEqual(r.status, 400)
        self.assertIn("관리자", json.loads(b)["error"])
        self.assertEqual(json.loads(self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1])["requests"], [])
        # 양성 대조 — 운영 권한은 요청할 수 있다(막기만 보면 '늘 막힘' 도 통과한다)
        self.assertEqual(self.s.req("POST", "/api/access/request",
                                    {"kind": "role", "want": "operator", "reason": "1차 대응"},
                                    cookie=ck)[0].status, 200)

    def test_the_blocked_screen_does_not_offer_what_the_server_refuses(self):
        """화면이 내민 요청이 서버에서 거절되면 그것은 어긋남이다."""
        ck = self._viewer()
        r, b = self.s.req("GET", "/admin", cookie=ck)
        self.assertEqual(r.status, 403)
        if 'action="/access-request"' in b.decode("utf-8"):
            body, h = form(kind="role", want="admin", action="GET /admin", reason="x")
            r2, _ = self.s.req("POST", "/access-request", body, h, cookie=ck)
            self.assertEqual(r2.status, 400)

    def test_the_admin_screen_says_the_cap(self):
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("관리자 권한은 요청으로 드리지 않습니다", page)

    # ── '즉시 사용' 은 화면에서 못 켠다 ──
    def test_open_cannot_be_turned_on_from_the_screen(self):
        r, b = self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "open"}, cookie=self.admin)
        self.assertEqual(r.status, 400)
        self.assertIn("conf/auth.json", json.loads(b)["error"])
        self.assertEqual(self.s.api.accounts.conf["signup"], "approve")
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        self.assertNotIn("open", j["signup"]["screen"])

    def test_the_screen_offers_exactly_what_the_server_accepts(self):
        """화면이 고르게 하는 것과 서버가 받는 것이 **같아야** 한다.

        실제로 어긋났다 — 서버는 '즉시 사용' 을 거절하는데 화면은 그대로 고르게 두고
        있었다(패치 스크립트가 중간에 죽어 한 줄이 반영되지 않았다). 눌러 보고 잡았다.
        여기서는 글자를 보지 않고, 화면이 받은 목록 그대로 **서버에 넣어 본다.**
        """
        j = json.loads(self.s.req("GET", "/api/admin/accounts", cookie=self.admin)[1])
        pickable, every = j["signup"]["screen"], list(j["signup"]["modes"])
        self.assertTrue(pickable and set(pickable) <= set(every))
        for m in every:
            r, _ = self.s.req("POST", "/api/admin/account_signup_mode", {"mode": m}, cookie=self.admin)
            with self.subTest(mode=m):
                if m in pickable:
                    self.assertEqual(r.status, 200, f"화면은 {m} 를 고르게 하는데 서버가 거절합니다")
                else:
                    self.assertEqual(r.status, 400, f"화면에 없는 {m} 를 서버가 받습니다")
        # 화면 대본도 서버가 준 목록을 쓴다(전체를 늘어놓지 않는다)
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("sm.screen", page)
        self.assertNotIn("Object.keys(modes).map", page)

    def test_open_still_works_when_set_in_the_file(self):
        """켜는 자리를 옮긴 것이지 기능을 없앤 것이 아니다."""
        with tempfile.TemporaryDirectory() as td:
            s2 = Srv(prep_base(Path(td), auth=conf("open")))
            try:
                self.assertEqual(s2.api.accounts.conf["signup"], "open")
            finally:
                s2.close()

    # ── ④ 가입 코드 동시 소비 ──
    def test_the_signup_code_cannot_be_overspent_by_racing(self):
        """같은 코드로 동시에 들이쳐도 **발급한 횟수보다 많이** 쓰이지 않아야 한다."""
        import threading
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code",
                                     {"max_uses": 2, "minutes": 60}, cookie=self.admin)[1])["code"]
        done, lock = [], threading.Lock()

        def go(i):
            r, _ = self._join(email="race%d@solideos.com" % i, password=PWU, code=code, name="경쟁%d" % i)
            with lock:
                done.append(r.status)

        ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(60)
        ok = sum(1 for st in done if st == 200)
        self.assertEqual(ok, 2, "2명까지인데 %d명이 들어왔습니다: %s" % (ok, done))
        self.assertEqual(self.s.api.accounts.signup_code_status()["uses"], 2)

    # ── ④ 폼의 CSRF ──
    def test_a_cross_origin_form_post_is_refused(self):
        """막힌 화면의 요청은 평범한 폼이다 — 남의 사이트가 흉내 내지 못해야 한다."""
        ck = self._viewer()
        import re as _re
        page = self.s.req("GET", "/resources", cookie=ck)[1].decode("utf-8")
        tok = _re.search(r'name="t" value="([0-9a-f]{32})"', page).group(1)
        body, h = form(kind="asset", want="LOCAL", action="x", reason="x", t=tok)
        for extra in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(**extra):
                r, _ = self.s.req("POST", "/access-request", body, dict(h, **extra), cookie=ck)
                self.assertEqual(r.status, 403)
        b2, h2 = form(email="evil@solideos.com", name="x", password=PWV, confirm=PWV)
        r, _ = self.s.req("POST", "/join", b2, dict(h2, Origin="https://evil.example"))
        self.assertEqual(r.status, 403)
        # 양성 대조 — 우리 화면에서 보낸 것은 지나간다
        r, _ = self.s.req("POST", "/access-request", body, h, cookie=ck)
        self.assertEqual(r.status, 200)

    # ── ④ 관리자 화면의 사유 XSS ──
    def test_a_reason_cannot_inject_script_into_the_admin_screen(self):
        ck = self._viewer()
        bad = "<script>alert(1)</script>"
        self.s.req("POST", "/api/access/request",
                   {"kind": "role", "want": "operator", "reason": bad, "action": bad}, cookie=ck)
        raw = self.s.req("GET", "/api/admin/requests", cookie=self.admin)[1].decode("utf-8")
        self.assertIn("script", raw)          # 값은 그대로 보관한다(지우지 않는다)
        page = self.s.req("GET", "/admin", cookie=self.admin)[1].decode("utf-8")
        for field in ("r.reason", "r.action", "r.login", "r.name", "r.dept", "r.email"):
            with self.subTest(field=field):
                self.assertNotIn("${" + field + "}", page,
                                 field + " 를 날글자로 넣고 있습니다 — esc() 로 감싸야 합니다")
        for want in ("esc(r.reason", "esc(r.action", "esc(r.email)", "esc(r.name"):
            with self.subTest(want=want):
                self.assertIn(want, page)

    # ── ① 원격 접속은 HTTPS 로 ──
    def test_the_setting_that_protects_remote_login_is_on(self):
        j = json.loads(self.s.req("GET", "/api/admin/conf", cookie=self.admin)[1])
        self.assertIn(j["auth"].get("require_https"), ("auto", True),
                      "원격 구간 평문 접속이 열려 있습니다")

    def test_a_plaintext_outside_leg_is_refused(self):
        """앞단이 '바깥 구간은 평문이었다' 고 알려 주면 **언제나 거절**한다 — 실제 왕복으로 본다."""
        r, b = self.s.req("GET", "/login", headers={"X-Forwarded-Proto": "http"})
        self.assertNotEqual(r.status, 200, "평문 구간을 그대로 받았습니다")
        self.assertIn("HTTPS", b.decode("utf-8", "replace"))
        body, h = form(email="hong@solideos.com", password=PWU)
        r, _ = self.s.req("POST", "/login", body, dict(h, **{"X-Forwarded-Proto": "http"}))
        self.assertNotEqual(r.status, 302, "평문 구간에서 로그인이 되었습니다")
        # 양성 대조 — 사내망에서 온 평문은 그대로 쓴다(모두 막히면 이 시험은 뜻이 없다)
        self.assertEqual(self.s.req("GET", "/login")[0].status, 200)

    def test_the_inside_is_still_told_apart_from_the_outside(self):
        from logtriage.server import Handler

        class Fake:
            headers = {}

            def __init__(self, ip):
                self.client_address = (ip, 5000)

        # 203.0.113.x(문서용 대역)는 파이썬이 private 로 센다 — 실제 인터넷 주소로 본다
        self.assertFalse(Handler._private_peer(Fake("8.8.8.8")), "인터넷 주소를 사내망으로 봅니다")
        self.assertFalse(Handler._private_peer(Fake("1.1.1.1")))
        self.assertTrue(Handler._private_peer(Fake("10.20.30.40")))
        self.assertTrue(Handler._private_peer(Fake("192.168.1.9")))


class FirstAdminTests(unittest.TestCase):
    """**첫 관리자 자리를 남이 먼저 차지하지 못하게** (GPT 21차).

    처음 기동 기본값이 계정 로그인으로 돌아오면서 모든 새 설치가 [관리자 계정 만들기] 를
    거친다. 그 화면이 망에 열려 있으면 서버를 띄운 담당자보다 먼저 누른 사람이 관리자가 된다.
    """

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=conf())
        self.s = Srv(self.base)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def test_a_remote_caller_needs_the_one_time_code(self):
        """새 설치의 기본값은 '서버에 앉아서만 코드 없이' 다 — 그 밖에서는 코드가 필요하다."""
        from logtriage.auth import FIRST_RUN_CONF
        self.assertEqual(FIRST_RUN_CONF["setup_scope"], "token")
        from logtriage.server import Handler

        class Fake:
            headers = {}
            path = "/setup"
            _proxied = Handler._proxied
            _loopback_peer = Handler._loopback_peer
            _private_peer = Handler._private_peer
            _setup_ok = Handler._setup_ok

            def __init__(self, api, ip):
                self.api = api
                self.client_address = (ip, 5000)
        # 코드가 없으면 **어디서 와도** 막힌다 — 루프백도 예외가 아니다
        for ip in ("10.20.30.40", "8.8.8.8", "127.0.0.1"):
            with self.subTest(ip=ip):
                self.assertFalse(Fake(self.s.api, ip)._setup_ok())
        # 코드를 들고 오면 된다
        self.assertTrue(Fake(self.s.api, "10.20.30.40")._setup_ok(self.s.api.setup_token))
        self.assertTrue(Fake(self.s.api, "127.0.0.1")._setup_ok(self.s.api.setup_token))
        self.assertFalse(Fake(self.s.api, "10.20.30.40")._setup_ok("틀린코드"))
        self.assertFalse(Fake(self.s.api, "10.20.30.40")._setup_ok("코드아님"))   # 한글이어도 터지지 않는다

    def test_a_proxy_on_the_same_machine_cannot_be_used_to_slip_in(self):
        """같은 PC 의 리버스 프록시 뒤에서는 **밖에서 온 사람도 127.0.0.1 로 보인다**(GPT 22차).

        그 자리를 '서버에 앉은 사람' 으로 쳐 주면 첫 관리자 자리가 밖으로 열린다. 프록시가
        X-Forwarded-* 를 붙이든 안 붙이든(손으로 만든 설정은 안 붙이기도 한다) 막혀야 한다.
        """
        from logtriage.server import Handler

        class Fake:
            path = "/setup"
            _proxied = Handler._proxied
            _loopback_peer = Handler._loopback_peer
            _private_peer = Handler._private_peer
            _setup_ok = Handler._setup_ok

            def __init__(self, api, hdr):
                self.api = api
                self.client_address = ("127.0.0.1", 5000)
                self.headers = hdr

        for hdr in ({}, {"X-Forwarded-For": "8.8.8.8"}, {"X-Real-IP": "8.8.8.8"},
                    {"X-Forwarded-Proto": "https"}):
            with self.subTest(hdr=hdr):
                self.assertFalse(Fake(self.s.api, hdr)._setup_ok(),
                                 "프록시 뒤에서 코드 없이 첫 관리자를 만들 수 있습니다")
        # 실제 왕복으로도 — 코드 없이 보낸 요청은 계정을 만들지 않는다
        body, h = form(email="sneak@solideos.com", name="x", password=PWA, confirm=PWA)
        r, _ = self.s.req("POST", "/setup", body, dict(h, **{"X-Forwarded-For": "8.8.8.8"}))
        self.assertEqual(r.status, 403)
        self.assertEqual(self.s.api.accounts.count(), 0)

    def test_only_one_first_admin_wins_a_race(self):
        """동시에 둘이 만들면 **정확히 하나**만 된다 — 확인과 생성 사이에 틈이 없어야 한다."""
        import threading
        out, lock = [], threading.Lock()

        tok = self.s.api.setup_token

        def go(i):
            body, h = form(email=f"race{i}@solideos.com", name=f"경쟁{i}",
                           password=PWA, confirm=PWA, t=tok)
            r, _ = self.s.req("POST", "/setup", body, h)
            with lock:
                out.append(r.status)

        ts = [threading.Thread(target=go, args=(i,)) for i in range(5)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(60)
        self.assertEqual(sum(1 for st in out if st == 302), 1, f"첫 관리자가 여럿 생겼습니다: {out}")
        self.assertEqual(self.s.api.accounts.count(), 1)
        self.assertEqual(self.s.api.setup_token, "", "초기 설정 화면이 닫히지 않았습니다")
        self.assertFalse((self.base / "conf" / "setup-code.txt").exists())
        # 그 뒤에는 코드를 들고 와도 더 만들 수 없다
        body, h = form(email="late@solideos.com", password=PWA, confirm=PWA, t=tok)
        self.assertEqual(self.s.req("POST", "/setup", body, h)[0].status, 403)


class ProxyHeaderTests(Base):
    """**프록시 머리글이 인증 보안의 권위가 되면 안 된다**(GPT 21차 상).

    평문으로 직접 들어온 사람이 `X-Forwarded-Proto: https` 를 적어 보내면? 그것을 믿으면
    평문을 암호화 구간으로 착각한다. 앞단 표시는 **같은 PC 의 프록시만** 믿어야 한다.
    """

    def _h(self, ip, **hdr):
        from logtriage.server import Handler

        class Fake:
            api = self.s.api
            server = type("S", (), {"tls": False})()
            _loopback_peer = Handler._loopback_peer
            _private_peer = Handler._private_peer
            _https_ok = Handler._https_ok
            _need_https = Handler._need_https

            def __init__(self, ip, hdr):
                self.client_address = (ip, 5000)
                self.headers = hdr
        return Fake(ip, hdr)

    def test_a_forged_https_header_from_outside_is_not_believed(self):
        h = self._h("8.8.8.8", **{"X-Forwarded-Proto": "https"})
        self.assertTrue(h._need_https(), "인터넷 구간인데 HTTPS 를 요구하지 않습니다")
        self.assertFalse(h._https_ok(), "위조한 머리글을 믿었습니다")

    def test_no_header_from_outside_still_needs_https(self):
        h = self._h("8.8.8.8")
        self.assertTrue(h._need_https())
        self.assertFalse(h._https_ok())

    def test_the_proxy_on_the_same_machine_is_believed(self):
        h = self._h("127.0.0.1", **{"X-Forwarded-Proto": "https"})
        self.assertTrue(h._https_ok(), "같은 PC 의 TLS 앞단을 못 믿으면 정상 구성이 막힙니다")

    def test_the_inside_is_still_allowed_plaintext(self):
        h = self._h("10.20.30.40")
        self.assertFalse(h._need_https(), "사내망 평문을 막으면 지금 운영이 멈춥니다")


class FormTokenTests(Base):
    """머리글이 **하나도 없는** 쓰기 요청도 증표 없이는 못 지나간다(GPT 21차 중상)."""

    def _viewer(self):
        self.s.req("POST", "/api/admin/account_signup_mode", {"mode": "code"}, cookie=self.admin)
        code = json.loads(self.s.req("POST", "/api/admin/account_signup_code", {},
                                     cookie=self.admin)[1])["code"]
        self._join(code=code)
        return cookie_of(self._login()[0])

    def test_a_request_without_any_origin_header_needs_the_token(self):
        ck = self._viewer()
        body, h = form(kind="role", want="operator", action="x", reason="x")   # 증표 없음
        r, b = self.s.req("POST", "/access-request", body, h, cookie=ck)
        self.assertEqual(r.status, 403)
        self.assertIn("우리 화면에서 보낸 것이 아닙니다", b.decode("utf-8"))
        self.assertEqual(json.loads(self.s.req("GET", "/api/admin/requests",
                                               cookie=self.admin)[1])["requests"], [])
        # 화면이 준 증표를 함께 보내면 지나간다(양성 대조)
        page = self.s.req("GET", "/resources", cookie=ck)[1].decode("utf-8")
        import re as _re
        m = _re.search(r'name="t" value="([0-9a-f]{32})"', page)
        self.assertTrue(m, "화면이 증표를 주지 않습니다")
        body, h = form(kind="asset", want="LOCAL", action="GET /resources", reason="자산 담당",
                       t=m.group(1))
        r, _ = self.s.req("POST", "/access-request", body, h, cookie=ck)
        self.assertEqual(r.status, 200)

    def test_the_token_is_bound_to_the_session(self):
        """남의 증표로는 안 된다 — 세션마다 다른 값이어야 한다."""
        ck1 = self._viewer()
        page1 = self.s.req("GET", "/resources", cookie=ck1)[1].decode("utf-8")
        import re as _re
        t1 = _re.search(r'name="t" value="([0-9a-f]{32})"', page1).group(1)
        ck2 = cookie_of(self._login("boss@solideos.com", PWA)[0])
        page2 = self.s.req("GET", "/admin", cookie=ck2)[1].decode("utf-8")
        self.assertNotIn(t1, page2)
        body, h = form(kind="asset", want="LOCAL", action="x", reason="x", t=t1)
        self.assertEqual(self.s.req("POST", "/access-request", body, h, cookie=ck2)[0].status, 403)

    def test_the_password_form_needs_it_too(self):
        ck = self._viewer()
        body, h = form(email="hong@solideos.com", current=PWU, new=PWV, confirm=PWV)
        r, b = self.s.req("POST", "/password", body, h, cookie=ck)
        self.assertEqual(r.status, 403)
        self.assertIn("우리 화면에서 보낸 것이 아닙니다", b.decode("utf-8"))
        # 바뀌지 않았는지 — 옛 비밀번호로 그대로 들어온다
        self.assertEqual(self._login()[0].status, 302)


class CliTests(unittest.TestCase):
    """서버에 들어갈 수 있는 사람의 길도 남겨 둔다 — 화면이 막혔을 때 쓸 수 있어야 한다."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=conf())
        self.store = A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3")
        self.acc = AC.Accounts(self.store, self.base, conf())

    def tearDown(self):
        self.td.cleanup()

    def test_pending_approve_reject(self):
        self.acc.signup("a@solideos.com", PWU, "가", "팀")
        self.assertEqual([r["email"] for r in self.acc.pending_list()], ["a@solideos.com"])
        with self.assertRaises(A.AuthError):
            self.acc.verify("a@solideos.com", PWU)
        self.acc.approve("a@solideos.com", role="operator")
        self.assertEqual(self.acc.verify("a@solideos.com", PWU)["role"], "operator")
        self.assertEqual(self.acc.pending_list(), [])
        self.acc.signup("b@solideos.com", PWV, "나", "팀")
        self.acc.reject("b@solideos.com", why="담당 아님")
        self.assertFalse(self.acc.exists("b@solideos.com"))

    def test_off_means_off(self):
        acc = AC.Accounts(self.store, self.base, conf("off"))
        with self.assertRaises(A.AuthError):
            acc.signup("a@solideos.com", PWU)
        self.assertEqual(acc.count(), 0)

    def test_an_unknown_signup_mode_is_a_config_error(self):
        with self.assertRaises(ValueError):
            AC.conf_of({"local": {"signup": "everyone"}})

    def test_an_old_install_keeps_working(self):
        """예전 설치(승인 칸이 없는 표)에 칸을 더해도 **쓰고 있던 계정은 승인된 것으로** 둔다."""
        db = self.base / "data" / "auth" / "auth.sqlite3"
        self.acc.create("old@solideos.com", PWU, "viewer", must_change=False)
        c = sqlite3.connect(db)                 # 칸을 지워 예전 모양으로 되돌린다
        try:                                     # with 는 **닫지 않는다**(커밋만) — 윈도에서 파일이 잠긴다
            c.execute("ALTER TABLE accounts RENAME TO acc_old")
            c.execute("""CREATE TABLE accounts(
              idx TEXT PRIMARY KEY, email_enc BLOB, verifier BLOB NOT NULL, history TEXT DEFAULT '[]',
              created REAL, pw_changed REAL, must_change INTEGER DEFAULT 1,
              fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, last_login REAL DEFAULT 0)""")
            c.execute("""INSERT INTO accounts SELECT idx,email_enc,verifier,history,created,pw_changed,
                         must_change,fails,locked_until,last_login FROM acc_old""")
            c.execute("DROP TABLE acc_old")
            c.commit()
        finally:
            c.close()
        acc2 = AC.Accounts(A.AuthStore(db), self.base, conf())
        self.assertFalse(acc2.list_one("old@solideos.com")["pending"])
        self.assertEqual(acc2.verify("old@solideos.com", PWU)["login"], "old@solideos.com")

    def test_the_code_counts_uses_once_per_signup(self):
        acc = AC.Accounts(self.store, self.base, conf("code"))
        r = acc.issue_signup_code(max_uses=2, minutes=60)
        acc.signup("a@solideos.com", PWU, code=r["code"])
        acc.signup("b@solideos.com", PWV, code=r["code"])
        self.assertEqual(acc.signup_code_status()["uses"], 2)
        with self.assertRaises(A.AuthError):
            acc.signup("c@solideos.com", "Zx9-Qmr4!tKw", code=r["code"])
        self.assertFalse(acc.exists("c@solideos.com"))

    def test_an_expired_code_is_dead(self):
        acc = AC.Accounts(self.store, self.base, conf("code"))
        r = acc.issue_signup_code(minutes=10)
        c = sqlite3.connect(self.base / "data" / "auth" / "auth.sqlite3")
        try:
            c.execute("UPDATE signup_code SET expires=? WHERE id=1", (time.time() - 1,))
            c.commit()
        finally:
            c.close()
        with self.assertRaises(A.AuthError):
            acc.signup("a@solideos.com", PWU, code=r["code"])


if __name__ == "__main__":
    unittest.main()
