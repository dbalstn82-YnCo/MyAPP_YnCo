# -*- coding: utf-8 -*-
"""권한 관문 전수 — **실제로 띄워서 권한별로 불러 본다** (2026-10-01)

왜 이 시험이 생겼나. 사이트 ID 잠금이 본사 모드에서 안 걸리는 결함을 포장본을 눌러 보고
찾았다. 그 자리를 지키던 시험은 **소스에 글자가 있는지** 보는 시험이었고, 글자는 있었고
가지만 틀려서 통과했다. 그 결은 하나다 — **화면이 막는 것을 서버가 막는다고 믿은 것.**

그래서 눈으로 찾지 않고, 서버를 띄워 보기·운영·관리자로 **쓰기 API 를 전부 불러 본다.**
거절은 401/403 이고, 그 밖의 답(200·400·404)은 **관문을 지났다**는 뜻이다. 200 인지
400 인지는 여기서 보지 않는다 — 우리가 보는 것은 '지났는가' 다.

[정찰이 함께 있다]
권한이 아니라 **로그인이 깨져서** 전부 401 이 되면, 이 시험은 아무것도 지키지 못하면서
통과한다. 실제로 한 번 그렇게 통과했다(계정 등록이 비밀번호 규칙에 걸려 조용히 실패했다).
그래서 관리자가 실제로 지나는지 먼저 확인하고, 아니면 **그 자리에서 실패시킨다.**
"""
import http.client
import json
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import accounts                                              # noqa: E402
from logtriage.auth import DEFAULT_CONF                                     # noqa: E402
from logtriage.server import API_NAMES, READ_APIS, ADMIN_APIS, make_server  # noqa: E402

PW = "Gm7-Qv2x-Rt9b"        # 반복·연속 문자가 없어야 비밀번호 규칙을 지난다
SITE = "LOCAL"              # 자산 권한은 사이트 ID 로 준다 — '*' 는 받지 않는다
ROLES = ("viewer", "operator", "admin")

# 경로로 갈리는 엔드포인트 — 표가 아니라 손으로 적은 목록이 관문이므로 특히 어긋나기 쉽다.
# (경로, 몸통, 누구부터 지나야 하나)
PATHS = (
    ("/api/admin/user_add", {"login": "x@solideos.com", "role": "viewer"}, "admin"),
    ("/api/admin/user_update", {"login": "viewer@solideos.com", "dept": "x"}, "admin"),
    ("/api/admin/user_delete", {"login": "nobody@solideos.com"}, "admin"),
    ("/api/admin/account_add", {"email": "y@solideos.com", "role": "viewer"}, "admin"),
    ("/api/hub/admin/mode", {"role": "none"}, "admin"),
    ("/api/hub/admin/site_add", {"id": "S1", "name": "s"}, "admin"),
    ("/api/hub/admin/site_reset", {"id": "S1"}, "admin"),
    ("/api/hub/admin/site_update", {"id": "S1", "disabled": True}, "admin"),
    ("/api/hub/admin/site_delete", {"id": "S1"}, "admin"),
    # 보고서가 나가는 폴더를 정하는 일 — 운영 권한에게 열어 두면 쓰기 경로를 고르게 된다
    ("/api/automation/set_outputs", {"dir": ""}, "admin"),
    ("/api/nms/delete", {"id": "nope"}, "operator"),
    ("/api/nms/settings", {}, "operator"),
    ("/api/nms/save", {"targets": []}, "operator"),
    ("/api/inventory/save", {}, "operator"),
    ("/api/inventory/apply", {}, "operator"),
    # 게시판은 **조회 권한도 글·답글을 쓴다**(서로 묻고 답하는 공간). 서버가 그렇게 정해 두었고
    # 화면도 쓰기 단추를 감추지 않는다 — 둘이 같아야 하므로 여기 적어 둔다.
    ("/api/board/create", {"kind": "question", "title": "t", "body": "b"}, "viewer"),
    ("/api/board/reply", {"id": 1, "body": "r"}, "viewer"),
)
# 비밀번호를 건드리는 호출은 **쓰지 않는 계정**에 건다. 전에 viewer 계정에 걸었더니
# 그 세션이 끊겨, 뒤따르는 정찰이 401 로 실패했다 — 시험이 서로를 망가뜨리면 안 된다.
SPARE = "spare@solideos.com"
LAST = (
    ("/api/admin/account_unlock", {"email": SPARE}, "admin"),
    ("/api/admin/account_reset", {"email": SPARE}, "admin"),
)


class Gate(unittest.TestCase):
    """한 번만 띄우고 모든 검사가 함께 쓴다 — 계정 등록·로그인이 느리다."""

    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.TemporaryDirectory()
        base = Path(cls.td.name)
        (base / "conf").mkdir(parents=True)
        conf = dict(DEFAULT_CONF)
        conf["mode"] = "local"       # 이메일 계정 — 권한이 계정마다 다른 유일한 모드
        (base / "conf" / "auth.json").write_text(json.dumps(conf, ensure_ascii=False),
                                                 encoding="utf-8")
        cls.httpd, h = make_server("127.0.0.1", 0, base, None)
        cls.port = cls.httpd.server_address[1]
        cls.api = h.api
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        for role in ROLES:
            accounts.main(["--base", str(base), "add", "--email", f"{role}@solideos.com",
                           "--role", role, "--password", PW,
                           "--sites", "*", "--asset-sites", SITE])
        accounts.main(["--base", str(base), "add", "--email", SPARE,
                       "--role", "viewer", "--password", PW])   # 비번을 건드려도 되는 계정
        cls.cook = {r: cls._login(f"{r}@solideos.com") for r in ROLES}

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.td.cleanup()

    @classmethod
    def _login(cls, email):
        # 이메일 로그인(mode=local)에서 칸 이름은 **email** 이다 — login= 은 통합 로그인 쪽 칸이다
        body = "email=" + urllib.parse.quote(email) + "&password=" + urllib.parse.quote(PW)
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=15)
        c.request("POST", "/login", body,
                  {"Content-Type": "application/x-www-form-urlencoded"})
        r = c.getresponse()
        r.read()
        ck = next((v.split(";")[0] for k, v in r.getheaders()
                   if k.lower() == "set-cookie" and v.startswith("lt_sid=")), "")
        c.close()
        return ck

    def req(self, method, path, body=None, role="admin"):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        hd = {"Cookie": self.cook[role]}
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            hd["Content-Type"] = "application/json"
        if method == "POST":
            hd["X-NMS-Request"] = "1"      # 우리 화면과 같은 표시(CSRF 관문)
        c.request(method, path, body, hd)
        r = c.getresponse()
        d = r.read()
        c.close()
        return r.status, d

    def blocked(self, path, body, role):
        st, _ = self.req("POST", path, body, role)
        return st in (401, 403)

    # ── 정찰 — 이것이 깨지면 아래 모든 검사가 헛돈다 ──────────────────────
    def test_the_canary_logs_in(self):
        """권한이 아니라 로그인이 깨져서 전부 막히면, 아래 검사는 **아무것도 지키지 않는다.**"""
        for role in ROLES:
            self.assertTrue(self.cook[role], f"{role} 로그인 쿠키가 없습니다")
            st, _ = self.req("GET", "/api/me", role=role)
            self.assertEqual(st, 200, f"{role} 가 /api/me 에서 {st}")

    def test_the_canary_passes_an_admin_only_api(self):
        self.assertFalse(self.blocked("/api/demo_status", {}, "admin"),
                         "관리자가 관리자 전용 API 를 못 지납니다 — 관문이 아니라 고장입니다")

    def test_each_role_can_actually_do_something(self):
        """권한마다 **되는 일이 하나는 실제로 되는지** 먼저 본다(GPT 5차 권고).

        막히는 것만 세면 "인증이 죽어서 보안 시험이 모두 통과" 하는 일이 또 생긴다.
        실제로 한 번 그렇게 통과했다 — 계정 등록이 비밀번호 규칙에 조용히 실패해 전부 401 이었다.
        그래서 역할별로 **되어야 하는 것** 을 하나씩 못 박는다.
        """
        st, _ = self.req("GET", "/api/me", role="viewer")
        self.assertEqual(st, 200, "조회 권한이 읽기조차 못 합니다")
        self.assertFalse(self.blocked("/api/history", {}, "viewer"),
                         "조회 권한이 읽기 API 를 못 지납니다")
        self.assertFalse(self.blocked("/api/action_add", {}, "operator"),
                         "운영 권한이 운영 작업을 못 지납니다")
        self.assertFalse(self.blocked("/api/admin/user_add",
                                      {"login": "canary@solideos.com", "role": "viewer"}, "admin"),
                         "관리자가 관리자 작업을 못 지납니다")

    # ── /api/<이름> — 표로 갈리는 쪽 ────────────────────────────────────
    def test_every_write_api_blocks_a_viewer(self):
        """쓰기 API 는 조회 권한을 막아야 한다."""
        for name in sorted(n for n in API_NAMES if n not in READ_APIS):
            with self.subTest(api=name):
                self.assertTrue(self.blocked(f"/api/{name}", {}, "viewer"),
                                f"/api/{name} 가 조회 권한을 지나게 했습니다")

    def test_admin_only_apis_block_an_operator(self):
        """기준을 바꾸는 일은 관리자만 — 필수를 내리는 한 번이 그 뒤 모든 대장을 헐겁게 한다."""
        for name in sorted(ADMIN_APIS):
            with self.subTest(api=name):
                self.assertTrue(self.blocked(f"/api/{name}", {}, "operator"),
                                f"/api/{name} 가 운영 권한을 지나게 했습니다")

    def test_admin_only_apis_let_an_admin_through(self):
        """막기만 보면 '전부 막힘' 도 통과한다 — 지나야 하는 쪽도 본다."""
        for name in sorted(ADMIN_APIS):
            with self.subTest(api=name):
                self.assertFalse(self.blocked(f"/api/{name}", {}, "admin"),
                                 f"/api/{name} 가 관리자까지 막습니다")

    def test_a_write_api_that_is_not_admin_only_lets_an_operator_through(self):
        ops = sorted(n for n in API_NAMES if n not in READ_APIS and n not in ADMIN_APIS)
        self.assertTrue(ops)
        for name in ops:
            with self.subTest(api=name):
                self.assertFalse(self.blocked(f"/api/{name}", {}, "operator"),
                                 f"/api/{name} 가 운영 권한을 막습니다")

    # ── 경로로 갈리는 쪽 — 사이트 ID 잠금 결함이 여기서 나왔다 ──────────
    def test_path_endpoints_gate_as_declared(self):
        for path, body, need in PATHS + LAST:
            with self.subTest(path=path):
                if need == "admin":
                    self.assertTrue(self.blocked(path, body, "viewer"), f"{path}: 조회가 지났습니다")
                    self.assertTrue(self.blocked(path, body, "operator"), f"{path}: 운영이 지났습니다")
                    self.assertFalse(self.blocked(path, body, "admin"), f"{path}: 관리자까지 막혔습니다")
                elif need == "operator":
                    self.assertTrue(self.blocked(path, body, "viewer"), f"{path}: 조회가 지났습니다")
                    self.assertFalse(self.blocked(path, body, "operator"), f"{path}: 운영이 막혔습니다")
                else:                                   # viewer — 게시판
                    self.assertFalse(self.blocked(path, body, "viewer"), f"{path}: 조회가 막혔습니다")

    def test_the_table_and_the_path_list_do_not_disagree(self):
        """표에 있는 이름이 경로 목록에도 있으면, 두 곳을 따로 고치다 어긋난다."""
        names = {p.rsplit("/", 1)[-1] for p, _, _ in PATHS + LAST}
        self.assertFalse(names & set(API_NAMES),
                         "같은 이름이 표와 경로 목록에 둘 다 있습니다 — 한 곳에서만 갈라야 합니다")



class ErrorLeakTests(Gate):
    """예상 못 한 예외를 **그대로 돌려주지 않는다.**

    전에는 파이썬 예외 글이 그대로 응답에 실렸다. 권한 관문을 훑다가 이것이 나왔다:
        "TypeError: ServerApi.asset_fields() takes 1 positional argument but 2 were given"
    내부 클래스·메서드 이름과 인자 개수가 그대로 나갑니다. 경로·SQL 이 실릴 수도 있다.
    우리가 일부러 띄운 안내(ValueError)는 사용자가 읽고 고쳐야 하므로 그대로 보낸다.
    """

    def test_an_unexpected_error_does_not_leak_internals(self):
        # 인자를 받지 않는 API 에 인자를 하나 보내면 TypeError 가 난다
        st, d = self.req("POST", "/api/asset_fields", [{}], "admin")
        body = d.decode("utf-8", "replace")
        self.assertEqual(st, 200, body)          # 관문이 아니라 내용 문제라 200 으로 답한다
        for leak in ("TypeError", "ServerApi", "positional argument", "Traceback"):
            self.assertNotIn(leak, body, f"응답에 {leak} 가 나옵니다")

    def test_our_own_message_still_reaches_the_user(self):
        """까닭을 적지 않은 항목 추가는 **왜 거절됐는지** 사용자가 읽을 수 있어야 한다."""
        st, d = self.req("POST", "/api/asset_field_add", ["새항목", "text", "advised", ""], "admin")
        body = d.decode("utf-8", "replace")
        self.assertIn("무엇을 못 하는지", body, body[:200])


class CookiePolicyTests(unittest.TestCase):
    """쿠키 정책을 올려도 **이미 발급된 쿠키는 그대로 남는다**(GPT 지적).

    SameSite 를 Lax 에서 Strict 로 올려도 브라우저가 들고 있는 옛 쿠키는 Lax 다.
    그래서 정책이 바뀐 판으로 처음 올라올 때 세션을 한 번 비운다. 다시 시작할 때마다
    로그아웃되면 안 되므로, **한 번만** 비우는 것까지 함께 본다.
    """

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.b = Path(self.td.name)
        (self.b / "conf").mkdir(parents=True)
        conf = dict(DEFAULT_CONF)
        conf["mode"] = "local"
        (self.b / "conf" / "auth.json").write_text(json.dumps(conf, ensure_ascii=False),
                                                   encoding="utf-8")

    def store(self):
        from logtriage.auth import AuthStore
        return AuthStore(self.b / "data" / "auth" / "auth.sqlite3")

    def test_it_clears_sessions_once_and_then_leaves_them_alone(self):
        st = self.store()
        st.add_user({"login": "a@solideos.com", "role": "admin"}, actor="t")
        st.new_session("a@solideos.com", "127.0.0.1")
        st.new_session("a@solideos.com", "127.0.0.1")
        # 계정당 세션이 한 줄로 유지되므로 건수는 1 이상이면 된다 — 중요한 것은 **비웠는가** 다
        self.assertGreaterEqual(st.apply_cookie_policy(self.b), 1, "처음에는 비워야 합니다")
        st.new_session("a@solideos.com", "127.0.0.1")
        self.assertEqual(st.apply_cookie_policy(self.b), 0,
                         "두 번째부터는 비우면 안 됩니다 — 재시작마다 로그아웃됩니다")

    def test_every_session_cookie_we_set_is_strict(self):
        src = (Path(__file__).resolve().parents[1] / "logtriage" / "server.py").read_text(encoding="utf-8")
        for line in src.splitlines():
            if "Set-Cookie" in line and ("lt_sid" in line or "lt_session" in line):
                self.assertIn("SameSite=Strict", line, line.strip()[:120])

if __name__ == "__main__":
    unittest.main()
