# -*- coding: utf-8 -*-
"""에이전트 토큰 — 대상별 발급 · 유효기간 · 배포물에 채워 넣기 (2026-09-22)

예전: 서버 하나에 공용 토큰 한 개, 기한 없음. 한 대만 유출돼도 전부 교체해야 했다.
지금: 감시 대상마다 따로 발급하고 유효기간을 둔다. 원문은 저장하지 않고(SHA-256) 발급 순간에만 준다.
      내려받는 스크립트·zip 에 그 대상의 토큰이 채워져 나가므로, 배포물 자체가 비밀이다 —
      그래서 그 장비의 자산 담당자(운영 권한 + 자산 조회 권한)만 받을 수 있어야 한다.
"""
import json
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage.server import _AGENT_FILL, agent_dir, agent_fill  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

CONF = {"mode": "local", "local": {"domain": "solideos.com", "scrypt_n": 12}}
PW1 = "Opr-9fQr!42w"
PW2 = "Vwr-7kLm2$eZ"
PW3 = "Noa-3xPt!91k"
JSON_H = {"Content-Type": "application/json"}
# NMS 쓰기 API 는 브라우저 밖 요청을 막는 표시(X-NMS-Request)를 요구한다 — 화면 대본도 같이 보낸다
NMS_H = {**JSON_H, "X-NMS-Request": "1"}


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class AgentFillTests(unittest.TestCase):
    """스크립트에 주소·토큰을 채워 넣는 규칙 — 스크립트를 고치면 여기서 먼저 깨진다."""

    URL = "http://10.20.30.5:8088"
    TOK = "TESTTOKEN123"

    def test_every_script_gets_url_and_token(self):
        for name in _AGENT_FILL:
            with self.subTest(script=name):
                raw = (agent_dir() / name).read_bytes()
                out = agent_fill(name, raw, self.URL, self.TOK)
                self.assertNotEqual(out, raw, f"{name}: 치환 규칙이 맞지 않습니다(스크립트가 바뀌었는지 확인)")
                t = out.decode("utf-8")
                self.assertIn(self.TOK, t)
                self.assertIn(self.URL, t)
                self.assertIn("[주의]", t)
                self.assertEqual(b"\r\n" in out, name.endswith((".ps1", ".cmd")))

    def test_leaves_file_alone_when_rules_do_not_match(self):
        broken = b"#!/bin/sh\necho hi\n"
        self.assertEqual(agent_fill("lt-agent.sh", broken, self.URL, self.TOK), broken)

    def test_no_token_means_no_change(self):
        raw = (agent_dir() / "lt-agent.sh").read_bytes()
        self.assertEqual(agent_fill("lt-agent.sh", raw, self.URL, ""), raw)


class AgentTokenStoreTests(unittest.TestCase):
    """발급·확인·폐기·만료 — 저장소 단위."""

    def setUp(self):
        from logtriage.nms import Store
        self.d = tempfile.TemporaryDirectory()
        self.n = Store(Path(self.d.name) / "nms.sqlite3")
        with self.n.db() as db:
            db.execute("INSERT INTO targets(id,name,address,metrics,enabled) VALUES('t1','was01','10.0.0.5','agent',1)")
            db.execute("INSERT INTO targets(id,name,address,metrics,enabled) VALUES('t2','db01','10.0.0.6','agent',1)")
            db.execute("INSERT INTO targets(id,name,address,metrics,enabled) VALUES('t3','sw01','10.0.0.7','none',1)")

    def tearDown(self):
        self.d.cleanup()

    def test_issue_and_check(self):
        r = self.n.issue_agent_token("t1", "", 365, "me@solideos.com")
        self.assertEqual(r["label"], "was01")
        self.assertAlmostEqual(r["expires"], time.time() + 365 * 86400, delta=60)
        got = self.n.check_agent_token(r["token"])
        self.assertEqual((got["target_id"], got["legacy"]), ("t1", False))

    def test_token_text_is_not_stored(self):
        r = self.n.issue_agent_token("t1", "", 30, "me")
        raw = (Path(self.d.name) / "nms.sqlite3").read_bytes()
        self.assertNotIn(r["token"].encode(), raw)      # DB 가 새도 토큰은 새지 않는다

    def test_expiry(self):
        r = self.n.issue_agent_token("t1", "", 1, "me")
        with self.n.db() as db:
            db.execute("UPDATE agent_tokens SET expires=? WHERE target_id='t1'", (time.time() - 1,))
        self.assertIn("유효기간", self.n.check_agent_token(r["token"])["error"])

    def test_never_expires_when_zero(self):
        r = self.n.issue_agent_token("t1", "", 0, "me")
        self.assertEqual(r["expires"], 0)
        self.assertEqual(self.n.check_agent_token(r["token"])["target_id"], "t1")

    def test_revoke(self):
        r = self.n.issue_agent_token("t1", "", 30, "me")
        sid = self.n.list_agent_tokens()[0]["id"]
        self.n.revoke_agent_token(sid)
        self.assertIn("폐기", self.n.check_agent_token(r["token"])["error"])
        with self.assertRaises(ValueError):
            self.n.revoke_agent_token(sid)              # 두 번은 안 된다

    def test_bad_input(self):
        for tid, days in (("nope", 30), ("t3", 30), ("t1", 99999), ("t1", -1)):
            with self.subTest(tid=tid, days=days), self.assertRaises(ValueError):
                self.n.issue_agent_token(tid, "", days, "me")

    def test_legacy_token_until_disabled(self):
        self.assertTrue(self.n.check_agent_token(self.n.agent_token)["legacy"])
        old = self.n.agent_token
        self.n.disable_legacy_token()
        self.assertIsNone(self.n.check_agent_token(old))
        from logtriage.nms import Store
        again = Store(Path(self.d.name) / "nms.sqlite3")
        self.assertEqual(again.agent_token, "")         # 다시 띄워도 꺼진 채로

    def test_list_has_no_secret(self):
        r = self.n.issue_agent_token("t1", "", 30, "me@solideos.com")
        rows = self.n.list_agent_tokens()
        self.assertNotIn(r["token"], json.dumps(rows, ensure_ascii=False))
        self.assertEqual(rows[0]["target_name"], "was01")
        self.assertEqual(rows[0]["created_by"], "me@solideos.com")


class AgentHttpTests(unittest.TestCase):
    """화면·API 를 통한 전체 흐름."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        prep_base(self.base, auth=CONF)
        self.s = Srv(self.base)
        acc = self.s.api.accounts
        acc.create("opr@solideos.com", PW1, role="operator", sites=["*"], asset_sites=["LOCAL"], must_change=False)
        acc.create("vwr@solideos.com", PW2, role="viewer", sites=["*"], asset_sites=["LOCAL"], must_change=False)
        acc.create("noasset@solideos.com", PW3, role="operator", sites=["*"], must_change=False)
        self.ck = self._login("opr@solideos.com", PW1)
        self.ck_vwr = self._login("vwr@solideos.com", PW2)
        self.ck_noasset = self._login("noasset@solideos.com", PW3)
        with self.s.api.nms.db() as db:   # 이 시험은 127.0.0.1 에서 보낸다
            db.execute("INSERT INTO targets(id,name,address,metrics,enabled) VALUES('t1','was01','127.0.0.1','agent',1)")
            db.execute("INSERT INTO targets(id,name,address,metrics,enabled) VALUES('t9','far01','10.9.9.9','agent',1)")

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def _login(self, email, pw):
        body, h = form(email=email, password=pw)
        return cookie_of(self.s.req("POST", "/login", body, h)[0])

    def _post(self, path, obj, cookie):
        r, b = self.s.req("POST", path, json.dumps(obj), NMS_H, cookie=cookie)
        return r, json.loads(b or b"{}")

    def _push(self, token, hostname="was01"):
        body = json.dumps({"hostname": hostname, "cpu": 10.0, "mem": 20.0, "disk": 30.0})
        r, b = self.s.req("POST", "/api/nms/metrics", body, {**JSON_H, "X-Agent-Token": token})
        return r.status, json.loads(b or b"{}")

    # ── 발급 ──
    def test_issue_returns_plaintext_once_and_list_never_does(self):
        r, d = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 90}, self.ck)
        self.assertEqual(r.status, 200)
        self.assertTrue(d["token"])
        lst = json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])
        self.assertNotIn(d["token"], json.dumps(lst, ensure_ascii=False))
        self.assertEqual(lst["tokens"][0]["target_name"], "was01")
        self.assertEqual(lst["tokens"][0]["days_left"], 89)

    def test_download_uses_a_one_time_ticket(self):
        """발급은 POST 에서만 — 내려받기(GET)는 상태를 바꾸지 않는다.

        조회가 토큰을 만들면 중복 클릭·미리 가져오기만으로 쓰지 않는 토큰이 쌓인다."""
        r, d = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)
        self.assertEqual(r.status, 200)
        self.assertTrue(d["ticket"])
        r2, b2 = self.s.req("GET", f"/static/lt-agent.sh?ticket={d['ticket']}", cookie=self.ck)
        self.assertEqual(r2.status, 200)
        tok = b2.decode("utf-8").split('TOKEN="${2:-', 1)[1].split('}"', 1)[0]
        self.assertEqual(tok, d["token"])
        self.assertEqual(self.s.api.nms.check_agent_token(tok)["target_id"], "t1")
        lst = json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])["tokens"]
        self.assertEqual(len(lst), 1)                    # POST 한 번 = 토큰 하나

    def test_ticket_is_single_use(self):
        d = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)[1]
        first = self.s.req("GET", f"/static/lt-agent.sh?ticket={d['ticket']}", cookie=self.ck)[1].decode("utf-8")
        again = self.s.req("GET", f"/static/lt-agent.sh?ticket={d['ticket']}", cookie=self.ck)[1].decode("utf-8")
        self.assertIn(d["token"], first)
        self.assertNotIn(d["token"], again)              # 두 번째에는 그 토큰이 들어가지 않는다

    def test_plain_get_does_not_issue(self):
        before = len(json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])["tokens"])
        for _ in range(3):
            self.s.req("GET", "/static/lt-agent.sh?target=t1&days=30", cookie=self.ck)
        after = json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])["tokens"]
        self.assertEqual(len(after), before)             # 조회만으로는 하나도 늘지 않는다

    def test_active_token_cap(self):
        for _ in range(self.s.api.nms.TOKEN_ACTIVE_MAX):
            self.assertEqual(self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)[0].status, 200)
        r, d = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)
        self.assertEqual(r.status, 400)
        self.assertIn("먼저 폐기", d["error"])
        sid = json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])["tokens"][0]["id"]
        self._post("/api/nms/agent_token_revoke", {"id": sid}, self.ck)
        self.assertEqual(self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)[0].status, 200)

    # ── 수신 ──
    def test_push_with_target_token(self):
        tok = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)[1]["token"]
        st, d = self._push(tok)
        self.assertEqual((st, d.get("targets")), (200, ["was01"]))

    def test_token_of_another_target_is_refused(self):
        tok = self._post("/api/nms/agent_token", {"target_id": "t9", "days": 30}, self.ck)[1]["token"]
        st, d = self._push(tok, hostname="was01")
        self.assertEqual(st, 403)
        self.assertIn("다른 감시 대상", d["error"])

    def test_expired_token_says_why(self):
        tok = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 1}, self.ck)[1]["token"]
        with self.s.api.nms.db() as db:
            db.execute("UPDATE agent_tokens SET expires=? WHERE target_id='t1'", (time.time() - 1,))
        st, d = self._push(tok)
        self.assertEqual(st, 401)
        self.assertIn("유효기간", d["error"])

    def test_revoked_token_says_why(self):
        tok = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck)[1]["token"]
        sid = json.loads(self.s.req("GET", "/api/nms/agent_tokens", cookie=self.ck)[1])["tokens"][0]["id"]
        self._post("/api/nms/agent_token_revoke", {"id": sid}, self.ck)
        st, d = self._push(tok)
        self.assertEqual(st, 401)
        self.assertIn("폐기", d["error"])

    def test_legacy_token_works_until_turned_off(self):
        old = self.s.api.nms.agent_token
        self.assertEqual(self._push(old)[0], 200)
        self._post("/api/nms/agent_token_legacy_off", {}, self.ck)
        self.assertEqual(self._push(old)[0], 401)

    # ── 권한 ──
    def test_only_asset_owner_can_get_the_artifacts(self):
        for ck, who, want in ((self.ck, "자산 담당자", 200),
                              (self.ck_vwr, "조회 권한", 403),
                              (self.ck_noasset, "자산 권한 없는 운영자", 403)):
            for path in ("/static/lt-agent.sh", "/static/lt-agent.zip", "/api/nms/agent_tokens"):
                with self.subTest(who=who, path=path):
                    r, b = self.s.req("GET", path, cookie=ck)
                    self.assertEqual(r.status, want, f"{who} → {path}")
                    if want == 403:
                        self.assertNotIn(self.s.api.nms.agent_token.encode(), b)

    def test_viewer_cannot_issue(self):
        r, _ = self._post("/api/nms/agent_token", {"target_id": "t1", "days": 30}, self.ck_vwr)
        self.assertEqual(r.status, 403)


if __name__ == "__main__":
    unittest.main()
