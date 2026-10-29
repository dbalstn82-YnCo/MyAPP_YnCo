"""10-23 부서 경계 가림 누락(발표 자료 제작 중 발견):
분석 이력(/api/history)은 다른 부서 분석의 호스트를 ** 로 가리는데, 같은 이력을 모아 만드는 다른 응답은 원본을 그대로 줬다.
  · /api/stats      전체 현황 '최근 분석'·TOP5 조치·날짜별 판정 — 가리지 않은 이력으로 집계했다
  · /api/home       '지금 할 일'(open·acting) — 저장소 칸을 바로 꺼내 등록자 정보 없이 나갔다
  · /api/log_incidents 로그 검색 분석 목록 — 가림 목록에 있었지만 행에 호스트 칸이 없어 가릴 값을 못 찾았다
  · 분석 ID 없이 부르는 generate_report·custom_form_preview·custom_form_analyze(예시 값) — 누구 것이든 '가장 최근 분석' 을 써서
    ID 를 넣으면 403 인 다른 부서 분석의 원본 보고서가 빈 ID 로 나갔다 → 이 계정이 쓸 수 있는 가장 최근 분석만 쓴다
  · /reports/<파일> — 로그인만 하면 다른 부서 분석의 보고서 파일도 내려갔다(파일 이름의 분석 ID 는 가린 이력에도 보여 추측된다)
기준은 하나다: 본인·같은 부서는 원본, 다른 부서는 가린 값 = 그 계정이 /api/history 로 받는 값과 같아야 한다.
화면이 아니라 실제 HTTP 응답을 계정별로 받아 대조한다(소스 훑기 시험은 '어디에 있는가' 를 못 본다)."""
from __future__ import annotations

import http.client
import json
import re
import secrets
import shutil
import tempfile
import threading
import unittest
import urllib.parse
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
SAMPLE = ENGINE / "samples" / "catalina.out"
HOST = "was-prod-77"


class CanSee(unittest.TestCase):
    def test_rule(self):
        from logtriage import privacy as P
        same = lambda o: o == "b@x"   # noqa: E731
        self.assertTrue(P.can_see("a@x", "a@x"))
        self.assertTrue(P.can_see("b@x", "a@x", same))
        self.assertFalse(P.can_see("c@x", "a@x", same))
        self.assertFalse(P.can_see("", "a@x", lambda o: True))     # 등록자 없는 분석은 가린다
        self.assertFalse(P.can_see("a@x", "", lambda o: True))     # 보는 사람이 없으면 가린다


class DeptMaskHttp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from logtriage import knowledge_seed as KS
        from logtriage.server import ServerApi, make_server, prepare_base
        cls.td = Path(tempfile.mkdtemp())
        old = KS.bundled_root
        KS.bundled_root = lambda: ENGINE
        try:
            assert not prepare_base(cls.td)
        finally:
            KS.bundled_root = old
        (cls.td / "conf").mkdir(exist_ok=True)
        (cls.td / "conf" / "auth.json").write_text(json.dumps({"mode": "local", "first_admin": "", "require_https": False,
                                                               "local": {"domain": "solideos.com", "scrypt_n": 12}}), encoding="utf-8")

        class Api(ServerApi):
            def _allowed(self, p):
                return True
        cls.httpd, cls.h = make_server("127.0.0.1", 0, cls.td, None, [str(ENGINE / "samples")], None, api_cls=Api)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]
        cls.pw = {}
        for email, role, dept in (("ops.a@solideos.com", "operator", "운영1팀"), ("ops.b@solideos.com", "operator", "운영1팀"),
                                  ("dev.c@solideos.com", "operator", "개발2팀"), ("view.d@solideos.com", "viewer", "개발2팀")):
            p = "Lt-" + secrets.token_urlsafe(9) + "!9a"
            cls.h.api.accounts.create(email, p, role, ["*"], ["LOCAL"], email.split("@")[0], dept, actor="(시험)", must_change=False)
            cls.pw[email] = p
        cls.h.api.setup_close()
        a = cls._login("ops.a@solideos.com")
        # 견본 폴더의 파일은 시연(DEMO-)으로 잡혀 전체 현황 집계에서 빠진다 — 일반 분석이 되게 옮겨서 넣는다
        work = cls.td / "uploads" / "t20"
        work.mkdir(parents=True, exist_ok=True)
        log = work / "catalina.out"
        log.write_bytes(SAMPLE.read_bytes())
        # 실제 사례와 같은 꼴 — 이름이 '호스트 + 빈칸 + 설명' 이라 이름만 보고는 호스트를 못 찾는다
        r = cls._api(a, "analyze", {"inputs": [{"path": str(log), "product": "tomcat", "host": HOST}], "name": f"{HOST} 톰캣 점검"})
        assert not r.get("error"), r
        cls.iid = r["id"]
        assert not cls.iid.startswith("DEMO-"), cls.iid
        cls.view = {}
        for email in cls.pw:
            ck = cls._login(email)
            cls.view[email] = {k: cls._api(ck, *a) for k, a in (("history", ("history",)), ("stats", ("stats", 0)),
                                                                 ("home", ("home",)), ("log_incidents", ("log_incidents",)))}

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.td, ignore_errors=True)

    @classmethod
    def _req(cls, m, path, body=None, hdr=None, ck=""):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=120)
        h = dict(hdr or {})
        h["Origin"] = f"http://127.0.0.1:{cls.port}"
        if ck:
            h["Cookie"] = ck
        c.request(m, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read(), r.getheader("Set-Cookie") or ""

    @classmethod
    def _login(cls, email):
        s, b, sc = cls._req("POST", "/login", urllib.parse.urlencode({"email": email, "password": cls.pw[email]}),
                            {"Content-Type": "application/x-www-form-urlencoded"})
        return "lt_sid=" + re.search(r"lt_sid=([^;]+)", sc).group(1)

    @classmethod
    def _api(cls, ck, name, *args):
        s, b, _ = cls._req("POST", "/api/" + name, json.dumps(list(args)), {"Content-Type": "application/json", "X-NMS-Request": "1"}, ck)
        assert s == 200, (name, s, b[:200])
        return json.loads(b or b"{}")

    def _rows(self, email):
        v = self.view[email]
        pick = lambda rows: [r for r in rows or [] if r.get("id") == self.iid]   # noqa: E731
        return {"history": pick(v["history"]), "stats.recent": pick(v["stats"].get("recent")),
                "home.open": pick(v["home"].get("open")), "log_incidents": pick(v["log_incidents"])}

    def test_positive_control_every_list_has_the_incident(self):
        # 정찰: 네 응답 모두 그 분석 건을 실제로 담고 있어야 아래 '안 보인다' 가 의미가 있다(로그인이 깨져 빈 목록이면 아무것도 안 지킨다)
        for email in self.pw:
            for k, rows in self._rows(email).items():
                self.assertEqual(len(rows), 1, (email, k))

    def test_owner_and_same_dept_see_original(self):
        for email in ("ops.a@solideos.com", "ops.b@solideos.com"):
            for k, rows in self._rows(email).items():
                self.assertEqual(rows[0].get("name", "").strip(), f"{HOST} 톰캣 점검", (email, k))

    def test_other_dept_gets_masked_everywhere(self):
        for email in ("dev.c@solideos.com", "view.d@solideos.com"):
            rows = self._rows(email)
            want = rows["history"][0]["name"].strip()
            self.assertNotIn(HOST, want)
            self.assertIn("톰캣 점검", want)                     # 다 지운 것이 아니라 호스트만 가렸다
            for k in ("stats.recent", "home.open", "log_incidents"):
                self.assertEqual(rows[k][0].get("name", "").strip(), want, (email, k))
            v = self.view[email]
            blob = json.dumps({"stats": v["stats"], "home": v["home"], "log_incidents": v["log_incidents"]}, ensure_ascii=False)
            self.assertNotIn(HOST, blob, email)               # TOP5 조치·날짜별 판정 등 다른 칸에도 없다

    def test_hidden_history_param_not_reachable_from_client(self):
        # stats 의 가린 이력 인자는 키워드 전용 — 화면이 보내는 위치 인자로는 원본 이력을 끼워 넣지 못한다
        ck = self._login("dev.c@solideos.com")
        s, b, _ = self._req("POST", "/api/stats", json.dumps([0, []]), {"Content-Type": "application/json", "X-NMS-Request": "1"}, ck)
        self.assertNotIn(HOST, b.decode("utf-8", "replace"))
        self.assertIn("error", json.loads(b))


    def _variant_form(self, name):
        # 기본 서식과 바이트가 같으면 '이미 등록된 서식' 으로 거절된다 — 글자 하나 바꾼 사본
        src = self.td / "report-template" / "form_status.hwpx"
        v = self.td / "uploads" / name
        with zipfile.ZipFile(src) as zi, zipfile.ZipFile(v, "w", zipfile.ZIP_DEFLATED) as zo:
            for n in zi.namelist():
                b = zi.read(n)
                if re.match(r"Contents/section\d+\.xml", n):
                    b = b.decode("utf-8").replace("○ 장애원인", "○ 발생 원인").encode("utf-8")
                zo.writestr(n, b)
        return v

    def test_latest_incident_fallbacks_respect_dept(self):
        # 분석 ID 없는 보고서: 같은 부서는 예전처럼 그 분석으로 만들어지고, 다른 부서는 그 분석을 쓰지 않는다
        b = self._login("ops.b@solideos.com")
        r = self._api(b, "generate_report", "")
        self.assertFalse(r.get("error"), r)
        self.assertIn(self.iid, json.dumps(r, ensure_ascii=False))
        for email in ("dev.c@solideos.com", "view.d@solideos.com"):
            ck = self._login(email)
            s, body, _ = self._req("POST", "/api/generate_report", json.dumps([""]), {"Content-Type": "application/json", "X-NMS-Request": "1"}, ck)
            txt = body.decode("utf-8", "replace")
            self.assertNotIn(self.iid, txt, email)
            self.assertNotIn(HOST, txt, email)
        # 서식 예시 값(운영 권한) — 같은 부서는 그 분석이 예시, 다른 부서는 예시에 그 분석이 없다
        v = self._variant_form("t20form.hwpx")
        a = self._api(b, "custom_form_analyze", str(v), "")
        self.assertFalse(a.get("error"), a)
        self.assertEqual(a.get("sample_id"), self.iid)                         # 정찰: 예시 값이 실제로 그 분석에서 온다
        c = self._login("dev.c@solideos.com")
        a2 = self._api(c, "custom_form_analyze", str(v), "")
        self.assertFalse(a2.get("error"), a2)
        self.assertNotEqual(a2.get("sample_id"), self.iid)
        self.assertNotIn(HOST, json.dumps(a2.get("sample"), ensure_ascii=False))
        # 서식 미리보기(조회 권한부터) — 같은 부서는 그 분석으로, 다른 부서는 그 분석으로 만들지 않는다
        from logtriage import report_custom as rc
        t = rc.save_template(self.td / "report-template", v, "t20 서식", a["fields"])
        p = self._api(b, "custom_form_preview", t["id"])
        self.assertEqual(p.get("incident"), self.iid, p)
        d = self._login("view.d@solideos.com")
        p2 = self._api(d, "custom_form_preview", t["id"])
        self.assertNotEqual(p2.get("incident"), self.iid, p2)
        self.assertNotIn(HOST, json.dumps(p2, ensure_ascii=False))


    def test_report_download_respects_dept(self):
        b = self._login("ops.b@solideos.com")
        r = self._api(b, "generate_report", self.iid)
        urls = [x["url"] for x in r.get("download_list") or []]
        self.assertTrue(urls, r)                                              # 정찰: 실제로 받을 파일이 있다
        c = self._login("dev.c@solideos.com")
        for u in urls:
            self.assertEqual(self._req("GET", u, ck=b)[0], 200, u)            # 같은 부서는 그대로 받는다
            s, body, _ = self._req("GET", u, ck=c)
            self.assertEqual(s, 403, u)
            self.assertNotIn(HOST, body.decode("utf-8", "replace"))
        self.assertIn(self.iid, self._req("GET", "/reports/", ck=b)[1].decode("utf-8"))
        self.assertNotIn(self.iid, self._req("GET", "/reports/", ck=c)[1].decode("utf-8"))   # 목록에서도 빠진다


if __name__ == "__main__":
    unittest.main()
