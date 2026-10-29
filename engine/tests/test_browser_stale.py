# -*- coding: utf-8 -*-
"""브라우저에 남는 옛 코드 — 지우는 길이 실제로 있는지 본다 (2026-10-02)

왜 이 파일이 생겼나. 최종 판을 내보내기 전에 "브라우저가 들고 있는 옛 코드를 어떻게
지우나" 를 짚었다. 재어 보니 **서버가 내주는 화면에 캐시 지시가 하나도 없었다** —
브라우저마다, 앞단 프록시마다 알아서 판단하라는 뜻이고, 그러면 "패치했는데 옛 화면" 을
막을 근거가 없다. 그리고 더 중요한 자리가 있었다: 캐시를 다 막아도 **이미 열려 있는 탭**
은 죽지 않는다. 상황실 벽화면처럼 며칠 열어 두는 자리에서 옛 코드가 새 서버를 상대로
계속 돈다. 화면이 스스로 '나는 옛 판이다' 를 알 근거가 없었다.

[무엇을 보는가]
  ① 화면을 내주는 모든 길목에 no-store 가 붙는다            (실제 응답을 받아서 본다)
  ② 모든 응답이 **돌고 있는 판의 지문**을 머리글에 싣는다     (열린 탭이 비교할 근거)
  ③ 화면 안에 그 지문이 박혀 있고, **대본보다 먼저** 나온다  (늦게 적으면 옛 코드가 최신인 줄 안다)
  ④ 분석 결과·보고서 내려받기도 캐시에 남지 않는다            (코드가 아니라 고객 로그다)
  ⑤ 화면을 내주는 길이 **하나뿐**이다                        (딴 길로 새면 ① 이 뚫린다)
  ⑥ 서비스 워커를 등록하는 곳이 없다                          (있으면 지울 수 없는 코드가 생긴다)
  ⑦ 띠를 띄우는 판단은 머리글 비교뿐이고, **스스로 새로 불러오지 않는다**

띠가 실제로 뜨고 단추로 해소되는지는 브라우저에서 눌러 확인했다(판 A 화면 → 서버 판 B
→ 띠 → [새로 불러오기] → 판 B 코드). 여기서 지키는 것은 그 길이 끊기지 않는 것이다.
"""
import json
import re
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import buildid, server as srv  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

PWA = "Kv4-Mzt9!qRb"
GUI = Path(srv.__file__).resolve().parent / "gui"
BUILD_HDR = "X-LogTriage-Build"


def conf():
    return {"mode": "local", "first_admin": "",
            "local": {"domain": "solideos.com", "scrypt_n": 12, "signup": "approve"}}


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class Base(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth=conf())
        self.s = Srv(self.base)
        body, h = form(email="boss@solideos.com", name="관리자", password=PWA,
                       confirm=PWA, t=self.s.api.setup_token)
        r, _ = self.s.req("POST", "/setup", body, h)
        self.assertEqual(r.status, 302, "관리자 계정을 만들지 못했습니다 — 뒤 시험이 뜻을 잃습니다")
        self.ck = cookie_of(r)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()

    def head(self, r, name):
        for k, v in r.getheaders():
            if k.lower() == name.lower():
                return v
        return None


# 화면을 내주는 길 — 로그인 전과 후를 모두 넣는다.
#
# /logout 은 넣지 않는다. 넣으면 **그 뒤 요청이 전부 비로그인으로 떨어져** 302 만 보고
# 통과한다(처음 쓸 때 실제로 그렇게 됐다 — 로그인 뒤 화면을 하나도 못 보고 초록이 됐다).
# 끊는 길은 자기 시험에서 따로 본다.
PAGES = ["/", "/admin", "/nms", "/resources", "/board", "/automation", "/hub",
         "/login", "/join", "/password"]


class CacheTests(Base):
    """① 화면은 저장하지 않는다."""

    def test_every_screen_refuses_to_be_stored(self):
        for p in PAGES:
            with self.subTest(화면=p):
                r, _ = self.s.req("GET", p, cookie=self.ck)
                cc = (self.head(r, "Cache-Control") or "").lower()
                self.assertIn("no-store", cc,
                              f"{p} 가 캐시 지시 없이 나갔습니다 — 브라우저·프록시가 옛 화면을 "
                              f"들고 있어도 막을 근거가 없습니다 (받은 값: {cc or '(없음)'})")

    def test_login_screen_too_even_without_a_session(self):
        # 로그인 화면에는 폼 토큰이 들어 있다 — 공용 PC 디스크에 남을 자리가 아니다.
        r, _ = self.s.req("GET", "/login")
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower())

    def test_logging_out_is_not_stored_either(self):
        r, _ = self.s.req("GET", "/logout", cookie=self.ck)
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower())

    def test_the_first_admin_screen_is_not_stored(self):
        """관리자가 아직 없는 서버의 /setup — **1회용 코드가 적혀 있는 화면**이다.

        관리자가 생긴 뒤에는 /setup 이 302 로 넘긴다. 302 만 보고 통과하면 정작 코드가
        적힌 그 화면을 한 번도 안 본 셈이 된다 — 그래서 빈 서버를 따로 세운다.
        """
        with tempfile.TemporaryDirectory() as td:
            s2 = Srv(prep_base(Path(td), auth=conf()))
            try:
                r, body = s2.req("GET", "/setup?t=" + s2.api.setup_token)
                self.assertEqual(r.status, 200, "첫 계정 만들기 화면이 안 떴습니다")
                self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower())
                self.assertIn(b'<meta name="lt-build"', body)
            finally:
                s2.close()

    def test_api_answers_are_not_stored(self):
        r, _ = self.s.req("GET", "/api/me", cookie=self.ck)
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower())

    def test_shared_stylesheet_is_not_stored(self):
        # 토큰이 없는 파일이지만 **새 화면에 옛 스타일**이 붙는 짝 어긋남을 막는다.
        r, _ = self.s.req("GET", "/static/_srv_common.css", cookie=self.ck)
        self.assertEqual(r.status, 200, "공용 스타일을 못 받았습니다")
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower())


class BuildHeaderTests(Base):
    """② · ③ 열린 탭이 '나는 옛 판이다' 를 알 근거."""

    def test_every_answer_carries_the_running_build(self):
        want = buildid.current()
        self.assertTrue(want, "판 지문이 비어 있습니다 — 비교할 것이 없습니다")
        for p in PAGES + ["/api/me", "/healthz", "/static/_srv_common.css"]:
            with self.subTest(길=p):
                r, _ = self.s.req("GET", p, cookie=self.ck)
                self.assertEqual(self.head(r, BUILD_HDR), want,
                                 f"{p} 응답에 판 지문이 없습니다 — 열린 탭이 비교할 수 없습니다")

    def test_even_the_answers_we_do_not_write_ourselves(self):
        """바닥 클래스가 스스로 내보내는 오류 응답에도 실려야 한다.

        전에는 _json·_html·정적 파일 세 자리에서 각각 붙였다. 그래서 그 셋을 지나지 않는
        응답에는 빠졌다 — 지원하지 않는 메서드의 501 이 그랬다(재어 보고 알았다).
        지금 화면이 그 경로를 쓰지 않더라도, **응답마다 따로 붙이는 구조**가 빠뜨릴 자리를
        계속 만든다. 나가는 문 하나(end_headers)에서 붙이는지 여기서 지킨다.
        """
        r, _ = self.s.req("DELETE", "/api/me", cookie=self.ck)
        self.assertEqual(r.status, 501, "이 시험은 바닥 클래스의 오류 응답을 보려는 것입니다")
        self.assertEqual(self.head(r, BUILD_HDR), buildid.current(),
                         "우리가 직접 쓰지 않은 응답에는 판 지문이 빠집니다")

    def test_errors_we_do_not_write_are_not_cached_either(self):
        """501 은 **기본적으로 캐시해도 되는** 응답이다.

        앞단 프록시가 담아 두면 같은 주소·메서드에 계속 501 을 돌려주는 자리가 생긴다.
        우리 손으로 쓰지 않는 응답이라 지시를 적을 자리가 없었다 — 나가는 문에서 붙인다.
        """
        r, _ = self.s.req("DELETE", "/api/me", cookie=self.ck)
        cc = (self.head(r, "Cache-Control") or "").lower()
        self.assertIn("no-store", cc, f"501 응답에 캐시 지시가 없습니다 (받은 값: {cc or '(없음)'})")

    def test_a_response_that_sets_its_own_directive_keeps_it(self):
        """화면의 지시는 더 촘촘하다 — 나가는 문이 그것을 덮어쓰거나 겹쳐 쓰면 안 된다."""
        r, _ = self.s.req("GET", "/admin", cookie=self.ck)
        got = [v for k, v in r.getheaders() if k.lower() == "cache-control"]
        self.assertEqual(len(got), 1, f"캐시 지시가 {len(got)}번 실렸습니다 — {got}")
        self.assertIn("must-revalidate", got[0], "화면의 촘촘한 지시가 사라졌습니다")

    def test_the_header_is_sent_exactly_once(self):
        """두 번 붙으면 읽는 쪽이 어느 값을 보는지가 구현에 달린다."""
        for p in ["/", "/admin", "/api/me", "/healthz"]:
            with self.subTest(길=p):
                r, _ = self.s.req("GET", p, cookie=self.ck)
                n = sum(1 for k, _v in r.getheaders() if k.lower() == BUILD_HDR.lower())
                self.assertEqual(n, 1, f"{p}: 판 지문이 {n}번 실렸습니다")

    def test_the_screen_knows_which_build_made_it(self):
        want = buildid.current()
        for p in ["/", "/admin", "/nms", "/login"]:
            with self.subTest(화면=p):
                _, body = self.s.req("GET", p, cookie=self.ck)
                html = body.decode("utf-8", "replace")
                m = re.search(r'<meta name="lt-build" content="([0-9a-f]*)"', html)
                self.assertIsNotNone(m, f"{p} 에 판 지문이 박히지 않았습니다")
                self.assertEqual(m.group(1), want)

    def test_the_fingerprint_comes_before_the_script(self):
        """늦게 적으면 뜻이 없다.

        화면이 첫 통신 때 받아 적게 하면, 판 올리기와 겹친 몇백 밀리초 사이에 **새 지문을
        자기 것으로** 적어 버린다 — 옛 코드인데 최신인 줄 안다. 그래서 문서에 박고, 대본이
        읽기 전에 파싱되도록 머리(head) 맨 앞에 둔다.
        """
        for p in ["/", "/admin", "/login"]:
            with self.subTest(화면=p):
                _, body = self.s.req("GET", p, cookie=self.ck)
                html = body.decode("utf-8", "replace")
                meta = html.find('<meta name="lt-build"')
                script = html.find("<script")
                self.assertGreater(meta, -1, f"{p}: 지문이 없습니다")
                self.assertGreater(script, -1, f"{p}: 대본이 없습니다")
                self.assertLess(meta, script,
                                f"{p}: 지문이 대본보다 뒤에 있습니다 — 대본이 읽을 때 없을 수 있습니다")

    def test_a_different_build_would_be_visible(self):
        """지문이 '늘 같은 값' 이면 아무것도 못 잡는다 — 코드가 바뀌면 값이 바뀐다."""
        items = buildid.compute_items([(Path(srv.__file__).name, b"aaa")])
        other = buildid.compute_items([(Path(srv.__file__).name, b"bbb")])
        self.assertNotEqual(items, other, "내용이 달라도 지문이 같습니다 — 비교가 뜻을 잃습니다")


class DownloadTests(Base):
    """④ 내려주는 것은 코드가 아니라 고객 로그에서 뽑은 내용이다."""

    def test_report_download_is_not_cached(self):
        rep = self.base / "reports"
        rep.mkdir(parents=True, exist_ok=True)
        (rep / "보고서.hwpx").write_bytes(b"PK\x03\x04dummy")
        r, _ = self.s.req("GET", "/reports/" + urllib.parse.quote("보고서.hwpx"), cookie=self.ck)
        self.assertEqual(r.status, 200, "보고서를 못 받았습니다")
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower(),
                      "보고서가 브라우저 캐시에 남습니다 — 공용 PC 에서 다음 사람이 봅니다")

    def test_the_shared_download_path_is_not_cached(self):
        """산출물·자산 대장·사이트 사본은 모두 _send_file 한 자리를 지난다.

        처음에는 이 경로를 아무 시험도 지나가지 않았다 — /reports/ 는 자기 머리글을 따로
        쓰기 때문에, _send_file 의 지시를 통째로 떼어도 초록이었다(결함을 되돌려 넣어
        확인했다). 고객 자산명이 든 XLSX 가 이 길로 나간다.
        """
        rep = self.base / "reports"
        rep.mkdir(parents=True, exist_ok=True)
        (rep / "산출물.xlsx").write_bytes(b"PK\x03\x04dummy")
        r, _ = self.s.req("GET", "/api/automation/download?area=reports&name="
                          + urllib.parse.quote("산출물.xlsx"), cookie=self.ck)
        self.assertEqual(r.status, 200, f"산출물을 못 받았습니다 — {r.status}")
        self.assertIn("no-store", (self.head(r, "Cache-Control") or "").lower(),
                      "내려받은 산출물이 브라우저 캐시에 남습니다")


class ChokepointTests(unittest.TestCase):
    """⑤ · ⑥ · ⑦ 구조 — 이 성질이 깨지면 위 시험이 모두 헛것이 된다."""

    def test_html_leaves_through_exactly_one_door(self):
        """화면을 내주는 자리가 둘이 되면 한쪽에 캐시 지시를 빠뜨린다."""
        src = Path(srv.__file__).read_text(encoding="utf-8")
        n = src.count('send_header("Content-Type", "text/html')
        self.assertEqual(n, 1, f"화면을 내주는 자리가 {n} 군데입니다 — _html() 하나로 모아야 "
                               f"캐시 지시와 판 지문을 한 자리에서 보장할 수 있습니다")

    def test_nobody_registers_a_service_worker(self):
        """서비스 워커가 한 번 깔리면 **서버를 바꿔도 지울 수 없는 코드**가 생긴다."""
        for f in list(GUI.glob("*.html")) + [Path(srv.__file__)]:
            s = f.read_text(encoding="utf-8")
            self.assertNotIn("serviceWorker.register", s,
                             f"{f.name} 이 서비스 워커를 등록합니다 — 옛 코드를 지울 길이 막힙니다")

    def test_the_screen_compares_the_header_with_its_own_build(self):
        js = srv.NAV_JS
        self.assertIn("meta[name=lt-build]", js, "화면이 자기 판을 읽지 않습니다")
        self.assertIn(BUILD_HDR, js, "화면이 서버 판을 읽지 않습니다")
        # 비교하는 자리가 실제로 불린다 — 함수만 있고 아무도 안 부르면 뜻이 없다.
        self.assertGreaterEqual(js.count("seen(r)"), 3,
                                "판 비교가 어느 통신에도 얹혀 있지 않습니다(정의 + 호출 2곳)")

    def test_it_never_reloads_by_itself(self):
        """분석 도중인 입력을 말없이 날리는 쪽이 더 큰 사고다 — 띠만 띄우고 사람이 누른다."""
        js = srv.NAV_JS
        self.assertEqual(js.count("location.reload()"), 1,
                         "새로 불러오는 자리가 하나가 아닙니다 — 스스로 다시 읽을 위험이 있습니다")
        i = js.find("location.reload()")
        around = js[max(0, i - 160):i]
        self.assertIn("addEventListener('click'", around,
                      "새로 불러오기가 사람의 누름과 묶여 있지 않습니다 — 저절로 돌 수 있습니다")

    def test_the_header_is_attached_at_one_place_only(self):
        """응답마다 따로 붙이면 빠뜨릴 자리가 계속 생긴다(501 이 그랬다)."""
        src = Path(srv.__file__).read_text(encoding="utf-8")
        n = src.count('send_header("' + BUILD_HDR + '"')
        self.assertEqual(n, 1, f"판 지문을 붙이는 자리가 {n} 군데입니다 — end_headers() 하나여야 합니다")
        i = src.find('send_header("' + BUILD_HDR + '"')
        self.assertIn("def end_headers", src[max(0, i - 1200):i],
                      "판 지문이 나가는 문(end_headers) 안에서 붙지 않습니다")

    def test_it_rechecks_when_the_browser_revives_the_page(self):
        """no-store 로도 막히지 않는 자리 — 브라우저가 실행 상태째로 화면을 되살린다.

        크롬이 2025년에 no-store 화면도 bfcache 에 담도록 바꿨다. 담기지 않는 조건이
        여럿 있고(우리 화면은 no-store 응답을 받는 조회를 하므로 지금은 담기지 않는 것을
        확인했다) **그 부수효과를 보장으로 삼지 않는다**(GPT 지적). 되살아난 순간에
        한 번 더 맞춰 본다.
        """
        js = srv.NAV_JS
        self.assertIn("pageshow", js, "되살아나는 순간을 듣지 않습니다")
        self.assertIn("persisted", js, "되살아남인지 첫 적재인지 가리지 않습니다")
        i = js.find("function revived(")
        self.assertGreater(i, -1, "되살아남 처리기가 없습니다")
        self.assertIn("seen", js[i:i + 260], "되살아나도 판을 맞춰 보지 않습니다")

    def test_it_sweeps_any_service_worker_it_finds(self):
        """우리가 깔지 않아도, 전에 깔린 것이 있으면 걷어낸다."""
        self.assertIn("getRegistrations", srv.NAV_JS)
        self.assertIn("unregister", srv.NAV_JS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
