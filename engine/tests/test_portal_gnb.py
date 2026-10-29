# -*- coding: utf-8 -*-
"""포털 1단계 — 공통 상단 바와 알림 (2026-09-29)

사용자 지시: "우리가 만든걸 포털 같은 개념의 UI/UX로 발전시키려해"
정한 것 — ① LogTriage 자체를 포털처럼 ② 첫 화면은 개인화 홈(다음 단계)
         ③ 가장 먼저 공통 상단 바 + 알림

여기서 지키는 것
  · 상단 바는 화면 아홉 개에 복사하지 않고 공용 대본(NAV_JS) 한 곳에서 그린다
  · 알림 종은 자주 부르므로 status(작업·실행·알림 200건) 전체가 아니라 가벼운 조회를 쓴다
  · 상단 바가 어디선가 터져도 화면은 그대로 쓸 수 있어야 한다(로고·사용자 카드가 되살아난다)
"""
import json
import re
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

import logtriage.server as S  # noqa: E402
from logtriage.server import ServerApi  # noqa: E402


def pages():
    for f in sorted(GUI.glob("*.html")):
        if '<nav class="nav"' in f.read_text(encoding="utf-8"):
            yield f.name


class OnePlaceTests(unittest.TestCase):
    def test_top_bar_is_drawn_in_one_place(self):
        self.assertIn("function gnb(", S.NAV_JS, "상단 바가 공용 대본에 없습니다")
        for name in pages():
            with self.subTest(page=name):
                src = (GUI / name).read_text(encoding="utf-8")
                self.assertNotIn("lt-gnb", src,
                                 f"{name}: 상단 바가 화면 파일에 복사돼 있습니다 — 한 곳에만 둡니다")

    def test_it_runs_on_boot_and_again_after_login_info(self):
        self.assertEqual(S.NAV_JS.count("nav();fold();tips();gnb()"), 2,
                         "상단 바를 늦게 한 번 더 그리지 않습니다(권한·이름이 늦게 옵니다)")
        self.assertIn("side.appendChild(d);try{gnb()}catch(e){}", S.NAV_JS,
                      "로그인 정보가 도착해도 상단 바에 이름이 반영되지 않습니다")


class LayoutTests(unittest.TestCase):
    def test_bar_sits_above_the_app_and_gives_back_the_height(self):
        """위에 얹은 만큼 아래 영역에서 빼야 한다 — 아니면 문서가 통째로 스크롤된다.

        높이는 두 군데 박지 않고 CSS 변수 한 곳에서 정한다(GPT 교차 검토)."""
        self.assertIn(":root{--lt-gnb-h:52px}", S.GNB_CSS)
        self.assertIn("html.lt-gnb-on .app{height:calc(100dvh - var(--lt-gnb-h))}", S.GNB_CSS)
        self.assertNotIn("calc(100vh - 52px)", S.GNB_CSS, "높이를 또 박아 두었습니다")

    def test_server_sends_the_bar_with_the_page(self):
        """JS 로만 끼워 넣으면 첫 그림에서 화면이 한 번 밀린다 — 뼈대는 서버가 함께 내보낸다."""
        src = Path(S.__file__).read_text(encoding="utf-8")
        self.assertIn('html.replace("<body>", "<body>" + GNB_HTML, 1)', src)
        self.assertIn('<html lang="ko" class="lt-gnb-on">', src,
                      "첫 그림부터 높이가 잡히도록 html 에 표시를 달지 않습니다")
        self.assertIn('id="lt-gnb"', S.GNB_BAR)
        self.assertIn('<style id="lt-gnb-css">', S.GNB_HTML)

    def test_markup_and_style_live_in_one_place(self):
        """같은 뼈대를 파이썬과 자바스크립트에 두 벌로 두면 반드시 갈라진다."""
        self.assertIn(json.dumps(S.GNB_BAR, ensure_ascii=False), S.NAV_JS,
                      "창 안에서 도는 화면이 서버와 다른 뼈대를 만듭니다")
        self.assertNotIn("@@GNB", S.NAV_JS, "토큰이 그대로 남아 있습니다")

    def test_sidebar_logo_hides_only_when_the_bar_exists(self):
        """상단 바가 못 뜨면 사이드바 로고·사용자 카드가 그대로 남아야 한다(조용한 실종 방지)."""
        self.assertIn("html.lt-gnb-on .side .logo,html.lt-gnb-on .lt-me{display:none}", S.NAV_JS)
        self.assertIn("classList.add('lt-gnb-on')", S.NAV_JS)
        # 표시는 바를 실제로 붙인 뒤에 세운다
        i = S.NAV_JS.index("document.body.insertBefore(bar,app)")
        j = S.NAV_JS.index("classList.add('lt-gnb-on')")
        self.assertLess(i, j, "바를 붙이기 전에 숨김 표시를 세우고 있습니다")

    def test_narrow_window_gets_its_height_back(self):
        self.assertIn("@media(max-width:760px){:root{--lt-gnb-h:48px}.lt-gnb{padding:0 8px}"
                      "html.lt-gnb-on .app{height:auto}}", S.GNB_CSS,
                      "좁은 창에서 세로 높이 계산이 그대로 걸려 있습니다")

    def test_failure_leaves_the_screen_usable(self):
        blk = S.NAV_JS[S.NAV_JS.index("function gnb("):]
        blk = blk[:blk.index("function boot(")]
        self.assertIn("catch(e){", blk, "상단 바가 터지면 화면까지 멈춥니다")
        self.assertIn("console.warn(", blk)


class CrumbTests(unittest.TestCase):
    def test_current_location_comes_from_the_menu(self):
        """현재 위치는 따로 적어 두지 않는다 — 메뉴의 활성 항목과 그 묶음에서 읽는다."""
        self.assertIn("function crumb(", S.NAV_JS)
        self.assertIn("n.querySelector('.on')", S.NAV_JS)
        self.assertIn("classList.contains('grp')", S.NAV_JS)


class BellTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.api = ServerApi(self.base, allow_dirs=[])
        self.auto = self.api.automation

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_light_read_exists(self):
        self.assertTrue(hasattr(self.auto, "notices"), "가벼운 알림 조회가 없습니다")
        src = Path(S.__file__).read_text(encoding="utf-8")
        self.assertIn('u.path == "/api/automation/notices"', src,
                      "알림 조회 경로가 서버에 없습니다")

    def test_counts_unread_and_returns_newest_first(self):
        self.auto.notice("alarm", "첫 번째")
        self.auto.notice("recovery", "두 번째")
        d = self.auto.notices()
        self.assertEqual(d["unack"], 2)
        self.assertEqual([n["message"] for n in d["notices"]], ["두 번째", "첫 번째"])

    def test_limit_is_bounded(self):
        for i in range(5):
            self.auto.notice("info", f"알림 {i}")
        self.assertEqual(len(self.auto.notices(2)["notices"]), 2)
        self.assertLessEqual(len(self.auto.notices(9999)["notices"]), 50,
                             "종 하나 때문에 알림을 통째로 끌어옵니다")
        self.assertEqual(len(self.auto.notices(0)["notices"]), 5)   # 0 이면 기본값

    def test_acking_lowers_the_unread_count(self):
        self.auto.notice("alarm", "확인해 볼 것")
        nid = self.auto.notices()["notices"][0]["id"]
        self.auto.command("ack", {"id": nid})
        self.assertEqual(self.auto.notices()["unack"], 0)

    def test_screen_asks_for_the_light_read_not_the_whole_status(self):
        self.assertIn("fetch('/api/automation/notices?limit=20'", S.NAV_JS)
        self.assertNotIn("fetch('/api/automation/status'", S.NAV_JS,
                         "종 하나 때문에 작업·실행 기록까지 끌어옵니다")

    def test_bell_stays_hidden_where_there_is_no_server(self):
        """그 경로가 없는 환경(이 PC 설치형)에서는 종이 아예 안 보여야 한다 — 죽은 단추 금지."""
        self.assertIn('id="lt-bell"', S.GNB_BAR)
        self.assertIn("hidden>", S.GNB_BAR.split('id="lt-bell"')[1][:200])
        self.assertIn("if(r.status===404||r.status===401||r.status===403){NOTE.gone=!NOTE.ok",
                      S.NAV_JS, "없는 기능과 서버 장애를 가르지 않습니다")

    def test_server_trouble_keeps_the_bell_and_says_so(self):
        """5xx 인데 종까지 없애면 '알림이 없다' 와 '알림이 죽었다' 를 구분할 수 없다(GPT 지적)."""
        self.assertIn("NOTE.err='서버 응답 '+r.status", S.NAV_JS)
        self.assertIn("b.classList.add('err')", S.NAV_JS)
        self.assertIn("알림을 불러오지 못했습니다", S.NAV_JS)

    def test_polling_does_not_pile_up_and_sleeps_in_background(self):
        """setInterval 은 응답이 느려지면 요청이 겹친다 — 끝난 뒤 다음 번을 잡는다."""
        self.assertNotIn("setInterval(note", S.NAV_JS)
        self.assertIn("noteTimer=setTimeout(notePoll,60000)", S.NAV_JS)
        self.assertIn("function notePoll(){clearTimeout(noteTimer);if(document.hidden)return;",
                      S.NAV_JS, "숨은 창에서도 60초마다 계속 부릅니다")
        self.assertIn("visibilitychange", S.NAV_JS)

    def test_first_read_happens_even_in_a_background_tab(self):
        """되풀이만 멈춘다 — 첫 조회까지 건너뛰면 배경 탭으로 열어 둔 화면에는 종이 아예 없다.
        (실제로 그렇게 나와서 고친 자리)"""
        self.assertIn("noteFetch().then(noteNext)}", S.NAV_JS)

    def test_ack_goes_through_the_existing_operation(self):
        self.assertIn("fetch('/api/automation/ack'", S.NAV_JS)


class FocusTests(unittest.TestCase):
    def test_escape_returns_focus_to_the_button(self):
        """Escape 로 닫았는데 초점이 문서 밖으로 날아가면 키보드로 이어 갈 수 없다(GPT 지적)."""
        self.assertIn("if(back&&POPOWN.focus){try{POPOWN.focus()}catch(e){}}", S.NAV_JS)
        self.assertIn("popClose(true)", S.NAV_JS)

    def test_outside_click_does_not_yank_focus_back(self):
        """바깥을 눌렀으면 누른 그 자리에 초점이 있어야 한다 — 억지로 되돌리지 않는다."""
        self.assertIn("!(POPOWN&&POPOWN.contains(e.target)))popClose()});", S.NAV_JS)

    def test_acked_row_hands_focus_on(self):
        """누르던 [확인] 단추가 사라지면 초점이 body 로 튄다."""
        self.assertIn("nx=box.querySelector('.ok:not([disabled])')", S.NAV_JS)
        self.assertIn("try{(nx||btn).focus()}catch(e){}", S.NAV_JS)


class PopupTests(unittest.TestCase):
    def test_only_one_popup_at_a_time(self):
        self.assertIn("function popOpen(btn,html){if(POPOWN===btn){popClose();return null}popClose();",
                      S.NAV_JS, "팝업이 겹쳐 열립니다")

    def test_it_closes_the_usual_ways(self):
        for bit in ("e.key==='Escape'", "window.addEventListener('resize',function(){popClose()})",
                    "window.addEventListener('scroll',function(){popClose()},true)"):
            with self.subTest(bit=bit):
                self.assertIn(bit, S.NAV_JS, f"팝업이 {bit} 에서 닫히지 않습니다")
        self.assertIn("if(POP&&!POP.contains(e.target)", S.NAV_JS, "바깥을 눌러도 안 닫힙니다")

    def test_it_stays_inside_the_window(self):
        self.assertIn("Math.min(r.right-w,window.innerWidth-8-w)", S.NAV_JS,
                      "팝업이 화면 오른쪽 밖으로 나갑니다")

    def test_user_text_is_escaped(self):
        """알림 문구에는 파일 경로·오류 메시지가 그대로 들어온다 — 그대로 그리면 안 된다."""
        self.assertIn("esc(v.message||'')", S.NAV_JS)
        self.assertIn("esc(me.name||me.login||'')", S.NAV_JS)


if __name__ == "__main__":
    unittest.main()
