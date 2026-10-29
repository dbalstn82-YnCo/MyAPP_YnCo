# -*- coding: utf-8 -*-
"""사이드바를 '누를 수 있는지' 시험 (2026-09-23)

2026-09-23 실제 장애: 게시판에 들어가면 왼쪽 메뉴 13개가 전부 죽어서, 브라우저 뒤로 가기
말고는 빠져나갈 수 없었다. 크롬·엣지 모두 같았다.

원인: 사이드바 항목은 <a data-href="/nms"> 처럼 href 가 없다. 그래서 '누르면 이동' 은
자바스크립트가 해 줘야 하는데, 그 대본을 화면마다 따로 복사해 두고 있었고
board.html 에는 그것이 빠져 있었다(화면을 새로 만들면서 누락). 화면은 멀쩡히 떠서
"게시판이 뜬다" 는 확인만으로는 아무도 눈치채지 못했다.

조치: ① 사이드바 링크에 진짜 href 를 넣어 대본 없이도 브라우저가 이동하게 하고
      ② 화면마다 복사돼 있던 누름 처리를 서버가 끼워 넣는 NAV_JS 한 곳으로 모았다
         (href 가 없는 본문 링크용 보조 장치. href 가 있으면 비켜선다)

이 시험이 지키는 것 — 화면이 뜨는지가 아니라 **그 화면에서 나갈 수 있는지**.
"""
import re
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

import logtriage.server as S  # noqa: E402


def click_handlers(js: str) -> int:
    """a[data-href] 를 누름으로 받는 자리가 몇 군데인가."""
    return len(re.findall(r"addEventListener\(\s*['\"]click['\"]", js)) if "a[data-href]" in js else 0


class NavJsTests(unittest.TestCase):
    """서버가 모든 화면에 끼워 넣는 대본이 누름·가운데누름·키보드를 모두 받는가."""

    def test_nav_js_handles_click(self):
        self.assertIn("a[data-href]", S.NAV_JS)
        for kind in ("click", "auxclick", "keydown"):
            self.assertRegex(S.NAV_JS, r"addEventListener\('%s'" % kind,
                             f"NAV_JS 가 {kind} 을 받지 않습니다")

    def test_nav_js_navigates_to_data_href(self):
        self.assertIn("location.href=h", S.NAV_JS, "NAV_JS 가 data-href 로 이동하지 않습니다")

    def test_nav_js_yields_when_page_already_handled_it(self):
        """화면이 제 대본을 들고 있으면 그쪽이 먼저 막는다 — 두 번 이동하면 안 된다."""
        self.assertIn("e.defaultPrevented", S.NAV_JS)

    def test_nav_js_ignores_blank_href(self):
        """모니터링의 내려받기 단추는 data-href 를 비워 두고 스스로 처리한다 — 가로채면 안 된다."""
        self.assertIn("if(!h||h==='#'", S.NAV_JS)


class ServedPageTests(unittest.TestCase):
    """서버가 실제로 내보내는 HTML 에 누름 처리가 들어가는가 (화면 파일 자체가 아니라 나가는 결과물)."""

    def _served(self, name: str) -> str:
        html = (GUI / name).read_text(encoding="utf-8")
        # server._page() 와 같은 방식으로 끼워 넣는다
        return html.replace("</body>", "<script>" + S.NAV_JS + "</script></body>", 1)

    def test_every_sidebar_page_can_be_left(self):
        checked = []
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            if 'data-href="' not in src:
                continue          # 로그인 화면처럼 사이드바가 없는 화면
            checked.append(f.name)
            with self.subTest(page=f.name):
                self.assertGreaterEqual(
                    click_handlers(self._served(f.name)), 1,
                    f"{f.name}: 이 화면에서는 메뉴를 눌러도 이동하지 않습니다"
                    " — 뒤로 가기 말고는 빠져나갈 수 없습니다")
        self.assertIn("board.html", checked, "게시판 화면이 검사 대상에서 빠졌습니다")
        self.assertGreaterEqual(len(checked), 7, f"검사한 화면이 너무 적습니다: {checked}")

    def test_board_sidebar_is_reachable_by_browser_alone(self):
        """게시판은 이 사고가 난 화면이다 — 대본 없이도 나갈 수 있어야 한다."""
        src = (GUI / "board.html").read_text(encoding="utf-8")
        nav = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', src, re.S)
        self.assertTrue(nav)
        links = re.findall(r"<a\b[^>]*>", nav.group(1))
        self.assertGreaterEqual(len(links), 10, "게시판 사이드바 항목이 너무 적습니다")
        dead = [a for a in links if not re.search(r'(?<!data-)href="', a)]
        self.assertEqual(dead, [], "게시판 사이드바에 href 없는 링크가 남아 있습니다")


class RealHrefTests(unittest.TestCase):
    """대본이 하나도 돌지 않아도 메뉴는 살아 있어야 한다 (2026-09-23 GPT 검토 반영).

    누름 처리를 자바스크립트가 '소유' 하면, 아무 관계 없는 다른 코드가 preventDefault()
    한 번만 불러도 메뉴가 같은 방식으로 다시 조용히 죽는다. 그래서 사이드바에는
    진짜 href 를 넣어 브라우저가 스스로 이동하게 했다.
    """

    def test_every_sidebar_link_has_a_real_href(self):
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            nav = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', src, re.S)
            if not nav:
                continue
            for tag in re.findall(r"<a\b[^>]*data-href=[^>]*>", nav.group(1)):
                with self.subTest(page=f.name, tag=tag[:60]):
                    real = re.search(r'(?<!data-)href="([^"]+)"', tag)
                    want = re.search(r'data-href="([^"]+)"', tag).group(1)
                    self.assertIsNotNone(
                        real, f"{f.name}: 사이드바 링크에 href 가 없습니다 — 대본이 죽으면 못 나갑니다")
                    self.assertEqual(real.group(1), want,
                                     f"{f.name}: href 와 data-href 가 다릅니다")

    def test_nav_js_steps_aside_for_real_links(self):
        self.assertIn("if(a.hasAttribute('href'))return;", S.NAV_JS,
                      "href 가 있는 링크는 브라우저에 맡겨야 합니다(이중 이동 방지)")

    def test_space_is_not_hijacked(self):
        """링크의 표준 활성화 키는 Enter 다. Space 는 화면 넘김으로 남겨 둔다."""
        self.assertNotIn("e.key!=='Enter'&&e.key!==' '", S.NAV_JS)

    def test_page_handlers_also_step_aside_for_real_links(self):
        """화면이 들고 있는 대본도 진짜 링크는 브라우저에 맡겨야 한다 — 주인이 둘이면 또 어긋난다."""
        guards = ('hasAttribute("href")', "hasAttribute('href')", "a[data-href]:not([href])")
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            if "closest" not in src or "a[data-href]" not in src:
                continue          # 제 대본을 들고 있지 않은 화면은 볼 것이 없다
            with self.subTest(page=f.name):
                self.assertTrue(any(g in src for g in guards),
                                f"{f.name}: 이 화면 대본이 href 있는 링크까지 가로챕니다"
                                " — 이동의 주인이 둘이 되어 또 어긋납니다")

    def test_agent_download_links_must_not_get_a_real_href(self):
        """에이전트 파일은 주소만으로 받을 수 없어야 한다 — 1회용 표로만."""
        src = (GUI / "nms.html").read_text(encoding="utf-8")
        for tag in re.findall(r"<a\b[^>]*lt-agent[^>]*>", src):
            with self.subTest(tag=tag[:60]):
                self.assertIsNone(re.search(r'(?<!data-)href="', tag),
                                  "내려받기 링크에 href 가 생기면 토큰 없이 받을 수 있게 됩니다")


class NativeShimTests(unittest.TestCase):
    """이 PC 설치형(창 안에서 도는 화면)도 같은 대본을 받는가."""

    def test_shim_carries_nav_js(self):
        src = Path(S.__file__).read_text(encoding="utf-8")
        self.assertIn('replace("%NAV%", NAV_JS)', src,
                      "설치형 화면에 NAV_JS 가 전달되지 않습니다")


if __name__ == "__main__":
    unittest.main()
