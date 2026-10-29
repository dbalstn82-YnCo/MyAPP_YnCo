# -*- coding: utf-8 -*-
"""왼쪽 메뉴(사이드바) 일관성 시험 (2026-09-22)

화면마다 사이드바를 따로 들고 있어서, 어떤 화면에서는 [게시판] 이 '전사' 에 있고 어떤 화면에서는
'관리' 에 있었다. 화면을 옮길 때마다 항목이 옮겨 다니는 것처럼 보이는 버그였다.
여기서는 모든 화면의 메뉴가 같은 순서·같은 그룹인지 기계로 확인한다.
"""
import re
import sys
import unittest
from pathlib import Path

GUI = Path(__file__).resolve().parents[1] / "logtriage" / "gui"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# 사이드바를 통째로 들고 있는 화면들(ui.html 은 해시 이동이라 따로 본다)
PAGES = ["hub.html", "admin.html", "automation.html", "nms.html",
         "inventory.html", "inventory_view.html", "board.html"]
BASE = "board.html"


def nav_items(html: str):
    """사이드바를 (그룹, 주소) 목록으로."""
    m = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', html, re.S)
    assert m, "사이드바(nav.nav)가 없습니다"
    out, grp = [], ""
    # 머리글은 2026-09-23 부터 진짜 <button> 이다(접기·펼치기). 옛 <div> 도 함께 읽는다
    for tok in re.finditer(r'<(?:div|button)[^>]*class="grp[^"]*"[^>]*>([^<]*)</(?:div|button)>'
                           r'|<(?:a|button)[^>]*data-(?:href|go)="([^"]+)"', m.group(1)):
        if tok.group(1) is not None:
            grp = tok.group(1).strip()
        else:
            out.append((grp, tok.group(2)))
    return out


class NavConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.base = nav_items((GUI / BASE).read_text(encoding="utf-8"))

    def test_every_page_has_the_same_menu(self):
        """모든 화면의 메뉴가 같은 그룹·같은 순서여야 한다 — 다르면 화면을 옮길 때 항목이 움직여 보인다."""
        for name in PAGES:
            with self.subTest(page=name):
                got = nav_items((GUI / name).read_text(encoding="utf-8"))
                self.assertEqual(got, self.base, f"{name} 의 메뉴가 {BASE} 와 다릅니다")

    def test_board_is_under_enterprise_group(self):
        """게시판은 '운영 관리' 묶음, [통합 현황] 바로 다음. (2026-09-23 이름 변경)"""
        pairs = self.base
        self.assertIn(("운영 관리", "/board"), pairs)
        i = pairs.index(("운영 관리", "/board"))
        self.assertEqual(pairs[i - 1], ("운영 관리", "/hub"))
        for name in PAGES + ["ui.html"]:
            with self.subTest(page=name):
                items = nav_items((GUI / name).read_text(encoding="utf-8"))
                grp = next((g for g, h in items if h == "/board"), None)
                self.assertEqual(grp, "운영 관리", f"{name}: 게시판이 '{grp}' 묶음에 있습니다")

    def test_desktop_only_items_are_hidden_until_server_mode(self):
        """ui.html 의 서버형 전용(.srv) 항목은 모두 hidden 으로 시작해야 한다.

        하나라도 빠지면 '전사' 머리글은 숨은 채 그 항목만 남아 윗 그룹에 붙어 보인다(게시판이 그랬다)."""
        html = (GUI / "ui.html").read_text(encoding="utf-8")
        nav = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', html, re.S).group(1)
        tags = re.findall(r'<(?:a|div)([^>]*\bsrv\b[^>]*)>', nav)
        self.assertGreater(len(tags), 3)
        missing = [t.strip()[:70] for t in tags if " hidden" not in t]
        self.assertEqual(missing, [], f"hidden 이 빠진 서버형 전용 항목: {missing}")

    def test_each_page_marks_its_own_menu_active(self):
        """각 화면은 자기 메뉴에만 'on' 표시를 달아야 한다."""
        own = {"hub.html": "/hub", "admin.html": "/admin", "automation.html": "/automation",
               "nms.html": "/nms", "inventory.html": "/resources", "inventory_view.html": "/resources",
               "board.html": "/board"}
        for name, href in own.items():
            with self.subTest(page=name):
                html = (GUI / name).read_text(encoding="utf-8")
                nav = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', html, re.S).group(1)
                on = re.findall(r'<a[^>]*\bclass="[^"]*\bon\b[^"]*"[^>]*data-href="([^"]+)"'
                                r'|<a[^>]*data-href="([^"]+)"[^>]*\bclass="[^"]*\bon\b[^"]*"', nav)
                marked = [a or b for a, b in on]
                self.assertEqual(marked, [href], f"{name}: 활성 표시가 {marked} 입니다(기대 {href})")


class NavRuntimeTests(unittest.TestCase):
    """화면에 주입되는 공통 대본(NAV_JS) — 권한에 따라 항목이 빠져도 메뉴가 망가지지 않아야 한다.

    GPT 교차 검토에서 나온 지적을 시험으로 굳힌 것:
      · 권한이 없으면 /admin·/resources 를 지우는데, 그 그룹의 항목이 다 없어지면 머리글만 남는다
      · data-href 는 진짜 링크가 아니라 키보드 Enter 로 움직이지 않는다
      · 활성 항목에 aria-current 가 없어 보조기기가 현재 위치를 알 수 없다
    """

    def setUp(self):
        from logtriage.server import NAV_JS
        self.js = NAV_JS

    def test_marks_current_page_for_assistive_tech(self):
        self.assertIn("aria-current", self.js)

    def test_keyboard_enter_moves(self):
        self.assertIn("keydown", self.js)
        self.assertIn("Enter", self.js)

    def test_hides_group_heading_when_all_items_gone(self):
        self.assertIn("grp", self.js)
        self.assertIn("hidden=(seen===0)", self.js.replace(" ", ""))

    def test_group_counter_counts_buttons_too(self):
        """머리글을 감출지 셀 때 <a> 만 세면 안 된다.

        분석·조회 그룹은 항목이 <button data-go=...> 라서, <a> 만 세면 그 머리글이 통째로 사라진다
        (실제로 한 번 그렇게 만들었다가 화면에서 잡아 고친 자리)."""
        js = self.js.replace(" ", "")
        self.assertIn("if(!el.hidden)seen++", js)
        self.assertNotIn("el.tagName==='A'&&!el.hidden", js)

    def test_runs_after_permission_filtering(self):
        """권한에 따라 항목을 지운 뒤에 다시 한 번 정리해야 한다(비동기 /api/me 응답 이후).

        2026-09-23: 묶음 접기가 생기면서 setTimeout(nav,...) 이 setTimeout(function(){nav();fold()},...)
        로 바뀌었다. 형태가 아니라 '늦게 한 번 더 도는가' 를 본다."""
        js = self.js.replace(" ", "")
        self.assertRegex(js, r"setTimeout\((?:nav|function\(\)\{nav\(\);[^}]*\}),\d{2,}\)",
                         "권한 반영 뒤 사이드바를 다시 정리하는 늦은 호출이 없습니다")


if __name__ == "__main__":
    unittest.main()
