# -*- coding: utf-8 -*-
"""사이드바 — 묶음 접기·펼치기와 메뉴 이름 (2026-09-23)

사용자 지시로 바뀐 것
  · 묶음 머리글을 눌러 접었다 펼 수 있고, 접어 둔 상태는 이 브라우저에 기억된다
  · 묶음 '전사'  → '운영 관리'
  · '전사 현황'  → '통합 현황'   (/hub)
  · '자원 관리'  → '자산 관리'   (/resources)

이름을 한 화면에서만 바꾸면 화면을 옮길 때마다 메뉴 이름이 달라 보인다.
여기서는 여덟 화면 전부를 기계로 확인한다.
"""
import re
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

import logtriage.server as S  # noqa: E402

OLD_NAMES = ("전사 현황", "자원 관리")


def nav_of(name: str):
    src = (GUI / name).read_text(encoding="utf-8")
    m = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', src, re.S)
    return m.group(1) if m else None


def pages():
    for f in sorted(GUI.glob("*.html")):
        if nav_of(f.name):
            yield f.name


class MenuNameTests(unittest.TestCase):
    def test_no_old_name_is_left_anywhere(self):
        """화면 어디에도 옛 이름이 남으면 안 된다 — 제목·머리글 포함."""
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            for old in OLD_NAMES:
                with self.subTest(page=f.name, name=old):
                    self.assertNotIn(old, src, f"{f.name}: 옛 이름 '{old}' 가 남아 있습니다")

    def test_every_page_uses_the_new_group_name(self):
        for name in pages():
            with self.subTest(page=name):
                self.assertIn(">운영 관리<", nav_of(name),
                              f"{name}: 묶음 이름이 '운영 관리' 가 아닙니다")
                self.assertNotIn(">전사<", nav_of(name))

    def test_every_page_uses_the_new_item_names(self):
        for name in pages():
            nav = nav_of(name)
            with self.subTest(page=name):
                self.assertIn("통합 현황", nav, f"{name}: /hub 항목 이름이 '통합 현황' 이 아닙니다")
                # 자산 관리는 권한이 없는 화면에서 지워지지만, 화면 파일에는 있어야 한다
                self.assertIn("자산 관리", nav, f"{name}: /resources 항목 이름이 '자산 관리' 가 아닙니다")

    def test_names_point_at_the_right_screens(self):
        nav = nav_of("board.html")
        for label, path in (("통합 현황", "/hub"), ("자산 관리", "/resources")):
            with self.subTest(label=label):
                m = re.search(r'<a[^>]*data-href="([^"]+)"[^>]*>(?:(?!</a>).)*?'
                              + re.escape(label), nav, re.S)
                self.assertIsNotNone(m, f"'{label}' 항목을 찾지 못했습니다")
                self.assertEqual(m.group(1), path, f"'{label}' 가 {path} 를 가리키지 않습니다")


class FoldTests(unittest.TestCase):
    """묶음 접기 — 모든 화면이 같이 쓰도록 NAV_JS 한 곳에 있어야 한다."""

    def test_fold_lives_in_nav_js(self):
        self.assertIn("function fold(", S.NAV_JS,
                      "묶음 접기가 공용 대본에 없습니다 — 화면마다 복사하면 또 한 곳이 빠집니다")

    def test_heading_becomes_a_real_button(self):
        for bit in ("setAttribute('role','button')", "tabIndex=0", "aria-expanded"):
            with self.subTest(bit=bit):
                self.assertIn(bit, S.NAV_JS, f"머리글이 단추 구실을 못 합니다: {bit}")

    def test_keyboard_toggles_the_group(self):
        self.assertIn("e.key==='Enter'||e.key===' '", S.NAV_JS,
                      "머리글을 키보드로 접을 수 없습니다")

    def test_state_is_remembered_but_never_fatal(self):
        """기억은 localStorage 로 하되, 못 쓰는 환경에서도 그냥 펼친 채 동작해야 한다."""
        self.assertIn("localStorage.getItem", S.NAV_JS)
        self.assertIn("localStorage.setItem", S.NAV_JS)
        self.assertGreaterEqual(S.NAV_JS.count("catch(e){"), 2,
                                "localStorage 접근이 try/catch 로 감싸여 있지 않습니다")

    def test_narrow_window_still_shows_every_item(self):
        """좁은 창에서는 머리글이 숨겨져 펼 방법이 없다 — 접혀 있어도 항목은 보여야 한다.

        숨김 규칙을 넓은 창에만 건다. 좁은 창에서 억지로 되돌리면(display:flex!important)
        항목이 모두 flex 라는 가정이 깨질 때 배치가 틀어진다(GPT 지적)."""
        self.assertIn("@media(min-width:761px){.nav .lt-hid{display:none!important}}", S.NAV_JS,
                      "좁은 창에서 접힌 항목이 사라져 되돌릴 수 없게 됩니다")
        self.assertNotIn(".nav .lt-hid{display:none!important}}", S.NAV_JS.replace(
            "@media(min-width:761px){.nav .lt-hid{display:none!important}}", ""),
            "숨김 규칙이 좁은 창에도 걸려 있습니다")

    def test_group_of_the_current_screen_is_opened(self):
        """지금 보고 있는 화면이 든 묶음은 접혀 있어도 펴서 보여 준다."""
        self.assertIn("matches('.on')", S.NAV_JS,
                      "현재 화면이 든 묶음을 펴 주는 처리가 없습니다")
        self.assertIn("querySelector('.on')", S.NAV_JS,
                      "항목이 한 겹 감싸이면 현재 화면을 못 찾습니다")

    def test_heading_is_a_real_button_in_every_page(self):
        """진짜 <button> 이어야 키보드·초점·보조기기 의미를 브라우저가 책임진다."""
        for name in pages():
            nav = nav_of(name)
            with self.subTest(page=name):
                heads = re.findall(r'<(\w+)[^>]*class="grp[^"]*"', nav)
                self.assertTrue(heads, f"{name}: 묶음 머리글이 없습니다")
                self.assertEqual(set(heads), {"button"},
                                 f"{name}: 머리글이 단추가 아닙니다 — {set(heads)}")

    def test_fold_state_key_survives_a_rename(self):
        """접어 둔 상태는 '보이는 이름' 이 아니라 고정 표로 기억한다 — 이름을 또 바꿔도 남도록."""
        self.assertIn("getAttribute('data-grp')", S.NAV_JS)
        for name in pages():
            nav = nav_of(name)
            ids = re.findall(r'data-grp="([a-z]+)"', nav)
            with self.subTest(page=name):
                self.assertEqual(len(ids), len(set(ids)), f"{name}: 묶음 표가 겹칩니다 — {ids}")
                self.assertGreaterEqual(len(ids), 4, f"{name}: 묶음 표가 빠진 머리글이 있습니다")

    def test_failure_leaves_the_menu_open(self):
        """접기가 어디선가 터져도 메뉴는 모두 보여야 한다 (GPT 가 릴리스 저지로 꼽은 항목).

        항목을 숨긴 뒤에 예외가 나면, 숨겨진 채로 굳어 또 '조용한 먹통' 이 된다.
        실패하면 숨긴 것을 모두 되돌린다."""
        js = S.NAV_JS
        self.assertIn("catch(e){", js)
        self.assertIn("querySelectorAll('.lt-hid')", js,
                      "실패했을 때 숨긴 항목을 되돌리는 처리가 없습니다")
        self.assertIn("classList.remove('lt-hid')", js)
        # 되돌리기는 fold() 안에 있어야 한다 — 다른 곳에 있으면 그 경로로 가지 않는다
        blk = js[js.index("function fold("):]
        self.assertIn("classList.remove('lt-hid')", blk[:blk.index("function boot(")])

    def test_wiring_is_safe_to_run_twice(self):
        """중간에 실패해도 굳지 않고, 여러 번 불려도 손잡이가 겹쳐 달리지 않아야 한다(GPT 지적).

        완료 표시를 일 시작 전에 nav 에 세우면, 중간에 예외가 났을 때 항목은 숨겨졌는데
        손잡이는 안 달린 채로 굳는다. 머리글마다 따로 표시한다."""
        self.assertNotIn("if(!n||n.dataset.ltFold)return", S.NAV_JS,
                         "완료 표시를 일 시작 전에 세우고 있습니다")
        self.assertIn("if(g.h.dataset.ltFold)return", S.NAV_JS,
                      "머리글마다 한 번만 다는 처리가 없습니다")


if __name__ == "__main__":
    unittest.main()
