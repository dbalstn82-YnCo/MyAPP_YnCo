# -*- coding: utf-8 -*-
"""빈 상태 문구 (2026-09-23)

처음 설치한 서버에서 화면마다 '없습니다.' 만 나오면 다음에 무엇을 해야 할지 알 수 없다.
빈 자리는 **다음 한 걸음**을 말해야 한다.
"""
import re
import sys
import unittest
from pathlib import Path

GUI = Path(__file__).resolve().parents[1] / "logtriage" / "gui"

# 빈 상태에 안내가 있어야 하는 자리 — (화면, 문구 조각, 함께 있어야 할 안내 낱말)
NEEDS = [
    ("ui.html", "아직 분석한 건이 없습니다", "로그 분석"),   # 2026-10-14 메뉴 이름 '로그 분석'(띄어 씀)으로 통일
    ("ui.html", "등록된 감시 항목이 없습니다", "모니터링"),
    ("ui.html", "업로드한 문서가 없습니다", "자산 관리"),
    ("ui.html", "조건에 맞는 분석 건이 없습니다", "넓혀"),
]


class EmptyStateTests(unittest.TestCase):
    def test_empty_states_point_at_the_next_step(self):
        for page, phrase, hint in NEEDS:
            src = (GUI / page).read_text(encoding="utf-8")
            with self.subTest(page=page, phrase=phrase):
                self.assertIn(phrase, src, f"{page}: '{phrase}' 문구가 사라졌습니다")
                # 문구 뒤 120자 안에 다음 걸음 안내가 있어야 한다
                for m in re.finditer(re.escape(phrase), src):
                    tail = src[m.end():m.end() + 120]
                    self.assertIn(hint, tail,
                                  f"{page}: '{phrase}' 뒤에 무엇을 하면 되는지가 없습니다")

    def test_bare_period_endings_are_gone(self):
        """'없습니다.' 로 끝나고 마는 자리가 남아 있으면 안 된다(위 네 곳 기준)."""
        src = (GUI / "ui.html").read_text(encoding="utf-8")
        for _, phrase, _ in NEEDS:
            with self.subTest(phrase=phrase):
                self.assertNotIn(phrase + ".", src, f"'{phrase}.' 가 그대로 남아 있습니다")

    def test_board_and_auto_card_already_guide(self):
        board = (GUI / "board.html").read_text(encoding="utf-8")
        self.assertRegex(board, r"첫 질문|올려 보세요", "게시판 빈 상태 안내가 없습니다")
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn("반입 폴더를 지켜보는 작업이 아직 없습니다", ui)
        self.assertIn("분석만</b> 하고 끝납니다", ui)


if __name__ == "__main__":
    unittest.main()
