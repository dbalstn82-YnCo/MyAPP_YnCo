# -*- coding: utf-8 -*-
"""예약·자동화 화면이 '설명'이 아니라 '콘솔'인지 (2026-09-23)

바꾼 이유: 첫 화면의 3분의 2가 일러스트와 설명문이고, 정작 돌고 있는 일은
스크롤해야 보였다. 먼저 보여야 하는 것은 '지금 무엇이 돌고 무엇이 걸렸는가' 다.

여기서 지키는 것
  · 지표 4장과 처리 흐름 5단계가 화면 위에 있다
  · 설명문은 없애지 않되 접혀 있다(처음 쓰는 사람에게는 필요하다)
  · 지표는 지어내지 않는다 — 실제 실행 기록에서 계산한다
  · 긴 저장 경로가 카드를 밀어내지 않는다(가로 스크롤이 생기던 자리)
"""
import re
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

SRC = (GUI / "automation.html").read_text(encoding="utf-8")


class ConsoleLayoutTests(unittest.TestCase):
    def test_marketing_hero_is_gone(self):
        self.assertNotIn('class="card hero"', SRC,
                         "설명용 히어로가 아직 첫 화면을 차지합니다")

    def test_kpi_and_pipeline_are_at_the_top(self):
        for need in ('<div class="kpi" id="kpi">', '<div class="pipe" id="pipe">'):
            with self.subTest(need=need):
                self.assertIn(need, SRC)
        # 지표·흐름이 작업 표보다 위에 있어야 한다
        self.assertLess(SRC.index('id="kpi"'), SRC.index('id="jobs"') if 'id="jobs"' in SRC else len(SRC))

    def test_explanation_is_kept_but_folded(self):
        self.assertIn('<details class="card intro"', SRC, "설명을 없애 버리면 처음 쓰는 사람이 막힙니다")
        m = re.search(r'<details class="card intro"[^>]*>', SRC)
        self.assertNotIn(" open", m.group(0), "설명이 펼쳐진 채면 다시 화면을 덮습니다")

    def test_illustration_moved_into_the_folded_part(self):
        i = SRC.index('<details class="card intro"')
        j = SRC.index("</details>", i)
        self.assertIn("data:image", SRC[i:j], "일러스트는 접힌 설명 안으로 옮겨야 합니다")

    def test_pipeline_has_five_named_steps(self):
        m = re.search(r"const PIPE=\[(.*?)\];", SRC, re.S)
        self.assertIsNotNone(m, "처리 흐름 단계 정의를 찾지 못했습니다")
        steps = re.findall(r"\['([^']+)'", m.group(1))
        self.assertEqual(steps, ["감지", "분석", "판정", "보고서 초안", "공유 · 통지"])


class HonestNumbersTests(unittest.TestCase):
    """지표는 실제 실행 기록에서 뽑아야 한다 — 시연용 상수를 박아 두면 안 된다."""

    def test_counts_come_from_runs_and_notices(self):
        for need in ("S.runs", "S.notices", "first_response", "JSON.parse(r.output"):
            with self.subTest(need=need):
                self.assertIn(need, SRC, f"지표 계산이 실제 기록({need})을 쓰지 않습니다")

    def test_no_hard_coded_demo_numbers(self):
        m = re.search(r"function renderKpi\(f\)\{(.*?)\n\}", SRC, re.S)
        self.assertIsNotNone(m)
        body = m.group(1)
        self.assertNotRegex(body, r"card\([^,]+,\s*\d{2,}", "지표에 숫자를 박아 두었습니다")

    def test_says_so_when_there_is_nothing(self):
        self.assertIn("오늘은 아직 없음", SRC)
        self.assertIn("반입 폴더 감시 작업이 없습니다", SRC)


class NoOverflowTests(unittest.TestCase):
    """긴 저장 경로가 카드를 밀어내 가로 스크롤을 만들던 자리."""

    def test_long_path_is_truncated_with_a_tooltip(self):
        self.assertIn('class="pill acc path"', SRC)
        self.assertIn("text-overflow:ellipsis", SRC)
        m = re.search(r'<span class="pill acc path" title="([^"]+)"', SRC)
        self.assertIsNotNone(m, "전체 경로를 툴팁으로 남겨야 합니다")

    def test_two_column_hero_rule_is_limited_to_wide_screens(self):
        """무조건부로 두면 반응형 축소를 덮어써 좁은 화면에서 넘친다(실제로 그랬다)."""
        self.assertNotRegex(SRC, r"\n\.hero\{grid-template-columns:minmax\(0,1fr\) 360px\}")

    def test_grids_collapse_on_narrow_screens(self):
        self.assertRegex(SRC, r"@media\(max-width:900px\)\{\.kpi\{grid-template-columns:repeat\(2")
        self.assertRegex(SRC, r"@media\(max-width:900px\)\{\.pipe\{grid-template-columns:repeat\(2")


if __name__ == "__main__":
    unittest.main()
