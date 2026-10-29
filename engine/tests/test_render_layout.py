"""렌더링 관문 겹침 검사(아이디어 8) — 일부러 겹친 PDF 는 잡고, 정상 PDF 는 0. PyMuPDF 없으면 건너뜀."""
import sys
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE / "tools" / "build"))
try:
    try:
        import pymupdf as fitz
    except ImportError:
        import fitz
except Exception:   # noqa: BLE001
    fitz = None
import render_gate as rg  # noqa: E402


@unittest.skipIf(fitz is None, "PyMuPDF 없음")
class LayoutIssues(unittest.TestCase):
    def test_clean_page_has_none(self):
        d = fitz.open()
        pg = d.new_page()
        pg.insert_text((72, 72), "First line ok", fontsize=11)
        pg.insert_text((72, 100), "Second line ok", fontsize=11)
        r = rg.layout_issues(d)
        self.assertEqual((r["overlap"], r["outside"], r["cross"]), (0, 0, 0))

    def test_cell_crossing_is_caught(self):
        """3차 아이디어 8: 표 세로선이 글 조각을 가로지르면(칸 밖으로 넘친 글) 잡는다. 글 옆의 선은 괜찮다."""
        d = fitz.open()
        pg = d.new_page()
        pg.insert_text((72, 100), "Text that runs past the cell border", fontsize=11)
        pg.draw_line((150, 80), (150, 120))                 # 글 한가운데를 지나는 칸 경계
        r = rg.layout_issues(d)
        self.assertGreaterEqual(r["cross"], 1)
        self.assertGreaterEqual(r["vlines"], 1)
        d2 = fitz.open()
        pg2 = d2.new_page()
        pg2.insert_text((72, 100), "Short", fontsize=11)
        pg2.draw_line((300, 80), (300, 120))                # 글과 떨어진 선
        self.assertEqual(rg.layout_issues(d2)["cross"], 0)

    def test_overlap_is_caught(self):
        d = fitz.open()
        pg = d.new_page()
        pg.insert_text((72, 72), "Overlapping text AAAA", fontsize=11)
        pg.insert_text((75, 73), "Overlapping text BBBB", fontsize=11)
        self.assertGreaterEqual(rg.layout_issues(d)["overlap"], 1)


if __name__ == "__main__":
    unittest.main()
