"""21차(2026-10-26 마스터): 실시간 관제 재구성 '트리아지 보드'(GPT 155 시안 · 156 검토) — 기능은 그대로, 표현만 LogTriage 식으로.
화면 실조작은 검증도구/live_redesign_check.py(1920 · 1366 · 420: 타일 → 상세 · 이벤트 → 상세 · 끌어 선택 · 목록 보기 · 키보드 열고 닫기 · 초점 복귀)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

LIVE = Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "nms_live.html"


class LiveRedesign(unittest.TestCase):
    def setUp(self):
        self.h = LIVE.read_text(encoding="utf-8")

    def test_new_parts_present(self):
        for want in ('<div class="sit" id="sit" aria-live="polite">', 'id="sitmain"', 'id="sitsub"',
                     "▤ 트리아지 보드", "◈ 응답 분포 지도", "◷ 이벤트 타임라인",
                     "hd.setAttribute('role','heading'); hd.setAttribute('aria-level','3');",   # 레인 머리는 화면 낭독기도 읽는다
                     "⚠ 수집 지연 — 값이 늦을 수 있음",
                     "-Math.PI/2+Math.PI*2*v/100"):                                            # 링은 0~100 그대로(축을 늘리지 않음)
            self.assertIn(want, self.h)

    def test_function_hooks_unchanged(self):
        """기능 연결부는 그대로 — 정렬 · 상세 열기 · 끌어 선택 · 목록 보기 · 키보드."""
        for want in (".sort((a,b)=>risk(b)-risk(a))", "if(best) openDetail(best[2][0],$('xview')); return; }",
                     "document.addEventListener('click',e=>{ const el=e.target.closest&&e.target.closest('[data-open]'); if(el) openDetail(el.dataset.open,el); });",
                     "if((e.key==='Enter'||e.key===' ')&&tg&&tg.dataset&&tg.dataset.open){ e.preventDefault(); openDetail(tg.dataset.open,tg); }",
                     "$('xview').addEventListener('mousedown'", '<div class="eqlist" id="eq"', '<div class="tiles" id="tiles"'):
            self.assertIn(want, self.h)

    def test_jennifer_like_expressions_gone(self):
        self.assertNotIn("(X-View)", re.sub(r"<!--.*?-->|/\*.*?\*/|//[^\n]*", "", self.h, flags=re.S))   # 제목 · 화면 글에서
        self.assertNotIn("g.fillText('95',cx,cy-R*.66);", self.h)                                       # 반원 속도계 눈금
        self.assertNotIn("#22D3EE", self.h)                                                              # 청록 → 브랜드 하늘색

    def test_lanes_do_not_replace_tiles(self):
        """레인 머리는 타일 사이에 끼울 뿐 — 타일 노드를 다시 만들지 않아 초점이 유지된다."""
        self.assertIn("box.querySelectorAll('.lane').forEach(x=>x.remove());", self.h)
        self.assertIn("box.insertBefore(hd,box.querySelector('.tile[data-open=\"'+CSS.escape(t.id)+'\"]'));", self.h)


if __name__ == "__main__":
    unittest.main()
