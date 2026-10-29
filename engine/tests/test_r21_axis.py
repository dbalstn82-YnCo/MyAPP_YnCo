"""21차(2026-10-26 마스터 신고): 실시간 관제 → 서버 상세(오른쪽 창) 그래프의 가로축 끝 눈금 글자가 캔버스 밖으로 잘림.
원인: 눈금 글자를 가운데 정렬로 x(t) 에 그려, 끝 눈금(x=W-오른쪽 여백 10~14px)의 절반이 밖으로 나감. 7일 기간('10-26 15시')은 더 많이 잘림.
수정: axisRow — 글자 기준점을 캔버스 안으로 당기고, 겹치면 중간 눈금부터 건너뜀(첫·끝 우선, GPT 151차). 세 그래프(서버 상세 · 성능 추이 · 응답 분포) 모두.
화면 실측은 검증도구/live_detail_clip.py(7개 폭 × 1시간 · 7일)."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

LIVE = Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "nms_live.html"


class AxisLabelTest(unittest.TestCase):
    def setUp(self):
        self.h = LIVE.read_text(encoding="utf-8")

    def test_no_raw_centered_axis_labels(self):
        """가로축 눈금은 모두 axisRow 로 — 옛 방식(눈금 글자를 x(t) 에 그대로 가운데 정렬)이 다시 생기면 안 된다."""
        self.assertEqual(self.h.count("axisRow(g,ax,H-6,W)"), 3)
        self.assertNotRegex(self.h, r"fillText\(fmtT\(t\)\.slice\(0,5\),\s*(x\(t\)|xx),\s*H-6\)")
        self.assertNotIn("pd(d.getMinutes()),x(t),H-6)", self.h)

    @unittest.skipUnless(shutil.which("node"), "node 없음 — 화면 함수 실행 시험은 node 가 있는 PC 에서")
    def test_axis_row_fits_and_no_overlap(self):
        src = self.h[self.h.index("function axisRow"):self.h.index("function fit(")]
        js = src + r"""
const R=[];
for (const [W,n,len] of [[901,7,5],[624,7,10],[320,7,10],[160,7,10],[40,7,10],[1221,11,5],[300,11,5],[683,7,10]]) {
  const out=[]; const g={measureText:t=>({width:t.length*6.2}),fillText:(t,x)=>out.push([t,x,t.length*6.2])};
  axisRow(g,[...Array(n)].map((_,k)=>['x'.repeat(len-1)+(k%10),36+(W-46)*k/(n-1)]),0,W);
  const inside=out.every(o=>o[1]-o[2]/2>=0&&o[1]+o[2]/2<=W);
  const apart=out.every((o,i)=>!i||out[i-1][1]+out[i-1][2]/2+6<=o[1]-o[2]/2);
  R.push({W,n,len,drawn:out.length,inside,apart,last:out.length?out[out.length-1][0]:null});
}
console.log(JSON.stringify(R));"""
        r = subprocess.run(["node", "-e", js], capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        for c in json.loads(r.stdout):
            self.assertTrue(c["inside"], c)          # 캔버스 밖으로 안 나감
            self.assertTrue(c["apart"], c)           # 눈금끼리 안 겹침
            if 10 * 6.2 <= c["W"] - 2 or c["len"] * 6.2 <= c["W"] - 2:
                self.assertGreaterEqual(c["drawn"], 1, c)
                self.assertTrue(c["last"].endswith(str((c["n"] - 1) % 10)), c)   # 끝 눈금(지금 시각)은 남김
        wide = [c for c in json.loads(r.stdout) if c["W"] >= 600]
        self.assertTrue(all(c["drawn"] == c["n"] for c in wide), wide)   # 넓은 창은 눈금을 다 그린다


if __name__ == "__main__":
    unittest.main()
