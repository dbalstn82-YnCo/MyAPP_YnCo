"""17차(2026-10-22 현장 피드백 + GPT 109·110):
 ① 실시간 관제 가용률이 늘 100%  ② 문구(친근한 말투·말끝 섞임)  ③ 전체 현황 숫자 카드 크기
 A 모니터링 응답 추이 아래 시간·곡선 설명 → 범례  B 모니터링 하단 안내 간소화  C 자산 ⚠ 줄 설명
 D 판정 리포트에 다른 사용자 분석이 먼저 뜸 → 내 분석 먼저 + 분석 고르기  E 예약 작업 표 아래 안내 간소화"""
from __future__ import annotations

import re
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
sys.path.insert(0, str(ENGINE))


def gui(name):
    return (GUI / name).read_text(encoding="utf-8")


class Avail24(unittest.TestCase):
    """① 가용률 = 항목별 최근 24시간 (성공 / 성공+실패) — 지금 상태 비율이 아니다."""

    def test_counts_per_target_and_cache(self):
        from logtriage.nms import Store
        with tempfile.TemporaryDirectory() as td:
            st = Store(Path(td) / "nms.sqlite3")
            a = st.save({"name": "가", "address": "127.0.0.1", "method": "tcp", "port": 1, "kind": "server"})["id"]
            b = st.save({"name": "나", "address": "127.0.0.2", "method": "tcp", "port": 1, "kind": "server"})["id"]
            now = time.time()
            with st.db() as db:
                for tid, res, at in ((a, "up", now - 60), (a, "up", now - 120), (a, "down", now - 180),
                                     (b, "error", now - 60), (a, "down", now - 2 * 86400)):   # 24시간 밖은 세지 않음
                    db.execute("INSERT INTO samples(target_id,at,result,latency,detail) VALUES(?,?,?,?,?)", (tid, at, res, 1.0, ""))
            st._avail_cache = None
            d = st.avail24()
            self.assertEqual(d["by"][a], [2, 1, 0])
            self.assertEqual(d["by"][b], [0, 0, 1])
            with st.db() as db:
                db.execute("INSERT INTO samples(target_id,at,result,latency,detail) VALUES(?,?,'down',1,'')", (a, now - 10))
            self.assertEqual(st.avail24()["by"][a], [2, 1, 0])      # 30초 캐시 — 관제 화면이 2초마다 불러도 매번 세지 않음
            st._avail_cache = None
            self.assertEqual(st.avail24()["by"][a], [2, 2, 0])
            self.assertIn("avail", st.live(600))

    def test_screen_uses_24h_not_current_ratio(self):
        h = gui("nms_live.html")
        self.assertNotIn("S.gaugeT=judged?100*c.up/judged:0", h)
        for want in ("if(live.avail) S.avail=live.avail;", "S.gaugeT=av.length?av.reduce((a,x)=>a+x[1],0)/av.length:0;",
                     "if(!ok){ S.avNone++; continue; }", "if(x[2]>0.2*(ok+x[2])) S.avNoisy++;", "'24시간 검사 성공률'",
                     "'항목 평균 · '+S.avN+'개'", "-Math.PI/2+Math.PI*2*v/100", "측정 불가 '+S.avNone+'개(평균 제외)"):   # 21차: 원형 링(0~100 그대로)
            self.assertIn(want, h)


class Wording(unittest.TestCase):
    def test_report_cards_business_tone(self):
        ui = gui("ui.html")
        for gone in ("<h3>무슨 일이 일어났나</h3>", "<h3>판단 근거</h3>", "<h3>하지 말 것</h3>", "✋ 하지 말 것", '"■ 하지 말 것"',
                     '"■ 지금 할 일(1차)"', "쉬운 설명 → 기술 근거", "분석이 끝났습니다", "샘플 로그로 체험", "<h4>뜻</h4>"):
            self.assertNotIn(gone, ui)
        for want in ("발생 현상</h3>", "판정 요지</h3>", "1차 대응 금지 사항</h3>", '"■ 우선 확인 사항(1차)"', "현상 → 판정 근거 → 로그 발췌 → 조치",
                     "분석 완료", "견본 로그로 체험", "<h4>의미</h4>", '<div class="hd">우선 확인 사항<span'):
            self.assertIn(want, ui)
        css = gui("_ds.css")
        self.assertIn(".explain .ex-what{border-top:3px solid #1A5FD0}", css)
        self.assertIn("1차 대응 금지 사항", (ENGINE / "logtriage" / "cli.py").read_text(encoding="utf-8"))
        self.assertIn("1차 대응 금지 사항", (ENGINE / "logtriage" / "report.py").read_text(encoding="utf-8"))

    def test_guidance_endings_unified(self):
        """안내문 말끝은 합쇼체(~십시오) 하나로 — '~하세요/주세요' 가 섞이지 않게."""
        for f in list(GUI.glob("*.html")) + [ENGINE / "logtriage" / "server.py"]:
            with self.subTest(f=f.name):
                self.assertEqual(re.findall(r"[가-힣]세요(?=[^가-힣])", f.read_text(encoding="utf-8")), [])


class Dashboard(unittest.TestCase):
    def test_kpi_cards_even_sizes(self):
        css, ui = gui("_ds.css"), gui("ui.html")
        self.assertNotIn(".dk4 b{font-size:clamp(", css)                 # 화면 폭 따라 32px 까지 커지던 값
        self.assertIn("font-size:22px;font-weight:700", css)
        self.assertIn(".dk4 .crit{border-left:4px solid", css)
        for want in ("분석 완료", "치명 포함 분석", "최다 최초 관측 계층", "평균 분석 소요 시간", '<span class="lchip">${esc(topL.layer)}</span>'):
            self.assertIn(want, ui)
        self.assertNotIn('<span class="lb">◆ 치명 포함</span>', ui)


class Concise(unittest.TestCase):
    """17차 2차(마스터: '간결한 문구 — 불필요한 텍스트는 삭제하거나 안내·도움말로'): 공통 접기 장치 + 부제 한 줄."""

    def test_condense_helper_wired_everywhere(self):
        import logtriage.server as S
        js = gui("_condense.js")
        self.assertIn(js.strip()[:60], S.NAV_JS)                                   # 모든 화면 공통(창 안 화면 포함)
        spec_p = ENGINE / "deploy" / "local" / "logtriage.spec"
        if spec_p.exists():                       # 리눅스 묶음에는 Windows 빌드 spec 이 없다(묶음 안 시험은 건너뜀)
            self.assertIn("('../../logtriage/gui/_condense.js', 'logtriage/gui')", spec_p.read_text(encoding="utf-8"))  # exe 에도 들어간다

    def test_condense_safety_rules(self):
        js = gui("_condense.js")
        skip = re.search(r"var SKIP='([^']*)'", js).group(1).split(",")
        for keep in ("[role=alert]", "[role=status]", "[aria-live]", ".empty", "td", "th", "[data-keep]", "details", ".warn", ".crit"):
            self.assertIn(keep, skip)                                                 # 접지 않는 자리(이미 접힌 상자 안 포함)
        self.assertIn("if(el.querySelector('input,select,textarea,button,a,details,canvas,svg,table,ul,ol,pre')) return false;", js)
        self.assertIn("위험|주의|경고|되돌릴 수 없|복구할 수 없|영구|삭제|비밀번호|인증키|개인키|토큰|외부로|전송", js)   # GPT 113 P0 조건부
        self.assertIn("b.setAttribute('aria-controls',el.id);", js)
        self.assertIn("if(o) OPEN[k]=1; else delete OPEN[k];", js)                  # 다시 그려져도 펼친 상태 유지
        self.assertIn("@media print{.ltc,.ltc *{white-space:normal!important", js)
        self.assertIn('data-keep style="margin:6px 0 0">본사 인증서는', gui("hub.html"))
        self.assertIn("""<div class="help" data-keep>'이 판정 전용' 연결 중""", gui("admin.html"))

    def test_page_subtitles_short(self):
        ui = gui("ui.html")
        subs = re.search(r"const subtitles=\{(.*?)\};", ui, re.S).group(1)
        for k, v in re.findall(r'(\w+):"([^"]*)"', subs):
            with self.subTest(page=k):
                self.assertLessEqual(len(v), 32, v)
        for f in ("admin.html", "automation.html", "board.html", "hub.html", "inventory.html", "nms.html"):
            with self.subTest(f=f):
                m = re.search(r'<p class="psub">(.*?)</p>', gui(f), re.S)
                self.assertLessEqual(len(re.sub(r"<[^>]+>", "", m.group(1))), 40, m.group(1))

    def test_helper_js_syntax(self):
        import json
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        bad = []
        for f in sorted(GUI.glob("*.js")):
            r = subprocess.run([node, "-e", "new Function(require('fs').readFileSync(process.argv[1],'utf8'))", str(f)],
                               capture_output=True, text=True, encoding="utf-8", timeout=30)
            if r.returncode:
                bad.append((f.name, r.stderr[:200]))
        self.assertEqual(bad, [])


class FieldAtoE(unittest.TestCase):
    def test_a_b_monitoring(self):
        h = gui("nms.html")
        self.assertNotIn("곡선: 성공 응답 시간", h)
        self.assertNotIn("${date(data[0].at)} → ${date(data.at(-1).at)}", h)
        self.assertIn('<div class="hlegend"><span class="lg"><i class="ln"></i>응답 시간</span>', h)
        self.assertIn("알림 팝업은 이 화면을 열어 둔 브라우저에서만 표시됩니다.", h)
        self.assertIn('<p class="note" data-keep style="margin-top:14px">상태는', h)   # 알림 팝업 문장은 접지 않는다(GPT 110 P1-03)
        self.assertNotIn("디스크는 모든 로컬 볼륨 중 가장 높은 값을 기준으로", h)

    def test_c_asset_tooltip(self):
        h = gui("inventory.html")
        self.assertNotIn("sc.title=SPEC.contract", h)
        self.assertIn("if(sc) sc.title='칸 이름(비밀번호·인증키·토큰 등)을 보고 그 열을 지웁니다.", h)

    def test_d_report_mine_first_and_picker(self):
        ui = gui("ui.html")
        self.assertNotIn("else if(!lastReport&&history.length){ lastReport=history[0]; renderReport(history[0]); }", ui)
        for want in ("else if(!lastReport&&history.length){ openDefaultReport(); }", "const mine=myLogin(me), h=mine?history.find(x=>x.owner===mine):history[0];",
                     '["내 분석",all.filter(([h])=>h.owner===mine)],["다른 사용자 분석"', 'data-change="pickInc"',
                     "pickInc:el=>{const h=history[+el.value];", "if(lastReport) return;"):
            self.assertIn(want, ui)

    def test_e_automation_note(self):
        h = gui("automation.html")
        self.assertNotIn("정기 상태 점검은 등록된 감시 장비 전체를 한 번에 확인합니다", h)
        self.assertIn("권장: 상태 점검은 <b>10분마다 알림만</b>", h)


if __name__ == "__main__":
    unittest.main()
