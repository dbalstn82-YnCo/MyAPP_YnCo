"""19차(2026-10-23 현장):
 ① 보고서 기본 정보 — A 가 넣은 값이 모든 판정 리포트(모든 사용자)에 똑같이 들어감 → 이 분석 > 내 기본값 > 없음, 초기화·불러오기
 ② 에이전트 설치 간편+보안 — 1회용 등록 코드 · SHA-256 확인 · 토큰 비노출(명령줄·화면) · 구멍 2(ps 노출, /api/nms/agent)
 ③ 실시간 관제 — 서버 타일 · 성능 추이 탭 · 가용률 하위 3 · 서버 상세(지표 6·기간 추이·볼륨·프로세스·최근 검사)
실서버 실증은 검증도구/chk_r19_profile.py · chk_r19_agent.py · shot_live.py."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
AGENT = ENGINE / "tools" / "agent"
sys.path.insert(0, str(ENGINE))


def gui(name):
    return (GUI / name).read_text(encoding="utf-8")


class ReportProfile(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def test_users_and_incidents_are_separate(self):
        from logtriage.report_forms import profile_write, resolve_profile
        profile_write(self.td, "user", "a@x", {"org": "A기관", "person": "김에이"}, "a@x", "김에이")
        profile_write(self.td, "inc", "INC-1", {"org": "이분석기관"}, "a@x", "김에이")
        self.assertEqual(resolve_profile(self.td, "b@x", "INC-2"), ({}, "none", {}))           # B 는 A 값을 받지 않는다
        v, src, meta = resolve_profile(self.td, "a@x", "INC-2")
        self.assertEqual((v["org"], src), ("A기관", "mine"))
        v, src, meta = resolve_profile(self.td, "b@x", "INC-1")                                  # 분석 저장값은 그 분석에(권한은 서버가 거른다)
        self.assertEqual((v["org"], src, meta["by_name"]), ("이분석기관", "incident", "김에이"))
        self.assertFalse(any("a@x" in p.name for p in (self.td / "profiles").iterdir()))        # 파일 이름에 계정이 그대로 나오지 않음

    def test_standalone_keeps_legacy_file(self):
        from logtriage.report_forms import load_profile, profile_write, resolve_profile, save_profile
        save_profile(self.td, {"org": "예전값"})
        self.assertEqual(resolve_profile(self.td, "", "")[0]["org"], "예전값")                   # PC 단독: 예전 그대로
        self.assertEqual(resolve_profile(self.td, "a@x", "")[1], "none")                         # 계정 서버: 예전 공용 값은 자동 적용 안 함
        profile_write(self.td, "user", "", {"org": "PC 기본"})
        self.assertEqual(load_profile(self.td)["org"], "PC 기본")                                  # 자동화·명령줄은 예전 파일

    def test_use_profile_is_per_request(self):
        from logtriage.report_forms import load_profile, save_profile, use_profile
        save_profile(self.td, {"org": "공용"})
        seen = {}

        def worker(name, val):
            with use_profile({"org": val}):
                time.sleep(0.05)
                seen[name] = load_profile(self.td)["org"]
        ts = [threading.Thread(target=worker, args=(n, n + "값")) for n in ("가", "나", "다")]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(seen, {"가": "가값", "나": "나값", "다": "다값"})
        self.assertEqual(load_profile(self.td)["org"], "공용")

    def test_incident_id_guard_and_cleaning(self):
        from logtriage.report_forms import profile_read, profile_write
        for bad in ("../x", "a/b", "", "..", "x" * 200):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                profile_write(self.td, "inc", bad, {"org": "x"})
        r = profile_write(self.td, "inc", "DEMO-1", {"org": "  가  ", "evil": "x", "phone": "1" * 500})
        self.assertNotIn("evil", r["values"])
        self.assertEqual(len(r["values"]["phone"]), 200)
        self.assertIsNone(profile_read(self.td, "inc", "DEMO-2"))

    def test_owner_default_for_unattended_reports(self):
        """GPT 119 P0-02: 요청한 계정이 없는 보고서(자동 1차 대응·예약)는 분석 등록자 기준 — 예전 공용 값이 남의 분석에 들어가지 않는다."""
        from logtriage.gui.app import Api
        from logtriage.report_forms import profile_delete, profile_write, save_profile
        save_profile(self.td / "report-template", {"org": "A가 예전에 넣은 공용 값"})
        profile_write(self.td / "report-template", "user", "b@x", {"org": "B 기본"})
        api = Api.__new__(Api)
        api._base = self.td
        api.history = lambda: [{"id": "INC-B", "owner": "b@x"}, {"id": "INC-C", "owner": "c@x"}, {"id": "INC-AUTO", "owner": ""}]
        self.assertEqual(api._profile_for("INC-B")[:2], ({"org": "B 기본"}, "mine"))
        self.assertEqual(api._profile_for("INC-C")[1], "none")                           # 공용 값이 저절로 들어가지 않음
        self.assertEqual(api._profile_for("INC-AUTO")[0]["org"], "A가 예전에 넣은 공용 값")   # 등록자 없는 분석(PC·자동 반입)만
        profile_write(self.td / "report-template", "inc", "INC-B", {"phone": "010"})
        self.assertTrue(profile_delete(self.td / "report-template", "INC-B"))           # P1-03: 분석을 지우면 개인정보도
        self.assertFalse(profile_delete(self.td / "report-template", "../x"))
        self.assertIn("profile_delete(api._base / \"report-template\", hid)", (ENGINE / "logtriage" / "demo_data.py").read_text(encoding="utf-8"))

    def test_server_gate_and_ui(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn('if name in ("report_profile", "save_report_profile", "report_profile_get"):', src)
        self.assertIn('res["incidents"] = [x for x in res.get("incidents") or [] if self._can_use_incident(str(x.get("id") or ""))]', src)
        self.assertIn("return not me          # 지워진 분석의 남은 값은 계정 서버에서 내주지 않는다", src)
        ui = gui("ui.html")
        for want in ('"report_profile","save_report_profile","report_profile_sources","report_profile_get"',   # 서버형 api() 다리
                     'data-click="pfLoad"', 'data-click="pfReset"', '이 분석에 저장</button>', 'api().save_report_profile(pfVals(),PF.inc,"incident")',
                     'if(PF.dirty&&PF.inc===lastReport.id', "보고서 기본 정보: "):
            self.assertIn(want, ui)
        app = (GUI / "app.py").read_text(encoding="utf-8")
        self.assertIn("with use_profile(prof):", app)
        self.assertNotIn("load_profile(self._tdir())", app)


class AgentEnroll(unittest.TestCase):
    def setUp(self):
        from logtriage.nms import Store
        self.td = Path(tempfile.mkdtemp())
        self.st = Store(self.td / "nms.sqlite3")
        self.tid = self.st.save({"name": "web01", "address": "10.0.0.5", "kind": "server", "method": "tcp", "port": 1, "metrics": "agent"})["id"]

    def tearDown(self):
        shutil.rmtree(self.td, ignore_errors=True)

    def test_flow_one_time_and_bound(self):
        e = self.st.issue_enroll(self.tid, "ops")
        self.assertRegex(e["code"], r"^LT-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
        with self.st.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM agent_enroll WHERE ch=?", (e["code"],)).fetchone()[0], 0)   # 원문 저장 안 함
        with self.assertRaises(PermissionError):
            self.st.redeem_enroll(e["code"], "10.9.9.9", "other")                    # 다른 서버
        r = self.st.redeem_enroll(e["code"], "192.168.1.9", "WEB01")                # NAT 뒤 — 호스트명이 항목 이름과 같으면
        self.assertTrue(self.st.check_agent_token(r["token"])["target_id"] == self.tid)
        with self.assertRaisesRegex(PermissionError, "이미 쓴"):
            self.st.redeem_enroll(e["code"], "10.0.0.5", "web01")
        self.assertTrue(self.st.enroll_state(self.tid, e["issued"])["used"])

    def test_fail_limit_expiry_and_target_kind(self):
        e = self.st.issue_enroll(self.tid)
        for _ in range(5):
            with self.assertRaises(PermissionError):
                self.st.redeem_enroll(e["code"], "1.1.1.1", "x")
        with self.assertRaisesRegex(PermissionError, "틀린 시도"):
            self.st.redeem_enroll(e["code"], "10.0.0.5", "web01")                   # 맞는 서버에서도 막힘
        e2 = self.st.issue_enroll(self.tid)
        with self.st.db() as db:
            db.execute("UPDATE agent_enroll SET expires=0 WHERE created>=?", (e2["issued"] - 1,))
        with self.assertRaisesRegex(PermissionError, "지났습니다"):
            self.st.redeem_enroll(e2["code"], "10.0.0.5", "web01")
        nid = self.st.save({"name": "sw", "address": "10.0.0.6", "kind": "network", "method": "tcp", "port": 1, "metrics": "none"})["id"]
        with self.assertRaises(ValueError):
            self.st.issue_enroll(nid)
        for bad in ("", "LT-AAAA", "lt-aaaa-bbbb-cccc' or 1=1"):
            with self.subTest(bad=bad), self.assertRaises(PermissionError):
                self.st.redeem_enroll(bad, "10.0.0.5", "web01")

    def test_server_helpers_and_rate_limit(self):
        import hashlib
        import logtriage.server as S
        body = S.agent_setup_script().decode("utf-8")
        self.assertNotIn("@@SHA:", body)
        for n in S._AGENT_SETUP_FILES:
            self.assertIn(n + "=" + hashlib.sha256(S.agent_plain(n)).hexdigest(), body)
        for bad in ("agent.conf.example", "../server.py", "lt-agent-install.sh", "lt-agent.ps1"):
            self.assertIsNone(S.agent_plain(bad))
        S._ENROLL_HITS.clear()
        now = 1000.0
        self.assertTrue(all(S.enroll_allow("9.9.9.9", now) for _ in range(10)))
        self.assertFalse(S.enroll_allow("9.9.9.9", now))
        self.assertTrue(S.enroll_allow("9.9.9.9", now + 601))
        S._ENROLL_HITS.clear()

    def test_routes_and_holes(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn('if u.path == "/agent/enroll":     # 19차 간편 설치', src)
        self.assertIn('path in ("/api/nms/agent_tokens", "/api/nms/agent", "/api/nms/agent_enroll_state")', src)   # 공용 토큰 원문 = 자산 권한
        self.assertNotIn('"/agent/enroll", "/healthz"', src)                          # HTTPS 강제 서버에서 등록은 예외로 두지 않는다
        self.assertIn('d["top"] = [{**t, "user": "***"} for t in d.get("top") or []]', src)    # GPT 119 P0-03: OS 계정 이름은 자산 권한자만


class AgentScripts(unittest.TestCase):
    def test_token_not_on_command_line(self):
        for n in ("lt-agent.sh", "lt-agent-posix.sh"):
            with self.subTest(n=n):
                t = (AGENT / n).read_text(encoding="utf-8")
                self.assertNotIn('-H "X-Agent-Token: $TOKEN"', t)
                self.assertNotIn('--header="X-Agent-Token: $TOKEN"', t)
                self.assertIn("| curl -K - -sS", t)
                self.assertIn("( umask 077; printf 'header = X-Agent-Token: %s", t)

    def test_setup_script_rules(self):
        t = (AGENT / "lt-agent-setup.sh").read_text(encoding="utf-8")
        for want in ("umask 077", "EnvironmentFile=$ETC/agent.env", 'if [ "$CODE" = "-" ] || [ -z "$CODE" ]; then', "IFS= read -r CODE || true", "NoNewPrivileges=yes", "ProtectSystem=strict", "User=$RUNAS",
                     "기준값과 다릅니다", '--data-binary "@$2"', "UURL=$(say \"$URL\" | sed 's/%/%%/g')", "LT-????-????-????"):
            self.assertIn(want, t)
        self.assertNotRegex(t, r'(say|echo|printf)[^\n]*"\$TOKEN"[^\n]*$(?<!agent\.env)', "")
        for line in t.splitlines():
            if "$TOKEN" in line:
                self.assertTrue(any(k in line for k in ("LT_AGENT_TOKEN=$TOKEN", "TOKEN=$TOKEN", 'case "$TOKEN"', "TOKEN=$(jget", '-z "$TOKEN"')), line)
        sh = shutil.which("sh")
        if sh:
            for n in ("lt-agent-setup.sh", "lt-agent-posix.sh", "lt-agent-ctl.sh"):
                r = subprocess.run([sh, "-n", str(AGENT / n)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, n + r.stderr)


class LiveScreen(unittest.TestCase):
    def test_layout_and_detail(self):
        h = gui("nms_live.html")
        for want in ('<div class="tiles" id="tiles"', 'id="tmet"', 'data-m="lat">응답</button>', 'id="avlow"', 'id="avmini"',
                     '<aside class="det" id="det" hidden role="dialog" aria-label="서버 상세">',
                     '<div class="dchart"><canvas id="dchart" aria-label="서버 사용률 추이"></canvas></div>',   # 캔버스는 고정 마크업(소독기)
                     "const RANGES=[[3600,'1시간'],[21600,'6시간'],[86400,'24시간'],[604800,'7일']];",
                     "api('metrics?id='+q+'&range='+D.range)", "api('procs?id='+q)", "api('history?id='+q)",
                     "if(best) openDetail(best[2][0],$('xview')); return; }",                        # X-View 점 → 상세
                     "el.dataset.open=r.id;",                                                      # 이퀄라이저 줄 → 상세
                     "'#srv='+encodeURIComponent(id)", "stepDetail(e.key==='ArrowRight'?1:-1)",
                     "g.fillText('24시간 검사 성공률',tx,cy-14);",   # 21차: 반원 눈금 → 원형 링 — 제목·큰 숫자·설명이 세 줄로 겹치지 않게
                     ".tile.cur{", "@media (min-width:1281px) and (min-height:860px){html,body{height:100%;overflow:hidden}"):
            self.assertIn(want, h)
        self.assertNotIn(".tile.sel{", h)                       # '.sel' 은 '선택한 검사' 창 — 겹치면 타일이 날아간다
        js = "\n".join(re.findall(r"<script>([\s\S]*?)</script>", h))
        self.assertNotRegex(js, r"innerHTML\s*=[^;]*<canvas")   # innerHTML 로 만든 캔버스는 소독기가 글자로 바꾼다
        self.assertNotIn("r.detail", js)                        # 검사 결과 상세 글(주소가 섞일 수 있음)은 보이지 않는다

    def test_quick_install_ui(self):
        h = gui("nms.html")
        for want in ('id="agquick"', "api('agent_enroll',{id:t.id})", "lt-setup.sh\" | sha256sum -c - && printf %s '+r.code+' | sudo sh lt-setup.sh '+r.base+' -'",   # GPT 119 P1-01: 코드는 ps 에 안 보이게
                     'id="aghttp"', "s.used_from?' · 등록한 곳 '+s.used_from",
                     "api('agent_enroll_state?id='", "agQuickWire(t);"):
            self.assertIn(want, h)

    def test_scripts_parse(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        for f in ("nms_live.html", "nms.html", "ui.html", "admin.html", "login.html"):
            js = "\n".join(re.findall(r"<script>([\s\S]*?)</script>", gui(f)))
            tf = Path(tempfile.mkdtemp()) / "s.js"
            tf.write_text(js, encoding="utf-8")
            r = subprocess.run([node, "-e", "new Function(require('fs').readFileSync(process.argv[1],'utf8'))", str(tf)],
                               capture_output=True, text=True, encoding="utf-8", timeout=30)
            with self.subTest(f=f):
                self.assertEqual(r.returncode, 0, r.stderr[:300])


if __name__ == "__main__":
    unittest.main()
