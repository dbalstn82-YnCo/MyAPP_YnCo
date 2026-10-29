"""UI 전면 개편(2026-10-14, 클로드·GPT 공동 검토 — design/40~42 시안) 고정 시험.

- 디자인 시스템(/static/_ds.css)이 모든 화면의 </head> 앞에 붙고 실제로 내려간다
- 메뉴는 한 정의(NAV_DEF)에서 그리고, 상단 바에는 늘 홈 단추가 있다(마스터 "어떤 화면에서도 홈으로")
- 분석 진행 조회는 작업을 만든 계정만 본다(작업 번호만 알아서는 못 본다 — GPT UI 3차 P0)
- 계층은 엔진이 정한다(files[].layer) — 화면이 제품→계층 표를 따로 들지 않는다(GPT UI 2차 P1)
- 화면 스크립트의 함정 회귀 막기: 전역 history 배열이 window.history 를 가린다, hidden 이 display 규칙에 진다
"""
import http.client
import re
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import server  # noqa: E402
from logtriage.auth import ensure_conf  # noqa: E402
from logtriage.server import make_server  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

GUI = ENGINE / "logtriage" / "gui"


class UiRedesign(unittest.TestCase):
    def _srv(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        base = Path(td.name)
        ensure_conf(base)
        httpd, h = make_server("127.0.0.1", 0, base, None, desktop=True, local_only=True)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        self.addCleanup(lambda: (httpd.shutdown(), httpd.server_close(), t.join()))
        port = httpd.server_address[1]
        r, _ = self._get(port, f"/auth/bootstrap?t={h.boot_token}")
        ck = "lt_session=" + re.search(r"lt_session=([0-9a-f]{32})", r.getheader("Set-Cookie") or "").group(1)
        return port, ck

    def _get(self, port, path, cookie=""):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request("GET", path, headers={"Host": f"127.0.0.1:{port}", **({"Cookie": cookie} if cookie else {})})
        r = c.getresponse()
        body = r.read().decode("utf-8", "replace")
        c.close()
        return r, body

    def test_design_system_on_every_page(self):
        port, ck = self._srv()
        r, css = self._get(port, "/static/_ds.css", ck)
        self.assertEqual(r.status, 200)
        self.assertIn("Precision Triage", css)
        self.assertIn("[hidden]{display:none!important}", css)            # hidden 이 .btn{display:…}에 지던 함정
        for path in ("/", "/nms", "/resources", "/automation", "/board", "/admin", "/hub"):
            r, body = self._get(port, path, ck)
            self.assertEqual(r.status, 200, path)
            self.assertIn(server.DS_LINK, body, path)
            self.assertLess(body.index(server.DS_LINK), body.index("</head>"), path)

    def test_nav_single_definition_and_home_button(self):
        js = server.NAV_JS
        self.assertIn("var NAV_DEF=", js)
        for k in ("home", "new", "dash", "report", "hist", "logsearch", "rules", "forms", "pack", "nms", "inv", "auto", "board", "admin", "hub"):
            self.assertIn(f"['{k}',", js, k)
        self.assertIn("window.LT_ROUTE=route", js)
        self.assertIn("Alt+Home", server.GNB_BAR)
        self.assertIn('id="lt-home"', server.GNB_BAR)
        self.assertIn("lt-cr-home", js)                                    # 경로 첫 마디는 홈 링크
        self.assertIn("var FOLD_SCHEMA='2'", js)                           # 접힘 기본은 마스터 결정 — 저장값도 버리지 않는다
        self.assertIn("return v===null?true:v==='1'", js)                  # 기본 접힘, 현재 화면 묶음만 route() 가 연다

    def test_progress_only_for_job_owner(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        api = server.ServerApi(td, [], None)
        self.assertIn("analyze_progress", server.API_NAMES)
        self.assertNotIn("analyze_progress", server.READ_APIS)             # 보기 권한(분석 못 함)은 진행도 못 본다
        api.actor.login = "alice"
        api._job_progress("ab" * 12)({"stage": "check", "files": 2})
        self.assertEqual(api.analyze_progress("ab" * 12)["steps"][0]["files"], 2)
        api.actor.login = "bob"
        self.assertEqual(api.analyze_progress("ab" * 12), {"steps": []})
        self.assertEqual(api.analyze_progress("nope"), {"steps": []})

    def test_engine_owns_layer_and_reports_progress(self):
        steps = []
        S = ENGINE / "samples"
        r = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                          {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                         rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes",
                         progress=steps.append)
        self.assertEqual([f["layer"] for f in r["files"]], ["db", "was"])
        self.assertEqual([s["stage"] for s in steps], ["check", "read", "read_done", "read", "read_done", "match", "judge"])
        self.assertEqual(steps[-2]["rules"] > 0, True)
        self.assertNotIn("%", "".join(str(s) for s in steps))              # 퍼센트를 지어내지 않는다

    def test_stats_exclude_demo_and_measure_time(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        api = server.ServerApi(td, [], None)
        real = {"id": "INC-1", "analyzed_at": "2026-10-14 10:00:00", "elapsed_sec": 4.0, "sev_totals": {"critical": 1},
                "first": {"layer_ko": "DBMS", "verdict": "x"}, "timeline": [{"severity": "critical"}]}
        demo = dict(real, id="DEMO-abc", elapsed_sec=99.0)
        api.history = lambda: [demo, real]
        st = api.stats()
        self.assertEqual((st["total"], st["demo_excluded"], st["elapsed_avg"], st["elapsed_n"]), (1, 1, 4.0, 1))   # 시연은 통계 밖, 평균은 잰 것만

    def test_dash_brief_period(self):
        """마스터 10-14: 전체 현황에 TOP5·최근 분석·기간을 간략히 — 기간은 서버가 잘라 계산한다."""
        from datetime import datetime, timedelta
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        api = server.ServerApi(td, [], None)
        at = lambda d: (datetime.now() - timedelta(days=d)).strftime("%Y-%m-%d %H:%M:%S")
        mk = lambda i, d, v: {"id": f"INC-{i}", "analyzed_at": at(d), "first": {"layer_ko": "DBMS", "verdict": v, "severity": "error"}}
        api.history = lambda: [mk(1, 1, "a"), mk(2, 10, "b"), mk(3, 40, "b")]
        self.assertEqual(api.stats()["total"], 3)
        self.assertEqual(api.stats(7)["total"], 1)
        self.assertEqual(api.stats(30)["total"], 2)
        self.assertEqual(api.stats(999)["total"], 3)                       # 정해진 기간 밖의 값은 전체
        st = api.stats(30)
        self.assertEqual([(t["verdict"], t["n"], t["severity"]) for t in st["top_types"]], [("a", 1, "error"), ("b", 1, "error")])
        self.assertEqual(st["recent"][0]["severity"], "error")
        old = {"id": "INC-9", "analyzed_at": at(0), "first": {"layer_ko": "DBMS", "verdict": "c", "rule_id": "R1"},
               "checklist": [{"rule_id": "R0", "severity": "warn"}, {"rule_id": "R1", "severity": "critical"}]}
        api.history = lambda: [old]                                         # 옛 이력: first.severity 없음 → 같은 룰의 등급
        self.assertEqual(api.stats()["top_types"][0]["severity"], "critical")   # 실측 결함: '치명' 분석이 '정보'로 보였다
        S = ENGINE / "samples"
        r = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"}], None,
                         rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        self.assertIn(r["first"]["severity"], ("critical", "error", "warn", "info"))
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn("api().stats(DASHDAYS)", ui)
        self.assertIn('$("#dashwrap").innerHTML=auto+per+kpi4+', ui)       # 무인 1차 대응 카드는 여전히 맨 위
        self.assertNotIn("toggleTop(${i})", ui)                            # 펼침형 TOP5(09-17 에 뺀 것)로 되돌리지 않는다
        self.assertIn('if(id==="dash") quiet(reloadHistory().then(()=>renderDash()));', ui)   # 들어올 때마다 새로(무인 대응 분석이 안 보이던 결함)
        rh = ui[ui.index("async function reloadHistory"):ui.index("async function refreshHistory")]
        self.assertNotIn("inc", rh)                                        # 딥링크를 다시 따라가지 않는다

    def test_monitoring_status_families(self):
        """시안 09(GPT 9·11차): 정상·이상·확인 불가를 섞지 않는다 — 예전엔 수집 지연·의심·복구 확인 중이 같은 주황, 미확인은 정보 파랑."""
        nms = (GUI / "nms.html").read_text(encoding="utf-8")
        self.assertNotIn("['수집 지연','warn']", nms)
        self.assertIn("t.stale?['수집 지연','unk','stale']", nms)                # 확인 불가 = 회색 ?
        self.assertIn("unknown:['미확인','unk']", nms)
        self.assertIn("k==='stale'?Math.min(3,ST_ORDER[t.status]??3)", nms)      # 열린 장애가 수집 지연으로 밀리지 않게
        self.assertIn("미종결 장애", nms)
        self.assertNotIn(">활성 장애<", nms)
        self.assertIn("else if(!autoPicked)", nms)                               # 자동 선택은 처음 한 번만
        self.assertIn("전 값 · 현재 미확인", nms)                                 # 지난 자원값을 현재값처럼 보이지 않게
        ds = (GUI / "_ds.css").read_text(encoding="utf-8")
        self.assertIn(".sev.recov", ds)
        self.assertIn(".sev.pause", ds)

    def test_hub_totals_do_not_count_stale_sites_as_up(self):
        """통합 현황: 수신이 끊긴 사이트의 마지막 '정상'을 지금 정상으로 세지 않는다(10-14 실측 결함). 장애는 남긴다."""
        import time as _t
        from logtriage import hub as hubmod
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        h = hubmod.HubStore(td)
        h.add_site("A", "사이트 A"); h.add_site("B", "사이트 B")
        now = _t.time()
        with h.db() as db:
            db.execute("UPDATE sites SET last_seen=?, interval=60 WHERE id='A'", (now - 10,))
            db.execute("UPDATE sites SET last_seen=?, interval=60 WHERE id='B'", (now - 3600,))   # 한 시간째 수신 없음
            for sid, tid, st, old in (("A", "1", "up", 0), ("A", "2", "down", 0), ("A", "3", "up", 1), ("A", "4", "down", 1),
                                      ("B", "1", "up", 0), ("B", "2", "up", 0), ("B", "3", "down", 0)):
                db.execute("INSERT INTO targets(site_id,tid,name,status,enabled,stale) VALUES(?,?,?,?,1,?)", (sid, tid, sid + tid, st, old))
        o = h.overview()
        st = {s["id"]: s["state"] for s in o["sites"]}
        self.assertEqual(st, {"A": "online", "B": "offline"})
        t = o["total"]
        # 지금 정상·장애 = 수신 중 사이트의 신선한 관측만(GPT 16차) · 오래된 측정(A3·A4)과 끊긴 사이트(B) = 확인 불가 · 장애는 '지난 장애'로 남김
        self.assertEqual((t["up"], t["down"], t["nochk"], t["down_past"]), (1, 1, 5, 2))
        self.assertEqual(sorted((r["site_id"], r["tid"], r["past"]) for r in o["down"]), [("A", "2", False), ("A", "4", True), ("B", "3", True)])
        hub = (GUI / "hub.html").read_text(encoding="utf-8")
        self.assertIn("? 마지막 수신 기준 값 · 현재 미확인", hub)
        self.assertNotIn("offline:['끊김','crit']", hub)

    def test_evidence_id_and_palette(self):
        """2026-10-15 마스터 지시로 넣은 두 기능 — 근거별 고유 ID, Ctrl+K 찾기(모든 화면·포장본 포함)."""
        S = ENGINE / "samples"
        r = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                          {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                         rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        ids = [t["eid"] for t in r["timeline"]]
        self.assertTrue(ids and all(re.fullmatch(r"E-[0-9A-F]{12}", x) for x in ids))
        self.assertEqual(len(ids), len(set(ids)))                          # 같은 줄에 룰 여럿이 걸려도 근거마다 다르다
        r2 = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                           {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                          rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        self.assertEqual(ids, [t["eid"] for t in r2["timeline"]])          # 같은 로그면 같은 ID(다시 분석해도 가리킬 수 있게)
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn('data-eid="${esc(t.eid||"")}"', ui)
        self.assertIn("■ 핵심 근거(근거 ID로 가리키십시오)", ui)
        self.assertIn("window.LT_OPEN_EV=", ui)
        self.assertIn('__ltPal', server.NAV_JS)                            # 모든 화면 공통 스크립트에 들어간다
        self.assertIn('id="lt-find"', server.GNB_BAR)                       # 상단 바 [찾기 Ctrl+K] 단추
        if not (ENGINE / "deploy" / "local" / "logtriage.spec").is_file():
            return                                                           # 리눅스 묶음 — PC 빌드 spec·bat 은 없다(위 화면 확인까지만)
        spec = (ENGINE / "deploy" / "local" / "logtriage.spec").read_text(encoding="utf-8")
        bat = (ENGINE / "deploy" / "local" / "build_exe.bat").read_text(encoding="utf-8")
        self.assertIn("_palette.js", spec)                                   # 포장본에서 조용히 빠지지 않게
        self.assertIn("build_pc.py", bat)                                    # 12차: bat 는 spec 을 쓰는 build_pc.py 만 부른다(옛 bat 는 spec 을 안 썼다)
        self.assertIn('"logtriage.spec"', (ENGINE / "tools" / "build" / "build_pc.py").read_text(encoding="utf-8"))

    def test_screen_script_traps(self):
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertNotIn("PROD_LAYER", ui)                                 # 계층 표는 엔진에만
        self.assertIsNone(re.search(r"(?<![.\w])history\.(pushState|replaceState|back)\(", ui))   # 전역 history 배열이 가린다
        self.assertIn("window.history.pushState", ui)
        self.assertIn('"analyze_progress"', ui)
        self.assertNotIn(">CLEAR<", ui)                                    # 영문 등급 대신 한글 등급(이상 미검출)
        self.assertNotIn("CRITICAL", ui)


if __name__ == "__main__":
    unittest.main()
