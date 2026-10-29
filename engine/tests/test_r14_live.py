"""14차(2026-10-22 마스터): ① '감시 항목 등록 후 서버 정보를 제니퍼처럼 액티브하게' — 실시간 관제(/nms/live, /api/nms/live)
② '자원 사용률 수집을 설정할 수 있게, 갱신해서 볼 수 있게' — 항목별 수집 주기(metrics_interval)·[지금 갱신](/api/nms/collect)·
방식·주기만 바꾸는 /api/nms/usage(가용성 상태는 그대로)·에이전트가 서버가 정한 주기를 따름."""
from __future__ import annotations

import http.client
import json
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import nms as N  # noqa: E402


def _target(st, name, metrics="none", interval=0, **kw):
    v = {"name": name, "address": "192.0.2.%d" % (10 + len(name)), "kind": "server", "method": "tcp", "port": 443, "interval": 86400,
         "timeout": 3, "fail_limit": 1, "recover_limit": 1, "enabled": True, "metrics": metrics, "procs": "none", "metrics_interval": interval}
    v.update(kw)
    return st.save(v)["id"]


class StoreLive(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.st = N.Store(self.td / "nms.db")

    def _rev(self, tid):
        with self.st.db() as db:
            return db.execute("SELECT revision FROM targets WHERE id=?", (tid,)).fetchone()[0]

    def test_live_samples_series_and_since(self):
        a = _target(self.st, "WEB-01", "agent")
        t0 = time.time()
        for k in range(5):
            self.st.record({"id": a, "revision": self._rev(a)}, "up" if k != 3 else "down", 10.0 + k if k != 3 else None, "주소 192.0.2.99 시간 초과", now=t0 - 50 + k)
            self.st.record_metrics(a, {"cpu": 10 + k, "mem": 20, "disk": 30}, now=t0 - 50 + k)
        d = self.st.live(600)
        self.assertEqual(len(d["samples"]), 5)
        self.assertEqual(d["samples"][3][2:], ["down", None])
        self.assertEqual(d["series"][a][-1][1:], [14, 20, 30])
        self.assertNotIn("192.0.2.99", json.dumps(d))                     # 상세 글(주소가 섞일 수 있음)은 내보내지 않는다
        with self.st.db() as db:
            ids = [r[0] for r in db.execute("SELECT id FROM samples ORDER BY id")]
        self.assertEqual(d["cursor"], ids[-1])
        p = self.st.live(600, after=ids[2])
        self.assertTrue(p["partial"])
        self.assertEqual([s[1] for s in p["samples"]], [s[1] for s in d["samples"][3:]])
        self.assertEqual(self.st.live(600, after=d["cursor"])["samples"], [])
        self.assertEqual(self.st.live(600, after=d["cursor"])["cursor"], d["cursor"])
        self.assertEqual(self.st.live(60)["seconds"], 60)
        self.assertEqual(N.Store.live.__defaults__[0], 600)

    def test_same_millisecond_samples_not_lost(self):
        """GPT 102차 P1-04: 같은(반올림하면 같은) 시각의 표본이 이어 받기 사이에 끼어도 놓치지 않는다 — 행 번호 커서."""
        a = _target(self.st, "API-02", "agent")
        t = time.time() - 10
        self.st.record({"id": a, "revision": self._rev(a)}, "up", 5.0, "", now=t)
        d = self.st.live(600)
        self.st.record({"id": a, "revision": self._rev(a)}, "up", 6.0, "", now=t + 0.0002)   # 첫 응답 뒤, 반올림하면 같은 시각
        p = self.st.live(600, after=d["cursor"])
        self.assertEqual([s[3] for s in p["samples"]], [6.0])

    def test_truncated_flag(self):
        a = _target(self.st, "MQ-01", "agent")
        old = N.Store.LIVE_SAMPLES_MAX
        N.Store.LIVE_SAMPLES_MAX = 3
        self.addCleanup(setattr, N.Store, "LIVE_SAMPLES_MAX", old)
        for k in range(5):
            self.st.record({"id": a, "revision": self._rev(a)}, "up", float(k), "", now=time.time() - 20 + k)
        d = self.st.live(600)
        self.assertTrue(d["truncated"])
        self.assertEqual([s[3] for s in d["samples"]], [2.0, 3.0, 4.0])          # 잘려도 최신 것을 남긴다

    def test_set_usage_keeps_availability_state(self):
        a = _target(self.st, "DB-01")
        self.st.record({"id": a, "revision": self._rev(a)}, "down", None, "x")
        with self.st.db() as db:
            before = dict(db.execute("SELECT status,revision,failures FROM targets WHERE id=?", (a,)).fetchone())
            alerts = db.execute("SELECT count(*) FROM alerts WHERE target_id=? AND closed IS NULL", (a,)).fetchone()[0]
        r = self.st.set_usage({"id": a, "metrics": "local", "metrics_interval": 5})
        self.assertEqual((r["metrics"], r["metrics_interval"], r["every"]), ("local", 5, 5))
        with self.st.db() as db:
            after = dict(db.execute("SELECT status,revision,failures FROM targets WHERE id=?", (a,)).fetchone())
            self.assertEqual(db.execute("SELECT count(*) FROM alerts WHERE target_id=? AND closed IS NULL", (a,)).fetchone()[0], alerts)
        self.assertEqual(before, after)                                     # 장애 상태·리비전·실패 횟수 그대로
        self.assertEqual(self.st.set_usage({"id": a, "metrics_interval": 0})["every"], 10)   # 기본: 자체 10초
        with self.assertRaisesRegex(ValueError, "커뮤니티"):
            self.st.set_usage({"id": a, "metrics": "snmp"})                 # 비밀값은 여기서 받지 않는다 — [편집]에서
        for bad in (3, 4000, "10", 7.5, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.st.set_usage({"id": a, "metrics_interval": bad})
        with self.assertRaises(ValueError):
            self.st.set_usage({"id": "없음", "metrics": "local"})

    def test_interval_rules_and_save(self):
        self.assertEqual([N.metrics_every(m, 0) for m in ("local", "agent", "snmp")], [10, 30, 30])
        self.assertEqual(N.metrics_every("snmp", 5), 10)                    # SNMP 는 장비 부하 — 10초 미만 안 받음
        self.assertEqual(N.metrics_every("agent", 60), 60)
        a = _target(self.st, "API-01", "agent", 60)
        self.assertEqual(self.st.usage_interval(a), 60)
        with self.assertRaises(ValueError):
            _target(self.st, "BAD-01", "agent", 2)


class CollectorSchedule(unittest.TestCase):
    def test_per_target_interval_and_collect_now(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        st = N.Store(td / "nms.db")
        a = _target(st, "FAST", "local", 5, address="127.0.0.1", port=1)
        b = _target(st, "SLOW", "local", 300, address="127.0.0.2", port=1)
        with st.db() as db:
            db.execute("UPDATE targets SET next_due=?", (time.time() + 86400,))   # 가용성 검사는 이 시험과 무관
        c = N.Collector(st, workers=2)
        c.start()
        self.addCleanup(c.stop)
        n = lambda tid: len(st.metrics(tid, 600))
        deadline = time.time() + 8
        while time.time() < deadline and not (n(a) >= 1 and n(b) >= 1):
            time.sleep(.2)
        self.assertGreaterEqual(n(a), 1)
        self.assertEqual(n(b), 1)                                             # 300초 주기 — 첫 수집 뒤에는 기다린다
        time.sleep(1.5)
        self.assertEqual(n(b), 1)
        c.collect_now(b)                                                      # [지금 갱신] — 주기와 무관하게 바로
        deadline = time.time() + 4
        while time.time() < deadline and n(b) < 2:
            time.sleep(.2)
        self.assertEqual(n(b), 2)
        self.assertFalse(c._force)                                            # 처리한 요청은 남지 않는다


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from logtriage import knowledge_seed as KS
        from logtriage.server import ServerApi, make_server, prepare_base
        cls.td = Path(tempfile.mkdtemp())
        KS_root = KS.bundled_root
        KS.bundled_root = lambda: ENGINE
        try:
            assert not prepare_base(cls.td)
        finally:
            KS.bundled_root = KS_root
        cls.httpd, cls.h = make_server("127.0.0.1", 0, cls.td, None, [], None, api_cls=ServerApi, desktop=True, native=False, local_only=True)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]
        cls.h.boot_token = secrets.token_hex(16)
        r = cls._req("GET", f"/auth/bootstrap?t={cls.h.boot_token}")
        cls.ck = r[2].split(";")[0]
        st = cls.h.api.nms
        cls.tid = _target(st, "WAS-01", "agent", address="127.0.0.1")
        cls.loc = _target(st, "LOCAL", "none", address="127.0.0.3")

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.td, ignore_errors=True)

    @classmethod
    def _req(cls, m, path, body=None, hdr=None):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=10)
        c.request(m, path, body=body, headers=hdr or {})
        r = c.getresponse()
        return r.status, r.read(), r.getheader("Set-Cookie") or "", r.getheader("Content-Security-Policy") or ""

    def _post(self, path, data, nms_hdr=True):
        h = {"Content-Type": "application/json", "Cookie": self.ck}
        if nms_hdr:
            h["X-NMS-Request"] = "1"
        return self._req("POST", path, json.dumps(data), h)

    def test_live_page_and_api(self):
        s, body, _, csp = self._req("GET", "/nms/live", hdr={"Cookie": self.ck})
        page = body.decode("utf-8")
        self.assertEqual(s, 200)
        self.assertIn("실시간 관제", page)
        self.assertRegex(page, r'<script nonce="[^"]+"')                    # 인라인 대본은 1회용 표가 붙는다(CSP)
        self.assertNotIn("_ds.css", page)                                     # 밝은 공통 디자인을 넣지 않는다(제목 글자가 덮였다)
        self.assertIn("nonce-", csp)
        self.assertEqual(self._req("GET", "/nms/live")[0], 302)               # 세션 없이는 안 열린다
        s, body, _, _ = self._req("GET", "/api/nms/live?range=600", hdr={"Cookie": self.ck})
        d = json.loads(body)
        self.assertEqual((s, d["seconds"], d["partial"]), (200, 600, False))
        self.assertEqual(self._req("GET", "/api/nms/live?after=abc", hdr={"Cookie": self.ck})[0], 400)
        self.assertEqual(self._req("GET", "/api/nms/live")[0], 401)

    def test_usage_and_collect(self):
        self.assertEqual(self._post("/api/nms/usage", {"id": self.loc, "metrics": "local"}, nms_hdr=False)[0], 403)   # 화면 표식 없이 못 바꿈
        s, body, _, _ = self._post("/api/nms/usage", {"id": self.loc, "metrics": "local", "metrics_interval": 30})
        self.assertEqual((s, json.loads(body)["every"]), (200, 30))
        s, body, _, _ = self._post("/api/nms/collect", {"id": self.loc})
        self.assertEqual(s, 200)
        self.assertIn("지금 수집", json.loads(body)["note"])
        s, body, _, _ = self._post("/api/nms/collect", {"id": self.tid})
        self.assertIn("에이전트", json.loads(body)["note"])                  # 원격이 보내는 값은 당길 수 없다고 알린다
        s, body, _, _ = self._post("/api/nms/usage", {"id": self.tid, "metrics_interval": 2})
        self.assertEqual(s, 400)

    def test_rejected_agent_reports_are_explained(self):
        """마스터: '응답 시간만 수집되고 자원 사용률이 안 된다' — 거절한 보고(토큰·주소/호스트명 불일치)를 원인·고치는 법과 함께 상태에 싣고,
        고쳐서 받으면 지운다. 자산 권한이 없으면 출발 주소는 가린다(기존 가림 규칙)."""
        st = self.h.api.nms
        st.agent_rejects.clear()
        import os
        from unittest import mock
        pe = mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": "7e" * 32})   # 23차: 우리 nginx(비밀 머리글)를 거친 X-Real-IP 만 출발지로 믿는다
        pe.start()
        self.addCleanup(pe.stop)
        hdr = {"Content-Type": "application/json", "X-Agent-Token": "틀린토큰".encode().hex(),
               "X-Forwarded-For": "10.9.9.9", "X-Real-IP": "10.9.9.9", "X-LogTriage-Proxy": "7e" * 32}   # 원격(다른 주소)에서 nginx 를 거쳐 온 보고
        self.assertEqual(self._req("POST", "/api/nms/metrics", json.dumps({"hostname": "web99", "cpu": 1}), hdr)[0], 401)
        hdr["X-Agent-Token"] = st.agent_token
        s, body, _, _ = self._req("POST", "/api/nms/metrics", json.dumps({"hostname": "web99", "cpu": 1, "mem": 2, "disk": 3}), hdr)
        self.assertEqual(s, 404)
        snap = json.loads(self._req("GET", "/api/nms/status", hdr={"Cookie": self.ck})[1])
        rj = snap["agent_rejects"]
        self.assertEqual(len(rj), 2)
        self.assertIn("호스트명 web99", rj[0]["reason"])
        self.assertEqual(rj[0]["address"], "10.9.9.9")
        self.assertIn("수집 방식을 '원격 서버 — 에이전트'", rj[0]["reason"])
        self.assertTrue(any("토큰이 맞지 않습니다" in r["reason"] for r in rj))
        st.set_usage({"id": self.loc, "metrics": "agent"})
        with st.db() as db:
            db.execute("UPDATE targets SET name='web99' WHERE id=?", (self.loc,))     # 고치는 법대로 이름을 호스트명으로
        s, body, _, _ = self._req("POST", "/api/nms/metrics", json.dumps({"hostname": "web99", "cpu": 1, "mem": 2, "disk": 3}), hdr)
        self.assertEqual(s, 200, body)
        left = json.loads(self._req("GET", "/api/nms/status", hdr={"Cookie": self.ck})[1])["agent_rejects"]
        self.assertFalse([r for r in left if r["hostname"] == "web99"])                # 받으면 그 거절 기록은 지운다
        st.agent_rejects.clear()
        st.note_reject("10.1.1.1", "db01", "진짜 원인", authed=True)
        for k in range(40):
            st.note_reject(f"10.0.0.{k}", "위조된이름", "x", authed=False)
        self.assertLessEqual(len(st.agent_rejects), st.REJECTS_MAX)                    # 토큰 없는 요청도 기록 — 개수 상한
        self.assertTrue(any(v["reason"] == "진짜 원인" for v in st.agent_rejects.values()))   # GPT 105차: 출처 확인 안 된 것부터 버린다
        self.assertFalse(any(v["hostname"] for v in st.agent_rejects.values() if not v["authed"]))   # 출처 확인 안 된 기록엔 호스트명 없음
        st.note_reject("10.2.2.2", "DB-01‮10-BD", "y")
        self.assertEqual(st.recent_rejects()[0]["hostname"], "DB-0110-BD")              # 방향 제어 문자 제거

    def test_agent_gets_interval(self):
        st = self.h.api.nms
        st.set_usage({"id": self.tid, "metrics_interval": 60})
        s, body, _, _ = self._req("POST", "/api/nms/metrics", json.dumps({"hostname": "WAS-01", "cpu": 12.5, "mem": 40, "disk": 50}),
                                  {"Content-Type": "application/json", "X-Agent-Token": st.agent_token})
        d = json.loads(body)
        self.assertEqual((s, d.get("ok"), d.get("interval")), (200, True, 60), d)


class Surfaces(unittest.TestCase):
    def test_agent_logs_real_send_error(self):
        """10-22 현장: 에이전트 로그가 '[HTTP 000]'·'전송 실패' 뿐이라 원인을 몰랐다 — curl 오류 문구(-S)·10초·닿지 못함 안내,
        설치 때 실제 전송 시험과 겹쳐 도는 에이전트 경고."""
        ag = ENGINE / "tools" / "agent"
        for n in ("lt-agent.sh", "lt-agent-posix.sh"):
            s = (ag / n).read_text(encoding="utf-8")
            self.assertIn("curl -K - -sS -m 10 -w ' [HTTP %{http_code}]'", s, n)   # 19차: 토큰은 명령줄이 아니라 표준 입력 설정(-K -)으로
            self.assertIn("서버에 닿지 못했습니다", s, n)
            self.assertNotIn("curl -s -m 5", s, n)
            self.assertNotIn(b"\r", (ag / n).read_bytes(), n)
        inst = (ag / "lt-agent-install.sh").read_text(encoding="utf-8")
        self.assertIn("전송 시험 OK", inst)
        self.assertIn("'HTTP 000'", inst)
        self.assertIn("pgrep -af 'lt-agent", inst)
        self.assertLess(inst.index("서비스 시작 OK"), inst.index("전송 시험"))      # 서비스를 띄운 뒤 실제 전송 한 번

    def test_agent_follows_server_interval(self):
        src = (ENGINE / "tools" / "agent" / "lt-agent.py").read_text(encoding="utf-8")
        self.assertIn('json.loads(r).get("interval")', src)
        self.assertIn("5 <= want <= 3600", src)

    def test_nms_page_controls_and_spec(self):
        html = (ENGINE / "logtriage" / "gui" / "nms.html").read_text(encoding="utf-8")
        for want in ('id="mint"', 'id="mnow"', 'id="mquick"', 'name="metrics_interval"', "'metrics_interval'])d[k]=Number(d[k])",
                     "nat.open_live()", "window.open('/nms/live','lt_live')"):   # 마스터: 실시간 관제는 새 창(데스크톱은 새 프로그램 창)
            self.assertIn(want, html)

    def test_open_live_desktop_window(self):
        """데스크톱: 새 프로그램 창(같은 창 엔진 → 세션 이어짐), 이 PC 주소일 때만, 이미 열려 있으면 앞으로."""
        from unittest import mock
        from logtriage.gui import app as A
        api = A.Api.__new__(A.Api)
        made = []

        class W:
            def __init__(self, url):
                self.url = url
                self.events = type("E", (), {"closed": self})()
                self.shown = 0

            def __iadd__(self, f):
                return self

            def get_current_url(self):
                return self.url

            def restore(self):
                pass

            def show(self):
                self.shown += 1
        api._window = W("http://127.0.0.1:51234/nms")
        api.__dict__["_origin"] = "http://127.0.0.1:51234"                       # 이 프로그램이 띄운 내장 서버
        fake = mock.Mock()
        fake.create_window.side_effect = lambda title, url, **k: made.append((title, url, k)) or W(url)
        with mock.patch.object(A, "webview", fake):
            self.assertEqual(api.open_live(), {"ok": True})
            self.assertEqual(made[0][1], "http://127.0.0.1:51234/nms/live")
            self.assertTrue(api.open_live()["reused"])                              # 두 번째는 새로 만들지 않고 앞으로
            self.assertEqual(len(made), 1)
            api.__dict__.pop("_live_win")
            api._window = W("https://evil.example/nms")
            self.assertIn("error", api.open_live())                                 # 이 PC 주소가 아니면 열지 않는다
            api._window = W("http://127.0.0.1:9999/nms")
            self.assertIn("error", api.open_live())                                 # GPT 105차 P0: 이 PC 의 **다른** 서버(다른 포트)면 열지 않는다
            api.__dict__.pop("_origin")
            api._window = W("http://127.0.0.1:51234/nms")
            self.assertIn("error", api.open_live())                                 # 내장 서버 주소를 모르면 열지 않는다
            self.assertEqual(len(made), 1)
        live = (ENGINE / "logtriage" / "gui" / "nms_live.html").read_text(encoding="utf-8")
        self.assertIn("window.opener.focus(); window.close();", live)              # 새 창이면 [감시 항목으로] 는 원래 창으로
        sp = ENGINE / "deploy" / "local" / "logtriage.spec"
        if sp.is_file():   # PC 포장 설정은 개발 트리에만 있다(리눅스 묶음 안에서 돌릴 때는 건너뜀)
            self.assertIn("logtriage/gui/nms_live.html", sp.read_text(encoding="utf-8"))   # 포장본에 화면이 들어간다
        live = (ENGINE / "logtriage" / "gui" / "nms_live.html").read_text(encoding="utf-8")
        self.assertFalse(re.search(r"\son[a-z]+=", live))                    # 인라인 이벤트 처리기(CSP 가 막음) 없음
        self.assertIn("api('usage'", live)
        self.assertIn("api('collect'", live)


if __name__ == "__main__":
    unittest.main()
