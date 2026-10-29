"""15차(2026-10-22 마스터 7건):
 1 업로드·분석 등 처리 중인 시간 표시   2 장애보고서 작성 완료 여부·내려받기 강조   3 같은 부서면 누가 분석해도 공유
 4 실시간 관제 서버 이퀄라이저 가독성   5 모니터링 상세(응답 시간 추이·자원 사용률·장애 이력) 세로 길이
 6 판정 리포트 '판정 근거' 간략 보기     7 로그인 화면 왼쪽 아래 문구·시인성"""
from __future__ import annotations

import http.client
import json
import re
import secrets
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
sys.path.insert(0, str(ENGINE))
SAMPLE = ENGINE / "samples" / "catalina.out"


class Screens(unittest.TestCase):
    def test_1_upload_progress(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        i = src.index("async function upload(files){")
        blk = src[src.index("function upPanel()"):src.index("api.pick_logs=", i)]
        for want in ("XMLHttpRequest", "x.upload.onprogress", "남은 약", "경과 ", "/s", "올리기 완료", "aria-label=\"닫기\"", "q('f').textContent='파일 '"):
            self.assertIn(want, blk)
        self.assertNotIn("innerHTML='파일", blk)                      # 파일 이름은 글자로만(textContent)
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn('id="runsec"', ui)                              # 분석 경과(기존)

    def test_2_report_done_and_download(self):
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        g = ui[ui.index("async function genReport(values){"):ui.index("async function exportHtml(){")]
        for want in ('id="repsec"', "장애 보고서 작성 중…", 'class="repdone"', "장애 보고서 작성 완료", 'class="dlbtn', "저장 폴더 열기",
                     "repfail", "scrollIntoView", "m.innerHTML=head+todoHtml+"):
            self.assertIn(want, g)
        self.assertIn("goReportDone:()=>goReportDone()", ui)
        self.assertIn(".dlbtn{", ui)

    def test_4_equalizer_rows(self):
        h = (GUI / "nms_live.html").read_text(encoding="utf-8")
        self.assertNotIn('<canvas id="eq"', h)
        self.assertIn('<div class="eqlist" id="eq"', h)
        for want in (".eqr{", ".eb .tr b", "'.eqr[data-id=\"'+CSS.escape(r.id)+'\"]'", "em.textContent=v==null?'—':Math.round(v)+'%'",
                     "u.style.left=Math.min(99,th[k])+'%'"):
            self.assertIn(want, h)

    def test_5_monitor_detail_two_columns(self):
        css = (GUI / "_ds.css").read_text(encoding="utf-8")
        self.assertIn("clamp(560px,40vw,860px)", css)
        self.assertIn(".nmsdet .mx{grid-template-columns:1fr 1fr!important}", css)
        self.assertNotIn(".nmsdet .mx{grid-template-columns:1fr!important}", css)

    def test_6_evidence_summary(self):
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn("function repEvidenceSummary(rows)", ui)
        self.assertIn('if(EVMODE!=="all") return repEvidenceSummary(rows);', ui)
        self.assertIn('data-evm="sum"', ui)
        self.assertIn("evMode:(el,e,m)=>evMode(m)", ui)
        self.assertIn('localStorage.getItem("lt.evmode")', ui)

    def test_7_login_copy(self):
        h = (GUI / "login.html").read_text(encoding="utf-8")
        for gone in ("3중 암호화 저장", "접근 기록 감사", "사이트별 권한 분리", "세 겹으로 보호해 보관합니다"):
            self.assertNotIn(gone, h)
        # 18차(대문 혹평·GPT 115): 네 기능은 한 낱말 묶음 + 아이콘으로 줄였다(자세한 확인은 test_r18_login_dept)
        for want in ("<span>장애 판정</span>", "<span>실시간 관제</span>", "<span>보고서 자동 작성</span>", "<span>부서 공유</span>"):
            self.assertIn(want, h)
        self.assertIn(".keys{position:relative;z-index:3;flex:none;list-style:none", h)


class Privacy(unittest.TestCase):
    def test_mask_for_viewer_shares(self):
        from logtriage import privacy as P
        inc = {"id": "X", "owner": "a@x", "hosts": ["was-prod-01"], "name": "was-prod-01 장애", "files": [{"host": "was-prod-01"}]}
        same = P.mask_for_viewer(inc, "b@x", shares=lambda o: o == "a@x")
        other = P.mask_for_viewer(inc, "c@x", shares=lambda o: False)
        self.assertIn("was-prod-01", json.dumps(same, ensure_ascii=False))
        self.assertNotIn("was-prod-01", json.dumps(other, ensure_ascii=False))


class DeptShare(unittest.TestCase):
    """3: 운영1팀 A 의 분석 — 같은 부서 B 는 원본·보고서 가능, 다른 부서 C 는 가림·보고서 막힘, 부서 없는 D 는 공유 안 됨."""
    @classmethod
    def setUpClass(cls):
        from logtriage import knowledge_seed as KS
        from logtriage.server import ServerApi, make_server, prepare_base
        cls.td = Path(tempfile.mkdtemp())
        old = KS.bundled_root
        KS.bundled_root = lambda: ENGINE
        try:
            assert not prepare_base(cls.td)
        finally:
            KS.bundled_root = old
        (cls.td / "conf").mkdir(exist_ok=True)
        (cls.td / "conf" / "auth.json").write_text(json.dumps({"mode": "local", "first_admin": "", "require_https": False,
                                                               "local": {"domain": "solideos.com", "scrypt_n": 12}}), encoding="utf-8")

        class Api(ServerApi):
            def _allowed(self, p):
                return True
        cls.httpd, cls.h = make_server("127.0.0.1", 0, cls.td, None, [str(ENGINE / "samples")], None, api_cls=Api)
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.port = cls.httpd.server_address[1]
        cls.pw = {}
        for email, dept in (("ops.a@solideos.com", "운영1팀"), ("ops.b@solideos.com", "운영1팀"), ("dev.c@solideos.com", "개발2팀"),
                            ("nodept.d@solideos.com", "")):
            p = "Lt-" + secrets.token_urlsafe(9) + "!9a"
            cls.h.api.accounts.create(email, p, "operator", ["*"], ["LOCAL"], email.split("@")[0], dept, actor="(시험)", must_change=False)
            cls.pw[email] = p
        cls.h.api.setup_close()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.td, ignore_errors=True)

    def _req(self, m, path, body=None, hdr=None, ck=""):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=120)
        h = dict(hdr or {})
        h["Origin"] = f"http://127.0.0.1:{self.port}"
        if ck:
            h["Cookie"] = ck
        c.request(m, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read(), r.getheader("Set-Cookie") or ""

    def _login(self, email):
        s, b, sc = self._req("POST", "/login", urllib.parse.urlencode({"email": email, "password": self.pw[email]}),
                             {"Content-Type": "application/x-www-form-urlencoded"})
        return "lt_sid=" + re.search(r"lt_sid=([^;]+)", sc).group(1)

    def _api(self, ck, name, *args):
        s, b, _ = self._req("POST", "/api/" + name, json.dumps(list(args)), {"Content-Type": "application/json", "X-NMS-Request": "1"}, ck)
        return json.loads(b or b"{}")

    def test_same_dept_shares_other_dept_masked(self):
        a = self._login("ops.a@solideos.com")
        r = self._api(a, "analyze", {"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "was-prod-01"}], "name": "공유 시험"})
        self.assertFalse(r.get("error"), r)
        iid = r["id"]
        out = {}
        for email in ("ops.b@solideos.com", "dev.c@solideos.com", "nodept.d@solideos.com"):
            ck = self._login(email)
            h = self._api(ck, "history")
            row = next(x for x in h if x.get("id") == iid)
            g = self._api(ck, "generate_report", iid)
            out[email] = ("was-prod-01" in json.dumps(row, ensure_ascii=False), not g.get("error"))
        self.assertEqual(out["ops.b@solideos.com"], (True, True))
        self.assertEqual(out["dev.c@solideos.com"], (False, False))
        self.assertEqual(out["nodept.d@solideos.com"], (False, False))     # 부서가 비면 공유하지 않는다(빈 값끼리 같다고 보지 않음)


if __name__ == "__main__":
    unittest.main()
