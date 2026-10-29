"""11차(2026-10-19 마스터: "빌드된 그대로 회사 해커톤에 제출 — 완성도를 극도로") — 첫 5분·완결성.

① 홈 '견본으로 30초 체험'(누구나) — 견본 넣기 → 분석 → 리포트, 결과는 DEMO- (시연 정리로 지움)
② 판정 리포트 목차(구획 이동·맨 위로, 인쇄 제외)
③ 긴 표(확인이 필요한 지식) 찾기 + 스크롤 상자 — 룰팩 화면 길이
④ 상태·정보 창(지식 줄 클릭 — 판·실행 파일·지식·자가 점검·이력, 읽기만)
⑤ 단독 실행 첫 기동 환영 안내(한 번, 시험 실행 창에는 안 띄움)
⑥ 접근성 — 라벨 없는 선택칸 0
⑦ 리포트 머리에 실제로 잰 분석 시간
⑨ 분석 실패 안내를 다음에 할 일로
⑩ 시연 정리(관리자) — DEMO- 만 지우고 실제 분석은 그대로
"""
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.server import make_server  # noqa: E402

UI = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
CSS = (ENGINE / "logtriage" / "gui" / "_ds.css").read_text(encoding="utf-8")
SAMPLE = ENGINE / "samples" / "catalina.out"


def _base(test):
    td = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, td, True)
    for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
        shutil.copytree(ENGINE / d, td / d)
    return td


def _api(test, base, allow=None):
    httpd, handler = make_server("127.0.0.1", 0, base, None, allow if allow is not None else [ENGINE / "samples", base], desktop=True, native=False)
    test.addCleanup(httpd.server_close)
    return handler.api


class SampleRunIsDemo(unittest.TestCase):
    def test_sample_run_demo_prefix_and_clear(self):
        b = _base(self)
        api = _api(self, b)
        s = api.sample_logs()
        r = api.analyze({"inputs": [{"path": x["path"], "product": x["product"], "host": "s"} for x in s]})
        self.assertTrue(r["id"].startswith("DEMO-"), r.get("id"))
        self.assertEqual(r["name"], "견본 체험 분석")
        real = b / "real.out"                                                # 견본과 같은 내용이라도 견본 폴더 밖이면 실제 분석
        real.write_text(SAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
        r2 = api.analyze({"inputs": [{"path": str(real), "product": "tomcat", "host": "h"}]})
        self.assertTrue(r2["id"].startswith("INC-"), r2.get("id"))
        mixed = api.analyze({"inputs": [{"path": s[0]["path"], "product": s[0]["product"], "host": "s"},
                                        {"path": str(real), "product": "tomcat", "host": "h"}]})
        self.assertTrue(mixed["id"].startswith("INC-"))                      # 하나라도 실제 로그면 실제 분석
        out = api.demo_clear()
        self.assertEqual(out["removed"]["incidents"], 1)
        ids = {h["id"] for h in api.history()}
        self.assertEqual(ids, {r2["id"], mixed["id"]})                       # 실제 분석은 그대로

    def test_named_sample_run_keeps_name(self):
        api = _api(self, _base(self))
        s = api.sample_logs()[:1]
        r = api.analyze({"name": "시연 1", "inputs": [{"path": s[0]["path"], "product": s[0]["product"], "host": "s"}]})
        self.assertEqual(r["name"], "시연 1")
        self.assertTrue(r["id"].startswith("DEMO-"))


class SampleIntegrity(unittest.TestCase):
    """GPT 81차 잠재 P0: 경로만 보면 견본 자리에 실제 로그를 덮어써도 DEMO- — 내용 지문까지 맞아야 시연. 정리는 접두어 + 시연 표시 둘 다."""

    def _swap_root(self):
        from logtriage.gui import app as A
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        root = td / "samples"
        shutil.copytree(ENGINE / "samples", root)
        old = A.Api.__dict__["_samples_root"]   # staticmethod 째로 보관(되돌릴 때 맨 함수가 되면 다른 시험이 깨진다)
        A.Api._samples_root = staticmethod(lambda: root)
        self.addCleanup(lambda: setattr(A.Api, "_samples_root", old))
        return root

    def test_tampered_or_unlisted_sample_is_real(self):
        root = self._swap_root()
        api = _api(self, _base(self), allow=[root])
        x = {"path": str(root / "catalina.out"), "product": "tomcat", "host": "s"}
        self.assertTrue(api.analyze({"inputs": [x]})["id"].startswith("DEMO-"))        # 손대지 않은 견본
        (root / "catalina.out").write_text(SAMPLE.read_text(encoding="utf-8") + "\n실제 로그를 덮어씀\n", encoding="utf-8")
        r = api.analyze({"inputs": [x]})
        self.assertTrue(r["id"].startswith("INC-"), r["id"])                            # 내용이 다르면 실제 분석
        self.assertNotIn("demo", r)
        (root / "catalina.out").write_bytes((ENGINE / "samples" / "catalina.out").read_bytes())
        (root / "SHA256SUMS.json").unlink()
        self.assertTrue(api.analyze({"inputs": [x]})["id"].startswith("INC-"))         # 지문 목록이 없으면 실제 분석

    def test_link_in_sample_folder_is_real(self):
        root = self._swap_root()
        real = root.parent / "real.out"
        real.write_bytes((root / "catalina.out").read_bytes())
        (root / "catalina.out").unlink()
        try:
            import os
            os.symlink(real, root / "catalina.out")
        except OSError:
            self.skipTest("심볼릭 링크 권한 없음")
        api = _api(self, _base(self), allow=[root, root.parent])
        r = api.analyze({"inputs": [{"path": str(root / "catalina.out"), "product": "tomcat", "host": "s"}]})
        self.assertTrue(r["id"].startswith("INC-"))

    def test_clear_needs_prefix_and_demo_mark(self):
        api = _api(self, _base(self))
        s = api.sample_logs()[:1]
        d = api.analyze({"inputs": [{"path": s[0]["path"], "product": s[0]["product"], "host": "s"}]})
        self.assertIs(next(h for h in api.history() if h["id"] == d["id"]).get("demo"), True)   # 표시가 저장됨
        api.store.save_incident({"id": "DEMO-REAL-0001", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": [], "name": "실제"})
        out = api.demo_clear()
        self.assertEqual(out["removed"]["incidents"], 1)
        self.assertEqual({h["id"] for h in api.history()}, {"DEMO-REAL-0001"})        # 접두어만 같고 표시 없는 건 그대로

    def test_analysis_uses_verified_bytes(self):
        """GPT 82차 P0-02(TOCTOU): 검증한 바이트를 쓴 임시 사본으로 분석 — 분석 도중 견본 원본이 바뀌어도 분석 내용은 검증본, 끝나면 사본 삭제."""
        from logtriage.gui import app as A
        root = self._swap_root()
        api = _api(self, _base(self), allow=[root])
        seen = {}
        real_run = A.run_analysis

        def spy(inputs, *a, **k):
            p = Path(inputs[0]["path"])
            seen["path"], seen["bytes"] = p, p.read_bytes()
            (root / "catalina.out").write_text("바꿔치기\n", encoding="utf-8")   # 검증 뒤 원본 교체
            return real_run(inputs, *a, **k)
        A.run_analysis = spy
        self.addCleanup(lambda: setattr(A, "run_analysis", real_run))
        r = api.analyze({"inputs": [{"path": str(root / "catalina.out"), "product": "tomcat", "host": "s"}]})
        self.assertTrue(r["id"].startswith("DEMO-"))
        self.assertNotEqual(seen["path"].parent, root)                         # 원본이 아니라 사본
        self.assertEqual(seen["bytes"], (ENGINE / "samples" / "catalina.out").read_bytes())
        self.assertFalse(seen["path"].parent.exists())                         # 사본은 지움
        self.assertGreater(r.get("findings_total", 0), 0)

    def test_legacy_demo_needs_generator_id_format(self):
        """GPT 82·83차: 표시(demo=true) 없는 옛 시연 자료는 ID 형식·이름이 맞아도 자동 삭제하지 않는다."""
        api = _api(self, _base(self))
        st = api.store
        st.save_incident({"id": "DEMO-0123456789abcdef", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": [], "name": "[시연] was01 — catalina.out"})
        st.save_incident({"id": "DEMO-REAL-2", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": [], "name": "[시연] 이름만 비슷한 실제"})
        st.save_incident({"id": "DEMO-fedcba9876543210", "analyzed_at": "2026-10-01 00:00:00", "files": [], "checklist": [], "name": "실제(이름 다름)"})
        out = api.demo_clear()
        self.assertEqual(out["removed"]["incidents"], 0)                      # GPT 83차: 출처를 입증 못 하는 옛 자료는 하나도 지우지 않음
        self.assertEqual({h["id"] for h in api.history()}, {"DEMO-0123456789abcdef", "DEMO-REAL-2", "DEMO-fedcba9876543210"})

    def test_report_band_static(self):
        self.assertIn("function renderReport(r){ renderReportBody(r); try{ demoBand(r); repToc(); }catch(e){} }", UI)
        b = UI[UI.index("function demoBand(r){"):UI.index("function renderReportBody(r){")]
        self.assertIn("합성 견본 시연 결과", b)
        self.assertNotIn("innerHTML", b)
        self.assertIn(".demoband{", CSS)

    def test_manifest_matches_samples(self):
        import hashlib
        import json
        man = json.loads((ENGINE / "samples" / "SHA256SUMS.json").read_text(encoding="utf-8"))
        from logtriage.gui.app import Api
        self.assertEqual(sorted(man), sorted(Api.SAMPLE_PICK))
        for n, h in man.items():
            self.assertEqual(hashlib.sha256((ENGINE / "samples" / n).read_bytes()).hexdigest(), h, n)


class FriendlyError(unittest.TestCase):
    def test_messages(self):
        from logtriage.gui.app import friendly_error
        from logtriage.service import NoKnowledgeError
        self.assertIn("찾을 수 없습니다: a.log", friendly_error(FileNotFoundError(2, "x", r"C:\x\a.log")))
        self.assertIn("권한이 없습니다", friendly_error(PermissionError(13, "x", "b.log")))
        self.assertIn("600MB", friendly_error(MemoryError()))
        self.assertIn("0개", friendly_error(NoKnowledgeError("판정 지식(룰)이 0개")))
        self.assertEqual(friendly_error(ValueError("그대로")), "그대로")

    def test_analyze_uses_it(self):
        api = _api(self, _base(self), allow=[])
        api._allowed = lambda p: True
        r = api.analyze({"inputs": [{"path": str(ENGINE / "없는파일.log"), "product": "tomcat", "host": "h"}]})
        self.assertIn("찾을 수 없습니다", r.get("error", ""))
        self.assertNotIn("Errno", r["error"])


class StaticUi(unittest.TestCase):
    def test_every_select_has_a_name(self):
        bad = [m for m in re.findall(r"<select[^>]*>", UI) if "aria-label" not in m and "title=" not in m]
        self.assertEqual(bad, [], "라벨 없는 선택칸 — aria-label 을 붙이십시오")

    def test_every_input_has_a_name(self):
        """exe26 화면 품질 점검이 잡은 빈틈 — 선택칸만 보던 정적 시험을 입력칸 전체로(숨김·체크·라디오·파일 제외, label for 연결 인정)."""
        named = set(re.findall(r'<label[^>]*for="([^"]+)"', UI))
        bad = []
        for t in re.findall(r"<input[^>]*>", UI):
            if re.search(r'type="(hidden|checkbox|radio|file)"', t) or "aria-label" in t or "title=" in t or "placeholder" in t:
                continue
            i = re.search(r'id="([^"]+)"', t)
            if i and i.group(1) in named:
                continue
            bad.append(t[:100])
        self.assertEqual(bad, [], "이름 없는 입력칸")

    def test_about_dialog(self):
        self.assertIn('id="metaline" role="button" tabindex="0"', UI)
        self.assertIn("async function showAbout()", UI)
        body = UI[UI.index("async function showAbout()"):UI.index("/* 11차 ②")]
        self.assertNotIn("innerHTML", body)                                   # 값은 글자로만
        self.assertIn('ml.addEventListener("keydown"', UI)
        self.assertIn(".aboutdlg", CSS)

    def test_report_toc(self):
        self.assertIn("function renderReport(r){ renderReportBody(r); try{ demoBand(r); repToc(); }catch(e){} }", UI)
        self.assertEqual(UI.count("function renderReportBody(r){"), 1)
        self.assertIn('nav.className="reptoc no-print"', UI)
        self.assertIn(".reptoc{position:sticky", CSS)

    def test_attention_scroll_and_search(self):
        self.assertIn('<div class="scrollbox" tabindex="0"', UI)
        self.assertIn('id="attq"', UI)
        self.assertIn(".scrollbox{max-height:560px", CSS)

    def test_home_quick_try_and_demo_clear(self):
        self.assertIn('data-click="quickTry"', UI)
        self.assertIn("quickTry:()=>quickTry(), clearDemo:()=>clearDemo()", UI)
        self.assertIn('"demo_clear"', UI)
        q = UI[UI.index("async function quickTry()"):UI.index("async function clearDemo()")]
        self.assertIn('$("#runbtn").click()', q)
        c = UI[UI.index("async function clearDemo()"):UI.index("async function tryDemo()")]
        self.assertIn("confirm(", c)
        self.assertLess(UI.index("let SAMPLES=[]"), UI.index("init().catch"))   # 홈이 먼저 그려져도 선언 전 접근 없음

    def test_welcome_once_guards(self):
        w = UI[UI.index("function welcomeOnce(d){"):UI.index("/* 11차 ④")]
        for k in ('startsWith("내장 지식")', "history.length", "d.test_run", 'localStorage.getItem("lt-welcome-1")'):
            self.assertIn(k, w)
        self.assertNotIn("innerHTML", w)
        self.assertIn("welcomeOnce(d);", UI)

    def test_elapsed_shown(self):
        self.assertIn("분석 시간 <b>${esc(String(r.elapsed_sec))}초</b>", UI)


if __name__ == "__main__":
    unittest.main()
