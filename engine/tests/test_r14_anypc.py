"""14차(2026-10-22 마스터: "다른 개개인에게 배포 — 디폴트 설정이 불특정 다수의 PC·개인 설정에서 반드시 동작").

기본값이 깨지던 자리와 지켜야 할 것:
  A. exe 폴더에 쓸 수 없음(Program Files·읽기 전용 USB·권한 없는 공유 폴더) → 사용자 자리(%LOCALAPPDATA%\\LogTriage\\home) — 경고 아닌 알림
  B. 압축 파일 안에서 바로 실행(탐색기·반디집·알집·7-Zip·WinRAR 임시 폴더) → 사용자 자리(창을 닫으면 지워질 자리에 이력을 두지 않음)
  C. 쓸 수 있는 보통 폴더(바탕화면·D:\\, 시험용 임시 폴더)는 예전처럼 exe 옆 — 이미 쓰는 사람의 자료 자리가 바뀌지 않는다
  D. 사용자 자리에서 exe 판이 오르면 옛 내장 지식은 백업으로 옮기고 새 내장본을 펼친다(끊겨도 이어서) — exe 옆·출시 지식은 손대지 않음
  E. 창 엔진(WebView2)이 없으면 깨진 IE 화면 대신 기본 브라우저(1회용 입장 토큰 새로)
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from logtriage.gui import app as A  # noqa: E402


class BaseChoice(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.home = self.td / "LocalAppData"
        saved = list(A._BASE)
        self.addCleanup(lambda: A._BASE.__setitem__(slice(None), saved))
        self.addCleanup(mock.patch.stopall)
        mock.patch.dict("os.environ", {"LOCALAPPDATA": str(self.home)}).start()
        mock.patch.object(A.sys, "frozen", True, create=True).start()

    def _choose(self, exe_dir: Path, writable=None):
        exe_dir.mkdir(parents=True, exist_ok=True)
        A._BASE.clear()
        mock.patch.object(A.sys, "executable", str(exe_dir / "LogTriage.exe")).start()
        if writable is not None:
            real = A._writable
            mock.patch.object(A, "_writable", lambda p: real(p) if Path(p) != exe_dir.resolve() else writable).start()
        return A.base_dir(), A.base_why()

    def test_plain_folder_stays_next_to_exe(self):
        d = self.td / "바탕 화면" / "LogTriage"
        b, why = self._choose(d)
        self.assertEqual((b, why), (d.resolve(), ""))
        self.assertFalse((self.home / "LogTriage" / "home").exists())

    def test_temp_test_folder_is_not_archive(self):
        d = Path(tempfile.mkdtemp())                              # 점검 도구가 쓰는 임시 폴더(tmpXXXX) — 압축 임시로 오인하지 않는다
        self.addCleanup(shutil.rmtree, d, True)
        self.assertEqual(self._choose(d)[1], "")

    def test_readonly_goes_to_user_home(self):
        d = self.td / "Program Files" / "LogTriage"
        b, why = self._choose(d, writable=False)
        self.assertEqual(why, "readonly")
        self.assertEqual(b, self.home / "LogTriage" / "home")
        self.assertEqual((b / A.USER_HOME_MARK).read_text(encoding="utf-8"), str(d.resolve()))
        self.assertEqual(A.base_dir(), b)                          # 한 번 정하면 그대로

    def test_archive_runs_go_to_user_home(self):
        tmp = Path(tempfile.gettempdir())
        for name in ("Temp1_LogTriage-1.0.0.zip", "BNZ.6712ab34", "7zO4A1B2C3D", "Rar$EXa1234.5678", "_alz1234"):
            d = tmp / name / "LogTriage"
            self.addCleanup(shutil.rmtree, tmp / name, True)
            self.assertEqual(self._choose(d)[1], "archive", name)
        d = self.td / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache" / "Content.Outlook" / "AB12CD34"
        self.assertEqual(self._choose(d)[1], "archive")                      # 메일 첨부를 바로 실행

    def test_onedrive_new_goes_to_user_home(self):
        od = self.td / "OneDrive"
        with mock.patch.dict("os.environ", {"OneDrive": str(od)}):
            b, why = self._choose(od / "Desktop" / "LogTriage")
        self.assertEqual((b, why), (self.home / "LogTriage" / "home", "onedrive"))

    def test_user_home_unwritable_falls_back_with_warning(self):
        d = self.td / "ro"
        d.mkdir()
        A._BASE.clear()
        mock.patch.object(A.sys, "executable", str(d / "LogTriage.exe")).start()
        mock.patch.object(A, "_writable", lambda p: False).start()
        self.assertEqual((A.base_dir(), A.base_why()), (d.resolve(), ""))   # 둘 다 못 쓰면 exe 옆 — not_writable 경고가 남는다

    def test_notice_not_warning(self):
        d = self.td / "Program Files" / "LogTriage"
        b, _ = self._choose(d, writable=False)
        api = A.Api()
        self.assertEqual(api._base, b)
        n = api._base_notice()
        self.assertTrue(n and "쓸 수 없어" in n[0] and str(b) in n[0], n)
        api2 = A.Api.__new__(A.Api)
        api2._base = self.td / "다른 자리"
        self.assertEqual(api2._base_notice(), [])                   # 사용자 자리가 아닌 Api(서버형·시험)는 알림 없음


class RefreshUserHome(unittest.TestCase):
    def setUp(self):
        from logtriage import knowledge_seed as KS
        self.KS = KS
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.src = self.td / "embedded"
        for d in ("rules", "errorcodes", "manuals", "report-template"):
            shutil.copytree(ENGINE / d, self.src / d)
        self.base = self.td / "home"
        self.base.mkdir()

    def _seed(self):
        r = self.KS.seed(self.base, self.src)
        self.assertFalse(r.get("error"), r)

    def _bump(self):
        f = next((self.src / "rules").rglob("*.yaml"))
        f.write_text(f.read_text(encoding="utf-8") + "\n# 판 올림\n", encoding="utf-8")

    def test_upgrade_refreshes_and_backs_up(self):
        from logtriage.knowledge_gen import check_gen, dir_hash
        self._seed()
        (self.base / self.KS.USER_HOME_MARK).write_text("x", encoding="utf-8")
        (self.base / "rules-local" / "site.yaml").write_text("rules: []\n", encoding="utf-8")
        self.assertEqual(self.KS.refresh_user_home(self.base, self.src), "")   # 같은 판 — 할 일 없음
        self._bump()
        moved = Path(self.KS.refresh_user_home(self.base, self.src))
        self.assertTrue((moved / "rules").is_dir() and (moved / "knowledge-gen.json").is_file())
        self.assertFalse((moved / ".moving").exists())
        self._seed()
        self.assertEqual(dir_hash(self.base / "rules"), dir_hash(self.src / "rules"))
        self.assertEqual(check_gen(self.base), "")
        self.assertTrue((self.base / "rules-local" / "site.yaml").is_file())    # 사이트 룰은 그대로

    def test_not_without_mark_or_not_embedded(self):
        self._seed()
        self._bump()
        self.assertEqual(self.KS.refresh_user_home(self.base, self.src), "")   # exe 옆 자리(표시 없음)는 손대지 않음
        (self.base / self.KS.USER_HOME_MARK).write_text("x", encoding="utf-8")
        g = json.loads((self.base / "knowledge-gen.json").read_text(encoding="utf-8"))
        g["source"] = "지식 출시 2026-10-20"
        (self.base / "knowledge-gen.json").write_text(json.dumps(g, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(self.KS.refresh_user_home(self.base, self.src), "")   # 출시·룰팩 지식은 손대지 않음

    def test_interrupted_move_resumes(self):
        self._seed()
        (self.base / self.KS.USER_HOME_MARK).write_text("x", encoding="utf-8")
        self._bump()
        dst = self.base / "backups" / "knowledge-before-20261022-120000"
        dst.mkdir(parents=True)
        (dst / ".moving").write_text("", encoding="utf-8")
        (self.base / "rules").replace(dst / "rules")                          # rules 만 옮기고 끊김
        self.assertEqual(Path(self.KS.refresh_user_home(self.base, self.src)), dst)
        self.assertTrue(all((dst / n).exists() for n in ("rules", "errorcodes", "manuals", "knowledge-gen.json")))
        self._seed()

    def test_prepare_base_runs_refresh(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        i = src.index("def prepare_base")
        self.assertLess(src.index("refresh_user_home(Path(base))", i), src.index("r = seed(Path(base))", i))


class BrowserMode(unittest.TestCase):
    def test_force_and_detect(self):
        with mock.patch.dict("os.environ", {"LOGTRIAGE_FORCE_BROWSER": "1"}):
            self.assertIn("브라우저 모드", A._no_webview2())
        with mock.patch.dict("os.environ", {"LOGTRIAGE_FORCE_BROWSER": ""}):
            with mock.patch("webview.platforms.winforms._is_chromium", lambda: False):
                self.assertIn("WebView2", A._no_webview2())
            with mock.patch("webview.platforms.winforms._is_chromium", lambda: True):
                self.assertEqual(A._no_webview2(), "")

    def test_browser_mode_issues_fresh_token(self):
        class H:
            boot_token = None
        seen = {}
        with mock.patch("webbrowser.open", lambda u: seen.setdefault("url", u) or True), \
                mock.patch.object(A, "_msgbox", lambda *a, **k: seen.setdefault("box", a[0])):
            A._browser_mode(H, 5555, "까닭")      # 실제처럼 처리기 **클래스**를 넘긴다
        self.assertTrue(H.boot_token and len(H.boot_token) == 32)
        self.assertEqual(seen["url"], f"http://127.0.0.1:5555/auth/bootstrap?t={H.boot_token}")
        self.assertIn("[확인]을 누르면 LogTriage 를 끝냅니다", seen["box"])

    def test_wired_before_window(self):
        src = (ENGINE / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")
        m = src.index("def main()")
        self.assertLess(src.index("why = _no_webview2()", m), src.index("api._window = webview.create_window(", src.index("why = _no_webview2()", m)))
        self.assertIn('_browser_mode(handler, port, f"프로그램 창을 열지 못했습니다', src)


class Gpt98(unittest.TestCase):
    """GPT 98차 반례를 실제로 재현해 막은 것."""
    def _base(self) -> Path:
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
            shutil.copytree(ENGINE / d, td / d)
        return td

    def _api(self, base: Path):
        from logtriage.server import ServerApi, make_server

        class Local(ServerApi):
            def _allowed(self, p):
                return True
        httpd, h = make_server("127.0.0.1", 0, base, None, [], None, api_cls=Local, desktop=True, native=False)
        self.addCleanup(httpd.server_close)
        return h.api

    def _an(self, api):
        r = api.analyze({"inputs": [{"path": str(ENGINE / "samples" / "catalina.out"), "product": "tomcat", "host": "h"}]})
        self.assertFalse(r.get("error"), r.get("error"))

    def test_p0_01_other_db_same_place_more_rows(self):
        """같은 자리(상대 경로 같음)에 **다른** DB 를 놓았고 건수는 더 많음 — 경로·건수로는 못 잡고 닻(지난번 ID)으로 잡는다."""
        a, b = self._base(), self._base()
        api = self._api(a)
        self._an(api)
        api._mark_history()
        self.assertTrue(json.loads((a / "data" / "history-mark.json").read_text(encoding="utf-8")).get("anc"))
        apib = self._api(b)
        for _ in range(3):
            self._an(apib)
        apib.store.close() if hasattr(apib.store, "close") else None
        api.store.close() if hasattr(api.store, "close") else None
        shutil.copy2(b / "data" / "logtriage.db", a / "data" / "logtriage.db")
        for x in ("-wal", "-shm"):
            (a / "data" / ("logtriage.db" + x)).unlink(missing_ok=True)
            if (b / "data" / ("logtriage.db" + x)).exists():
                shutil.copy2(b / "data" / ("logtriage.db" + x), a / "data" / ("logtriage.db" + x))
        d = self._api(a)._history_drop()
        self.assertTrue(d["replaced"], d)

    def test_p0_01_growth_is_not_replacement(self):
        a = self._base()
        api = self._api(a)
        self._an(api)
        api._mark_history()
        api2 = self._api(a)
        self._an(api2)
        self._an(api2)
        self.assertFalse(self._api(a)._history_drop()["replaced"])

    def test_p0_02_auto_import_only_once(self):
        from logtriage.gui.app import AUTO_LEGACY_ONCE, _auto_legacy
        src = self._base()
        r = self._api(src).analyze({"inputs": [{"path": str(ENGINE / "samples" / "catalina.out"), "product": "tomcat", "host": "h"}]})
        rows = [dict(r, id=f"LEG-{k}") for k in range(2)]
        b = self._base()
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        self.assertTrue(_auto_legacy(self._api(b))["done"])
        self.assertTrue((b / AUTO_LEGACY_ONCE).is_file())
        shutil.rmtree(b / "data")                                                # 사용자가 이력을 일부러 비움(DB·표시 모두)
        self.assertFalse(_auto_legacy(self._api(b))["done"])                    # 되살리지 않는다 — 원하면 관리자 [가져오기]

    def test_onedrive_new_only(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        od = td / "OneDrive - 회사"
        exe = od / "바탕 화면" / "LogTriage"
        exe.mkdir(parents=True)
        with mock.patch.dict("os.environ", {"OneDriveCommercial": str(od), "OneDrive": "", "OneDriveConsumer": ""}):
            self.assertTrue(A._onedrive_new(exe.resolve()))
            (exe / "data").mkdir()
            (exe / "data" / "logtriage.db").write_bytes(b"")
            self.assertFalse(A._onedrive_new(exe.resolve()))                    # 이미 거기서 쓰던 이력은 그대로
            self.assertFalse(A._onedrive_new((td / "elsewhere").resolve()))


if __name__ == "__main__":
    unittest.main()
