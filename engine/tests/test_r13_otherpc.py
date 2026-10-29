"""13차(2026-10-22 마스터: "PC 단독 exe 를 다른 PC 에서 실행하면 '환경 점검 — 설치 상태를 확인하세요'가 뜬다 — 왜·어떻게·왜 저절로 안 되나").

재현(검증도구/sim_other_pc.py): ① 설치 폴더를 통째 다른 경로로 옮기면 'DB 위치가 지난번과 다릅니다'(절대 경로만 비교) ② 자료(data) 없이 옮기면
'예전 분석 26건이 이관 파일에만' — 가져올 때까지 매번. 둘 다 사람이 할 일이 없거나(①) 첫 기동에 해도 되는 일(②)이었다.
조치와 지켜야 할 것:
  A. 설치 폴더 기준 상대 위치가 같으면 같은 DB(폴더째 이동은 경고 안 함) — 정말 다른 DB(폴더 밖·상대 위치 다름)는 여전히 경고
  B. 새 PC 첫 기동(이력 0 · 그 자리에 이력이 있던 표시 없음 · 이관 파일에 빠진 건)이면 저절로 가져오고 알림 — 이력이 줄어든 자리는 저절로 안 함
  C. 경고마다 코드·사라지는 조건·단추 — 화면 제목이 '설치 상태'로 뭉뚱그리지 않음, 실행 기록에 경고 코드
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
SAMPLE = ENGINE / "samples" / "catalina.out"


class _Base(unittest.TestCase):
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

    def _legacy_rows(self, n=3) -> list:
        """합성 견본으로 만든 분석 결과를 '예전 분석' 모양으로 — 실제 이관 파일(사용자 자료)을 쓰지 않는다."""
        b = self._base()
        r = self._api(b).analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertFalse(r.get("error"), r.get("error"))
        return [dict(r, id=f"LEG-{k}", analyzed_at=f"2026-09-0{k + 1} 10:00:00") for k in range(n)]


class DbLocation(_Base):
    def test_folder_move_is_not_db_changed(self):
        b = self._base()
        api = self._api(b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api._mark_history()
        m = json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))
        self.assertEqual(m.get("db_rel"), "data/logtriage.db")
        # 옛 PC 경로가 남은 표시(설치 폴더째 옮긴 것과 같음) — 상대 위치가 같으면 같은 DB
        m["db"] = r"D:\옛PC\LogTriage\data\logtriage.db"
        (b / "data" / "history-mark.json").write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")
        api2 = self._api(b)
        self.assertFalse(api2._history_drop()["db_changed"])
        self.assertNotIn("db_changed", [i["code"] for i in api2.diag()["warn_items"]])

    def test_old_mark_without_rel_and_folder_move(self):
        b = self._base()
        api = self._api(b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api._mark_history()
        m = json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))
        m.pop("db_rel")
        m["db"] = r"C:\Users\other\Desktop\LogTriage\data\logtriage.db"     # 12차 이전 표시(절대 경로만) — 꼬리가 같으면 같은 DB
        (b / "data" / "history-mark.json").write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")
        self.assertFalse(self._api(b)._history_drop()["db_changed"])

    def test_really_different_db_still_warns(self):
        b = self._base()
        api = self._api(b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        api._mark_history()
        m = json.loads((b / "data" / "history-mark.json").read_text(encoding="utf-8"))
        m["db"], m["db_rel"] = r"C:\Users\x\AppData\Local\LogTriage\logtriage.db", ""   # 지난번엔 폴더 밖(쓰기 불가로 빠진 곳)
        (b / "data" / "history-mark.json").write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")
        api2 = self._api(b)
        self.assertTrue(api2._history_drop()["db_changed"])
        it = next(i for i in api2.diag()["warn_items"] if i["code"] == "db_changed")
        self.assertIn("한 번만", it["clears"])
        self.assertFalse(self._api(b)._history_drop()["db_changed"])                  # 다음 기동부터는 지금 위치가 기준


class AutoLegacy(_Base):
    def test_new_pc_first_launch_imports_with_backup(self):
        from logtriage.gui.app import _auto_legacy
        rows = self._legacy_rows(3)
        b = self._base()
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        api = self._api(b)
        r = _auto_legacy(api)
        self.assertTrue(r["done"], r)
        self.assertEqual(r["restored"], 3)
        self.assertTrue((b / "backups" / r["backup"]).is_file())
        d = api.diag()
        self.assertNotIn("legacy_missing", [i["code"] for i in d["warn_items"]])
        self.assertTrue(any("저절로 가져왔습니다" in n for n in d["notices"]))
        self.assertFalse(_auto_legacy(self._api(b))["done"])                          # 두 번째 기동 — 이미 있음

    def test_not_when_history_exists(self):
        from logtriage.gui.app import _auto_legacy
        rows = self._legacy_rows(2)
        b = self._base()
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        api = self._api(b)
        api.analyze({"inputs": [{"path": str(SAMPLE), "product": "tomcat", "host": "h"}]})
        self.assertFalse(_auto_legacy(api)["done"])                                   # 이력이 있는 PC — 섞일 수 있어 사람이 판단
        it = next(i for i in api.diag()["warn_items"] if i["code"] == "legacy_missing")
        self.assertEqual(it["action"], "restoreLegacy")

    def test_not_when_history_dropped(self):
        """그 자리에 이력이 있었다는 표시(high>0)가 있는데 0건 — 유실·바꿔치기일 수 있어 저절로 채우지 않고 '줄어듦' 경고를 남긴다."""
        from logtriage.gui.app import _auto_legacy
        rows = self._legacy_rows(2)
        b = self._base()
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        (b / "data").mkdir(exist_ok=True)
        (b / "data" / "history-mark.json").write_text(json.dumps({"db": str(b / "data" / "logtriage.db"), "db_rel": "data/logtriage.db",
                                                                  "high": 5, "fp": "x"}), encoding="utf-8")
        api = self._api(b)
        self.assertFalse(_auto_legacy(api)["done"])
        codes = {i["code"]: i for i in api.diag()["warn_items"]}
        self.assertIn("history_dropped", codes)
        self.assertEqual(codes["history_dropped"]["action"], "ackHistory")

    def test_not_when_unwritable(self):
        from logtriage.gui import app as A
        rows = self._legacy_rows(1)
        b = self._base()
        (b / "incidents.json.migrated").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
        api = self._api(b)
        with mock.patch.object(A, "_writable", lambda p: False):
            self.assertFalse(A._auto_legacy(api)["done"])


class Surfaces(unittest.TestCase):
    def test_banner_and_log(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        self.assertNotIn("설치 상태를 확인하세요", ui)                                 # 설치 문제가 아닌 것까지 '설치'로 뭉뚱그리지 않는다
        self.assertIn("d.warn_items", ui)
        self.assertIn("사라지는 조건: ", ui)
        self.assertIn('data-click="restoreLegacy">가져오기(관리자)', ui)
        app = (ENGINE / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")
        self.assertIn("warnings=%d codes=%s", app)
        self.assertLess(app.index("_auto_legacy(api)   # 13차"), app.index("threading.Thread(target=_diag_log"))

    def test_every_warning_has_code_and_clears(self):
        b = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, b, True)
        (b / "rules").mkdir()                                                          # 빈 rules — 여러 경고가 한꺼번에
        from logtriage.gui.app import Api
        api = Api.__new__(Api)
        api._base = b
        api._history_file = b / "incidents.json"
        d = Api.diag(api)
        self.assertTrue(d.get("warn_items"), d)
        self.assertEqual([i["text"] for i in d["warn_items"]], d["warnings"])
        for i in d["warn_items"]:
            self.assertTrue(i["code"] and i["clears"], i)


if __name__ == "__main__":
    unittest.main()
