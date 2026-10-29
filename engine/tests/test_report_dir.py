# -*- coding: utf-8 -*-
"""보고서 저장 경로 (2026-09-23)

사용자 요청: 로그 분석 결과와 리포트의 저장·내려받기 경로를 지정할 수 있어야 한다.

있던 것 — 이 PC 설치형은 `report_dir` 설정과 폴더 선택 대화상자가 있었다.
없던 것 — 서버형에서는 [예약·자동화 → 저장 경로]가 정기 산출물에만 적용되고,
          장애 보고서·분석요약은 <설치경로>/reports 고정이라 화면에서 바꿀 수 없었다.

고친 뒤 지켜야 할 것
  · 저장 경로 한 곳이 모든 산출물을 덮는다(정기 보고서와 장애 보고서가 갈라지지 않는다)
  · 경로가 비었거나 쓸 수 없으면 예전 위치로 돌아간다(기능이 죽지 않는다)
  · 예전 위치에 이미 만들어 둔 보고서도 계속 내려받을 수 있다
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage.server import ServerApi  # noqa: E402


class ReportDirTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.api = ServerApi(self.base, allow_dirs=[])

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_default_is_the_install_folder(self):
        self.assertEqual(self.api.reports_dir().resolve(), (self.base / "reports").resolve())

    def test_follows_the_saved_output_path(self):
        want = self.base / "밖에" / "보고서"
        self.api.automation.set_outputs({"dir": str(want)})
        self.assertEqual(self.api.reports_dir().resolve(), want.resolve())
        self.assertTrue(want.is_dir(), "지정한 폴더를 만들어 두어야 합니다")

    def test_old_reports_are_still_reachable(self):
        want = self.base / "새폴더"
        self.api.automation.set_outputs({"dir": str(want)})
        dirs = [str(Path(d).resolve()) for d in self.api.report_dirs()]
        self.assertIn(str(want.resolve()), dirs)
        self.assertIn(str((self.base / "reports").resolve()), dirs,
                      "예전 위치의 보고서를 못 찾게 되면 안 됩니다")

    def test_blank_goes_back_to_the_install_folder(self):
        self.api.automation.set_outputs({"dir": str(self.base / "잠깐")})
        self.api.automation.set_outputs({"dir": ""})
        self.assertEqual(self.api.reports_dir().resolve(), (self.base / "reports").resolve())

    def test_reports_dir_never_raises(self):
        """경로가 망가져도 보고서 생성 자체가 죽으면 안 된다."""
        class Broken:
            def output_dir(self):
                raise OSError("장치가 준비되지 않았습니다")
        self.api.automation = Broken()
        self.assertEqual(self.api.reports_dir().resolve(), (self.base / "reports").resolve())

    def test_relative_path_is_refused(self):
        with self.assertRaises(ValueError):
            self.api.automation.set_outputs({"dir": "reports/여기"})


if __name__ == "__main__":
    unittest.main()
