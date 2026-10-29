# -*- coding: utf-8 -*-
"""실 보고서(HWP/HWPX/DOCX)에서 서식 통계만 학습 → report-template/style_profile.json  (본체: logtriage/report_style.py)
사용: python tools/report_style.py <보고서.zip 또는 폴더> [report-template 폴더] [출력 json]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logtriage.report_style import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
