"""CLI 래퍼 — 실제 구현은 logtriage/report.py (GUI와 공용).

사용: python tools/report_gen.py <template.yaml> <incidents.json> <출력폴더> [분석ID]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from logtriage.report import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
