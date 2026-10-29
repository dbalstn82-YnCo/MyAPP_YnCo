"""시험용 개인 임시 폴더 — 삭제 경계(GPT 38~40차)는 지울 폴더와 뿌리까지의 위 경로 권한을 본다.
사용자 Temp 에 다른 계정(샌드박스 등)의 지우기 권한이 있는 PC 에서도 '실제로 지워지는' 경로를 시험하려고
엔진 폴더 아래(사용자 개인 권한)에 만든다. 권한 거절 쪽은 따로 시험한다(test_round3_ideas.SafeDeleteBoundary)."""
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / ".test-tmp"


def mkdtemp() -> str:
    ROOT.mkdir(exist_ok=True)
    return tempfile.mkdtemp(dir=ROOT)
