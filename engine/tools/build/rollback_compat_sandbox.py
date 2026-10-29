# -*- coding: utf-8 -*-
"""되돌리기 호환 시험을 Windows Sandbox(일회용 가상 PC)에서 돌리는 구성 파일 만들기(3차 아이디어 9 — 준비만).

지금 개발 PC 는 Windows 11 Home 이라 Windows Sandbox 가 없다(Pro/Enterprise 전용 기능, 켜려면 관리자·보안 담당 승인).
이 스크립트는 .wsb 파일만 만든다 — 아무것도 켜거나 실행하지 않는다. Pro PC 에서 기능을 켠 뒤 만든 .wsb 를 두 번 누르면:
  · 엔진 폴더·파이썬 설치 폴더는 **읽기 전용**으로, 결과 폴더 하나만 쓰기 가능으로 연결
  · 네트워크 끔(<Networking>Disable</Networking>), 클립보드·프린터·오디오·비디오 연결 끔
  · 샌드박스 안에서 rollback_compat.py 를 돌려 결과 JSON 을 결과 폴더에 남기고 끝(샌드박스를 닫으면 안의 모든 것이 사라짐)
사용: python tools/build/rollback_compat_sandbox.py [--out 결과폴더]
"""
from __future__ import annotations

import sys
from pathlib import Path
from xml.sax.saxutils import escape

ENGINE = Path(__file__).resolve().parents[2]


def make_wsb(out_dir: Path, python_home: Path | None = None) -> Path:
    py = Path(python_home or Path(sys.executable).parent)
    out_dir.mkdir(parents=True, exist_ok=True)
    sb_engine, sb_py, sb_out = r"C:\lt\engine", r"C:\lt\python", r"C:\lt\out"
    cmd = (f'cmd /c "{sb_py}\\python.exe -I {sb_engine}\\tools\\build\\rollback_compat.py --no-save > {sb_out}\\rollback_compat_sandbox.txt 2>&1"')

    def folder(host: Path, sb: str, ro: bool) -> str:
        return (f"    <MappedFolder><HostFolder>{escape(str(host))}</HostFolder><SandboxFolder>{escape(sb)}</SandboxFolder>"
                f"<ReadOnly>{'true' if ro else 'false'}</ReadOnly></MappedFolder>")
    xml = "\n".join([
        "<Configuration>",
        "  <VGpu>Disable</VGpu>", "  <Networking>Disable</Networking>", "  <AudioInput>Disable</AudioInput>",
        "  <VideoInput>Disable</VideoInput>", "  <PrinterRedirection>Disable</PrinterRedirection>",
        "  <ClipboardRedirection>Disable</ClipboardRedirection>", "  <ProtectedClient>Enable</ProtectedClient>",
        "  <MappedFolders>",
        folder(ENGINE, sb_engine, True), folder(py, sb_py, True), folder(out_dir, sb_out, False),
        "  </MappedFolders>",
        f"  <LogonCommand><Command>{escape(cmd)}</Command></LogonCommand>",
        "</Configuration>", ""])
    p = out_dir / "rollback_compat.wsb"
    p.write_text(xml, encoding="utf-8")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = Path(argv[argv.index("--out") + 1]) if "--out" in argv else ENGINE / "deploy" / "local" / "build" / "sandbox"
    print(make_wsb(out))
    print("Windows Sandbox(Pro/Enterprise) 를 켠 PC 에서 이 파일을 두 번 누르면 일회용 가상 PC 에서 호환 시험이 돕니다 — 이 도구는 아무것도 켜지 않습니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
