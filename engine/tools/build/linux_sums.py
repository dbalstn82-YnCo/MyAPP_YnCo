"""반출/SHA256-<판>.txt 를 지금 묶음으로 다시 쓴다(12차) — 설치 안내(README-INSTALL)가 `sha256sum -c` 로 대조하라는 파일인데
10-06 에 손으로 만든 값이 그대로 남아 새 묶음과 맞지 않았다. build_linux_pkgs.py 가 끝에 부르고, 혼자 돌려도 된다.
판 지문·코드 지문은 묶음 안 engine/logtriage/_build_id.json 에서 읽는다(손으로 적지 않는다)."""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
OUT = ENGINE.parent / "반출"
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _buildstamp as _bs  # noqa: E402


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main() -> int:
    ver = _bs.build_id(ENGINE)
    names = [f"logtriage-patch-{ver}.zip", f"logtriage-patch-py311-{ver}.zip", f"logtriage-server-{ver}.zip"]
    with zipfile.ZipFile(OUT / f"logtriage-server-{ver}.zip") as z:
        st = json.loads(z.read("logtriage-server/engine/logtriage/_build_id.json").decode("utf-8"))
    lines = [f"LogTriage {ver} 무결성 확인값", "",
             f"제품 판(Version): {ver}     ← 사람이 보는 이름. 패치해도 바뀌지 않습니다.",
             f"판 지문(Build)  : {st['id']}     ← 배포물(engine/logtriage 전부 + run.sh + stop.sh).",
             f"코드 지문(Code) : {st['code']}     ← 엔진 꾸러미만. 설치 뒤에 파일이 바뀌면 달라집니다. PC(LogTriage.exe) 상태 창의 '코드 지문'과 같으면 같은 판.",
             "", "  curl -s http://127.0.0.1:8088/healthz",
             "    → build_id 가 판 지문과 같으면 **이 판이 돌고 있는 것**입니다.",
             "    → code_id 가 코드 지문과 다르면(code_modified) 설치 뒤에 파일이 바뀐 것입니다.", "",
             "직접 업그레이드 지원 최소 판: 2026.09.30", "",
             "[첫 기동] 계정이 없으면 [관리자 계정 만들기] 가 뜹니다 — **1회용 코드**가 필요합니다(같은 PC 에서 열어도 필요).",
             "          bash run.sh 로 띄우면 '기동 완료' 바로 아래 상자에 1회용 코드와 '바로 열기' 주소가 나옵니다 —",
             "          그 주소를 열어 첫 관리자 아이디(회사 이메일)와 비밀번호를 **직접** 정합니다(정해진 계정 없음).",
             "          코드는 기동할 때마다 새로 나오고, 관리자를 만들면 사라집니다. 남에게 보이지 마십시오.",
             "          (정식 설치(systemd)는 journalctl -u logtriage-server 에, 파일로는 <자료 폴더>/conf/setup-code.txt 에도 있습니다)", ""]
    lines += [f"{sha(OUT / n)}  {n}" for n in names]
    lines += ["", f"확인:  sha256sum -c SHA256-{ver}.txt", "룰팩 키(rulepack.key)는 이 묶음과 **따로** 전달합니다.", ""]
    (OUT / f"SHA256-{ver}.txt").write_bytes("\n".join(lines).encode("utf-8"))
    print(f"  무결성 확인값: SHA256-{ver}.txt — 판 지문 {st['id']} · 코드 {st['code']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
