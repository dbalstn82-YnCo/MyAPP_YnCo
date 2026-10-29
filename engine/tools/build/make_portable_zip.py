"""PC 휴대용 배포 묶음(10-28) — 반출/LogTriage-PC-<판>.zip 을 휴대용으로, exe 묶음은 LogTriage-PC-<판>-exe.zip 으로 나눈다(GPT 187차 D: 둘을 한 ZIP 에 섞지 않음).

묶는 조건(시험한 그 바이트만):
  · 점검 12종(검증도구/exe_all.py <점검용 복사본>) 기록 portable_checks.json 이 통과이고, 그 실행 부분 지문 = 이 묶음의 지문
  · 실행 층 점검(검증도구/portable_check.py <이 묶음>) 기록 portable_launch_check.json 이 통과이고 지문이 같음
  · 묶음 폴더에 점검이 만든 자료(data · reports · instance.json …)가 없음 — 갓 만든 그대로
묶은 뒤 다시 열어 파일 목록 · 바이트가 폴더와 같은지 확인하고 SHA256-PC-<판>.txt 를 두 묶음 모두로 다시 쓴다.
사용: python tools/build/make_portable_zip.py <갓 만든 묶음 폴더>   예) ..\\검증도구\\exe49\\portable\\LogTriage-PC-1.0.0"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
import os  # noqa: E402
# 10-29 최종본: 반출 폴더를 덮지 않고 다른 경로에(LT_RELEASE_OUT — make_pc_zip.py 와 같은 값)
OUT = Path(os.environ["LT_RELEASE_OUT"]).resolve() if os.environ.get("LT_RELEASE_OUT") else ENGINE.parent / "반출"
BUILD = ENGINE / "deploy" / "local" / "build"
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE.parent / "검증도구"))
from lt_launch import tree_sha  # noqa: E402

ALLOWED_TOP = {"agent", "errorcodes", "logtriage", "manuals", "report-template", "rules", "rules-local", "runtime", "samples", "tools",
               "__pycache__", "knowledge-gen.json", "knowledge-manifest.json", "portable-files.json", "_preflight.py", "run_gui.py",
               "run_logtriage.py", "LogTriage.cmd", "logtriage-cli.cmd", "LogTriage-server.cmd", "server.conf.example", "사용법.txt",
               "LogTriage-1.0.0_소개.html"}


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def main(argv: list) -> int:
    from logtriage import __version__ as ver
    if len(argv) != 1:
        print(__doc__)
        return 2
    src = Path(argv[0]).resolve()
    ts = tree_sha(src)
    for rec_name in ("portable_checks.json", "portable_launch_check.json"):
        try:
            rec = json.loads((BUILD / rec_name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print(f"[거부] {rec_name} 이 없습니다 — 점검부터")
            return 1
        if not rec.get("ok") or str(rec.get("tree_sha", "")).upper() != ts:
            print(f"[거부] {rec_name}: 통과 {rec.get('ok')} · 지문 {str(rec.get('tree_sha'))[:16]} ≠ 이 묶음 {ts[:16]}")
            return 1
    extra = sorted(p.name for p in src.iterdir() if p.name not in ALLOWED_TOP)
    if extra:
        print(f"[거부] 묶음 폴더에 갓 만든 묶음에 없는 것이 있습니다(점검 자료?): {extra}")
        return 1
    top = f"LogTriage-PC-{ver}"
    files = sorted(p for p in src.rglob("*") if p.is_file())
    zp, exe_zp = OUT / f"{top}.zip", OUT / f"{top}-exe.zip"
    tmp = zp.with_suffix(".zip.new")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for f in files:
            z.write(f, f"{top}/{f.relative_to(src).as_posix()}")
    with zipfile.ZipFile(tmp) as z:
        names = z.namelist()
        same = len(names) == len(files) and all(hashlib.sha256(z.read(f"{top}/{f.relative_to(src).as_posix()}")).hexdigest() == sha(f)
                                                 for f in files)
        exes = [n for n in names if n.lower().endswith(".exe") and not n.startswith(f"{top}/runtime/")]
    if not same or exes:
        tmp.unlink()
        print(f"[거부] 묶음 확인 실패 — 바이트 동일 {same} · runtime 밖 exe {exes}")
        return 1
    if zp.exists():   # 지금 이름에 있는 것이 exe 묶음이면 -exe 로 옮긴다(덮지 않음)
        with zipfile.ZipFile(zp) as z:
            was_exe = f"{top}/LogTriage.exe" in z.namelist()
        if was_exe:
            if exe_zp.exists():
                print(f"[거부] {exe_zp.name} 가 이미 있습니다 — 확인 뒤 다시")
                tmp.unlink()
                return 1
            zp.replace(exe_zp)
    tmp.replace(zp)
    lines = [f"LogTriage PC 단독용 {ver} 무결성 확인값", "",
             f"{sha(zp)}  {zp.name}      ← 휴대용(기본) — 서명된 파이썬 런타임 + 원본, 서명 없는 exe 없음. 압축을 풀고 LogTriage.cmd 실행"]
    if exe_zp.exists():
        lines.append(f"{sha(exe_zp)}  {exe_zp.name}  ← exe 판 — 백신 예외 등록된 PC · 서명 인증서 적용 전에는 백신이 막을 수 있음")
    lines += ["", f"휴대용 실행 부분 지문(런타임 · 원본): {ts}",
              "확인(PowerShell): Get-FileHash .\\" + zp.name + " -Algorithm SHA256",
              "두 묶음 모두 분석 이력 · 계정 · 설정 · 토큰을 담지 않습니다(받은 PC 에서 새로 만들어집니다)."]
    (OUT / f"SHA256-PC-{ver}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[완료] {zp}  {zp.stat().st_size // 1024:,} KB · 파일 {len(names)}개(폴더와 바이트 동일)" + (f" · exe 묶음 → {exe_zp.name}" if exe_zp.exists() else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
