"""PC 단독용 배포 묶음(14차, 2026-10-22 마스터 '다른 개개인에게 배포') — 반출/LogTriage-PC-<판>.zip

설치 폴더(dist)·빌드 폴더(run)는 이 PC 의 자료(분석 이력 DB·이관 파일·계정·설정·1회용 코드·실행 기록)를 함께 갖고 있다.
그대로 넘기면 남에게 이 PC 의 자료가 간다 — 묶음은 **허용 목록**만 담는다(exe 둘 + 안내 글). 판정 지식은 exe 안에 들어 있어
받은 사람이 어느 폴더에 풀든(쓸 수 없는 곳·압축 안에서 바로 실행이면 사용자 자리) 첫 기동 때 펼친다.

사용: python tools/build/make_pc_zip.py <빌드 run 폴더>     (예: ..\\검증도구\\exe30\\run)
  · exe 해시가 빌드 장부(ledger.jsonl) 마지막 줄과 같아야 묶는다(시험한 그 바이트만 배포)
  · 묶은 뒤 다시 열어 허용 목록 밖 파일이 없는지·exe 해시가 같은지 확인하고, 묶음 해시를 SHA256-PC-<판>.txt 로 남긴다
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
import os  # noqa: E402
# 10-29 최종본: 반출 폴더를 덮지 않고 다른 경로에 만들 수 있게(LT_RELEASE_OUT)
OUT = Path(os.environ["LT_RELEASE_OUT"]).resolve() if os.environ.get("LT_RELEASE_OUT") else ENGINE.parent / "반출"
DOCS = ENGINE / "deploy" / "local"
LEDGER = DOCS / "build" / "ledger.jsonl"
EXE_CHECKS = DOCS / "build" / "exe_checks.json"
EXES = ("LogTriage.exe", "logtriage-cli.exe")
TEXTS = ("사용법.txt", "LogTriage-1.0.0_소개.html")
# 21차(10-26): 원격 서버 감시(서버 모드)에 쓰는 파일 — 사용법의 '서버 모드' 절차가 exe 옆에 있다고 안내하는데 묶음에 없었다
SERVE = ("server.conf.example", "LogTriage-server.cmd")
# 10-29 마스터 '실행 시 로그를 찍어야': 보안 프로그램이 exe 실행을 막으면 exe 는 한 줄도 돌지 않아 스스로 기록할 수 없다 → 바깥(cmd)에서 기록
LAUNCH = "LogTriage-실행.cmd"
EXE_HEAD = """LogTriage {ver} — PC exe 판 (먼저 읽기)
=====================================

■ 열리지 않을 때: LogTriage.exe 대신 LogTriage-실행.cmd 를 더블클릭하십시오.
  실행을 시도한 결과(실행됨 · 거부됨 · 시작 직후 종료)와 거부 까닭 · 이 PC 의 보안 제품 이름 · exe 확인값을
  같은 폴더의 LogTriage-실행기록.txt 에 남기고, 화면에 할 일을 안내합니다.
  - '[관리자 권한으로 실행]으로도 열리지 않음' + '액세스가 거부되었습니다' 는 대개 백신의 '평판 기반 실행 차단'입니다.
    서명 없는 새 프로그램(사용자 수 · 경과 일수 미달)을 막는 기능이라 관리자 권한과 무관합니다.
    → 휴대용 묶음(LogTriage-PC-{ver}.zip, 서명된 파이썬 런타임으로 실행)을 쓰거나, 보안 담당에게 이 exe 의 예외 등록을 요청하십시오.
    보안 기능을 끄는 것은 권하지 않습니다.

"""
AGENT_DIR = ENGINE / "tools" / "agent"   # 자원 사용률 에이전트 원본 — 비밀값 없음(주소·토큰은 설치 때 넣음)


LAUNCH_LINES = [
    "@echo off",
    "chcp 65001 >nul",
    "rem LogTriage exe 판 실행 + 실행 기록(10-29) — 백신 · 사내 정책이 LogTriage.exe 실행을 막으면 exe 는 한 줄도 돌지 않아 스스로 기록하지 못한다.",
    "rem 그래서 여기(바깥)에서 실행을 시도하고 결과 · 까닭 · 보안 제품 이름 · exe 확인값을 LogTriage-실행기록.txt 에 남긴다.",
    "setlocal",
    'set "LT_HERE=%~dp0"',
    'set "LT_LOG=%~dp0LogTriage-실행기록.txt"',
    'if not exist "%LT_HERE%LogTriage.exe" (echo  LogTriage.exe 가 없습니다 - 압축을 모두 푼 뒤 실행하십시오 & pause & exit /b 1)',
    "echo  LogTriage 를 여는 중입니다(실행 확인 몇 초)...",
    # PowerShell 은 경로를 환경 변수로만 받는다(따옴표 · 한글 경로 안전). 0 실행 중 · 2 실행 거부 · 3 시작 직후 종료
    'powershell -NoProfile -Command "$e=$env:LT_HERE+\'LogTriage.exe\'; function W($m){ Add-Content -LiteralPath $env:LT_LOG -Value (\'[\'+(Get-Date -Format \'yyyy-MM-dd HH:mm:ss\')+\'] [exe] \'+$m) -Encoding UTF8 }; '
    "W ('실행 시도 · Windows '+[Environment]::OSVersion.Version); "
    "try { $p=Start-Process -FilePath $e -WorkingDirectory $env:LT_HERE -PassThru -ErrorAction Stop } catch { "
    "W ('실행 거부: '+$_.Exception.Message); "
    "W ('보안 제품: '+((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName }) -join ', ')); "
    "W ('exe SHA-256: '+(Get-FileHash -LiteralPath $e -Algorithm SHA256).Hash); exit 2 }; "
    # GPT 194차 P1-02: '살아 있음'이 아니라 이 폴더의 LogTriage.exe 가 이번 실행 뒤에 만든 창(MainWindowHandle)을 확인(한 파일형은 자식 프로세스가 창을 띄움)
    "$since=$p.StartTime.AddSeconds(-1); for($i=0;$i -lt 80;$i++){ "
    "$w=@(Get-Process -Name LogTriage -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $e -and $_.StartTime -ge $since -and $_.MainWindowHandle -ne 0 }); "
    "if($w.Count){ W ('창 열림 확인(pid '+$w[0].Id+' · 창 제목 '+$w[0].MainWindowTitle+')'); exit 0 }; "
    "if($p.HasExited -and -not @(Get-Process -Name LogTriage -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $e -and $_.StartTime -ge $since }).Count){ "
    "W ('시작 직후 종료(종료 코드 '+$p.ExitCode+') - logtriage_gui.log 확인'); exit 3 }; Start-Sleep -Milliseconds 500 }; "
    "W '40초 안에 창이 나타나지 않음(프로세스는 떠 있음)'; exit 0\"",
    "if errorlevel 9009 goto noshell",   # powershell 을 찾지 못함(cmd 9009) — 3 보다 먼저 본다
    "if errorlevel 4 goto noshell",
    "if errorlevel 3 goto quit",
    "if errorlevel 2 goto blocked",
    "if errorlevel 1 goto noshell",
    "exit /b 0",
    ":blocked",
    "echo.",
    "echo  LogTriage — 이 PC 에서 LogTriage.exe 실행이 거부되었습니다(관리자 권한으로도 풀리지 않는 유형).",
    "echo  대개 백신의 '평판 기반 실행 차단'(서명 없는 새 프로그램 차단)이나 사내 실행 통제 정책입니다.",
    "echo  - 휴대용 묶음(LogTriage-PC-1.0.0.zip)의 LogTriage.cmd 를 쓰거나, 보안 담당에게 이 exe 의 예외 등록을 요청하십시오.",
    "echo  - 거부 까닭 · 보안 제품 이름 · exe 확인값은 LogTriage-실행기록.txt 에 남겼습니다(담당자에게 이 파일을 보내 주십시오).",
    "echo.",
    "pause",
    "exit /b 2",
    ":quit",
    "echo.",
    "echo  LogTriage — 프로그램이 시작 직후 끝났습니다. 같은 폴더(또는 %LOCALAPPDATA%\\LogTriage)의 logtriage_gui.log 끝부분과",
    "echo  LogTriage-실행기록.txt 를 담당자에게 보내 주십시오.",
    "echo.",
    "pause",
    "exit /b 3",
    ":noshell",
    "echo  (실행 확인 도구 PowerShell 을 쓸 수 없어 LogTriage.exe 를 바로 엽니다)",
    'echo [%date% %time%] [exe] PowerShell 없음 - 바로 실행>>"%LT_LOG%"',
    'start "" /D "%LT_HERE%" "%LT_HERE%LogTriage.exe"',
    "exit /b 0",
]


def launcher_bytes() -> bytes:
    return ("\r\n".join(LAUNCH_LINES) + "\r\n").encode("utf-8")


def agent_files() -> list:
    """묶음에 넣을 에이전트 파일(캐시·숨김 제외) — 이름 순."""
    # lt-agent-setup.sh 는 서버가 파일 해시(@@SHA:…@@)를 채워 내주는 틀이라 그대로는 못 쓴다 — 묶지 않는다
    return sorted(f.name for f in AGENT_DIR.iterdir() if f.is_file() and not f.name.startswith((".", "_")) and f.suffix != ".pyc"
                  and f.name != "lt-agent-setup.sh")


def agent_bytes(name: str) -> bytes:
    """대상 서버에서 그대로 돌게 줄끝을 맞춘다 — 셸·파이썬은 LF, 윈도우용(.cmd/.ps1)은 CRLF(서버가 내려주는 lt-agent.zip 과 같은 규칙)."""
    b = (AGENT_DIR / name).read_bytes().replace(b"\r\n", b"\n")
    return b.replace(b"\n", b"\r\n") if name.endswith((".cmd", ".ps1")) else b


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
    run = Path(argv[0]).resolve()
    last = json.loads(LEDGER.read_text(encoding="utf-8").strip().splitlines()[-1])
    got = {"gui": sha(run / EXES[0]), "cli": sha(run / EXES[1])}
    bad = [k for k in got if str(last.get(k, "")).lower() != got[k]]
    if bad:   # 10-29: 설치(장부 기록) 전 최종본은 포장본 점검 기록(exe_checks.json — 그 바이트로 12종 전부 통과)으로 대신 확인
        try:
            ck = json.loads(EXE_CHECKS.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            ck = {}
        if ck.get("ok") and str(ck.get("gui_sha", "")).lower() == got["gui"] and str(ck.get("cli_sha", "")).lower() == got["cli"]:
            print(f"  장부 대신 포장본 점검 기록으로 확인: 12종 통과 · {ck.get('at')}")
            bad = []
    if bad:
        print(f"[거부] exe 해시가 빌드 장부 마지막 줄 · 포장본 점검 기록과 다릅니다({', '.join(bad)}) — 시험한 빌드만 묶습니다")
        return 1
    top = f"LogTriage-PC-{ver}"
    agents = agent_files()
    allow = {f"{top}/{n}" for n in EXES + TEXTS + SERVE + (LAUNCH,)} | {f"{top}/agent/{n}" for n in agents}
    zp = OUT / f"{top}.zip"
    tmp = zp.with_suffix(".zip.new")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for n in EXES:
            z.write(run / n, f"{top}/{n}")
        for n in TEXTS + SERVE:
            if n == "사용법.txt":
                z.writestr(f"{top}/{n}", (EXE_HEAD.format(ver=ver) + (DOCS / n).read_text(encoding="utf-8")).encode("utf-8"))
            else:
                z.write(DOCS / n, f"{top}/{n}")
        z.writestr(f"{top}/{LAUNCH}", launcher_bytes())
        for n in agents:
            zi = zipfile.ZipInfo(f"{top}/agent/{n}", date_time=time.localtime((AGENT_DIR / n).stat().st_mtime)[:6])
            zi.external_attr = (0o755 if n.endswith(".sh") else 0o644) << 16   # 리눅스에서 풀면 .sh 는 실행 권한
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, agent_bytes(n))
    with zipfile.ZipFile(tmp) as z:   # 다시 열어 확인 — 허용 목록 밖 파일 0 · exe 바이트 동일
        names = set(z.namelist())
        extra = names - allow
        same = all(hashlib.sha256(z.read(f"{top}/{n}")).hexdigest() == got[k] for n, k in zip(EXES, ("gui", "cli")))
        same = same and all(z.read(f"{top}/agent/{n}") == agent_bytes(n) for n in agents)
        crs = [n for n in agents if not n.endswith((".cmd", ".ps1")) and b"\r" in z.read(f"{top}/agent/{n}")]
    if crs:
        tmp.unlink()
        print(f"[거부] 리눅스용 에이전트에 CR 이 남았습니다 {crs}")
        return 1
    if extra or names != allow or not same:
        tmp.unlink()
        print(f"[거부] 묶음 확인 실패 — 밖 파일 {sorted(extra)} · exe 동일 {same}")
        return 1
    tmp.replace(zp)
    zs = sha(zp)
    (OUT / f"SHA256-PC-{ver}.txt").write_text(
        f"LogTriage PC 단독용 {ver} 무결성 확인값\n\n"
        f"{zs}  {zp.name}\n{got['gui']}  {top}/LogTriage.exe\n{got['cli']}  {top}/logtriage-cli.exe\n\n"
        "확인(PowerShell): Get-FileHash .\\" + zp.name + " -Algorithm SHA256\n"
        "묶음: exe 둘 · 안내 글 · 서버 모드 파일(server.conf.example · LogTriage-server.cmd) · agent 폴더(원격 서버 자원 사용률 에이전트).\n"
        "분석 이력·계정·설정·토큰은 담지 않습니다(받은 PC 에서 새로 만들어지고, 에이전트의 주소·토큰은 설치 때 넣습니다).\n",
        encoding="utf-8")
    print(f"[완료] {zp}  {zp.stat().st_size // 1024:,} KB  sha256 {zs[:16]}…  파일 {len(names)}개(허용 목록과 같음)")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(ENGINE))
    sys.exit(main(sys.argv[1:]))
