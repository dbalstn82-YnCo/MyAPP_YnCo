"""PC 휴대용 묶음 — 서명된 파이썬 런타임 + 원본(10-28 마스터: "불특정 다수의 PC 에서 실행돼야 하는데 V3 가 exe 를 막아 제출 불가").

왜: V3 가 서명 없는 LogTriage.exe(PyInstaller 창 실행 파일)를 '액세스 거부'로 막았다 — 같은 바이트의 설치본도, 새로 푼 복사본도.
    이 묶음에는 **서명 없는 실행 파일이 없다**. 실행되는 프로그램은 Python Software Foundation 이 서명한 pythonw.exe · python.exe 뿐이고,
    LogTriage 는 그 런타임이 읽는 원본(.py)이다. 코드는 exe 빌드와 **같은 원본** — 코드 지문이 그 빌드의 _pc_build.json 과 같아야 묶는다.

구성(<출력>/LogTriage-PC-<판>/):
  LogTriage.cmd · logtriage-cli.cmd · LogTriage-server.cmd   ← 실행(더블클릭은 LogTriage.cmd)
  runtime/        CPython(이 PC 에 설치된 같은 판) — python<판>._pth 로 격리(PYTHONPATH·사용자 site·레지스트리를 보지 않음)
  logtriage/ · run_gui.py · run_logtriage.py   원본(미리 컴파일한 __pycache__ 포함)
  rules/ · errorcodes/ · manuals/ · knowledge-gen.json   판정 지식(빌드의 지식 지문과 같아야 함) · report-template/ · rules-local/(빈 폴더)
  samples/ · tools/agent/ · agent/ · 사용법.txt · 소개 · server.conf.example
  — 원본이 묶음 맨 위에 있어 '자료 자리'(분석 이력·보고서·server.conf·server.pid)가 exe 옆과 같은 곳(LogTriage.cmd 옆)이다.

사용: python tools/build/build_portable.py <exe 빌드 이름>   예) exe49  → 검증도구/<이름>/portable/LogTriage-PC-<판>
설치·묶음(zip)은 하지 않는다 — 점검(검증도구/portable_check.py) 뒤 make_pc_zip.py --portable 이 묶는다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
LOCAL = ENGINE / "deploy" / "local"
TOOLS = ENGINE.parent / "검증도구"
sys.path.insert(0, str(ENGINE))

PYHOME = Path(sys.base_prefix)
# exe 빌드(PyInstaller 분석)가 실제로 묶은 외부 패키지와 같은 목록 — 검증도구/exe49/build/logtriage/PYZ·PKG 목록에서 뽑음(설치·빌드 도구는 뺌)
SITE_TOPS = ("PIL", "bottle.py", "bs4", "cffi", "charset_normalizer", "clr.py", "clr_loader", "cryptography", "defusedxml", "docx",
             "et_xmlfile", "lxml", "olefile", "openpyxl", "packaging", "proxy_tools", "psycopg2", "psycopg2_binary.libs", "pycparser",
             "pythonnet", "soupsieve", "typing_extensions.py", "webview", "yaml", "_cffi_backend.cp313-win_amd64.pyd", "_yaml")
LIB_SKIP = {"site-packages", "test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3", "venv", "__phello__", "pydoc_data"}
DLL_SKIP = ("_tkinter", "tcl", "tk", "_test", "xxlimited", "_ctypes_test")
RUNTIME_FILES = ("python.exe", "pythonw.exe", "python3.dll", f"python{sys.version_info.major}{sys.version_info.minor}.dll",
                 "vcruntime140.dll", "vcruntime140_1.dll", "LICENSE.txt")
TEXTS = ("사용법.txt", "LogTriage-1.0.0_소개.html", "server.conf.example")
NOCACHE = shutil.ignore_patterns("__pycache__", "*.pyc")
GUIDE_HEAD = """LogTriage {ver} — PC 휴대용 묶음 (먼저 읽기)
=============================================

■ 실행: 압축을 모두 푼 뒤 LogTriage.cmd 를 더블클릭하십시오.
  검은 창이 잠깐 떠서 실행 전 점검을 한 뒤 분석기 창이 열립니다(점검에 걸리면 그 창에 까닭과 할 일이 나옵니다).
  - 이 묶음에는 별도 제품 exe 가 없습니다. 실제로 실행되는 프로그램은 내장 파이썬 runtime\\pythonw.exe · python.exe
    (Python Software Foundation 서명)이고, LogTriage 는 그 런타임이 읽는 원본입니다.
    서명이 확인되는 것은 파이썬 런타임이며, LogTriage 제품 코드 자체는 서명되어 있지 않습니다.
    일부 백신(V3 등)이 서명 없는 LogTriage.exe 를 '액세스 거부'로 막는 PC 에서도 실행되도록 만든 배포 형태입니다.
  - 아래 안내의 'LogTriage.exe' 는 'LogTriage.cmd', 'logtriage-cli.exe' 는 'logtriage-cli.cmd' 로 읽으십시오.
    화면 · 기능 · 판정은 exe 판과 같은 원본입니다(코드 지문 {code}).

■ 실행 전 점검(자동) — 다음 경우는 까닭을 보여 주고 열지 않습니다
  압축 안에서 바로 실행 · 쓸 수 없는 폴더 · OneDrive 동기화 폴더(분석 로그가 클라우드로 동기화됨) ·
  관리자 권한으로 실행([관리자 권한으로 실행] 대신 그냥 더블클릭) · 묶음 파일 누락/변경(백신 격리 · 손상 감지용 —
  악의적 변조 방지는 아니므로 받은 ZIP 은 함께 받은 SHA256 값으로 확인) · 판정 지식 불완전 · 구성 요소 차단

■ 실행 기록 — 열리지 않으면 이 파일부터
  LogTriage.cmd 는 실행할 때마다 같은 폴더의 LogTriage-실행기록.txt 에 점검 결과 · 창이 실제로 떴는지 · 멈춘 까닭을 남깁니다.
  창이 안 열렸다면 이 파일(멈춘 까닭 · 이 PC 의 보안 제품 이름 · 프로그램 기록 끝부분)을 담당자에게 보내 주십시오.
  계정 · 비밀번호는 적지 않습니다(프로그램 기록 끝 5줄에는 파일 경로가 들어갈 수 있으니 보내기 전에 한 번 보십시오).

■ 인터넷 · 메일로 받은 ZIP
  풀기 전에 ZIP 파일 [속성] → [차단 해제] 를 체크하고 [확인] 하면, 실행할 때 Windows 보안 경고가 뜨지 않습니다.

■ exe 판과 다른 점
  - 쓸 수 없는 폴더 · 압축 안에서 자동으로 사용자 자리(%LOCALAPPDATA%)로 비켜 가지 않고, 안내한 뒤 멈춥니다.
  - [상태] 창의 '실행 파일' 칸은 '개발 실행'으로 보입니다(설치 기록 대조가 없는 원본 실행 — 정상).
  - 크기가 큽니다(풀린 상태 약 100MB · 파일 약 3천 개).
  - 관리자 권한 실행을 거부합니다(LogTriage.cmd 를 거치지 않고 직접 띄워도). UAC 가 꺼져 늘 관리자 권한인 PC 는
    일반 계정으로 로그온해 실행하십시오 — exe 판은 관리자 실행을 막지 않으므로 그 PC 의 보안 정책을 확인한 뒤에만 쓰십시오.
  - 서버 모드 자동 시작은 로그온 시(내 계정)만 됩니다. SYSTEM 으로 부팅 직후 받기는 리눅스 서버형을 쓰십시오.

■ 막지 못하는 것
  사내 정책(AppLocker · WDAC · EDR)이 스크립트(.cmd)나 파이썬 실행 자체를 막는 PC 에서는 이 묶음도 실행되지 않을 수 있습니다.
  그때는 보안 담당에게 예외 등록을 요청하거나, 회사 코드 서명 인증서로 서명한 판을 쓰십시오.

"""


ADMIN_GUARD = '''    import ctypes   # 휴대용: 관리자 권한 실행 거부(GPT 188 · 189차 — LogTriage.cmd 를 거치지 않고 직접 띄운 경우까지)
    try:
        _adm = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        _adm = False
    if _adm:
        _msg = "휴대용 LogTriage 는 관리자 권한으로 실행하지 않습니다.\\n[관리자 권한으로 실행] 대신 LogTriage.cmd 를 그냥 더블클릭하십시오."
        if sys.stderr:
            print(_msg, file=sys.stderr)
        if "--serve" not in sys.argv and not sys.stderr:   # 창 없는 GUI(pythonw)만 알림 창 — 서버 · 예약 작업은 막히지 않게 글로만
            ctypes.windll.user32.MessageBoxW(None, _msg, "LogTriage", 0x10)
        sys.exit(1)
'''


def norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(".", "_")


def copy_runtime(rt: Path) -> None:
    rt.mkdir(parents=True)
    for f in RUNTIME_FILES:
        shutil.copy2(PYHOME / f, rt / f)
    (rt / "DLLs").mkdir()
    for f in (PYHOME / "DLLs").iterdir():
        if f.is_file() and not f.name.lower().startswith(DLL_SKIP):
            shutil.copy2(f, rt / "DLLs" / f.name)
    lib = rt / "Lib"
    lib.mkdir()
    for f in (PYHOME / "Lib").iterdir():
        if f.name in LIB_SKIP:
            continue
        if f.is_dir():
            shutil.copytree(f, lib / f.name, ignore=shutil.ignore_patterns("test", "tests", "idle_test"))
        else:
            shutil.copy2(f, lib / f.name)
    sp_src, sp = PYHOME / "Lib" / "site-packages", lib / "site-packages"
    sp.mkdir()
    want = {norm(t.split(".")[0] if t.endswith((".py", ".pyd")) else t) for t in SITE_TOPS}
    for t in SITE_TOPS:
        s = sp_src / t
        if not s.exists():
            raise SystemExit(f"외부 패키지가 없습니다: {s}")
        (shutil.copytree(s, sp / t, ignore=NOCACHE) if s.is_dir() else shutil.copy2(s, sp / t))
    for d in sp_src.glob("*.dist-info"):   # 라이선스·메타데이터(cryptography 등은 판 확인에 씀) — 위 목록의 것만
        if norm(d.name.split("-")[0]) in want or norm(d.name.split("-")[0]).replace("_binary", "") in want:
            shutil.copytree(d, sp / d.name)
    v = f"{sys.version_info.major}{sys.version_info.minor}"
    # 격리: ._pth 가 있으면 sys.path 가 이 목록뿐(PYTHONPATH · PYTHONHOME · 사용자 site · 레지스트리 무시). 맨 끝 '..' = 묶음 폴더(원본)
    (rt / f"python{v}._pth").write_text("Lib\nDLLs\nLib\\site-packages\n..\n", encoding="utf-8")


def cmd_text(lines: list) -> bytes:
    """cmd 는 CRLF · UTF-8 — 첫 줄 chcp 65001 로 한글 안내가 깨지지 않게."""
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


UNZIP = [
    ":unzip",
    "echo.",
    "echo  LogTriage — 압축을 먼저 모두 푼 뒤 실행하십시오.",
    "echo  압축 파일 안에서 바로 실행하면 runtime 폴더(파이썬)가 함께 풀리지 않습니다.",
    "echo  ZIP 을 마우스 오른쪽 단추 - [압축 풀기] 로 바탕화면 등에 푼 뒤, 그 폴더의 LogTriage.cmd 를 실행하십시오.",
    "echo.",
    "pause",
    "exit /b 1",
]
# GPT 187차: GUI 는 인자가 필요 없다(%* 를 넘기지 않음 — 서버 모드는 LogTriage-server.cmd) · 작업 폴더를 묶음으로 고정(start /D)
# 띄우기 전 점검(_preflight.py, 콘솔): 압축 안 · 쓰기 불가 · OneDrive · 관리자(188차: 위치 무관) · 파일 누락/바뀜 · 지식 · 모듈 — pythonw 는 오류를 보여 주지 못한다
LAUNCHER = [
    "@echo off",
    "chcp 65001 >nul",
    "rem LogTriage 휴대용 실행 — 서명된 파이썬 런타임(runtime\\pythonw.exe · Python Software Foundation 서명)이 이 폴더의 원본을 띄운다.",
    "rem 서명 없는 실행 파일(exe)이 없어 백신이 '처음 보는 서명 없는 프로그램'으로 막을 대상이 없다(10-28).",
    "setlocal",
    'set "HERE=%~dp0"',
    'if not exist "%HERE%runtime\\python.exe" goto unzip',
    'if not exist "%HERE%_preflight.py" goto unzip',
    'echo  LogTriage 를 여는 중입니다(실행 전 점검)...',
    '"%HERE%runtime\\python.exe" "%HERE%_preflight.py" gui',
    "if errorlevel 1 (echo. & pause & exit /b 1)",
    'start "" /D "%HERE%" "%HERE%runtime\\pythonw.exe" "%HERE%run_gui.py"',
    # 10-29 마스터 '실행 시 로그를 찍어야': 창 프로그램이 실제로 떠 있는지 확인하고 LogTriage-실행기록.txt 에 남긴다(막히면 까닭 후보 · 보안 제품 이름)
    "echo  창이 열리는지 확인하는 중입니다(몇 초)...",
    '"%HERE%runtime\\python.exe" "%HERE%_preflight.py" watch',
    "if errorlevel 1 (echo. & pause & exit /b 1)",
    "exit /b 0",
] + UNZIP

CLI = [
    "@echo off",
    "chcp 65001 >nul",
    "rem LogTriage 명령줄(휴대용) — logtriage-cli.exe 와 같은 사용법:  logtriage-cli.cmd --input <로그 파일>:<제품>:<호스트> [옵션]   (인자 없이 실행하면 대화형)",
    "setlocal",
    'set "HERE=%~dp0"',
    'if not exist "%HERE%runtime\\python.exe" goto unzip',
    '"%HERE%runtime\\python.exe" "%HERE%_preflight.py" cli || exit /b 1',
    '"%HERE%runtime\\python.exe" "%HERE%run_logtriage.py" %*',
    "exit /b %ERRORLEVEL%",
] + UNZIP


def server_cmd() -> bytes:
    """LogTriage-server.cmd 를 휴대용으로 — 실행 대상만 바꾼다(pythonw + run_gui.py --serve). 다른 줄은 그대로."""
    t = (LOCAL / "LogTriage-server.cmd").read_text(encoding="utf-8").replace("\r\n", "\n")
    rep = [
        ('set "EXE=%HERE%LogTriage.exe"', 'set "EXE=%HERE%runtime\\pythonw.exe"\nset "APP=%HERE%run_gui.py"'),
        ("그 PID 가 정말 LogTriage.exe --serve 인지 확인", "그 PID 가 정말 휴대용 LogTriage(pythonw run_gui.py --serve)인지 확인"),
        # GPT 187차 P1-04: 이름 · 일부 명령줄만이 아니라 실행 파일 전체 경로 + 이 묶음의 run_gui.py 경로로 대조(다른 묶음의 서버를 끄지 않게)
        ("$p.Name -eq 'LogTriage.exe' -and $p.CommandLine -like '*--serve*'",
         "$p.ExecutablePath -eq '!EXE!' -and $p.CommandLine.Contains('!APP!') -and $p.CommandLine.Contains('--serve')"),
        ('start "" "%EXE%" --serve',
         '"%HERE%runtime\\python.exe" "%HERE%_preflight.py" serve || exit /b 1\nstart "" /D "%HERE%" "%EXE%" "%APP%" --serve'),
        # GPT 188차: 자동 시작 작업이 pythonw 를 바로 띄우면 실행 전 점검(무결성 · 지식 · 관리자 거부)을 건너뛴다
        # → 이 cmd 의 start 를 부르게 한다(점검을 거쳐 띄움). SYSTEM 부팅 등록 안내는 관리자 실행 거부와 맞지 않아 뺀다
        ('schtasks /Create /F /SC ONLOGON /TN LogTriageServer /TR "\\"%EXE%\\" --serve" /RL LIMITED',
         'schtasks /Create /F /SC ONLOGON /TN LogTriageServer /TR "\\"%~f0\\" start" /RL LIMITED'),
        ('echo 로그온 없이 부팅 직후부터 받으려면 관리자 콘솔에서:  schtasks /Create /F /SC ONSTART /RU SYSTEM /TN LogTriageServer /TR "\\"%EXE%\\" --serve"',
         'echo 휴대용은 관리자 · SYSTEM 권한 실행을 거부합니다 - 로그온 없이 부팅 직후부터 받아야 하면 리눅스 서버형을 쓰십시오'),
    ]
    for a, b in rep:
        n = t.count(a)
        if not n:
            raise SystemExit(f"LogTriage-server.cmd 에서 바꿀 줄을 찾지 못함: {a}")
        t = t.replace(a, b)
    if "LogTriage.exe" in t.replace("LogTriage.exe 가", ""):
        left = [ln for ln in t.splitlines() if "LogTriage.exe" in ln]
        raise SystemExit(f"휴대용 서버 cmd 에 exe 이름이 남았습니다: {left}")
    lines = t.split("\n")
    lines.insert(1, "chcp 65001 >nul")
    return cmd_text(lines)


def main(argv=None) -> int:
    from logtriage import __version__ as ver, buildid
    from logtriage.knowledge_gen import dir_hash, write_gen, check_gen
    name = (argv or sys.argv[1:] or [""])[0]
    rec_p = TOOLS / name / "run" / "_pc_build.json"
    if not name or not rec_p.is_file():
        raise SystemExit("사용: python tools/build/build_portable.py <exe 빌드 이름>   (예: exe49 — 검증도구/<이름>/run/_pc_build.json 이 있어야 함)")
    rec = json.loads(rec_p.read_text(encoding="utf-8"))
    code = buildid.compute(ENGINE / "logtriage")
    if code != rec["code"]:
        raise SystemExit(f"엔진 원본 코드 지문 {code} 가 {name} 빌드({rec['code']})와 다릅니다 — 같은 원본만 묶습니다")
    kh = {d: dir_hash(ENGINE / d) for d in ("rules", "errorcodes", "manuals")}
    if kh != rec["knowledge"]:
        raise SystemExit(f"엔진 판정 지식이 {name} 빌드와 다릅니다: {kh}")
    if sys.version_info[:2] != (3, 13):
        raise SystemExit(f"exe 빌드와 같은 파이썬 3.13 으로 실행하십시오(지금 {sys.version.split()[0]})")
    out = TOOLS / name / "portable" / f"LogTriage-PC-{ver}"
    if out.exists():
        raise SystemExit(f"{out} 가 이미 있습니다 — 지우거나 옮긴 뒤 다시(지난 묶음을 덮지 않는다)")
    out.mkdir(parents=True)
    print(f"[휴대용] 판 {ver} · 코드 지문 {code} · 파이썬 {sys.version.split()[0]} ({PYHOME})", flush=True)
    copy_runtime(out / "runtime")
    shutil.copytree(ENGINE / "logtriage", out / "logtriage", ignore=NOCACHE)
    shutil.copy2(LOCAL / "build" / "pc_stamp" / "_build_id.json", out / "logtriage" / "_build_id.json")
    for f in ("run_gui.py", "run_logtriage.py"):
        # GPT 189차 P1-01: runtime\pythonw.exe run_gui.py 를 직접 띄우면 _preflight 를 건너뛴다 → 진입점에도 관리자 거부(묶음 사본만 — 엔진 원본 · 코드 지문 무변경)
        t = (ENGINE / f).read_text(encoding="utf-8")
        head = 'if __name__ == "__main__":\n'
        if t.count(head) != 1:
            raise SystemExit(f"{f} 의 진입 줄을 찾지 못함")
        (out / f).write_text(t.replace(head, head + ADMIN_GUARD), encoding="utf-8")
    for d in ("rules", "errorcodes", "manuals", "report-template", "samples"):
        shutil.copytree(ENGINE / d, out / d, ignore=NOCACHE)
    (out / "report-template" / "custom").mkdir(exist_ok=True)
    (out / "rules-local").mkdir()
    shutil.copy2(ENGINE / "rules-local" / "_readme.txt", out / "rules-local" / "_readme.txt")
    (out / "tools").mkdir()
    shutil.copytree(ENGINE / "tools" / "agent", out / "tools" / "agent", ignore=NOCACHE)
    sys.path.insert(0, str(Path(__file__).parent))
    from make_pc_zip import agent_bytes, agent_files
    (out / "agent").mkdir()
    for n in agent_files():
        (out / "agent" / n).write_bytes(agent_bytes(n))
    for f in TEXTS:
        shutil.copy2(LOCAL / f, out / f)
    guide = (LOCAL / "사용법.txt").read_text(encoding="utf-8")
    (out / "사용법.txt").write_text(GUIDE_HEAD.format(ver=ver, code=code) + "\n" + guide, encoding="utf-8")
    shutil.copy2(Path(__file__).with_name("portable_preflight.py"), out / "_preflight.py")
    (out / "LogTriage.cmd").write_bytes(cmd_text(LAUNCHER))
    (out / "logtriage-cli.cmd").write_bytes(cmd_text(CLI))
    (out / "LogTriage-server.cmd").write_bytes(server_cmd())
    write_gen(out, f"휴대용 묶음(LogTriage {ver} · 코드 {code})")
    # 매니페스트(gen_era) — 세대 기록이 지워지면 '옛 설치'로 오인하지 않고 기동을 거부하게(exe 는 내장 지식 펼치기가 이 몫을 한다)
    r = subprocess.run([sys.executable, str(ENGINE / "tools" / "build" / "check_dist_knowledge.py"), "--after", "--dist", str(out)],
                       cwd=str(ENGINE), capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode or not json.loads((out / "knowledge-manifest.json").read_text(encoding="utf-8")).get("gen_era"):
        raise SystemExit(f"지식 매니페스트 실패: {r.stdout[-600:]} {r.stderr[-600:]}")
    g = check_gen(out)
    if g:
        raise SystemExit(f"지식 세대 기록 대조 실패: {g}")
    # 원본을 묶음의 런타임으로 미리 컴파일 — 읽기 전용 자리에서도 첫 기동이 느리지 않게, 그리고 런타임이 격리돼 뜨는지 여기서 처음 확인
    py = out / "runtime" / "python.exe"
    r = subprocess.run([str(py), "-m", "compileall", "-q", "-j", "0", str(out / "logtriage"), str(out / "run_gui.py"),
                        str(out / "run_logtriage.py")], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        raise SystemExit(f"미리 컴파일 실패: {r.stdout[-800:]} {r.stderr[-800:]}")
    probe = ("import sys, json, logtriage, webview, cryptography, openpyxl, lxml, yaml, clr_loader;"
             "from logtriage import buildid;"
             "print(json.dumps({'path': sys.path, 'code': buildid.code(), 'flags_isolated': sys.flags.isolated, 'nosite': 'site' not in sys.modules,"
             "'exe': sys.executable}))")
    env = {**os.environ, "PYTHONPATH": r"C:\nowhere-should-be-ignored", "PYTHONHOME": r"C:\nowhere-home"}
    r = subprocess.run([str(py), "-c", probe], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env)
    if r.returncode:
        raise SystemExit(f"런타임 확인 실패: {r.stderr[-1500:]}")
    info = json.loads(r.stdout.strip().splitlines()[-1])
    outside = [p for p in info["path"] if not Path(p).resolve().is_relative_to(out.resolve())]
    if outside:
        raise SystemExit(f"런타임이 묶음 밖 경로를 봅니다(격리 실패): {outside}")
    if info["code"] != code:
        raise SystemExit(f"묶음 원본의 코드 지문 {info['code']} ≠ {code}")
    # 실행 부분 목록(실행 전 점검이 대조) — 런타임은 크기, 원본 · 실행 글은 SHA-256. 판정 지식은 룰팩으로 바뀌므로 세대 기록이 따로 지킨다
    files = {}
    for top in ("runtime", "logtriage", "run_gui.py", "run_logtriage.py", "_preflight.py"):
        base = out / top
        for f in sorted([base] if base.is_file() else base.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts:
                rel = f.relative_to(out).as_posix()
                files[rel] = [f.stat().st_size, "" if top == "runtime" else hashlib.sha256(f.read_bytes()).hexdigest()]
    (out / "portable-files.json").write_text(json.dumps({"build": ver, "code": code, "files": files}, ensure_ascii=False), encoding="utf-8")
    r = subprocess.run([str(py), str(out / "_preflight.py"), "gui"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode:
        raise SystemExit(f"실행 전 점검이 갓 만든 묶음을 거부했습니다: {r.stdout[-800:]} {r.stderr[-400:]}")
    (out / "LogTriage-실행기록.txt").unlink(missing_ok=True)   # 10-29: 빌드 때 돌린 점검 기록은 묶음에 넣지 않는다(받은 PC 에서 새로 생김)
    size = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
    stamp = {"build": ver, "code": code, "exe_build": name, "python": sys.version.split()[0], "knowledge": kh, "size": size}
    (out.parent / "_portable_build.json").write_text(json.dumps(stamp, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[휴대용] 끝 — {out}\n  {size / 1048576:.1f} MB · 코드 지문 {info['code']}(묶음 런타임으로 계산) · 경로 격리 ✓ · PYTHONPATH/PYTHONHOME 무시 ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
