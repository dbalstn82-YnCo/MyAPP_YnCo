"""휴대용 묶음 실행 전 점검 — 묶음에는 _preflight.py 로 들어간다(LogTriage.cmd · logtriage-cli.cmd · LogTriage-server.cmd 가 먼저 부른다).

pythonw.exe 는 창이 없어 시작 오류가 조용히 사라진다(GPT 187차 E). 띄우기 전에 콘솔(python.exe)에서 확인하고, 문제가 있으면 까닭과 할 일을 보여 주고 멈춘다.
  1) 압축 안 · 메일 첨부 임시 폴더에서 실행        → 압축을 풀라고 안내
  2) 쓸 수 없는 폴더                               → 옮기라고 안내
  3) OneDrive 동기화 폴더                          → 거부: 분석 로그 · 보고서가 클라우드로 동기화된다(exe 는 사용자 자리로 비켜 갔다 — 휴대용은 막는다)
  4) 관리자 권한(위치 무관)                        → 거부: 다른 계정이 바꿔 넣을 수 있는 원본 · DLL 을 관리자 권한으로 돌리게 된다(GPT 187차 조건부 P0-02)
     GPT 188차: '내 사용자 폴더 안이면 허용'은 다른 계정의 쓰기 권한 · 정션을 배제하지 못한다 → 휴대용은 관리자 실행을 모두 거부
  5) 묶음 파일 누락 · 바뀜(portable-files.json)    → 백신 격리 · 덜 풀림 · 손상 감지(목록도 같은 폴더라 악의적 변조 방지는 아님 — 받은 ZIP 은 SHA-256 으로)
  6) 판정 지식: 세대 기록 · 매니페스트 둘 다 있어야 하고 세대 기록과 내용이 같아야 함(GPT 187차 조건부 P0-01 — 둘 다 지워진 틈)
  7) 핵심 모듈 불러오기(화면 · .NET 연결 · 암호)  → 백신이 DLL · PYD 를 막았는지
  8) watch(10-29, LogTriage.cmd 가 창 프로그램을 띄운 뒤) — 이 묶음의 pythonw run_gui.py 가 실제로 떠서 5초 넘게 살아 있는지
실행 기록(10-29 마스터: "실행 시 자체적으로 로그를 찍어야"): 점검 결과 · 기동 확인 · 실패 까닭을 LogTriage-실행기록.txt 에 남긴다.
  보안 프로그램이 실행 자체를 막으면 프로그램 코드는 한 줄도 돌지 않아 스스로 기록할 수 없다 — 그래서 실행을 시도하는 쪽(여기)이 기록한다.
  실패 때는 이 PC 의 보안 제품 이름(Windows 보안 센터)도 적는다 — 다른 PC 에서 '왜 안 열리나'를 물을 때 이 파일 하나로 답이 나오게.
제품 원본(logtriage/)은 바꾸지 않는다 — 이 파일은 묶음 밖 점검이다(코드 지문에 들지 않음)."""
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODE = sys.argv[1] if len(sys.argv) > 1 else "gui"
LOG = HERE / "LogTriage-실행기록.txt"
try:
    sys.stdout.reconfigure(encoding="utf-8")
except (AttributeError, ValueError):
    pass


def record(*lines: str) -> None:
    """실행 기록 한 덩어리 — 묶음 폴더에 못 쓰면(읽기 전용 · 압축 안) %LOCALAPPDATA%\\LogTriage 에(GPT 194차 P1-03).
    둘 다 못 써도 점검 · 기동은 막지 않는다. 256KB 를 넘으면 뒤쪽 절반만 남긴다."""
    global LOG
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    alt = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "LogTriage" / LOG.name
    for target in (LOG, alt):
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists() and target.stat().st_size > 256 * 1024:
                target.write_bytes(target.read_bytes()[-128 * 1024:])
            with open(target, "a", encoding="utf-8") as f:
                for ln in lines:
                    f.write(f"[{stamp}] [{MODE}] {ln}\n")
            LOG = target
            return
        except OSError:
            continue


def security_products() -> str:
    """Windows 보안 센터에 등록된 백신 이름(없거나 못 읽으면 '확인 못 함')."""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | "
                            "ForEach-Object { $_.displayName }) -join ', '"],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout.strip() or "확인 못 함"
    except (OSError, subprocess.SubprocessError):
        return "확인 못 함"


def stop(title: str, *lines: str) -> None:
    print()
    print(f"  LogTriage — {title}")
    for ln in lines:
        print(f"  {ln}")
    print(f"  위치: {HERE}")
    print(f"  이 내용은 {LOG.name} 에도 남겼습니다.")
    record(f"멈춤: {title}", *lines, f"위치: {HERE}", f"보안 제품: {security_products()}")
    sys.exit(1)


def watch() -> None:
    """LogTriage.cmd 가 창 프로그램을 start 로 띄운 직후 — 이 묶음의 run_gui.py 를 돌리는 pythonw 가 떠서 살아 있는지 본다.
    없거나 곧 끝나면(보안 프로그램 차단 · 시작 직후 오류) 까닭 후보와 logtriage_gui.log 끝부분을 보여 주고 기록한다."""
    # GPT 194차 P1-02: 다른 pythonw · 예전 창을 이 실행으로 오인하지 않게 — 이 묶음의 runtime\pythonw.exe(실행 파일 전체 경로) +
    # 이 묶음의 run_gui.py + 이 점검이 시작된 뒤에 생긴 프로세스만 보고, 그 프로세스가 실제 창(MainWindowHandle)을 만들 때까지 기다린다(최대 40초).
    # (이미 열려 있던 창이 있으면 새 프로세스는 '이미 실행 중' 알림 창을 띄운다 — 그것도 창이므로 '열림'으로 기록하되 문구를 나눈다)
    script = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $exe=$env:LT_PYW; $t=$env:LT_RUNGUI; $since=(Get-Date).AddSeconds(-20); $pid0=0; "
              "for($i=0;$i -lt 80;$i++){ "
              "$p=@(Get-CimInstance Win32_Process -Filter \"Name='pythonw.exe'\" | Where-Object { $_.ExecutablePath -eq $exe -and $_.CommandLine -and "
              "$_.CommandLine.Contains($t) -and $_.CreationDate -ge $since } | Sort-Object CreationDate -Descending); "
              "if($p.Count){ $pid0=$p[0].ProcessId; $g=Get-Process -Id $pid0 -ErrorAction SilentlyContinue; "
              "if(-not $g){ Write-Output \"pid=$pid0\"; exit 3 }; if($g.MainWindowHandle -ne 0){ Write-Output \"pid=$pid0 title=$($g.MainWindowTitle)\"; exit 0 } } "
              "elseif($i -ge 20){ exit 2 }; Start-Sleep -Milliseconds 500 }; Write-Output \"pid=$pid0\"; exit 4")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env={**os.environ, "LT_RUNGUI": str(HERE / "run_gui.py"), "LT_PYW": str(HERE / "runtime" / "pythonw.exe")},
                           timeout=90, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        rc, info = r.returncode, r.stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        record(f"기동 확인을 하지 못함({type(e).__name__}) — 창이 열렸는지 직접 확인")
        sys.exit(0)
    if rc == 0:
        title = info.split("title=", 1)[-1] if "title=" in info else ""
        record(f"창 열림 확인({info.split(' ')[0]} · 창 제목 '{title}')" + (" — 이미 열린 창이 있어 새 실행은 안내만 띄움" if title == "LogTriage" else ""))
        sys.exit(0)
    if rc == 4:
        stop("창 프로그램은 떠 있지만 40초 안에 창이 나타나지 않았습니다.",
             "느린 PC 이면 잠시 더 기다려 보십시오. 그래도 창이 없으면 작업 관리자에서 pythonw.exe 를 끝내고 다시 실행하십시오.",
             f"({info})")
    tail = []
    for base in (HERE, Path(os.environ.get("LOCALAPPDATA", "")) / "LogTriage"):
        gl = base / "logtriage_gui.log"
        if gl.is_file():
            tail = gl.read_text(encoding="utf-8", errors="replace").splitlines()[-5:]
            break
    stop("창 프로그램이 " + ("시작되지 않았습니다." if rc == 2 else "시작 직후 끝났습니다."),
         "보안 프로그램(백신 · 사내 정책)이 실행을 막았거나, 시작 중 오류가 났을 수 있습니다.",
         "백신 기록에서 pythonw.exe 또는 LogTriage 항목을 확인하고, 아래 프로그램 기록 끝부분을 담당자에게 전달하십시오.",
         *(["프로그램 기록(logtriage_gui.log) 끝부분:"] + [f"  {x[:200]}" for x in tail] if tail else ["프로그램 기록(logtriage_gui.log) 없음 — 파이썬 코드가 시작되지 못함"]))


if MODE == "watch":
    watch()
record(f"실행 전 점검 시작 · Windows {platform.version()} · 파이썬 {platform.python_version()}")


def under(p: Path, root: str) -> bool:
    if not root:
        return False
    try:
        return p.resolve().is_relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False


here = HERE
parts = {x.lower() for x in here.parts}
if "content.outlook" in parts or "inetcache" in parts or under(here, tempfile.gettempdir()):
    stop("압축을 먼저 모두 푼 뒤 실행하십시오.",
         "압축 파일 안이나 메일 첨부에서 바로 실행하면 임시 폴더라 창을 닫을 때 지워집니다.",
         "ZIP 을 마우스 오른쪽 단추 - [압축 풀기] 로 바탕화면 등에 푼 뒤 그 폴더의 LogTriage.cmd 를 실행하십시오.")
od = [os.environ.get(k, "") for k in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer")]
if any(under(here, r) for r in od):
    stop("OneDrive 동기화 폴더에서는 실행하지 않습니다.",
         "분석한 로그 · 보고서 · 이력이 이 폴더에 저장되어 클라우드로 동기화됩니다(사내 로그 반출).",
         "폴더째 동기화 밖(예: C:\\LogTriage 또는 D:\\LogTriage)으로 옮긴 뒤 실행하십시오.")
probe = here / f".lt-write-probe-{os.getpid()}"
try:
    probe.write_text("x", encoding="utf-8")
    probe.unlink()
except OSError:
    stop("이 폴더에 쓸 수 없습니다.",
         "분석 이력 · 보고서 · 설정을 이 폴더에 저장합니다.",
         "폴더째 쓸 수 있는 곳(바탕화면 · D:\\ 등)으로 옮긴 뒤 다시 실행하십시오.")
try:
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
except (AttributeError, OSError):
    admin = False
if admin:
    stop("휴대용 묶음은 관리자 권한으로 실행하지 않습니다.",
         "묶음 폴더의 프로그램 파일을 다른 계정이 바꿔 넣었을 때 그 코드가 관리자 권한으로 돌게 되기 때문입니다.",
         "[관리자 권한으로 실행]이 아니라 그냥 더블클릭으로 실행하십시오.",
         "(UAC 가 꺼져 늘 관리자 권한인 PC 는 일반 계정으로 로그온해 실행하십시오 —",
         " exe 판은 관리자 실행을 막지 않으므로 그 PC 의 실행 권한 · 보안 정책을 보안 담당과 확인한 뒤에만 쓰십시오)")

try:
    want = json.loads((here / "portable-files.json").read_text(encoding="utf-8"))
except (OSError, ValueError):
    stop("묶음 목록(portable-files.json)이 없거나 깨졌습니다.", "압축을 처음부터 다시 풀어 주십시오.")
bad = []
for rel, (size, sha) in want["files"].items():
    p = here / rel
    try:
        if p.stat().st_size != size:
            bad.append(rel)
        elif sha and hashlib.sha256(p.read_bytes()).hexdigest() != sha:
            bad.append(rel)
    except OSError:
        bad.append(rel)
if bad:
    stop(f"묶음 파일 {len(bad)}개가 없거나 바뀌었습니다.",
         "백신이 격리했거나, 압축이 덜 풀렸거나, 누가 손댔을 수 있습니다. 예: " + ", ".join(bad[:4]),
         "압축을 처음부터 다시 풀어 주십시오. 다시 풀어도 같으면 백신 격리 목록을 확인하십시오.")

sys.path.insert(0, str(here))
from logtriage.knowledge_gen import check_gen  # noqa: E402

miss = [n for n in ("knowledge-gen.json", "knowledge-manifest.json") if not (here / n).is_file()]
g = check_gen(here)
if miss or g:
    stop("판정 지식이 온전하지 않아 띄우지 않습니다(거짓 '미검출' 방지).",
         (f"없는 기록: {', '.join(miss)}" if miss else g.splitlines()[0]),
         "압축을 처음부터 다시 풀어 주십시오. 룰팩을 적용한 사이트라면 룰팩을 다시 적용하십시오.")

try:
    import cryptography.hazmat.bindings._rust  # noqa: F401,E402  서명 확인(룰팩)
    import lxml.etree  # noqa: F401,E402
    import webview  # noqa: F401,E402
    if MODE == "gui":
        import clr_loader  # noqa: E402
        clr_loader.get_netfx()   # 창(WebView2)이 쓰는 .NET 연결 — Python.Runtime.dll 을 막으면 여기서 드러난다
except Exception as e:  # noqa: BLE001
    stop("필요한 구성 요소를 불러오지 못했습니다.",
         f"{type(e).__name__}: {str(e)[:200]}",
         "백신이 묶음 안 파일(.dll · .pyd)을 막았을 수 있습니다 — 압축을 다시 풀고, 같으면 백신 격리 목록을 확인하십시오.")
record("실행 전 점검 통과")
sys.exit(0)
