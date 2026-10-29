"""Linux 설치 패키지 + 패치 zip 생성.

산출물 이름은 **제품 이름 + 버전 하나**다. 날짜·r번호를 쓰지 않는다(사용자 결정 2026-10-01).
버전은 engine/logtriage/__init__.py 의 BUILD 한 곳에서만 나오고, **완전히 새로워지기 전까지
바꾸지 않는다.** /healthz 가 돌려주는 값과 파일 이름이 같은 값이다.

  반출/logtriage-server-<ver>.zip       전체(독립 Python 포함, 기존 zip 에서 python tar.gz 재사용)
  반출/logtriage-patch-<ver>.zip        소스·데이터만 + apply_patch.sh (이미 풀어 둔 서버에 덮어쓰기)
  반출/logtriage-patch-py311-<ver>.zip  위와 같되 wheels 는 py3.11 만
"""
import io, os, re, shutil, sys, time, zipfile
# 콘솔이 cp949 여도 끝까지 돈다 — 찍기 실패로 빌드 표시 전수 확인이 건너뛰어진 일이 있었다
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass
from pathlib import Path
ROOT = Path(r"C:\Users\dbals\Desktop\로그수집기"); ENG = ROOT / "engine"; OUT = ROOT / "반출"
NAME = "logtriage"      # 제품 이름 — 파일 이름의 앞머리
sys.path.insert(0, str(Path(__file__).resolve().parent))
import _buildstamp as _bs                      # 빌드 표시는 여기 한 곳에서만 읽고 치환한다
LT_BUILD = _bs.build_id(ENG)
VER = LT_BUILD          # 파일 이름에 박는 버전 = 제품 판 표시. 두 곳이 갈라지지 않게 한 값을 쓴다
sys.path.insert(0, str(ENG))
from logtriage import buildid as _bid     # noqa: E402  판 지문 — 코드 내용에서 뽑는다
# python tar·스크립트는 지난 묶음에서 재사용한다 — 옛 이름(날짜판)도 찾는다
_prev = (sorted(OUT.glob(f"{NAME}-server-*.zip")) or sorted(OUT.glob("logtriage-linux-test-*.zip"))
         or sorted(OUT.glob("LogTriage-Linux-Install-*.zip")))
PREV_FULL = _prev[-1]
STAGE = OUT / "_stage_linux"; shutil.rmtree(STAGE, ignore_errors=True)
S = STAGE / f"{NAME}-server"; (S / "engine").mkdir(parents=True); (S / "wheels").mkdir()

def copy_engine(dst: Path):
    for d in ("logtriage", "rules", "rules-local", "errorcodes", "manuals", "report-template", "tools", "tests", "samples"):   # 12차: samples(합성 견본 — 30초 체험)
        shutil.copytree(ENG / d, dst / d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "custom", "report_profile.json"))
    for f in ("run_logtriage.py", "run_gui.py"):
        if (ENG / f).exists(): shutil.copy(ENG / f, dst / f)
    (dst / "deploy").mkdir(exist_ok=True)
    shutil.copytree(ENG / "deploy" / "server", dst / "deploy" / "server", ignore=shutil.ignore_patterns("pkgs", "__pycache__"))  # wheels(py3.9~3.13) 포함 — 폐쇄망 install.sh 용
    # 12차(PC·리눅스 같은 판): install.sh 가 deploy/local/사용법.txt 를 복사하는데 묶음에 없었다 — PC 와 같은 사용법·소개서를 함께 싣는다
    (dst / "deploy" / "local").mkdir(parents=True, exist_ok=True)
    for f in ("사용법.txt", f"LogTriage-{LT_BUILD}_소개.html"):
        shutil.copy2(ENG / "deploy" / "local" / f, dst / "deploy" / "local" / f)
    bad = [p for p in dst.rglob("*") if p.suffix.lower().startswith(".hwp") and p.name not in ("form_status.hwpx", "form_postmortem.hwpx")]
    assert not bad, bad

copy_engine(S / "engine")
# 동봉 wheel — 이름을 **적어 두고 전부 있는지 확인**한다.
#
# 전에는 glob("*cp311*") 하나였다. 그래서 cryptography 가 요구하는 cffi·pycparser 가
# 빠졌고(pycparser 는 py3-none-any 라 그 glob 에 걸리지도 않는다), 폐쇄망에서
# `pip install cryptography` 가 **언제나 실패**했다. 서버는 순수 파이썬 암호로 돌면서
# "운영 전에 cryptography 를 설치하십시오" 라고 찍었다 — 인터넷이 없으니 할 수 없는 일을
# 권하고 있었던 것이다(현장 기동 기록에서 발견, 2026-10-02).
WHEEL_NEED = ("pyyaml", "lxml", "psycopg2", "cryptography", "cffi", "pycparser")
_got: dict = {}
for w in (ENG / "deploy/server/wheels").glob("*.whl"):
    tag = w.name.lower()
    if not ("cp311" in tag or "py3-none-any" in tag):
        continue
    for need in WHEEL_NEED:
        if tag.startswith(need.replace("-", "_")) or tag.startswith(need):
            _got.setdefault(need, w)
_missing = [n for n in WHEEL_NEED if n not in _got]
assert not _missing, (f"동봉 wheel 이 빠졌습니다: {_missing} — 폐쇄망에서 설치가 됩니다 하고 "
                      f"안 되는 상태가 됩니다. deploy/server/wheels 에 cp311 wheel 을 넣으십시오.")
for w in _got.values():
    shutil.copy(w, S / "wheels" / w.name)
print("  동봉 wheel:", ", ".join(sorted(_got)))
# 스크립트·README·python tar 는 기존 zip 에서 재사용
with zipfile.ZipFile(PREV_FULL) as z:
    for n in z.namelist():
        base = n.split("/", 1)[1] if "/" in n else n
        if base in ("run.sh", "stop.sh", "python-3.11-linux-x86_64.tar.gz") or base.startswith("README"):
            (S / base).write_bytes(z.read(n))
assert (S / "python-3.11-linux-x86_64.tar.gz").exists() and (S / "run.sh").exists()
# README 도 **옛 zip 에서 그대로 복사**돼 오고 있었다 — 한 번도 갱신되지 않아, 없는 파일
# (upgrade.sh·docs/·rulepack/·SHA256SUMS)을 가리키고 run.sh 가 거절하는 '비밀번호 인자' 를
# 쓰라고 적고 있었다. 사람은 적혀 있는 것을 믿는다. 갱신본이 있으면 그것을 쓴다(2026-10-02).
for _n in ("run.sh", "stop.sh", "README-INSTALL.txt"):
    _upd = OUT / f"_{_n}"
    if _upd.exists():
        (S / _n).write_bytes(_upd.read_bytes().replace(b"\r\n", b"\n"))  # 갱신된 스크립트·안내 우선
assert b"upgrade.sh" not in (S / "README-INSTALL.txt").read_bytes(), \
    "설치 안내가 묶음에 없는 upgrade.sh 를 가리킵니다"

# .py·.yaml 은 바꾸지 않는다 — 코드·지식 지문(PC 와 대조하는 값)이 바이트로 세어져, 바꾸면 '설치 뒤 손댐'으로 잘못 보인다(파이썬·YAML 은 CRLF 도 읽는다)
LF_SUFFIX = (".sh", ".service", ".timer", ".conf", ".example", ".env", ".sql")
LF_NAMES = ("README-INSTALL.txt", "VERSION.txt", "SHA256SUMS")


def zipdir(root: Path, out: Path):
    n = 0
    with zipfile.ZipFile(out, "w") as z:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                zi = zipfile.ZipInfo(rel, time.localtime(p.stat().st_mtime)[:6])
                zi.compress_type = zipfile.ZIP_STORED if p.suffix in (".gz", ".whl") else zipfile.ZIP_DEFLATED
                zi.external_attr = (0o755 if p.suffix == ".sh" else 0o644) << 16
                data = p.read_bytes()
                # 12차(GPT 93차 P1 → 실측 확인): 10-06 묶음의 install.sh·backup.sh·uninstall.sh·에이전트 .sh·systemd 유닛이 CRLF 였다 —
                # 리눅스에서 `bash install.sh` 는 첫 줄부터 $'\r' 오류. 리눅스가 읽는 글 파일은 묶을 때 LF 로 강제한다
                if p.suffix in LF_SUFFIX or p.name in LF_NAMES:
                    data = data.replace(b"\r\n", b"\n")
                z.writestr(zi, data); n += 1
    return n

# 전체 묶음에는 apply_patch.sh 가 없어 **판 표시가 한 곳도 없었다.** 푼 폴더만 보고는
# 어느 판인지 알 수 없었고, 판 표시 전수 검사도 그래서 아무것도 못 찾았다.
# 포장한 **그 소스**로 지문을 구한다 — 돌고 있는 서버가 구하는 값과 같아야 한다.
#
# 2026-10-01: 지문 범위를 **기동 스크립트까지** 넓혔다. run.sh 만 고친 판에서
# '엔진 같음 → 지문 같음 → 기동 동작은 바뀜' 이 되어 지문의 뜻이 무너졌다(GPT 19차).
LT_CODE = _bid.compute(S / "engine" / "logtriage")          # 코드만 — 설치 뒤 손댐 확인용
for _sh in ("run.sh", "stop.sh"):                           # 12차: 배포 지문에 들어가는 기동 스크립트는 LF 여야 한다(묶을 때 바꾸면 지문과 어긋남)
    assert b"\r" not in (S / _sh).read_bytes(), f"{_sh} 에 CR(윈도 줄끝)이 있습니다 — 리눅스에서 실행 실패"
LT_ID = _bid.compute_items(_bid.dist_items(S))              # 코드 + run.sh + stop.sh
print(f"  판 지문: {LT_ID}  (코드 {LT_CODE})")


def stamp(stage: Path, dist_id: str, code_id: str) -> None:
    """지문을 꾸러미 안에 적어 둔다 — 서버는 기동할 때 한 번 읽는다.

    돌고 있는 프로세스가 스크립트 파일을 **다시 읽어** 계산하면, 옛 프로세스가 새 파일을
    보고 거짓 성공을 말한다. 그것이 이 값으로 잡으려는 상황이다(GPT 8차·19차).
    """
    import json as _json
    (stage / "engine" / "logtriage" / _bid.STAMP).write_text(_json.dumps(
        {"_설명": "빌드가 만들어 넣는 파일 — 손으로 고치지 마십시오(지문 계산에서는 빠집니다)",
         "id": dist_id, "code": code_id, "scope": "engine+run.sh+stop.sh"},
        ensure_ascii=False, indent=2) + chr(10), encoding="utf-8")


stamp(S, LT_ID, LT_CODE)
(S / "VERSION.txt").write_text(
    f"LogTriage" + chr(10) + f"Version: {LT_BUILD}" + chr(10) + f"Build: {LT_ID}" + chr(10) * 2
    + "이 폴더가 어느 판인지 적어 둡니다. 돌고 있는 서버의 판은 /healthz 로 확인합니다:" + chr(10)
    + "  curl -s http://127.0.0.1:8088/healthz" + chr(10)
    + "  → \"build\" 가 Version 과, \"build_id\" 가 Build 와 같으면 이 판이 돌고 있는 것입니다." + chr(10)
    + chr(10)
    + "Version 은 사람이 보는 제품 판이라 패치해도 바뀌지 않습니다." + chr(10)
    + "Build 는 배포물 내용에서 뽑은 값이라 한 줄만 고쳐도 달라집니다 —" + chr(10)
    + "**패치가 실제로 먹었는지는 Build 로 봅니다.**" + chr(10)
    + chr(10)
    + "Build 에 들어가는 것 : engine/logtriage · run.sh · stop.sh" + chr(10)
    + "들어가지 않는 것     : apply_patch.sh·upgrade.sh(이 값을 박아 만드는 스크립트라 자기 참조),"
    + chr(10)
    + "                       python 런타임·wheel(우리 코드가 아님 — zip 의 SHA256 으로 봅니다)."
    + chr(10)
    + f"Code: {LT_CODE}" + chr(10)
    + "Code 는 엔진 코드만 본 값입니다. /healthz 의 code_id 와 다르면 설치 뒤에 파일이"
    + chr(10) + "바뀐 것입니다(그때는 code_modified 가 함께 나옵니다)." + chr(10),
    encoding="utf-8")

full = OUT / f"{NAME}-server-{VER}.zip"
n = zipdir(STAGE, full); print(full.name, full.stat().st_size // 1024 // 1024, "MB", n, "files")

# 패치 zip: engine 소스·데이터 + apply_patch.sh
P = STAGE / "_patch" / f"{NAME}-patch"; (P / "engine").mkdir(parents=True)
copy_engine(P / "engine")
for _n in ("run.sh", "stop.sh"):  # 기동 스크립트도 패치에 포함(run.sh 갱신)
    (P / _n).write_bytes((S / _n).read_bytes())
_up = OUT / "_upgrade.sh"
if _up.exists(): (P / "upgrade.sh").write_bytes(_up.read_bytes().replace(b"\r\n", b"\n"))
# 패치에도 VERSION.txt 를 넣는다 — 패치한 폴더의 VERSION.txt 가 옛 판이면 run.sh 의
# 판 지문 대조가 **거짓 경고**를 낸다(거짓 경고는 진짜 경고를 무디게 만든다).
(P / "VERSION.txt").write_bytes((S / "VERSION.txt").read_bytes())
stamp(P, LT_ID, _bid.compute(P / "engine" / "logtriage"))
_PATCH_ID = _bid.compute_items(_bid.dist_items(P))
assert _PATCH_ID == LT_ID, f"전체 묶음과 패치의 판 지문이 다릅니다: {LT_ID} vs {_PATCH_ID}"
_PATCH_CODE = _bid.compute(P / "engine" / "logtriage")
assert _PATCH_CODE == LT_CODE, f"전체 묶음과 패치의 코드 지문이 다릅니다: {LT_CODE} vs {_PATCH_CODE}"
(P / "apply_patch.sh").write_bytes(_bs.inject_id(_bs.inject(("""#!/usr/bin/env bash
# LogTriage Linux 패치 적용 — 이미 풀어 둔 구동 테스트 폴더(run.sh 가 있는 곳) 위에서 실행
#   unzip logtriage-patch-DATE.zip && bash logtriage-patch/apply_patch.sh /home/yms/log_svr
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-$(pwd)}"
echo "패치 폴더: $HERE"
echo "대상 폴더: $TARGET"
[ -d "$HERE/engine/logtriage" ] || { echo "! 패치 폴더 구조가 다릅니다 — $HERE/engine/logtriage 가 없습니다. zip 을 다시 풀고 'ls $HERE/engine' 에 logtriage·rules·errorcodes 가 보이는지 확인하십시오."; ls -la "$HERE"; exit 1; }
[ -f "$TARGET/run.sh" ] || { echo "! 대상 폴더에 run.sh 가 없습니다: $TARGET  (사용: bash apply_patch.sh <run.sh 가 있는 log_svr 경로>)"; exit 1; }
# 22차(GPT 166 P1-01): 예전 세 번째 자리(비밀번호)는 받지 않는다 — 명령행은 ps · /proc/<PID>/cmdline · 셸 기록에 남는다(run.sh 도 이미 거절)
if [ -n "${3:-}" ]; then
  echo "! 비밀번호를 명령행 인자로 받지 않습니다 — ps · /proc/<PID>/cmdline · 셸 기록에 남습니다. 아무것도 바꾸지 않고 멈춥니다."
  echo "  인자를 빼고 다시 실행하십시오:  bash apply_patch.sh <run.sh 폴더> [포트]"
  echo "  구동 테스트 서버의 비밀번호는 run.sh 가 가려서 묻거나 LOGTRIAGE_PASSWORD_FILE=<0600 파일> 로 줍니다."
  exit 1
fi
# 22차(GPT 165 P1-01): 새 판은 약한 공용 비밀번호로 뜨지 않는다 — **바꾸기 전에** 지금 쓰는 값을 새 규칙으로 진단한다
PYCHK=""
for c in "$TARGET/python/bin/python3" "${INSTALL_DIR:-/opt/logtriage}/venv/bin/python" python3; do
  [ -x "$c" ] || command -v "$c" >/dev/null 2>&1 || continue; PYCHK="$c"; break
done
pw_precheck() {   # $1=어디 값인지, 표준 입력=비밀번호 한 줄(원문은 화면 · 인자 · 파일 어디에도 남기지 않는다)
  [ -n "$PYCHK" ] || { echo "  (사전 진단 건너뜀: 파이썬을 찾지 못함 — $1)"; return 0; }
  local out rc=0
  out="$(cd "$HERE/engine" && "$PYCHK" -E -s -m logtriage.server --check-password --password-stdin 2>/dev/null)" || rc=$?
  if [ "$rc" = 2 ]; then
    echo "! $1 의 공용 비밀번호가 새 판 규칙에 걸립니다: $(printf '%s' "$out" | sed -n 's/.*"reason": *"\\([^"]*\\)".*/\\1/p')"
    echo "  아무것도 바꾸지 않고 멈춥니다. 비밀번호를 바꾼 뒤 다시 실행하십시오(예시 값 · 8자 미만 · 숫자만 · 흔한 낱말+숫자 · 키보드 연속 불가)."
    exit 3
  elif [ "$rc" != 0 ]; then echo "  (사전 진단 못 함: $1 — 새 판 기동 때 서버가 다시 검사합니다)"; fi
  return 0
}
SENV=/etc/logtriage/server.env
if [ -r "$SENV" ] || sudo -n test -r "$SENV" 2>/dev/null; then
  { grep -E '^LOGTRIAGE_PASSWORD=' "$SENV" 2>/dev/null || sudo -n grep -E '^LOGTRIAGE_PASSWORD=' "$SENV" 2>/dev/null || true; } \\
    | head -n 1 | cut -d= -f2- | tr -d '\\r' | { read -r P || true; [ -z "${P:-}" ] || printf '%s\\n' "$P" | pw_precheck "$SENV"; }
fi
if [ -n "${LOGTRIAGE_PASSWORD_FILE:-}" ] && [ -r "$LOGTRIAGE_PASSWORD_FILE" ]; then head -n 1 "$LOGTRIAGE_PASSWORD_FILE" | tr -d '\\r' | pw_precheck "$LOGTRIAGE_PASSWORD_FILE"; fi
mkdir -p "$TARGET/engine"
echo "[1/3] 소스 교체 → $TARGET/engine"
for d in logtriage rules rules-local errorcodes manuals tools deploy tests samples; do
  rm -rf "$TARGET/engine/$d"; cp -r "$HERE/engine/$d" "$TARGET/engine/$d"
done
# 공식 서식은 갱신하되 사용자가 등록한 서식(custom)·기본 정보(report_profile.json)는 보존
mkdir -p "$TARGET/engine/report-template"; cp -f "$HERE/engine/report-template/"*.hwpx "$HERE/engine/report-template/"*.yaml "$HERE/engine/report-template/"style_profile.json "$TARGET/engine/report-template/" 2>/dev/null || true
echo "[2/3] 데이터 폴더의 룰·코드·매뉴얼 갱신 (분석 이력·보고서·업로드는 유지)"
if [ -d "$TARGET/data" ]; then
  for d in rules errorcodes manuals; do rm -rf "$TARGET/data/$d"; cp -r "$HERE/engine/$d" "$TARGET/data/$d"; done
  cp -f "$HERE/engine/report-template/"*.hwpx "$HERE/engine/report-template/"*.yaml "$HERE/engine/report-template/"style_profile.json "$TARGET/data/report-template/" 2>/dev/null || true
  # 전사 설정 예시(r4): conf/*.example — 예시 파일이라 켜지지 않는다. auth.json·hub.json 으로 복사해야 적용
  mkdir -p "$TARGET/data/conf"; cp -f "$HERE/engine/deploy/server/conf-examples/"*.example "$TARGET/data/conf/" 2>/dev/null || true
fi
# 정식 설치(systemd logtriage-server, 기본 /opt/logtriage)가 있으면 그쪽 소스·룰도 함께 갱신하고 서비스를 재시작한다
INST="${INSTALL_DIR:-/opt/logtriage}"
SVC_OK=0
if [ -f /etc/systemd/system/logtriage-server.service ] && [ -d "$INST/logtriage" ]; then
  SUDO=""; [ "$(id -u)" != 0 ] && SUDO="sudo"
  # 2026-10-22 현장: 10-06 묶음으로 깐 유닛·환경 파일이 윈도 줄끝(CRLF)이라 User= 값이 'logtriage\\r' 로 읽혀
  # chown 이 '잘못된 그룹'으로 실패했고, set -e 로 패치가 여기서 멈춰 run.sh·stop.sh·VERSION.txt 갱신(3/3)을 건너뛰었다.
  # 그래서 ① 옛 설치 파일의 CR 을 먼저 고치고 ② 서비스 계정이 실제로 있는지 **바꾸기 전에** 확인한다(없으면 정식 설치 갱신만 건너뜀).
  for U in /etc/systemd/system/logtriage-server.service /etc/systemd/system/logtriage-cleanup.service /etc/logtriage/server.env; do
    if [ -f "$U" ] && [ "$(wc -c < "$U")" != "$(tr -d '\\r' < "$U" | wc -c)" ]; then   # CR 이 있으면(grep 은 환경마다 CR 처리가 달라 쓰지 않음)
      $SUDO sed -i 's/\\r$//' "$U" && echo "  옛 설치 파일의 윈도 줄끝(CRLF)을 고쳤습니다: $U"
      command -v restorecon >/dev/null 2>&1 && $SUDO restorecon "$U" 2>/dev/null || true   # sed -i 는 새 파일로 바꾼다 — SELinux 라벨을 기본값으로 되돌림
    fi
  done
  SVC_USER="$(grep -E '^User=' /etc/systemd/system/logtriage-server.service | head -n 1 | cut -d= -f2 | tr -d '\\r[:space:]')"; SVC_USER="${SVC_USER:-logtriage}"
  if id -u "$SVC_USER" >/dev/null 2>&1; then SVC_OK=1
  else echo "  ! 정식 설치 서비스 계정 '$SVC_USER' 이 이 서버에 없습니다 — 정식 설치(/opt) 갱신은 건너뛰고 구동 테스트 서버만 갱신합니다"; fi
fi
if [ "$SVC_OK" = 1 ]; then
  echo "[2.5/3] 정식 설치 갱신 → $INST (systemd logtriage-server, 서비스 계정 $SVC_USER)"
  BAK="$INST/.patch-bak-$(date +%Y%m%d%H%M%S)"; $SUDO mkdir -p "$BAK"
  for d in logtriage rules errorcodes manuals tools report-template samples; do [ -d "$INST/$d" ] && $SUDO cp -a "$INST/$d" "$BAK/$d"; done
  for d in logtriage rules errorcodes manuals tools samples; do $SUDO rm -rf "$INST/$d"; $SUDO cp -r "$HERE/engine/$d" "$INST/$d"; done
  $SUDO mkdir -p "$INST/report-template"; $SUDO cp -f "$HERE/engine/report-template/"*.hwpx "$HERE/engine/report-template/"*.yaml "$HERE/engine/report-template/"style_profile.json "$INST/report-template/" 2>/dev/null || true
  # 소유권: 코드(logtriage/·tools/)는 root, 룰팩으로 갱신되는 지식 파일(rules·errorcodes·manuals·report-template)과 data/ 는 서비스 계정
  $SUDO chown -R root:root "$INST/logtriage" "$INST/tools"; $SUDO chmod -R a+rX "$INST/logtriage" "$INST/tools"
  [ -d "$INST/samples" ] && { $SUDO chown -R root:root "$INST/samples"; $SUDO chmod -R a+rX,go-w "$INST/samples"; }   # 12차: 합성 견본도 root·읽기 전용
  $SUDO chown root:"$SVC_USER" "$INST"; $SUDO chmod 1770 "$INST"   # GPT 94차: 설치 폴더는 root:서비스그룹+sticky — root 소유 코드·견본을 서비스가 갈아 끼우지 못하게
  # GPT 95차 P0: 서비스가 쓸 수 있는 설치 폴더가 import 경로(작업 폴더)에 있으면 yaml.py 같은 가짜 모듈이 먼저 잡힌다 —
  # root 소유 import 전용 폴더(venv/lt-import, logtriage 링크 하나)를 작업 폴더로, venv 도 root 소유로(서비스가 site-packages 를 못 고치게)
  $SUDO mkdir -p "$INST/venv/lt-import"; $SUDO ln -sfn "$INST/logtriage" "$INST/venv/lt-import/logtriage"
  [ -d "$INST/venv" ] && { $SUDO chown -R root:root "$INST/venv"; $SUDO chmod -R go-w "$INST/venv"; }
  $SUDO sed -i "s#^WorkingDirectory=.*#WorkingDirectory=$INST/venv/lt-import#" /etc/systemd/system/logtriage-server.service
  for w in /usr/local/bin/logtriage /usr/local/bin/logtriage-server; do [ -f "$w" ] && $SUDO sed -i 's#cd "'"$INST"'" #cd "'"$INST"'/venv/lt-import" #' "$w"; done
  # GPT 96차: 옛 설치의 유닛·감싸개에도 -E -s(PYTHON* 환경 변수 무시)와 UnsetEnvironment
  U=/etc/systemd/system/logtriage-server.service
  $SUDO sed -i 's#/venv/bin/python -m logtriage.server#/venv/bin/python -E -s -m logtriage.server#' "$U"
  $SUDO grep -q '^UnsetEnvironment=' "$U" || $SUDO sed -i '/^ExecStart=/i UnsetEnvironment=PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONINSPECT' "$U"
  for w in /usr/local/bin/logtriage /usr/local/bin/logtriage-server; do [ -f "$w" ] && $SUDO sed -i 's#/venv/bin/python" -m#/venv/bin/python" -E -s -m#' "$w"; done
  $SUDO "$INST/venv/bin/python" -E -s -m compileall -q "$INST/logtriage" >/dev/null 2>&1 || true
  IMPORT_CHECK='import sys, os
bad = [p for p in (q or os.getcwd() for q in sys.path) if os.path.isdir(p) and os.access(p, os.W_OK)]
import logtriage
pk = os.path.dirname(os.path.realpath(logtriage.__file__))
for r, ds, fs in os.walk(pk):
    for n in ds + fs:
        q = os.path.join(r, n)
        if os.access(q, os.W_OK):
            bad.append(q)
print("  import 경로 점검(서비스 계정): 서비스가 쓸 수 있는 곳", len(bad))
for b in bad[:10]:
    print("    ", b)
sys.exit(1 if bad else 0)'
  if ! ( cd "$INST/venv/lt-import" && $SUDO runuser -u "$SVC_USER" -- "$INST/venv/bin/python" -E -s -c "$IMPORT_CHECK" ); then
    echo "  ! 서비스 계정이 고칠 수 있는 import 경로가 있습니다 — 서비스를 다시 띄우지 않고 이전 소스로 되돌립니다"
    for d in logtriage rules errorcodes manuals tools report-template samples; do [ -d "$BAK/$d" ] && { $SUDO rm -rf "$INST/$d"; $SUDO cp -a "$BAK/$d" "$INST/$d"; }; done
    exit 1
  fi
  $SUDO chown -R "$SVC_USER:$SVC_USER" "$INST/rules" "$INST/errorcodes" "$INST/manuals" "$INST/report-template"
  $SUDO install -d -o "$SVC_USER" -g "$SVC_USER" -m 0750 "$INST/data" "$INST/rules-local" "$INST/uploads" "$INST/reports"
  $SUDO install -d -o root -g "$SVC_USER" -m 0750 "$INST/conf"; $SUDO cp -f "$HERE/engine/deploy/server/conf-examples/"*.example "$INST/conf/" 2>/dev/null || true
  $SUDO chown root:"$SVC_USER" "$INST/conf/"* 2>/dev/null; $SUDO chmod 0640 "$INST/conf/"* 2>/dev/null || true
  command -v restorecon >/dev/null 2>&1 && $SUDO restorecon -RF "$INST" 2>/dev/null || true
  $SUDO systemctl daemon-reload
  if $SUDO systemctl restart logtriage-server && sleep 3 && $SUDO systemctl is-active --quiet logtriage-server; then
    echo "  systemd logtriage-server: active  ($(grep -E '^LOGTRIAGE_PORT=' /etc/logtriage/server.env 2>/dev/null || echo 'port: /etc/logtriage/server.env 참조'))"
    # 23차: 정식 설치는 nginx ↔ 앱 비밀이 있어야 사내망 평문 로그인 · 접속자 주소가 맞다 — 패치는 nginx 설정을 바꾸지 않으므로 알린다
    if { [ -f /etc/nginx/conf.d/logtriage.conf ] || [ -f /etc/nginx/sites-available/logtriage ]; } && ! $SUDO grep -q '^LOGTRIAGE_PROXY_SECRET=' /etc/logtriage/server.env 2>/dev/null; then
      echo "  ! 이 판부터 정식 설치는 nginx ↔ 앱 비밀(LOGTRIAGE_PROXY_SECRET)이 필요합니다 — 없으면 nginx 뒤 사내망 평문 로그인이 403 입니다."
      echo "    자료 · 비밀번호 · 포트는 그대로 두고 한 번만:  sudo bash $HERE/engine/deploy/server/install.sh --skip-pkgs"
      echo "    그다음 점검(읽기만):  sudo bash $INST/check_install.sh"
    fi
    $SUDO rm -rf "$BAK"
  else
    echo "  ! 서비스 재시작 실패 — 이전 소스로 되돌립니다 (journalctl -u logtriage-server -n 50 확인)"
    for d in logtriage rules errorcodes manuals tools report-template samples; do [ -d "$BAK/$d" ] && { $SUDO rm -rf "$INST/$d"; $SUDO cp -a "$BAK/$d" "$INST/$d"; }; done
    $SUDO systemctl daemon-reload; $SUDO systemctl restart logtriage-server || true
    echo "  롤백 완료: $(systemctl is-active logtriage-server)  (백업 보관: $BAK)"
  fi
fi
echo "[3/3] 구동 테스트 서버(run.sh) 재기동"
# 2026-10-22: 새 stop.sh 를 **먼저** 넣고 그것으로 끈다 — 옛 stop.sh 는 pid 파일(하위 셸 번호)만 봐서 남은 서버를 못 껐다
[ -f "$HERE/run.sh" ] && cp -f "$HERE/run.sh" "$HERE/stop.sh" "$TARGET/" && echo "  run.sh·stop.sh 갱신"
# VERSION.txt 도 함께 — run.sh 가 이 파일의 Build 와 /healthz 를 견준다. 옛 파일이 남으면 거짓 경고가 난다
[ -f "$HERE/VERSION.txt" ] && cp -f "$HERE/VERSION.txt" "$TARGET/" && echo "  VERSION.txt 갱신"
bash "$TARGET/stop.sh" || true
[ -f "$HERE/upgrade.sh" ] && cp -f "$HERE/upgrade.sh" "$TARGET/" || true
sleep 1
PORT="${2:-8088}"
bash "$TARGET/run.sh" "$PORT" || {
  echo "  run.sh 기동 실패(위 메시지 참조). 정식 설치(systemd)를 쓰는 서버라면 그쪽은 이미 갱신·재시작되었으므로 nginx/서비스 포트로 접속하십시오."; }

# ── [4/4] 실제로 돌고 있는 서버가 이번 판인지 확인한다 ────────────────────────────
# 지금까지 "패치했는데 화면이 그대로"인 일이 있었다. 대개 브라우저로 보는 포트가
# 갱신되지 않은 다른 인스턴스(대개 systemd /opt/logtriage 또는 nginx 뒤의 다른 포트)였다.
WANT="@@LOGTRIAGE_BUILD@@"
# 제품 판은 패치해도 그대로다(1.0.0 고정). **패치가 실제로 먹었는지는 판 지문으로 본다.**
WANT_ID="@@LOGTRIAGE_BUILDID@@"
echo "[4/4] 돌고 있는 서버 확인 (기대 빌드: $WANT)"
check_port() {
  local port="$1" body=""
  body="$(curl -fsS --max-time 5 "http://127.0.0.1:${port}/healthz" 2>/dev/null || true)"
  [ -z "$body" ] && { echo "  !!  포트 ${port} — 응답이 없습니다(서버가 안 뗴거나 다른 포트입니다)"; return 1; }
  local got
  got_id="$(printf '%s' "$body" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("build_id",""))
except Exception: print("")' 2>/dev/null || true)"
  if [ -n "$WANT_ID" ] && [ "$got_id" != "$WANT_ID" ]; then
    echo "  !!  포트 ${port} — 판 지문 ${got_id:-(없음)} (기대 ${WANT_ID})"
    echo "      제품 판은 같아도 **코드가 이 판이 아닙니다** — 옛 프로세스가 그대로 떠 있을 수 있습니다."
    return 2
  fi
  got="$(printf '%s' "$body" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("build",""))
except Exception: print("")' 2>/dev/null || true)"
  if [ "$got" = "$WANT" ]; then
    echo "  OK  포트 ${port} — 제품 판 ${got} · 판 지문 ${got_id}"
  elif [ -z "$got" ]; then
    echo "  !!  포트 ${port} — 빌드 표시가 없습니다(이번 판 이전 소스가 돌고 있습니다)"
    return 2
  else
    echo "  !!  포트 ${port} — 빌드 ${got} (기대 ${WANT}) — 갱신되지 않았습니다"
    return 2
  fi
}
sleep 2
BAD=0
PORTS="$PORT"
if [ -f /etc/logtriage/server.env ]; then
  SP="$(sed -n 's/^LOGTRIAGE_PORT=//p' /etc/logtriage/server.env | tr -dc '0-9')"
  [ -n "$SP" ] && [ "$SP" != "$PORT" ] && PORTS="$PORTS $SP"
fi
for p in $PORTS; do check_port "$p" || BAD=1; done
if [ "$BAD" != 0 ]; then
  echo
  echo "  ── 갱신되지 않은 서버가 있습니다. 아래를 확인하십시오 ──"
  echo "   1) 브라우저로 접속하는 주소·포트를 확인:  ss -ltnp | grep -E 'python|logtriage'"
  echo "   2) 그 포트를 띄운 프로세스의 소스 경로를 확인:  ps -ef | grep -m3 logtriage.server"
  echo "   3) 그 경로가 이 패치의 대상이 아니면 그 경로로 다시 실행:"
  echo "        INSTALL_DIR=<그 경로> bash $(basename "$0") <run.sh 폴더> <포트>"
  echo "   4) nginx 를 앞에 두었다면 nginx 가 바라보는 upstream 포트를 확인하십시오."
  echo '   확인용:  curl -s http://127.0.0.1:<포트>/healthz   →  "build_id" 가 위 기대 지문과 같으면 정상'
else
  echo "  모든 포트가 이번 판입니다."
fi
""").replace("DATE", VER), LT_BUILD, "apply_patch.sh"), LT_ID, "apply_patch.sh").encode("utf-8"))
(P / "README-패치.txt").write_bytes(f"""LogTriage {LT_BUILD} 패치
[이번 판에서 바뀐 것 — 먼저 보십시오]
1) [통합 현황] 에서 **운영 모드를 화면으로 고릅니다** — 단독 설치 / 본사 서버 / 사이트 서버.
   전에는 conf/hub.json 을 손으로 만들고 서비스를 다시 시작해야 했습니다. 이제 서비스를
   다시 시작하지 않고 바뀝니다. 관리자만 바꿀 수 있고, 누가 언제 바꿨는지 남습니다.
   · 사이트 서버로 바꾸면 이 서버가 본사로 자료를 보내기 시작합니다(원본 로그는 보내지 않습니다).
   · 보낼 수 있는 본사를 제한하려면 목록 파일을 두십시오(화면에서는 못 고칩니다).
     **서비스 계정이 쓸 수 없는 곳에 두는 것이 맞습니다** — 유닉스에서는 파일이 읽기 전용이어도
     부모 폴더에 쓸 수 있으면 지우고 새로 만들 수 있습니다.
       /etc/logtriage/trusted_hubs     (root 소유 0644, 서비스 계정 쓰기 불가 — 이쪽을 먼저 봅니다)
       <설치경로>/conf/hub_allow.txt   (위 파일이 없을 때만 봅니다)
       # 우리가 보낼 수 있는 본사
       https://logtriage.corp.local
     파일이 없으면 제한하지 않고, 화면이 "아무 데나 보낼 수 있는 상태" 라고 알려 줍니다.
   · 본사 주소는 https 만 받습니다. 인증서 검사를 끄거나 평문으로 보내는 길은 없앴습니다.
   · 본사 주소나 사이트 ID 를 바꾸면 **새 사이트 토큰을 넣어야 합니다**(쓰던 토큰을 다른 곳으로
     보내지 않습니다). 본사로 한 번 보낸 뒤에는 사이트 ID 를 바꿀 수 없습니다.

2) **회사 이메일 계정 로그인을 이번 판에서 내렸습니다**(요청하신 "메일 인증기능 제거, 추후 도입").
   처음 기동하는 서버는 **로그인 없이** 씁니다 — 내부망 전용입니다.
   ※ 이미 이메일 로그인을 쓰고 있는 서버는 **그대로 유지됩니다.** 끄려면:
        python3 -m logtriage.authmode --base <설치경로> off
     나중에 다시 켜려면 마지막 낱말을 local 로 바꾸면 됩니다(설정은 남아 있습니다).
   [알아 두십시오] 로그인이 없으면 **접속할 수 있는 사람이 모두 관리자**입니다.
   자산 기준 바꾸기·본사 연동 켜기도 막히지 않습니다. 망에서 이 서버에 닿을 수 있는 범위가
   곧 권한 범위가 됩니다. 접속을 망으로 막아 주십시오.

3) [이번 재빌드에서 정리한 것 — 동작은 같고, 판정이 더 믿을 만해졌습니다]
   · **올려 주신 파일의 머리글을 들고 있지 않습니다.** 빠르게 하려고 머리글을 그대로 캐시에
     담아 두었는데, 머리글 자체가 비밀일 수 있습니다('password=P@ssw0rd' 같은 머리글이 실제로
     있어서 가려서 보여 주기로 했습니다). 가려서 보여 주면서 한편으로 들고 있는 것은
     어긋나므로, 바깥에서 온 글자에 걸어 둔 캐시를 걷어냈습니다.
   · **보안 낱말 목록을 고치면 그 자리에서 반영됩니다.** 전에는 목록이 바뀌었는지를 길이로
     보았는데, 하나 빼고 하나 넣으면(길이가 같습니다) 놓쳤습니다. 이제 낱말 내용을 봅니다.
   · **사이트 ID 가 잠겼는지를 서버와 화면이 같은 값으로 봅니다.** 전에는 화면이 '보낸 적
     있음' 상태 파일로 칸을 잠갔는데, 그 파일이 지워지면 "칸은 열렸는데 저장하면 거절" 이
     됐습니다. 화면도 서버가 못 박은 신원을 그대로 받습니다.
   · 쓰이지 않게 된 코드를 지웠습니다. 남겨 두면 다음 사람이 그 기준으로 또 판단합니다.
   · **사이트 ID 가 본사 모드에서도 잠깁니다.** 포장한 서버를 띄워 눌러 보니, 화면은 칸을
     읽기 전용으로 잠가 두는데 본사 모드로는 다른 ID 가 그대로 들어갔습니다. 설정과 못 박은
     신원이 서로 달라지고, 본사 서버가 자기 과거 자료와 끊기는 길이었습니다. 이제 사이트 ID 를
     받는 모든 모드에서 같은 검사를 지납니다. 잠긴 ID 를 바꿔야 한다면 재설치로 가십시오.
   · 권한 관문을 **권한별로 전부 불러 보는 시험**을 넣었습니다(쓰기 API 전수 + 경로 엔드포인트).
   · **옛 설치를 올릴 때 사이트 신원을 승계합니다.** 구버전에는 신원 파일이 없어서, 이미 본사로
     보내 오던 서버가 새 판에서는 '잠기지 않은 새 설치' 로 보였습니다 — 업그레이드 한 번으로
     잠금이 풀렸습니다. 이제 보낸 적이 없다고 **확인될 때만** 열어 두고, 모르면 잠급니다.
   · **쿠키 정책이 올라가 기존 로그인을 한 번 끊습니다.** 다시 로그인해 주십시오. 코드만 고치면
     브라우저가 들고 있는 옛 쿠키는 그대로 남아, 세게 만든 보호가 걸리지 않습니다.
   · 예상 못 한 오류를 **그대로 돌려주지 않습니다.** 전에는 파이썬 예외 글에 내부 이름이 실려
     나갔습니다. 자세한 내용은 서버 기록에만 남깁니다(사용자에게 하는 안내는 그대로 보입니다).
   · 모드 변경이 어긋난 채 남으면 **화면이 크게 알리고 무엇을 확인할지 적어 줍니다.**
     전에는 "표식을 지우고 다시 시작" 만 적혀 있었는데, 표식만 지운다고 설정이 맞다는 보장이 없습니다.
   · 포장할 때 **들어가면 안 되는 것을 전수로 검사합니다** — 운영 자료·데이터베이스·열쇠·토큰·
     설치 신원·허용 목록·중간 파일·캐시. 소스가 깨끗한 것과 zip 이 깨끗한 것은 별개입니다.
   · **업그레이드가 서비스 중단이 되지 않습니다.** 옛 설정이 지금 검사에 걸려도 서버는 뜹니다 —
     본사 연동만 켜지 않고, 까닭을 기동 안내와 화면에 남깁니다. 전에는 그 자리에서 죽었습니다.
   · **옛 설정에 남은 없앤 항목을 파일에서도 지웁니다**(allow_http·verify_tls=false). 돌고 있는
     설정은 전부터 안전했지만, 파일에 남아 있으면 운영자가 읽고 '검사가 꺼져 있다' 고 믿습니다.
     옛 파일은 hub.json.bak 으로 남습니다. 평문(http) 본사 주소는 사이트 서버로 올라오지 않습니다.
   · 역할을 바꾸며 남은 **묵은 사이트 ID 를 진짜 신원으로 못 박지 않습니다.**
   · **'단독' 과 '본사 연동 중지됨' 을 구분해서 보여 줍니다.** 전에는 설정이 잘못돼 막힌 것도
     '단독 설치' 로 보였습니다 — 보내고 있다고 믿는 서버가 조용히 멈춰 있는 것을 몰랐습니다.
     연동이 막혀도 **로그 분석·자산·게시판은 그대로 씁니다.**
   · **읽을 수 없는 설정은 건드리지 않습니다.** 짐작해서 다시 쓰면 장애 원인과 운영자의
     증거를 한꺼번에 없앱니다. 지금 틀로 온전히 읽히는 설정만 정리합니다.
   · 설정에 **틀 번호(schema_version)** 를 적습니다. 이 판이 모르는 더 새 틀로 적힌 파일은
     읽지도 고치지도 않고 연동만 끕니다 — 되돌리기·내리기에서 새 설정이 지워지는 것을 막습니다.
   · 멈춤 표식에 **까닭 코드**가 들어갑니다(설정 오류·신원 충돌·되돌리기 실패). 비밀은 적지
     않고 설정 지문만 남겨, 복구할 때 '그때 그 설정 그대로인가' 를 판별합니다.

   [파일을 손으로 지우는 절차를 없앴습니다]
   전에는 잠금·멈춤을 풀려면 파일을 지우라고 안내했습니다. 그 손놀림은 **실제로 송신했던
   서버의 잠금도 똑같이 풀어 버립니다.** 이제 검사를 지나야 풀리는 명령을 씁니다.
     python3 -m logtriage.hubadmin --base <설치경로> status
     python3 -m logtriage.hubadmin --base <설치경로> recover --confirm
     python3 -m logtriage.hubadmin --base <설치경로> identity-reset --new-site <새 ID> --confirm
   무엇을 확인했는지 보여 주고, 누가 언제 풀었는지 기록에 남습니다. 설정을 고치지 않은 채
   풀려고 하면 거절합니다 — 같은 일을 또 겪는 길이기 때문입니다.

   [설정을 바꾸려고 서비스를 다시 시작하지 않습니다]
   모드 전환·본사 주소·토큰·주기는 전부터 재기동 없이 됐고, **복구 두 가지도 이제 화면에서**
   **합니다** — [통합 현황] 의 [검사하고 연동 다시 켜기] · [사이트 신원 바꾸기…].
   위 콘솔 명령은 **서버가 아예 못 떠서 화면을 열 수 없을 때**만 쓰십시오.

   [사이트 신원을 바꾸면 새 토큰이 필요합니다]
   쓰던 토큰은 옛 이름의 것입니다. 이름만 바꿔 그대로 보내면 '보내는 곳이나 사이트가 바뀌면
   새 토큰' 이라는 경계를 비켜 가는 것이라, 본사에서 재등록하고 받은 토큰을 함께 넣어야 합니다.
     소스에 글자가 있는지 보는 시험은 위 결함을 놓쳤습니다 — 글자는 있었고 자리만 틀렸습니다.
   ※ 이 셋 모두 쓰는 방법이 달라지는 것은 없습니다. 저장해 둔 자료·설정도 그대로입니다.

[먼저 읽어 주십시오 — 우리가 할 수 있는 약속]
LogTriage 는 비밀번호·토큰·개인키 같은 자격 정보를 **보관하는 기능을 두지 않습니다.**
자격 정보임을 알아볼 수 있는 머리글·값 표기는 읽는 자리에서 막습니다.
**다만 뜻 표시 없이 일반 글자 칸에 적힌 비밀값까지 완전히 판별하는 것은 보장하지 않습니다.**
  'Admin1234' 가 비밀번호인지 장비 이름인지 임시 코드인지는 글자만 보고 정할 수 없습니다.
  무작위해 보이는지로도 안 됩니다 — UUID·일련번호·인증서 지문이 똑같이 생겼습니다.
**비밀번호·키는 금고에 두십시오.** 지킬 수 없는 약속을 적어 두면, 그 약속을 믿고
사람들이 비밀번호를 적어 넣습니다. 그래서 못 하는 것을 못 한다고 적습니다.

[이번 판] 자산 기준 2판 · 현장이 항목을 더할 수 있습니다 · 보안 보강
- 자산 기준을 **2판**으로 고쳤습니다. 빠져 있던 셋을 넣었습니다.
  · 운영 환경(운영/검증/개발/시험) — 없으면 운영 장애인지 개발계 장애인지 몰라 대응 강도를 잘못 잡습니다.
  · 운영 상태(가동/대기/정비/폐기) — 없으면 **죽어 있어야 정상인 대기·폐기 장비를 장애로 잡습니다.**
  · 운영 책임 조직 — 책임을 사람이 아니라 조직에 묶습니다(사람은 퇴사·이동으로 빨리 낡습니다).
    1차 담당자는 권장으로 내렸습니다.
- **조건부 필수**라는 등급이 생겼습니다. "이 중 하나는 있어야 한다" 를 그대로 요구합니다.
  · 접속할 수 있는 주소: 관리 IP | 접속 이름(FQDN·URL) | 원격 콘솔
  · 로그와 이을 이름: 호스트명 | 인스턴스
  · 로그를 볼 곳: 로그 경로 | 로그를 보는 다른 방법(Windows 이벤트 로그·중앙 수집)
  'IP 필수' 로 못 박으면 NAT·VIP·DNS 환경에서 거짓 값을 채우게 됩니다. 빈칸을 막으려고
  억지값을 넣는 순간 대장은 거짓이 됩니다.
- OS·제품 버전은 공통에서 권장이고, **유형이 정해질 때 올려 받습니다**(서버: OS·호스트명,
  DBMS: 제품·포트, WAS·WEB: 제품·포트, 네트워크·SW: 제품).
- 정보의 나이를 답니다 — 최종 확인일·정보 출처. 낡은 대장은 없는 것보다 위험합니다.
- **기준이 올라가도 이미 등록된 자산을 막거나 지우지 않습니다.** '확인 필요' 로만 표시합니다.
  항목 id 는 한 번 정하면 바꾸지 않습니다(이름만 바꿉니다).

[기준 손보기 — 현장이 더 요구할 수 있습니다]  [자산 관리] 화면, 관리자만
- 기본 기준은 우리가 대는 최소한입니다. 현장에 더 필요한 항목을 더하고, 등급을 올리거나 내릴 수 있습니다.
- **'없으면 장애 때 무엇을 못 하는지' 를 적지 않으면 만들 수 없습니다** — 기준을 대는 쪽이 까닭을 대야 합니다.
- 내리는 것은 '쓰지 않음' 으로 두는 것이고 **지우지 않습니다**(그 항목으로 등록된 자산이 있을 수 있습니다).
- 누가 언제 무엇을 바꿨는지 남습니다.
- 핵심 아홉 항목(자산ID·자산명·유형·사이트·서비스·중요도·운영환경·운영상태·책임조직)은
  **필수 아래로 내릴 수 없습니다.** 한 사람이 내리면 그 뒤 전사의 대장이 헐거워집니다.

[보안 보강 — 이번 판에서 막은 것]
- **비밀번호·키 계열은 항목으로 만들 수 없습니다.** 만들 때와 **이름을 바꿀 때** 같은 검사를 지납니다
  (무해한 이름으로 만들고 개칭하는 길이 열려 있었습니다).
- 민감 열 판정을 다시 짰습니다. 한글 합성어 안에 숨은 것을 놓치고 있었습니다 —
  접속암호 · 계정비번 · 암호값 · 접속토큰 · 개인키값 · 키스토어암호 · JDBC URL · Connection String
  같은 표기가 이제 걸립니다(정상 열 'JDBC 드라이버 버전'·'DB 포트'·'Shipping' 은 살아남습니다).
- 칸 안의 비밀을 다섯 겹으로 봅니다 — 이름=값 · 주소 안의 자격 정보(scheme://user:pass@host) ·
  인증 헤더(Bearer·Basic) · 개인키 원문(BEGIN PRIVATE KEY) · JWT. 걸리면 그 칸을 통째로 버립니다.
- **자유롭게 적는 항목은 파일에서 자동으로 채우지 않습니다.** 그 칸에 들어온 글자가 비밀번호인지
  장비 이름인지 알아낼 방법이 없기 때문입니다. 코드·번호·IP·날짜처럼 **모양을 검사할 수 있는 것만**
  자동으로 채웁니다. 모양이 아닌 값은 넣지 않고 '확인 필요' 로 남깁니다.
- **뜻이 겹치는 열은 자동으로 맞추지 않습니다.** 틀린 자리에 넣는 것보다 비워 두는 편이 낫습니다.
- 버린 열의 머리글은 가려서 보여 줍니다(머리글 자리에 값이 들어와 있는 파일이 있습니다).
- 화면에서 보낸 요청이 아니면 API 를 받지 않습니다(다른 사이트의 폼이 관리자 권한을 빌려 쓰지 못하게).
  ※ 이 때문에 **우리 화면을 거치지 않고 /api/<이름> 을 직접 부르던 외부 스크립트가 있다면
     `X-NMS-Request: 1` 과 `Content-Type: application/json` 을 함께 보내야 합니다.**
     에이전트(/api/nms/agent)와 GET 요청은 영향이 없습니다.
- 세션 쿠키를 SameSite=Strict 로 올렸습니다. **바깥 링크를 눌러 들어오면 한 번 더 눌러야**
  로그인 상태로 보일 수 있습니다 — 보안을 앞세운 결과입니다.
- 사람이 화면에서 **직접 적는 값**도 같은 검사를 지납니다(전에는 파일만 봤습니다).
  접속 방법에 'ssh pw=1234' 처럼 적으면 받지 않고 '확인 필요' 로 표시합니다.
- 우리 보안 사전이 늘어나면, **이미 만들어 둔 현장 항목도 다시 검사합니다.** 어긋나면 지우지 않고
  자동 채움에서만 빼고 관리자에게 알립니다.
- 기준 손보기는 사람별 120회/10분으로 제한합니다(계정이 탈취돼도 기록을 무한히 불리지 못하게).

[받아들인 불편]  보안을 세게 잡은 대가로 아래 열은 자동으로 읽지 않습니다. 필요하시면 머리글을
바꿔 다시 올리시면 됩니다(무엇 때문에 걸렸는지 화면이 낱말까지 알려 줍니다).
  인증서 지문 · Keystore/PEM 경로 · 로그인 URL · 인증 방식 · OTP 사용 여부 · PW 변경일 · Token 만료일
  그리고 칸 안의 값도 같은 기준으로 봅니다 — 'Community 서버'·'Token 만료일 2027-01-01' 처럼
  낱말+공백+값 꼴이면 그 칸을 가져오지 않습니다. 예외 규칙은 만들지 않았습니다
  (예외가 늘면 그것이 곧 우회로가 됩니다).

[누적 내용]
- 로그인: conf/auth.json 의 mode 를 "local" 로 두면 회사 이메일(@solideos.com)과 비밀번호로 로그인합니다.
  비밀번호는 원문 저장 없이 ① 서버 키 페퍼(HMAC-SHA256) ② scrypt ③ ChaCha20-Poly1305 암호화의 3겹으로 보관하고,
  첫 로그인 때 반드시 변경하게 합니다. 화면은 (주)솔리데오 CI(크림슨)로 맞췄습니다.
  계정 발급:  python3 -m logtriage.accounts --base <설치경로> add --email ○○@solideos.com --role operator [--asset-sites <사이트ID>]
  서버 키 conf/secret.key 는 백업·이전 시 DB 와 함께 옮기고, 백업 묶음과는 분리 보관하십시오(유실 시 전체 비밀번호 초기화).
- 전사 배포: conf/auth.json(통합 로그인·권한·사이트별 자산 조회 권한) · conf/hub.json(본사 중앙 수집). 예시는 conf/*.example 로 함께 들어갑니다.
- 예약 자동화: 상시 상태 점검·정기 보고(HTML·PDF·HWPX), 저장 경로 설정과 화면에서 바로 내려받기.
- 이전 패치 내용(인프라 감시·자원 관리·수행 절차·버전 카탈로그 등)도 모두 포함된 누적판입니다.
[직접 업그레이드 지원 최소 판]  2026.09.30
  이보다 오래된 설치는 2026.09.30 을 거쳐 올리십시오. 지원 범위를 정해 두지 않은 채 훨씬
  오래된 설치가 바로 올라오는 것이 가장 위험합니다 — 그 경로는 시험하지 않았습니다.

적용:  unzip -o logtriage-patch-{VER}.zip
       bash logtriage-patch/apply_patch.sh <run.sh 가 있는 폴더> [포트=8088]   (예: /home/yms/log_svr 8088 — 비밀번호는 인자로 받지 않음)
       → 소스·룰·코드·매뉴얼 교체 후 서버 자동 재기동. 정식 설치(systemd)가 있으면 /opt/logtriage 도 함께 갱신·재시작합니다.
확인:  브라우저 접속 → 로그인 화면이 흰 바탕 + 붉은색(CI)인지 → 발급받은 계정으로 로그인 → 첫 로그인 비밀번호 변경 안내가 뜨는지.
자체 시험: cd <설치경로>/engine && python3 -m unittest tests.test_accounts tests.test_enterprise tests.test_automation_r4
""".encode("utf-8"))
for f in (P / "apply_patch.sh", P / "run.sh", P / "stop.sh"):
    f.write_bytes(f.read_bytes().replace(b"\r\n", b"\n"))
patch = OUT / f"{NAME}-patch-{VER}.zip"
n = zipdir(STAGE / "_patch", patch); print(patch.name, patch.stat().st_size // 1024, "KB", n, "files")
shutil.rmtree(STAGE, ignore_errors=True)

# py311 전용 패치 zip(작음): wheels 는 py3.11 에서 쓰는 것만 남김
#
# 전에는 'cp311 아니면 버린다' 였다. 그래서 **py3-none-any 인 pycparser 가 함께 버려졌고**,
# 이 작은 패치만으로는 cryptography 가 끝내 안 깔렸다 — 전체 패치에서 고친 것과 똑같은
# 실수를 여기서 한 번 더 한 셈이다(2026-10-02). 판을 하나로 모은다.
import zipfile as _zf


def _keep_wheel(name: str) -> bool:
    low = name.lower()
    return "cp311" in low or "py3-none-any" in low      # 어느 파이썬에서나 쓰는 순수 wheel


small = OUT / f"{NAME}-patch-py311-{VER}.zip"
with _zf.ZipFile(patch) as zin, _zf.ZipFile(small, "w") as zout:
    n = 0
    for zi in zin.infolist():
        if "/deploy/server/wheels/" in zi.filename and not _keep_wheel(zi.filename):
            continue
        zout.writestr(zi, zin.read(zi.filename)); n += 1
print(small.name, small.stat().st_size // 1024, "KB", n, "files")
# 작은 패치도 **혼자서** 암호 라이브러리를 깔 수 있어야 한다 — 빠지면 빌드를 멈춘다.
with _zf.ZipFile(small) as _zs:
    _wh = [x.rsplit("/", 1)[-1].lower() for x in _zs.namelist() if x.endswith(".whl")]
_miss = [k for k in WHEEL_NEED if not any(w.startswith(k) for w in _wh)]
assert not _miss, f"py311 패치에 wheel 이 빠졌습니다: {_miss} — 폐쇄망에서 설치가 실패합니다"

# 다 만든 뒤 zip 을 다시 열어 빌드 표시가 이번 판 하나뿐인지 본다
_bs.audit_zip(patch, LT_BUILD)
_bs.audit_zip(small, LT_BUILD)
_bs.audit_zip(full, LT_BUILD)
# 소스 트리가 깨끗한 것과 **최종 zip 이 깨끗한 것은 별개다**(GPT) — 셋 다 열어 본다
for _z in (full, patch, small):
    _bs.audit_contents(_z)
# 12차: 설치 안내가 대조하라는 SHA256 파일도 이 묶음으로 다시 쓴다(10-06 손으로 만든 값이 남아 새 묶음과 어긋났다)
import linux_sums as _ls  # noqa: E402
_ls.main()
