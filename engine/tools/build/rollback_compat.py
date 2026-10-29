# -*- coding: utf-8 -*-
"""되돌리기 호환 시험(2026-10-15 아이디어 12) — '되돌리기 판의 코드가 새 판이 만든 자료를 읽을 수 있는가'.

빌드마다 그 판의 엔진 소스를 deploy/local/backup/src/src-<GUI 해시 앞16>.zip 으로 남긴다(snapshot).
되돌리기 판(dist/LogTriage.exe.이전판)의 소스 스냅숏을 풀어, **지금 판이 만든 자료**로 다음을 돌려 본다:
  ① 서식 통계(style_profile.json — 서식별·문장 끝·상한 포함)로 공식 서식 2종 채우기
  ② 지금 판이 등록한 사용자 서식(원본 지문·자동 판단 기록 포함) 채우기
  ③ 룰·코드 읽기 ④ 격리 폴더(.backup-QZ_…)를 자동 정리가 지우지 않음
스냅숏 옆 .sha256 은 '손상·바뀜 확인'이지 진위(누가 만들었나) 보증이 아니다 — 빌드 PC 의 엔진 소스와 같은 신뢰 수준이다.
옛 코드는 감사 훅 울타리(작업 폴더 밖 쓰기·읽기, 프로세스·네트워크 거부) 안에서만 돈다 — 보조 장치일 뿐 OS 수준 보안 격리가 아니다
(파이썬 감사 훅은 ctypes·네이티브 코드로 우회될 수 있다, GPT 35차). 그래서 이 도구는 이 빌드 체계가 만든 자체 스냅숏만 돌린다 —
외부·사용자 코드를 넣어 돌리면 안 된다.
결과는 deploy/local/build/rollback_compat.json — build_ledger.py 가 '되돌리기 자격' 칸에 적는다.
사용: python tools/build/rollback_compat.py [--rollback-exe 경로] [--snapshot zip]
       python tools/build/rollback_compat.py snapshot   (지금 소스를 지금 배포 exe 해시 이름으로 남김)
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
LOCAL = ENGINE / "deploy" / "local"
SRC = LOCAL / "backup" / "src"
RESULT = LOCAL / "build" / "rollback_compat.json"

GUARD = r'''
# 되돌리기 호환 시험의 울타리(GPT 34차) — 옛 코드가 돌기 전에 감사 훅을 건다. 한 번 걸면 풀 수 없다.
#   쓰기·지우기·이름 바꾸기·폴더 만들기: 일회용 작업 폴더 안만 / 읽기: 작업 폴더 + 파이썬 설치 폴더(표준·외부 모듈)만
#   프로세스 실행·네트워크 연결: 모두 거부. OS 계정 격리는 아니지만(보안 설정 변경 없이), 파이썬으로 하는 파일·프로세스·망 접근은 여기서 막힌다.
import os as _os, sys as _sys, site as _site
_W = _os.path.normcase(_os.path.realpath(_sys.argv[3]))
_R = [_W] + [_os.path.normcase(_os.path.realpath(x)) for x in {_sys.prefix, _sys.base_prefix, _sys.exec_prefix, *(_site.getsitepackages() if hasattr(_site, "getsitepackages") else [])}]
_WF = getattr(_os, "O_WRONLY", 1) | getattr(_os, "O_RDWR", 2) | getattr(_os, "O_CREAT", 0x100) | getattr(_os, "O_APPEND", 8) | getattr(_os, "O_TRUNC", 0x200)
def _under(p, roots):
    p = _os.path.normcase(_os.path.realpath(_os.fsdecode(p)))
    return any(p == r or p.startswith(r + _os.sep) for r in roots)
def _hook(ev, a):
    if ev == "open":
        path, mode, flags = (list(a) + [None, None, 0])[:3]
        if path is None or isinstance(path, int):
            return
        w = (isinstance(mode, str) and any(c in mode for c in "wax+")) or bool((flags or 0) & _WF)
        if not _under(path, [_W] if w else _R):
            raise PermissionError(f"울타리 밖 {'쓰기' if w else '읽기'} 거부")
    elif ev in ("os.remove", "os.rename", "os.replace", "os.rmdir", "os.mkdir", "shutil.rmtree", "shutil.move", "os.truncate", "os.chmod", "os.link", "os.symlink"):
        for x in a:
            if isinstance(x, (str, bytes)) or hasattr(x, "__fspath__"):
                if not _under(x, [_W]):
                    raise PermissionError("울타리 밖 변경 거부")
    elif ev in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.startfile", "ctypes.dlopen",
                "socket.connect", "socket.bind", "socket.getaddrinfo", "winreg.OpenKey", "winreg.CreateKey"):
        if ev == "ctypes.dlopen":
            return   # 표준 모듈이 내부적으로 부르는 경우가 있다 — 실행·망·파일 쪽에서 막는다
        raise PermissionError("울타리: 프로세스·네트워크·레지스트리 거부")
_sys.addaudithook(_hook)
'''

OLD_SCRIPT = r'''
import json, sys, shutil, time
from pathlib import Path
data = Path(sys.argv[1]); engine = Path(sys.argv[2])
out = {"steps": {}}
def _fence():
    probe = Path(sys.argv[4])
    for what, fn in (("밖 읽기", lambda: probe.read_text(encoding="utf-8")),
                     ("밖 쓰기", lambda: probe.with_name("written_by_old.txt").write_text("x", encoding="utf-8")),
                     ("밖 지우기", lambda: probe.unlink()),
                     ("프로세스", lambda: __import__("subprocess").run(["cmd", "/c", "echo x"])),
                     ("네트워크", lambda: __import__("socket").create_connection(("127.0.0.1", 9), 1))):
        try:
            fn()
        except PermissionError:
            continue
        except Exception as e:   # 다른 이유로 실패 = 울타리가 막은 것이 아님
            raise RuntimeError(f"{what}: 울타리가 아닌 다른 이유로 실패 {type(e).__name__}")
        raise RuntimeError(f"{what}: 막히지 않았습니다")
    return {}
def step(name, fn):
    try:
        out["steps"][name] = {"ok": True, **(fn() or {})}
    except Exception as e:
        out["steps"][name] = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}"}
from logtriage import report, service, safe_backup, rules
step("fence", _fence)
import logtriage as _lt
if "lt_rbc_" not in str(Path(_lt.__file__)):   # 옛 소스가 아니라 지금 소스를 불렀다면 시험이 뜻이 없다
    out["steps"]["code"] = {"ok": False, "error": "되돌리기 판 소스가 아닌 코드를 읽었습니다"}
else:
    out["steps"]["code"] = {"ok": True}
def gen():
    inc = service.run_analysis([{"path": str(engine / "samples" / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                               rules_dir=engine / "rules", local_dir=engine / "rules-local", codes_dir=engine / "errorcodes")
    r = report.generate(data / "tdir" / "template.yaml", inc, data / "out")
    n_custom = sum(1 for f in r.get("files", []) if f.get("form") == "custom")
    err = r.get("forms_error") or r.get("custom_errors") or r.get("error")
    if err or len(r.get("hwpx_all") or []) < 3 or n_custom < 1:
        raise RuntimeError(f"보고서 {len(r.get('hwpx_all') or [])}건 · 사용자 서식 {n_custom} · 오류 {err}")
    return {"forms": len(r["hwpx_all"])}
step("report", gen)
def rl():
    rs = rules.load_rules(engine / "rules", engine / "rules-local")
    if len(rs) < 100:
        raise RuntimeError(f"룰 {len(rs)}개")
    return {"rules": len(rs)}
step("rules", rl)
def qz():
    q = data / "base" / ".backup-QZ_compat"
    safe_backup._sweep_stale(data / "base")
    if not q.exists():
        raise RuntimeError("격리 폴더가 자동 정리로 지워짐")
    return {}
step("quarantine", qz)
print(json.dumps(out, ensure_ascii=False))
'''


def sha16(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()[:16]


def snapshot(exe: Path | None = None) -> Path:
    """지금 엔진 소스(logtriage/)를 배포 exe 해시 이름으로 남긴다 — 이 판이 나중에 되돌리기 판이 될 때 쓴다."""
    exe = exe or LOCAL / "dist" / "LogTriage.exe"
    SRC.mkdir(parents=True, exist_ok=True)
    out = SRC / f"src-{sha16(exe)}.zip"
    if out.exists():
        return out
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted((ENGINE / "logtriage").rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts:
                z.write(p, p.relative_to(ENGINE).as_posix())
    # 무결성(GPT 33차): 만든 때의 sha256 을 옆에 남기고, 시험 전에 다시 잰다 — 바뀌었으면 그 코드를 돌리지 않는다
    out.with_suffix(".zip.sha256").write_text(_sha(out) + "\n", encoding="utf-8")
    return out


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def verify_snapshot(snap: Path) -> str:
    """'' = 정상, 아니면 이유. 지문 파일이 없거나 다르면 돌리지 않는다."""
    side = snap.with_suffix(".zip.sha256")
    if not side.is_file():
        return "스냅숏 지문 파일(.sha256)이 없습니다"
    want = side.read_text(encoding="utf-8").split()[0].lower() if side.read_text(encoding="utf-8").strip() else ""
    return "" if want == _sha(snap) else "스냅숏이 만든 뒤 바뀌었습니다(지문 불일치)"


def make_new_data(root: Path) -> None:
    """지금 판(이 소스) 코드로 자료를 만든다 — 서식 통계·사용자 서식(지문 포함)·격리 폴더."""
    sys.path.insert(0, str(ENGINE))
    import re
    from logtriage import report_custom as rc
    tdir = root / "tdir"
    tdir.mkdir(parents=True)
    for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json", "template.yaml"):
        if (ENGINE / "report-template" / f).exists():
            shutil.copyfile(ENGINE / "report-template" / f, tdir / f)
    v = root / "v.hwpx"
    zi = zipfile.ZipFile(tdir / "form_status.hwpx")
    with zipfile.ZipFile(v, "w", zipfile.ZIP_DEFLATED) as zo:
        for n in zi.namelist():
            b = zi.read(n)
            if re.match(r"Contents/section\d+\.xml", n):
                b = b.decode("utf-8").replace(">소속<", ">부서<").encode("utf-8")
            zo.writestr(zi.getinfo(n), b)
    rc.save_template(tdir, v, "호환 시험 서식", rc.analyze_form(v)["fields"])
    q = root / "base" / ".backup-QZ_compat"
    (q / "stage").mkdir(parents=True)
    (q / "stage" / "x").write_text("x", encoding="utf-8")
    (q / ".qz").write_text(json.dumps({"at": time.time() - 3 * 86400, "from": ".backup-compat"}), encoding="utf-8")


def run(snap: Path) -> dict:
    res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "snapshot": snap.name, "result": "fail", "steps": {}}
    why = verify_snapshot(snap)
    if why:
        res["steps"] = {"integrity": {"ok": False, "error": why}}
        return res
    work = Path(tempfile.mkdtemp(prefix="lt_rbc_"))
    try:
        old = work / "old"
        with zipfile.ZipFile(snap) as z:
            for n in z.namelist():   # 압축 안 경로 검사 — 바깥으로 풀리지 않게
                if n.startswith("/") or ".." in Path(n).parts or not n.startswith("logtriage/"):
                    raise ValueError(f"스냅숏 안에 허용되지 않는 경로: {n[:60]}")
            z.extractall(old)
        data = work / "data"
        make_new_data(data)
        # 원본 격리(GPT 33차): python -I 는 샌드박스가 아니다 — 옛 코드에는 엔진·배포 폴더 경로를 주지 않고,
        # 필요한 룰·코드·표본만 일회용 복사본으로 넘긴다(옛 코드가 무엇을 쓰든 이 임시 폴더 안)
        eng = work / "eng"
        for d in ("rules", "rules-local", "errorcodes"):
            if (ENGINE / d).is_dir():
                shutil.copytree(ENGINE / d, eng / d)
        (eng / "samples").mkdir(parents=True)
        shutil.copyfile(ENGINE / "samples" / "alert_orcl.log", eng / "samples" / "alert_orcl.log")
        script = work / "old_check.py"
        script.write_text(GUARD + OLD_SCRIPT, encoding="utf-8")
        outside = Path(tempfile.mkdtemp(prefix="lt_rbc_out_"))     # 작업 폴더 밖 — 옛 코드가 건드리면 안 되는 곳
        (outside / "probe.txt").write_text("keep", encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC", "PATHEXT")}
        env.update({"PYTHONIOENCODING": "utf-8", "PYTHONPATH": str(old), "PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(work), "TMP": str(work)})
        r = subprocess.run([sys.executable, "-I", "-c", f"import sys;sys.path.insert(0,{str(old)!r});exec(open({str(script)!r},encoding='utf-8').read())",
                            str(data), str(eng), str(work), str(outside / "probe.txt")], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=600, cwd=str(work))
        try:
            out = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"steps": {"run": {"ok": False, "error": (r.stderr or r.stdout)[-300:]}}}
        res["steps"] = out["steps"]
        # 바깥 파일이 그대로인지 부모가 다시 본다(자식의 보고만 믿지 않는다)
        intact = (outside / "probe.txt").read_text(encoding="utf-8") == "keep" and not (outside / "written_by_old.txt").exists()
        res["steps"]["fence_check"] = {"ok": intact} if intact else {"ok": False, "error": "작업 폴더 밖 파일이 바뀌었습니다"}
        shutil.rmtree(outside, ignore_errors=True)
        res["result"] = "pass" if out["steps"] and all(s.get("ok") for s in out["steps"].values()) else "fail"
    except Exception as e:   # noqa: BLE001
        res["steps"] = {"setup": {"ok": False, "error": f"{type(e).__name__}: {e}"}}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return res


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["snapshot"]:
        print(snapshot())
        return 0
    exe = Path(argv[argv.index("--rollback-exe") + 1]) if "--rollback-exe" in argv else LOCAL / "dist" / "LogTriage.exe.이전판"
    snap = Path(argv[argv.index("--snapshot") + 1]) if "--snapshot" in argv else (SRC / f"src-{sha16(exe)}.zip" if exe.is_file() else None)
    if not snap or not snap.is_file():
        res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "result": "no_snapshot", "steps": {},
               "why": "되돌리기 판의 소스 스냅숏이 없습니다 — 그 판을 빌드할 때 snapshot 을 남겨야 합니다"}
    else:
        res = run(snap)
    if "--no-save" not in argv:
        RESULT.parent.mkdir(parents=True, exist_ok=True)
        RESULT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"되돌리기 호환: {res['result']} — " + " · ".join(f"{k} {'통과' if v.get('ok') else '실패: ' + v.get('error', '')}" for k, v in res["steps"].items())
          + (f" {res.get('why', '')}" if res.get("why") else ""))
    return 0 if res["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
