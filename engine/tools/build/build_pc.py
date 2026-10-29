"""PC(단독 실행·Windows 서버 모드) 빌드 한 명령 — 12차(마스터: "PC 와 리눅스 서버 설치용이 같은 판으로 빌드되어 관리").

이번 차수에 손으로 네 번 되풀이하며 한 번 틀린 순서를 고정한다(설치 폴더 자료를 복제하면 지식 폴더까지 옛것으로 덮였다).
  1) 판 도장: 엔진 원본(logtriage/)의 코드 지문을 deploy/local/build/pc_stamp/_build_id.json 에 — 두 spec 이 exe 안 logtriage/ 로 넣는다.
     리눅스 묶음(build_linux_pkgs.py)이 같은 원본에서 세는 code 와 같은 값이어야 한다(release_parity.py 가 대조).
  2) PyInstaller: logtriage.spec(GUI) · logtriage-cli.spec(CLI) → <검증도구>/<이름>/dist
  3) run 폴더: exe 둘을 옮기고 → 설치본 자료 복제(exe_guard --clone-data, 설치 폴더는 읽기만) → **그다음** 엔진 지식(rules·errorcodes·manuals)을
     다시 넣는다 → report-template/custom 빈 폴더 → 사용법·소개서
  4) 지식 세대 기록(knowledge_gen.write_gen) + 매니페스트(check_dist_knowledge --after) + check_gen 통과
  5) run/_pc_build.json: 제품 판·코드 지문·지식 지문·exe 해시 — 판 대조와 장부가 읽는다
사용: python tools/build/build_pc.py <이름>      예) exe29  → C:\\Users\\dbals\\Desktop\\로그수집기\\검증도구\\exe29\\run
설치는 하지 않는다(포장본 점검 exe_all → install_move.py 가 따로).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
LOCAL = ENGINE / "deploy" / "local"
TOOLS = ENGINE.parent / "검증도구"
sys.path.insert(0, str(ENGINE))
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def knowledge_hashes(base: Path) -> dict:
    from logtriage.knowledge_gen import dir_hash
    return {d: dir_hash(base / d) for d in ("rules", "errorcodes", "manuals")}


def stamp() -> dict:
    from logtriage import BUILD, buildid
    code = buildid.compute(ENGINE / "logtriage")
    st = {"id": code, "code": code, "scope": "pc", "build": BUILD, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
          "knowledge": knowledge_hashes(ENGINE)}
    d = LOCAL / "build" / "pc_stamp"
    d.mkdir(parents=True, exist_ok=True)
    (d / "_build_id.json").write_text(json.dumps(st, ensure_ascii=False, indent=1), encoding="utf-8")
    return st


def run(cmd: list, cwd: Path, log: Path | None = None) -> None:
    if log:
        with open(log, "wb") as fo:
            r = subprocess.run(cmd, cwd=str(cwd), stdout=fo, stderr=subprocess.STDOUT, env=ENV)
    else:
        r = subprocess.run(cmd, cwd=str(cwd), env=ENV)
    if r.returncode:
        raise SystemExit(f"실패({r.returncode}): {' '.join(map(str, cmd))}" + (f" — 기록 {log}" if log else ""))


def main(argv=None) -> int:
    name = (argv or sys.argv[1:] or [""])[0]
    if not name or "/" in name or "\\" in name:
        raise SystemExit("사용: python tools/build/build_pc.py <이름>  (예: exe29)")
    out = TOOLS / name
    if out.exists():
        raise SystemExit(f"{out} 가 이미 있습니다 — 새 이름을 주십시오(지난 빌드를 덮지 않는다)")
    st = stamp()
    print(f"[PC 빌드] 판 {st['build']} · 코드 지문 {st['code']}", flush=True)
    for spec, wp in (("logtriage.spec", "build"), ("logtriage-cli.spec", "build-cli")):
        run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--distpath", str(out / "dist"), "--workpath", str(out / wp),
             str(LOCAL / spec)], ENGINE, TOOLS / f"{name}-{wp}.log")
    rd = out / "run"
    rd.mkdir(parents=True)
    for exe in ("LogTriage.exe", "logtriage-cli.exe"):
        shutil.move(str(out / "dist" / exe), str(rd / exe))
    run([sys.executable, str(TOOLS / "exe_guard.py"), "--clone-data", str(rd)], TOOLS)
    for d in ("rules", "errorcodes", "manuals"):                 # 복제가 설치본(옛) 지식으로 덮었다 — 엔진 것으로 다시
        shutil.rmtree(rd / d, ignore_errors=True)
        shutil.copytree(ENGINE / d, rd / d, ignore=shutil.ignore_patterns("__pycache__"))
    if not (rd / "rules-local").is_dir():
        shutil.copytree(ENGINE / "rules-local", rd / "rules-local")
    (rd / "report-template" / "custom").mkdir(parents=True, exist_ok=True)
    for f in ("사용법.txt", "LogTriage-1.0.0_소개.html", "LogTriage-server.cmd", "server.conf.example"):
        if (LOCAL / f).is_file():
            shutil.copy2(LOCAL / f, rd / f)
    from logtriage.knowledge_gen import check_gen, write_gen
    write_gen(rd, "knowledge_release")
    run([sys.executable, str(ENGINE / "tools" / "build" / "check_dist_knowledge.py"), "--after", "--dist", str(rd)], ENGINE)
    g = check_gen(rd)
    if g:
        raise SystemExit(f"지식 세대 기록 대조 실패: {g}")
    kh = knowledge_hashes(rd)
    if kh != st["knowledge"]:
        raise SystemExit(f"run 폴더 지식이 엔진과 다릅니다: {kh} vs {st['knowledge']}")
    rec = {**st, "gui_sha": sha(rd / "LogTriage.exe"), "cli_sha": sha(rd / "logtriage-cli.exe"), "run": str(rd)}
    (rd / "_pc_build.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"[PC 빌드] 끝 — {rd}\n  GUI {rec['gui_sha'][:16]} · CLI {rec['cli_sha'][:16]} · 지식 {', '.join(f'{k} {v[:8]}' for k, v in kh.items())}")
    print("  다음: python 검증도구/exe_all.py <run> → tools/build/build_linux_pkgs.py → tools/build/release_parity.py <run>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
