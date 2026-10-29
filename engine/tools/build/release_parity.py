"""PC ↔ 리눅스 서버 판 대조 — 12차(마스터: "PC(단독설치용)과 리눅스 서버 설치용이 동일한 버전으로 빌드되어 관리").

같은 판이란 무엇인가 — 여기서 하나씩 대조하고, 하나라도 다르면 실패(종료 코드 1):
  ① 제품 판(BUILD)            PC 빌드 기록 = 리눅스 묶음 engine/logtriage/__init__.py = VERSION.txt
  ② 코드 지문(code)           PC exe 에 박은 도장 = 리눅스 묶음 도장 = 리눅스 묶음 원본에서 다시 센 값 = 엔진 원본에서 센 값
                              (리눅스 '배포 지문 id' 는 run.sh·stop.sh 까지 넣은 값이라 PC 와 다른 것이 정상 — 그래서 code 로 본다)
  ③ 지식 지문                  rules·errorcodes·manuals: PC run 폴더 = PC exe 도장(내장 지식) = 리눅스 묶음 = 엔진
  ④ 12차 기능 파일             os_solution.py·parallel.py·solutions_osmatrix.yaml·py39_compat.py·이력 가져오기 띠 — 두 쪽 모두
  ⑤ 리눅스 전용                3.9 호환(py39_compat) 0 · 셸 스크립트 bash -n 0 · 패치 두 묶음도 같은 code
결과: deploy/local/LogTriage-1.0.0-판대조.md · .json (빌드 장부가 읽는다)
사용: python tools/build/release_parity.py <PC 빌드 run 폴더> [--out 반출]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import BUILD, buildid  # noqa: E402
from logtriage.knowledge_gen import dir_hash  # noqa: E402
import py39_compat  # noqa: E402

DIRS = ("rules", "errorcodes", "manuals")
R12 = ("logtriage/os_solution.py", "logtriage/parallel.py", "manuals/solutions_osmatrix.yaml", "tools/build/py39_compat.py")
BASH = next((b for b in (r"C:\Program Files\Git\bin\bash.exe", r"C:\Program Files\Git\usr\bin\bash.exe", shutil.which("bash") or "")
             if b and Path(b).is_file()), "")


def _extract(z: Path, dst: Path) -> Path:
    with zipfile.ZipFile(z) as zf:
        zf.extractall(dst)
    roots = [p for p in dst.iterdir() if p.is_dir()]
    if len(roots) != 1:
        raise RuntimeError(f"{z.name}: 최상위 폴더가 하나가 아닙니다 {roots}")
    return roots[0]


def _build_of(eng: Path) -> str:
    m = re.findall(r'^BUILD\s*=\s*"([^"]+)"', (eng / "logtriage" / "__init__.py").read_text(encoding="utf-8"), re.M)
    return m[0] if len(m) == 1 else f"정의 {len(m)}개"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--out", default=str(ENGINE.parent / "반출"))
    a = ap.parse_args(argv)
    run, out = Path(a.run).resolve(), Path(a.out)
    rows, bad = [], []

    def chk(name, ok, pc="", lx="", note=""):
        rows.append({"항목": name, "결과": "같음" if ok else "다름", "PC": str(pc)[:80], "리눅스": str(lx)[:80], "메모": note})
        if not ok:
            bad.append(name)

    pcb = json.loads((run / "_pc_build.json").read_text(encoding="utf-8"))
    eng_code = buildid.compute(ENGINE / "logtriage")
    eng_kn = {d: dir_hash(ENGINE / d) for d in DIRS}
    run_kn = {d: dir_hash(run / d) for d in DIRS}
    full = out / f"logtriage-server-{BUILD}.zip"
    patches = [out / f"logtriage-patch-{BUILD}.zip", out / f"logtriage-patch-py311-{BUILD}.zip"]
    tmp = Path(tempfile.mkdtemp(prefix="lt-parity-"))
    try:
        root = _extract(full, tmp / "full")
        le = root / "engine"
        lst = json.loads((le / "logtriage" / buildid.STAMP).read_text(encoding="utf-8"))
        ver = (root / "VERSION.txt").read_text(encoding="utf-8")
        lx_code_re = buildid.compute(le / "logtriage")
        lx_kn = {d: dir_hash(le / d) for d in DIRS}
        chk("① 제품 판", pcb.get("build") == BUILD == _build_of(le) and f"Version: {BUILD}" in ver, pcb.get("build"), _build_of(le), "VERSION.txt 포함")
        chk("② 코드 지문(도장)", pcb.get("code") == lst.get("code"), pcb.get("code"), lst.get("code"), "PC exe 도장 = 리눅스 묶음 도장")
        chk("② 코드 지문(다시 셈)", lx_code_re == lst.get("code") == eng_code, eng_code, lx_code_re, "엔진 원본·리눅스 묶음 원본에서 다시 센 값")
        for d in DIRS:
            chk(f"③ 지식 {d}", run_kn[d] == pcb["knowledge"][d] == lx_kn[d] == eng_kn[d], run_kn[d][:16], lx_kn[d][:16],
                "PC run = exe 내장(도장) = 리눅스 = 엔진")
        for f in R12:
            chk(f"④ 12차 파일 {f}", (ENGINE / f).is_file() and (le / f).is_file()
                and (ENGINE / f).read_bytes() == (le / f).read_bytes(), "있음", "있음" if (le / f).is_file() else "없음")
        ui = (le / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        chk("④ 이력 가져오기 띠(legacybar)", 'id="legacybtn"' in ui, "", "있음" if 'id="legacybtn"' in ui else "없음")
        import py_compile
        comp_bad = []
        for pyf in sorted(root.rglob("*.py")):          # 12차: 시험 파일 한 줄 오타(괄호)가 리눅스 묶음에 그대로 실린 일 — 묶음 안 모든 .py 를 컴파일
            try:
                py_compile.compile(str(pyf), cfile=str(tmp / "c.pyc"), doraise=True)
            except py_compile.PyCompileError as e:
                comp_bad.append(f"{pyf.relative_to(root)}: {str(e)[:100]}")
        chk("⑤ 묶음 안 파이썬 전부 컴파일", not comp_bad, "", f"오류 {len(comp_bad)}", "; ".join(comp_bad[:3]))
        probs = py39_compat.check(le / "logtriage")
        chk("⑤ 3.9 호환(RHEL 9 시스템 python)", not probs, "", f"문제 {len(probs)}", "; ".join(probs[:3]))
        shs = sorted(root.rglob("*.sh"))
        sh_bad = []
        if BASH:
            for s in shs:
                r = subprocess.run([BASH, "-n", str(s)], capture_output=True, text=True, encoding="utf-8", errors="replace")
                if r.returncode:
                    sh_bad.append(f"{s.relative_to(root)}: {r.stderr.strip()[:120]}")
        chk("⑤ 셸 스크립트 문법(bash -n)", bool(BASH) and not sh_bad, "", f"{len(shs)}개 · 오류 {len(sh_bad)}", "; ".join(sh_bad[:3]) or ("bash 없음" if not BASH else ""))
        # GPT 93차 P1: bash -n 은 통과해도 CRLF·실행 권한·shebang 이 틀리면 리눅스에서 직접 실행이 실패한다 — zip 항목 그대로 본다
        lf_bad = []
        with zipfile.ZipFile(full) as zf:
            for zi in zf.infolist():
                nm = zi.filename
                if nm.endswith((".sh", ".service", ".timer", ".conf", ".example", ".env", ".sql")):
                    b = zf.read(zi)
                    if b"\r" in b:
                        lf_bad.append(f"{nm}: CR")
                    if nm.endswith(".sh") and ((zi.external_attr >> 16) & 0o111 == 0 or not b.startswith(b"#!")):
                        lf_bad.append(f"{nm}: 실행 권한·shebang")
                elif nm.endswith(".py"):                     # GPT 94차: 직접 실행하는 .py(shebang)는 첫 줄 LF
                    b = zf.read(zi)
                    if b.startswith(b"#!") and b"\r" in b.split(b"\n", 1)[0]:
                        lf_bad.append(f"{nm}: shebang 줄 CR")
        chk("⑤ 리눅스 글 파일 LF·실행 권한·shebang(zip 항목)", not lf_bad, "", f"문제 {len(lf_bad)}", "; ".join(lf_bad[:4]))
        whl = sorted((le / "deploy" / "server" / "wheels").glob("pyyaml-*cp39*.whl")) + sorted((root / "wheels").glob("pyyaml-*.whl"))
        whl_ok = bool(whl) and all(any("_yaml" in n and n.endswith(".so") for n in zipfile.ZipFile(w).namelist()) for w in whl)
        chk("⑤ 리눅스 PyYAML C 확장(_yaml.so) — C 안전 파서", whl_ok, "", ", ".join(w.name.split("-")[2] for w in whl))
        # GPT 93차 P1: 도장은 원본 일치 표시일 뿐 — PC exe 는 '포장본 점검을 통과한 그 exe 해시'와 대조한다
        exe_ok_path = ENGINE / "deploy" / "local" / "build" / "exe_checks.json"
        ec = json.loads(exe_ok_path.read_text(encoding="utf-8")) if exe_ok_path.is_file() else {}
        chk("② PC exe = 포장본 점검 통과본(해시)", ec.get("ok") is True and ec.get("gui_sha") == pcb.get("gui_sha") and ec.get("cli_sha") == pcb.get("cli_sha"),
            (pcb.get("gui_sha") or "")[:16], (ec.get("gui_sha") or "")[:16], f"exe_checks {ec.get('at', '')} ok={ec.get('ok')}")
        comps = {}                                            # OS 별 구성요소 지문(대조가 아니라 기록 — 판마다 무엇이 실렸는지)
        import hashlib as _h
        for rel in ["run.sh", "stop.sh", "VERSION.txt", "README-INSTALL.txt"] + \
                [p.relative_to(root).as_posix() for p in sorted((le / "deploy" / "server").glob("*")) if p.is_file()] + \
                [p.relative_to(root).as_posix() for p in sorted(root.glob("python-*.tar.gz"))]:
            f = root / rel
            if f.is_file():
                comps[rel] = _h.sha256(f.read_bytes()).hexdigest()[:16]
        comps["wheels(목록)"] = _h.sha256("\n".join(sorted(p.name for p in (root / "wheels").glob("*.whl"))).encode()).hexdigest()[:16]
        for i, pz in enumerate(patches):
            pr = _extract(pz, tmp / f"p{i}")
            pst = json.loads((pr / "engine" / "logtriage" / buildid.STAMP).read_text(encoding="utf-8"))
            chk(f"⑤ 패치 묶음 {pz.name} 코드 지문", pst.get("code") == lst.get("code") and pst.get("id") == lst.get("id"), lst.get("code"), pst.get("code"))
        # 12차: 설치본(dist) 지식도 같은 판이어야 한다 — 지식 출시 검사가 시각 한 줄만 다시 써서 설치본만 달라졌던 일(자체 발견)
        dist = ENGINE / "deploy" / "local" / "dist"
        if dist.is_dir():
            dk = {d: dir_hash(dist / d) for d in DIRS}
            chk("⑥ 설치본(dist) 지식 = 이 판", dk == eng_kn, ", ".join(f"{k} {v[:8]}" for k, v in dk.items()), "", "PC 설치 폴더")
        # 12차: 설치 안내가 대조하라는 SHA256 파일이 10-06 값 그대로였다 — 지금 묶음 해시와 같은지
        sf = out / f"SHA256-{BUILD}.txt"
        stxt = sf.read_text(encoding="utf-8") if sf.is_file() else ""
        sums_ok = all(f"{__import__('hashlib').sha256(z.read_bytes()).hexdigest()}  {z.name}" in stxt for z in [full] + patches) and lst.get("id", "?") in stxt
        chk("⑤ SHA256 안내 파일 = 지금 묶음", sums_ok, "", sf.name, "README-INSTALL 의 sha256sum -c 대조 대상")
        rec = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "build": BUILD, "code": eng_code, "linux_id": lst.get("id"),
               "pc": {"gui_sha": pcb.get("gui_sha"), "cli_sha": pcb.get("cli_sha"), "run": str(run)},
               "linux": {z.name: __import__("hashlib").sha256(z.read_bytes()).hexdigest().upper() for z in [full] + patches},
               "knowledge": eng_kn, "linux_components": comps, "rows": rows, "ok": not bad}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    dst = ENGINE / "deploy" / "local"
    (dst / f"LogTriage-{BUILD}-판대조.json").write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    md = [f"# LogTriage {BUILD} — PC ↔ 리눅스 서버 판 대조", "",
          f"- 대조 시각: {rec['at']} · 제품 판 {BUILD} · 코드 지문 `{eng_code}` · 리눅스 배포 지문 `{rec['linux_id']}`(run.sh·stop.sh 포함이라 PC 와 다른 것이 정상)",
          f"- PC: LogTriage.exe `{rec['pc']['gui_sha']}` · logtriage-cli.exe `{rec['pc']['cli_sha']}`",
          *[f"- 리눅스: {k} `{v}`" for k, v in rec["linux"].items()],
          f"- 결과: **{'같은 판' if rec['ok'] else '다름 — ' + ', '.join(bad)}**", "",
          "| 항목 | 결과 | PC | 리눅스 | 메모 |", "|---|---|---|---|---|",
          *[f"| {r['항목']} | {r['결과']} | {r['PC']} | {r['리눅스']} | {r['메모']} |" for r in rows],
          "", "## 리눅스 구성요소 지문(기록)", "", "| 파일 | SHA-256 앞 16자 |", "|---|---|",
          *[f"| {k} | `{v}` |" for k, v in rec["linux_components"].items()],
          "", "판정 범위: PC·리눅스 공통 소스·지식 동등성과 리눅스 묶음의 Windows 호스트 모의 실행까지 — RHEL 실기 설치·기동(systemd·SELinux·python 3.9 실행)은 별도(GPT 93차)."]
    (dst / f"LogTriage-{BUILD}-판대조.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    for r in rows:
        print(("같음 " if r["결과"] == "같음" else "다름 ") + r["항목"], r["PC"], "|", r["리눅스"], r["메모"][:100])
    print(f"[판 대조] {'같은 판' if rec['ok'] else '다름'} — {len(rows)}항목 · 다름 {len(bad)}")
    return 0 if rec["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
