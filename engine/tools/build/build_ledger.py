# -*- coding: utf-8 -*-
"""빌드 지문 장부(2026-10-15 아이디어 11) — 판마다 '무엇을 내보냈고 무엇을 통과했나'를 한 줄로 남긴다.

한 줄 = 기록 시각 · 버전 · 배포본 해시(GUI·CLI·되돌리기 판) · 회귀 시험 결과 · 한글 렌더링 관문 결과 · 되돌리기 자격 · V3 승인(손으로 적는 칸).
V3 승인 칸은 보안 담당이 예외 등록을 마친 뒤 사람이 적는다 — 이 도구는 V3 설정을 건드리거나 확인하지 않는다.
장부: deploy/local/LogTriage-빌드장부.md (기계용 사본 deploy/local/build/ledger.jsonl)

사용:
  python tools/build/build_ledger.py record [--run-tests] [--rollback 통과|실패|미확인] [--note 메모]
      --run-tests: 회귀 시험을 돌려 결과를 적는다(실패면 장부에 '실패'로 남기고 종료 코드 1)
  python tools/build/build_ledger.py check
      지금 배포 폴더의 exe 해시가 장부 마지막 줄과 같은지 — 장부에 없는 exe 가 배포 폴더에 있으면 1
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage import __version__  # noqa: E402

LOCAL = ENGINE / "deploy" / "local"
DIST = LOCAL / "dist"
MD = LOCAL / "LogTriage-빌드장부.md"
JL = LOCAL / "build" / "ledger.jsonl"
FILES = (("gui", "LogTriage.exe"), ("cli", "logtriage-cli.exe"), ("rollback", "LogTriage.exe.이전판"))
HEAD = ("# LogTriage 빌드 지문 장부\n\n"
        "판마다 배포본 해시와 점검 결과를 남긴다. **V3 승인** 칸은 보안 담당이 해시 예외 등록을 마친 뒤 손으로 적는다(이 도구는 V3 를 건드리지 않는다).\n"
        "해시는 앞 16자리만 적는다 — 전체 해시는 build/ledger.jsonl 과 V3 예외 신청서에 있다.\n"
        "해시가 같다는 것은 '같은 파일'이라는 뜻일 뿐 만든 사람을 보증하지 않는다(서명이 아님). 정식 배포본은 한글 렌더링 '통과'여야 한다(건너뜀은 개발 빌드만).\n\n"
        "| 기록 시각 | 버전 | GUI | CLI | 되돌리기 판 | 서명(GUI) | 회귀 시험 | 한글 렌더링 | 되돌리기 자격 | V3 승인 | 메모 |\n"
        "|---|---|---|---|---|---|---|---|---|---|---|\n")
HEAD2 = ("\n## 2판 — 서명 칸 추가(2026-10-15 아이디어 9)\n\n"
         "서명 칸은 실행 파일의 코드 서명(Authenticode)을 **읽기만** 한다. 사내 코드 서명 인증서가 생기면 '유효 · 발행자 지문'이 찍히고,\n"
         "V3 예외를 파일 해시가 아닌 발행자 기준으로 바꿀 수 있다. 지금은 '서명 없음'.\n"
         "되돌리기 자격 '통과(호환 시험)'은 되돌리기 판의 **자체 빌드 소스 스냅숏**을 새 판 자료로 돌려 본 결과다. 감사 훅 울타리는 보조 장치일 뿐\n"
         "**OS 수준 보안 격리를 제공하지 않으며**, 외부·사용자 코드를 안전하게 실행한다는 뜻이 아니다(GPT 35차).\n\n"
         "| 기록 시각 | 버전 | GUI | CLI | 되돌리기 판 | 서명(GUI) | 회귀 시험 | 한글 렌더링 | 되돌리기 자격 | V3 승인 | 메모 |\n"
         "|---|---|---|---|---|---|---|---|---|---|---|\n")
HEAD3 = ("\n## 3판 — 지식 검증 칸 추가(2026-10-16 아이디어 2)\n\n"
         "**지식 검증 분포**는 축별 개수다(교차=GPT 표본 실검증 판정 수 · 문법/실행=tools/build/knowledge_exec_check.py · 근거=공식 근거 보관 주장 수).\n"
         "문법 통과 ≠ 실행 성공 ≠ 진단 정확성. **표본 실검증**은 이번 판 회차의 표본 결과다 — 표본 비율을 전체 정확도로 읽지 않는다(GPT 55차).\n\n"
         "| 기록 시각 | 버전 | GUI | CLI | 되돌리기 판 | 서명(GUI) | 회귀 시험 | 한글 렌더링 | 되돌리기 자격 | V3 승인 | 지식 검증 분포 | 표본 실검증 | 메모 |\n"
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
HEAD4 = ("\n## 4판 — 포장본 점검 칸 추가(2026-10-19 9차 아이디어 6)\n\n"
         "**포장본 점검**은 검증도구/exe_all.py 가 빌드 폴더에서 그 exe 로 돌린 점검 9종의 결과다(기록의 exe 해시가 배포 폴더 GUI·CLI 와 같을 때만 적는다).\n"
         "설치(tools/build/install_move.py)는 이 기록이 전부 통과일 때만 한다.\n\n"
         "| 기록 시각 | 버전 | GUI | CLI | 되돌리기 판 | 서명(GUI) | 회귀 시험 | 한글 렌더링 | 되돌리기 자격 | V3 승인 | 지식 검증 분포 | 표본 실검증 | 포장본 점검 | 메모 |\n"
         "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n")
QDIR = LOCAL / "지식검증"


def exe_checks_label(h: dict) -> str:
    try:
        c = json.loads((LOCAL / "build" / "exe_checks.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "기록 없음"
    if c.get("gui_sha") != h.get("gui") or c.get("cli_sha") != h.get("cli"):
        return "기록 없음(다른 판의 점검)"
    n = len(c.get("results") or {})
    good = sum(1 for v in (c.get("results") or {}).values() if v.get("ok"))
    return f"{'통과' if c.get('ok') else '실패'} {good}/{n} ({c.get('at', '')})"


def knowledge_dist() -> str:
    try:
        import yaml
        v = yaml.safe_load((ENGINE / "errorcodes" / "_verification.yaml").read_text(encoding="utf-8")) or {}
        e = yaml.safe_load((ENGINE / "errorcodes" / "_evidence.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return "기록 없음"
    n = lambda k: len(v.get(k) or [])  # noqa: E731
    return (f"교차 {n('gpt')} · 문법 {n('syntax_pass')}/실패 {n('syntax_fail')} · 실행 {n('exec_pass')}/실패 {n('exec_fail')}"
            f" · 근거 {len({x.get('claim') for x in (e.get('evidence') or []) if isinstance(x, dict)})}")


def sample_result() -> str:
    try:
        rows = [json.loads(l) for l in (QDIR / "결과.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    except (OSError, ValueError):
        return "없음"
    if not rows:
        return "없음"
    last = max(str(r.get("round", "")) for r in rows)
    cur = [r for r in rows if str(r.get("round", "")) == last]
    c = lambda k, rs=cur: sum(1 for r in rs if r.get("verdict") == k)  # noqa: E731
    out = f"{last}: {len(cur)}건 — 정확 {c('정확')} · 부분 {c('부분')} · 오류 {c('오류')} · 고침 {sum(1 for r in cur if r.get('fixed'))}"
    # 8차 ⑫: 층이 적힌 회차면 층별로 따로(가중 층 비율을 모집단 정확도로 읽지 않게) · 8차 ①: 고침 뒤 다시 안 본 건수
    st = {}
    for r in cur:
        st.setdefault(str(r.get("stratum") or ""), []).append(r)
    if set(st) & {"가중", "무작위"}:
        out += " · " + " · ".join(f"{'무작위(미검증 집합)' if k == '무작위' else '가중(결함 찾기)'} {c('정확', v)}/{c('부분', v)}/{c('오류', v)}"
                                  for k, v in st.items() if k in ("가중", "무작위"))
    try:
        sys.path.insert(0, str(ENGINE / "tools" / "build"))
        import knowledge_sample_queue as q
        q.QDIR = QDIR
        pend = q.pending_items()
        out += f" · 재검증 대기 {len(pend)}" + (f"(원문 그대로 {sum(1 for x in pend if x['state'].startswith('원문 그대로'))})"
                                            if any(x['state'].startswith('원문 그대로') for x in pend) else "")
    except Exception as e:   # 장부 기록은 막지 않는다 — 셈 실패를 그대로 적는다
        out += f" · 재검증 대기 셈 실패({type(e).__name__})"
    return out


def signature(p: Path) -> dict:
    """코드 서명 상태 읽기(Windows PowerShell Get-AuthenticodeSignature) — 바꾸지 않는다. 못 읽으면 '확인 불가'."""
    if not p.is_file():
        return {"status": "없음", "thumbprint": ""}
    cmd = ("$s=Get-AuthenticodeSignature -LiteralPath $env:LT_SIG_PATH;"
           "[pscustomobject]@{status=[string]$s.Status;thumb=[string]$s.SignerCertificate.Thumbprint;subject=[string]$s.SignerCertificate.Subject}|ConvertTo-Json -Compress")
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=60, env={**__import__("os").environ, "LT_SIG_PATH": str(p)})
        d = json.loads(r.stdout.strip() or "{}")
    except Exception:   # noqa: BLE001 — 서명 확인은 장부 기록을 막지 않는다
        return {"status": "확인 불가", "thumbprint": ""}
    return {"status": d.get("status") or "확인 불가", "thumbprint": (d.get("thumb") or "").upper(), "subject": (d.get("subject") or "")[:80]}


SIG_BAD = ("HashMismatch", "NotTrusted", "UnknownError", "NotSupportedFileFormat", "Incompatible")
SIGNERS = LOCAL / "code_signing.json"   # {"expected_thumbprints": ["…"]} — 사내 인증서를 받은 뒤 사람이 적는다(도구는 쓰지 않음)


def expected_signers() -> list:
    """GPT 38차: 등록 파일을 넓은 집단(모든 사람·Users·인증된 사용자…)이 고칠 수 있으면 믿지 않는다(빈 목록 = 유효해도 실패)."""
    try:
        sys.path.insert(0, str(ENGINE))
        from logtriage.safe_backup import _shared_writable
        if SIGNERS.exists() and _shared_writable(SIGNERS, SIGNERS.parent):
            return []
        return [str(x).upper().replace(" ", "") for x in json.loads(SIGNERS.read_text(encoding="utf-8")).get("expected_thumbprints", [])]
    except (OSError, ValueError, AttributeError):
        return []


def signer_ok(sig: dict) -> bool:
    """Valid 는 '누군가 서명했고 체인이 맞다'일 뿐 — 우리가 등록한 발행자 지문과 같아야 우리 판이다."""
    return sig.get("status") == "Valid" and sig.get("thumbprint", "").upper() in expected_signers()


def sig_label(sig: dict) -> str:
    st = sig.get("status", "")
    if st == "Valid":
        return (f"유효 · `{sig.get('thumbprint', '')[:16]}`" if signer_ok(sig)
                else f"**유효하나 등록 안 된 발행자** · `{sig.get('thumbprint', '')[:16]}`")
    return {"NotSigned": "서명 없음", "HashMismatch": "**서명 깨짐**", "NotTrusted": "신뢰 안 됨"}.get(st, st or "확인 불가")


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def hashes(dist: Path) -> dict:
    return {k: (sha256(dist / n) if (dist / n).is_file() else "") for k, n in FILES}


def run_tests() -> tuple[str, bool]:
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"], cwd=str(ENGINE),
                       capture_output=True, text=True, encoding="utf-8", errors="replace", env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})
    tail = r.stderr[-4000:]
    m = re.search(r"Ran (\d+) tests?", tail)
    n = m.group(1) if m else "?"
    ok = r.returncode == 0 and re.search(r"^OK", tail, re.M) is not None
    fails = re.search(r"FAILED \(([^)]*)\)", tail)
    return (f"통과 {n}건" if ok else f"실패 {n}건 중 {fails.group(1) if fails else '?'}"), ok


FP_DIRS = ("logtriage", "tests", "rules", "errorcodes", "manuals")


def engine_fp() -> str:
    """시험 결과를 넘겨받을 때 대조할 엔진 지문 — 코드·시험·지식 파일 내용(경로 포함). 시험을 돌린 뒤 하나라도 바뀌면 달라진다."""
    h = hashlib.sha256()
    for d in FP_DIRS:
        for f in sorted((ENGINE / d).rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and f.suffix.lower() in (".py", ".yaml", ".yml", ".json", ".txt", ".md", ".html", ".css", ".js"):
                h.update(f.relative_to(ENGINE).as_posix().encode() + b"\0" + hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def tests_from(p: Path, max_age: float = 7200.0) -> tuple[str, bool]:
    try:
        r = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "넘겨받은 시험 결과 없음", False
    if r.get("engine_fp") != engine_fp():
        return "넘겨받은 시험 결과 무효(시험 뒤 소스·지식 바뀜)", False
    if time.time() - float(r.get("ts") or 0) > max_age:
        return "넘겨받은 시험 결과 무효(2시간 지남)", False
    return str(r.get("label")), bool(r.get("ok"))


def render_result() -> str:
    p = LOCAL / "build" / "render_gate.json"
    try:
        r = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "미실행"
    return {"pass": f"통과 {r.get('checked', 0)}건", "fail": f"실패 {r.get('failed', 0)}건", "skip": "건너뜀(한글 없음)"}.get(r.get("result"), "미실행") + f" ({r.get('at', '')})"


def record(a) -> int:
    h = hashes(DIST)
    if not h["gui"]:
        print("배포 폴더에 LogTriage.exe 가 없습니다 —", DIST)
        return 1
    tests, ok = run_tests() if a.run_tests else ("미실행", True)
    if not a.run_tests and getattr(a, "tests_from", ""):   # 8차 ④ 지식 출시가 방금 돌린 결과 — 그 뒤 소스·지식이 안 바뀌었을 때만 인정
        tests, ok = tests_from(Path(a.tests_from))
    sig = signature(DIST / "LogTriage.exe")
    sig_cli = signature(DIST / "logtriage-cli.exe")
    # 3차 아이디어 10: 서명 관문 — 서명이 없으면 지금처럼 통과(인증서 발급 전), 서명이 있는데 깨졌거나 신뢰되지 않으면 실패
    sig_bad = [n for n, x in (("GUI", sig), ("CLI", sig_cli))
               if x.get("status") in SIG_BAD or (x.get("status") == "Valid" and not signer_ok(x))]   # 유효해도 등록 안 된 발행자면 실패
    if sig_bad:
        ok = False
    # 아이디어 12: 되돌리기 자격을 손으로 적지 않으면 호환 시험으로 정한다 + 이 판의 소스 스냅숏을 남긴다(나중에 이 판이 되돌리기 판이 될 때)
    import rollback_compat as rbc
    rbc.snapshot(DIST / "LogTriage.exe")
    if a.rollback == "미확인":
        prev = DIST / "LogTriage.exe.이전판"
        snap = rbc.SRC / f"src-{rbc.sha16(prev)}.zip" if prev.is_file() else None
        if not snap or not snap.is_file():
            a.rollback = "미확인(스냅숏 없음)"
        else:
            rr = rbc.run(snap)
            import rollback_rehearsal as rbr   # 9차 ⑧: 서식·룰 호환에 더해 옛 판 코드로 새 판 분석 DB 를 열고 읽어 본다
            rh = rbr.run(snap)
            rbr.RESULT.write_text(json.dumps(rh, ensure_ascii=False, indent=1), encoding="utf-8")
            both = rr["result"] == "pass" and rh["result"] == "pass"
            a.rollback = ("통과(호환 시험·DB 예행)" if both else
                          f"실패({'호환 시험' if rr['result'] != 'pass' else ''}{'·' if rr['result'] != 'pass' and rh['result'] != 'pass' else ''}{'DB 예행' if rh['result'] != 'pass' else ''})")
            ok = ok and both
    row = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "version": __version__, **h, "signature": sig, "tests": tests, "render": render_result(),
           "rollback_ok": a.rollback, "v3": "", "knowledge": knowledge_dist(), "sample": sample_result(), "exe_checks": exe_checks_label(h),
           "note": (a.note or "")[:120]}
    JL.parent.mkdir(parents=True, exist_ok=True)
    with JL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    if not MD.exists():
        MD.write_text(HEAD, encoding="utf-8")
    elif "서명(GUI)" not in MD.read_text(encoding="utf-8"):
        with MD.open("a", encoding="utf-8") as f:
            f.write(HEAD2)
    if "지식 검증 분포" not in MD.read_text(encoding="utf-8"):
        with MD.open("a", encoding="utf-8") as f:
            f.write(HEAD3)
    if "| 포장본 점검 |" not in MD.read_text(encoding="utf-8"):
        with MD.open("a", encoding="utf-8") as f:
            f.write(HEAD4)
    cut = lambda x: f"`{x[:16]}`" if x else "-"
    note = row["note"].replace("|", "/")
    with MD.open("a", encoding="utf-8") as f:
        f.write(f"| {row['at']} | {row['version']} | {cut(h['gui'])} | {cut(h['cli'])} | {cut(h['rollback'])} | {sig_label(sig)} | {tests} | {row['render']} | {row['rollback_ok']} | (수동) | {row['knowledge']} | {row['sample']} | {row['exe_checks']} | {note} |\n")
    print(f"장부 기록: {row['version']} · GUI {h['gui'][:16]} · 서명 {sig_label(sig)} · 시험 {tests} · 렌더링 {row['render']} → {MD}")
    if sig_bad:
        print("서명 관문 실패 —", ", ".join(sig_bad), "의 코드 서명이 깨졌거나 신뢰되지 않습니다. 배포하지 마십시오.")
    return 0 if ok else 1


def check(_a) -> int:
    try:
        last = json.loads(JL.read_text(encoding="utf-8").strip().splitlines()[-1])
    except (OSError, ValueError, IndexError):
        print("장부가 비어 있습니다")
        return 1
    now = hashes(DIST)
    diff = [k for k in ("gui", "cli", "rollback") if now[k] != last.get(k, "")]
    print("배포 폴더 = 장부 마지막 줄" if not diff else f"장부와 다른 파일: {', '.join(diff)} — 장부에 없는 판이 배포 폴더에 있습니다")
    return 1 if diff else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    r.add_argument("--run-tests", action="store_true")
    r.add_argument("--rollback", default="미확인", choices=("통과", "실패", "미확인"))   # 미확인 = 호환 시험으로 자동 판정
    r.add_argument("--note", default="")
    r.add_argument("--tests-from", default="", help="knowledge_release 가 남긴 시험 결과 json(엔진 지문이 같을 때만 인정)")
    sub.add_parser("check")
    a = ap.parse_args(argv)
    return record(a) if a.cmd == "record" else check(a)


if __name__ == "__main__":
    sys.exit(main())
