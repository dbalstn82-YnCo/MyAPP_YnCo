"""지식 출시 한 명령(8차 아이디어 ④) — 지식을 바꾼 뒤 배포 폴더에 내보내기까지를 정해진 순서로, 하나라도 실패하면 배포 폴더는 손대지 않고 멈춘다.

순서(10-16 실측: 실행 검사가 _verification.yaml 을 고쳐 복사 뒤 동기화가 깨졌다 — 그래서 **고치는 단계를 모두 끝낸 뒤** 복사한다):
  1) 문법·실행 검사(knowledge_exec_check) — 실패 판정 0 이어야(이 단계가 errorcodes/_verification.yaml 을 갱신한다)
  2) 연결 감사(knowledge_link_audit) — 유령 연결 0 · 적합성 낮음 대기열 0
  3) 회귀 시험 전체 — 실패 0. 결과는 엔진 지문과 함께 남겨 장부가 넘겨받는다(시험 뒤 파일이 바뀌면 장부가 거절)
  4) 배포 폴더 검사 --before — 배포 폴더에만 있는 지식이 없어야(덮으면 사라짐)
  5) 전환 — 배포 폴더의 LogTriage 가 돌고 있으면 멈춤. 지식 세 폴더 전체를 준비 폴더에 만들어 해시 대조한 뒤 폴더 단위로 바꿔치기
     (GPT 64차 P0-④: 파일 하나씩 바꾸면 도중에 멈출 때 신구 지식이 섞인다). 실행 파일은 건드리지 않는다
  6) 배포 폴더 검사 --after — 엔진과 해시 전부 같아야. 실패하면 구판으로 되돌림. 지난 출시가 전환 도중 멈췄으면 시작할 때 구판으로 되돌린다
  7) 빌드 장부 기록(3 의 결과를 넘겨받음)
  지문(엔진 지문·준비본 대조)은 지식 로더가 읽는 세 폴더 전부(_metrics·_verification·_evidence*·_link_approvals 포함)를 덮는다.
사용: python tools/build/knowledge_release.py --note "무엇을 바꿨나" [--dist deploy/local/dist] [--dry-run]
  --dry-run: 1~4 만 하고 복사·장부는 하지 않는다.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
TB = ENGINE / "tools" / "build"
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(TB))
KNOW = ("rules", "errorcodes", "manuals")
SUFFIX = (".yaml", ".yml", ".json", ".txt", ".md")
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def _run(args: list) -> tuple[int, str]:
    r = subprocess.run([sys.executable] + args, cwd=str(ENGINE), capture_output=True, text=True, encoding="utf-8", errors="replace", env=ENV)
    return r.returncode, (r.stdout + r.stderr)


def step_exec() -> tuple[bool, str]:
    code, out = _run([str(TB / "knowledge_exec_check.py")])
    import yaml
    v = yaml.safe_load((ENGINE / "errorcodes" / "_verification.yaml").read_text(encoding="utf-8")) or {}
    sf, xf = len(v.get("syntax_fail") or []), len(v.get("exec_fail") or [])
    tail = " | ".join(l for l in out.splitlines() if l.startswith(("문법", "명령")))[:300]
    return code == 0 and sf == 0 and xf == 0, f"문법 실패 {sf} · 실행 실패 {xf} — {tail}"


def step_audit() -> tuple[bool, str]:
    code, out = _run([str(TB / "knowledge_link_audit.py")])
    try:
        j = json.loads((ENGINE / "deploy" / "local" / "지식검증" / "연결감사.json").read_text(encoding="utf-8"))
        g, lf = len(j.get("ghosts") or []), len(j.get("low_fit") or [])
    except (OSError, ValueError) as e:
        return False, f"연결감사.json 못 읽음 {e}"
    from logtriage.kb_audit import rollback_gaps   # 9차 ⑪: 2차 위험 명령마다 되돌리기 칸
    rb = rollback_gaps(ENGINE)
    return code == 0 and g == 0 and lf == 0 and not rb, (f"유령 {g} · 적합성 낮음 {lf} · 되돌리기 칸 빠진 2차 위험 명령 {len(rb)}"
                                                       + (f" {[(x['procedure'], x['do']) for x in rb[:3]]}" if rb else ""))


def step_tests(out_json: Path) -> tuple[bool, str]:
    import build_ledger as bl
    label, ok = bl.run_tests()
    out_json.write_text(json.dumps({"label": label, "ok": ok, "ts": time.time(), "engine_fp": bl.engine_fp()}, ensure_ascii=False), encoding="utf-8")
    return ok, label


def step_dist(dist: Path, phase: str) -> tuple[bool, str]:
    code, out = _run([str(TB / "check_dist_knowledge.py"), f"--{phase}", "--dist", str(dist)])
    return code == 0, out.strip().splitlines()[-1] if out.strip() else ""


NEW, OLD = ".lt-know-new", ".lt-know-old"
GEN_FILE = "knowledge-gen.json"   # 지식 세대 기록(logtriage/knowledge_gen.py — 세 폴더 내용 지문, 룰팩 적용도 갱신)
NO_GEN = ".no-gen"                 # 출시 전 세대 기록이 없었다는 표시(recover 가 새 기록을 지운다)


def _tree(root: Path) -> dict:
    return {f.relative_to(root).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest()
            for f in sorted(root.rglob("*")) if f.is_file() and "__pycache__" not in f.parts}


def recover(dist: Path) -> str:
    """지난 출시가 전환 도중 멈췄으면(.lt-know-old 가 남음) 구판으로 되돌린다 — 반쯤 바뀐 지식으로 앱이 뜨지 않게."""
    old, new = dist / OLD, dist / NEW
    msg = ""
    if old.is_dir():
        for sub in KNOW:
            if (old / sub).is_dir():
                if (dist / sub).exists():
                    shutil.rmtree(dist / sub)
                os.replace(old / sub, dist / sub)
        if (old / GEN_FILE).is_file():          # 세대 기록도 구판 것으로(폴더를 다 되돌린 뒤 — 구판 삭제는 그다음)
            os.replace(old / GEN_FILE, dist / GEN_FILE)
        elif (old / NO_GEN).exists() and (dist / GEN_FILE).exists():
            (dist / GEN_FILE).unlink()
        shutil.rmtree(old, ignore_errors=True)
        msg = "지난 출시가 전환 중 멈춤 → 구판 지식으로 되돌림"
    if new.is_dir():
        shutil.rmtree(new, ignore_errors=True)
        msg = msg or "지난 출시의 준비 폴더 정리"
    return msg


def copy_knowledge(dist: Path) -> int:
    """GPT 64차 P0-④: 파일 하나씩 바꾸면 도중에 멈출 때 신구 지식이 섞인다 →
    ① 준비: 배포 폴더 안 .lt-know-new 에 지식 세 폴더 전체를 만든다(배포 폴더에만 있는 비지식 파일도 함께 옮겨 잃지 않음)
    ② 검증: 준비본 해시 = 엔진(지식 파일) — 다르면 준비본을 지우고 멈춘다
    ③ 전환: 폴더 단위 바꿔치기(구판은 .lt-know-old 로) — 같은 볼륨이라 각각 원자적. 도중에 멈추면 다음 실행의 recover() 가 구판으로 되돌린다
    ④ 사후: 구판 폴더 삭제. 바뀐 지식 파일 수를 돌려준다."""
    dist = Path(dist)
    new, old = dist / NEW, dist / OLD
    if new.exists() or old.exists():
        raise RuntimeError("지난 출시가 남긴 준비·구판 폴더가 있습니다 — recover() 를 먼저 하십시오")
    want, changed = {}, 0
    new.mkdir()
    try:
        for sub in KNOW:
            src, cur, stg = ENGINE / sub, dist / sub, new / sub
            stg.mkdir(parents=True)
            if cur.is_dir():   # 배포 폴더에만 있는 지식 아닌 파일(그림 등)은 그대로 옮긴다 — 지식 파일은 엔진 것으로 덮인다
                for f in cur.rglob("*"):
                    if f.is_file() and f.suffix.lower() not in SUFFIX:
                        d = stg / f.relative_to(cur)
                        d.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(f, d)
            for f in sorted(src.rglob("*")):
                if not f.is_file() or "__pycache__" in f.parts or f.suffix.lower() not in SUFFIX:
                    continue
                rel = f.relative_to(src)
                d = stg / rel
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(f, d)
                want[f"{sub}/{rel.as_posix()}"] = hashlib.sha256(f.read_bytes()).hexdigest()
                prev = cur / rel
                if not (prev.is_file() and prev.read_bytes() == f.read_bytes()):
                    changed += 1
        got = {f"{sub}/{k}": v for sub in KNOW for k, v in _tree(new / sub).items() if Path(k).suffix.lower() in SUFFIX}
        if got != want:
            raise RuntimeError(f"준비본이 엔진과 다릅니다({len(set(got) ^ set(want))}개)")
    except BaseException:
        shutil.rmtree(new, ignore_errors=True)
        raise
    if not changed and all(set(_tree(dist / s)) == set(_tree(new / s)) for s in KNOW if (dist / s).is_dir()):
        shutil.rmtree(new, ignore_errors=True)
        return 0
    old.mkdir()
    if (dist / GEN_FILE).is_file():   # 구판 세대 기록을 먼저 보관(복구가 되돌린다)
        shutil.copy2(dist / GEN_FILE, old / GEN_FILE)
    else:
        (old / NO_GEN).write_text("", encoding="utf-8")
    for sub in KNOW:
        if (dist / sub).is_dir():
            os.replace(dist / sub, old / sub)
        os.replace(new / sub, dist / sub)
    shutil.rmtree(new, ignore_errors=True)
    from logtriage.knowledge_gen import write_gen   # GPT 70·71차: 흔적 없이 한 폴더만 바뀐 것도 기동 때 알아채게 — 세 폴더 내용 지문 기록
    write_gen(dist, "knowledge_release")
    return changed      # 구판(.lt-know-old)은 사후 검사(--after)가 통과한 뒤에 지운다 — 실패하면 recover() 가 되돌린다


def running_from(root: Path) -> list:
    """그 폴더의 LogTriage 실행 파일로 돌고 있는 프로세스(경로로 가린다)."""
    if os.name != "nt":
        return []
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith('"
          + str(root).replace("'", "''") + "', 'OrdinalIgnoreCase') } | ForEach-Object { $_.ProcessId }")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--note", required=True)
    ap.add_argument("--dist", default=str(ENGINE / "deploy" / "local" / "dist"))
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    dist = Path(a.dist).resolve()
    r0 = recover(dist)
    if r0:
        print(f"[지식 출시] {r0}")
    res = ENGINE / "deploy" / "local" / "build" / "release_tests.json"
    res.parent.mkdir(parents=True, exist_ok=True)
    steps = [("1 문법·실행 검사", step_exec), ("2 연결 감사", step_audit), ("3 회귀 시험", lambda: step_tests(res)),
             ("4 배포 폴더 검사(전)", lambda: step_dist(dist, "before"))]
    for name, fn in steps:
        t0 = time.time()
        ok, info = fn()
        print(f"[지식 출시] {name}: {'통과' if ok else '실패'} — {info} ({time.time() - t0:.0f}초)", flush=True)
        if not ok:
            print("[지식 출시] 멈춤 — 배포 폴더는 손대지 않았습니다")
            return 1
    if a.dry_run:
        print("[지식 출시] --dry-run: 복사·장부 생략")
        return 0
    busy = running_from(dist)
    if busy:   # GPT 64차 P0-④: 앱이 지식을 읽는 중에 바꾸지 않는다
        print(f"[지식 출시] 멈춤 — 배포 폴더의 LogTriage 가 돌고 있습니다({busy}). 끈 뒤 다시 하십시오")
        return 1
    try:
        n = copy_knowledge(dist)
    except Exception as e:   # noqa: BLE001
        print(f"[지식 출시] 멈춤 — 전환 실패: {e} · {recover(dist) or '배포 폴더는 그대로'}")
        return 1
    print(f"[지식 출시] 5 복사: {n}개 파일", flush=True)
    ok, info = step_dist(dist, "after")
    print(f"[지식 출시] 6 배포 폴더 검사(후): {'통과' if ok else '실패'} — {info}", flush=True)
    if not ok:
        print(f"[지식 출시] 멈춤 — 복사 뒤 불일치 → {recover(dist) or '되돌릴 구판 없음(바뀐 것 없음)'}")
        return 1
    shutil.rmtree(dist / OLD, ignore_errors=True)
    import build_ledger as bl
    rc = bl.main(["record", "--tests-from", str(res), "--note", a.note])
    print(f"[지식 출시] 7 장부 기록: {'통과' if rc == 0 else '실패'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
