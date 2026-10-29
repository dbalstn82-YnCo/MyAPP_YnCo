"""지식 출시 강제 종료 반복 시험(9차 아이디어 ⑦) — 실제 전원 차단에 가장 가까운 모의.

임시 배포 폴더에서 knowledge_release.copy_knowledge 를 **별도 프로세스**로 돌리다 무작위 시점에 강제로 끝낸다(taskkill /F).
매번 확인하는 불변식:
  ① 끝난 직후: 흔적(.lt-know-old·.lt-know-new)이 없으면 지식 세 폴더는 폴더마다 '구판 그대로' 또는 '신판 그대로'여야 하고
     세 폴더가 섞여(어떤 것은 구판, 어떤 것은 신판) 있으면 안 된다. 흔적이 있으면 앱이 뜨지 않는다(server.release_leftover 가 글을 낸다).
  ② recover() 뒤: 흔적 0, 세 폴더 모두 구판 그대로(전환은 사후 검사 뒤에만 확정되므로 멈춘 출시는 언제나 구판으로).
한계: 같은 볼륨 안 이름 바꾸기·파일 쓰기 도중의 프로세스 종료이지 OS·디스크 수준 전원 차단은 아니다(쓰기 캐시 유실은 재현 못 함).
사용: python tools/build/release_crash_fuzz.py [--n 60] [--seed 1] [--max-delay 3.0]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import knowledge_release as kr  # noqa: E402
from logtriage.server import release_leftover  # noqa: E402


def tree(d: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(d.rglob("*")) if d.is_dir() else []:
        if f.is_file() and f.suffix.lower() in kr.SUFFIX:   # 지식 파일만(세대 표식 .lt-gen 은 출시마다 달라 비교에서 뺀다)
            h.update(f.relative_to(d).as_posix().encode() + hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def kill(p):
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True)
    else:
        p.kill()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        pass


def run(n: int, seed: int, max_delay: float, out: Path | None = None) -> dict:
    rnd = random.Random(seed)
    work = Path(tempfile.mkdtemp(prefix="lt-crash-"))
    dist = work / "dist"
    dist.mkdir()
    try:
        kr.copy_knowledge(dist)
        shutil.rmtree(dist / kr.OLD, ignore_errors=True)
        for sub in kr.KNOW:   # 구판을 신판과 다르게 — 폴더마다 표식 줄
            f = next(p for p in sorted((dist / sub).rglob("*.yaml")))
            f.write_text(f.read_text(encoding="utf-8") + f"\n# 구판 표식 {sub}\n", encoding="utf-8")
        old = {s: tree(dist / s) for s in kr.KNOW}
        new = {s: tree(ENGINE / s) for s in kr.KNOW}
        code = ("import sys; sys.path.insert(0, %r); sys.path.insert(0, %r); import knowledge_release as kr; from pathlib import Path; "
                "kr.copy_knowledge(Path(%r))" % (str(ENGINE), str(Path(__file__).resolve().parent), str(dist)))
        stats = {"n": n, "killed_mid": 0, "finished": 0, "leftover_seen": 0, "violations": [], "phases": {}, "injected": 0}
        # 무작위 종료는 폴더 바꿔치기 순간(아주 짧음)을 거의 못 맞힌다 → 이름 바꾸기 k번째 직후에 스스로 죽는 '주입' 회를 먼저 돈다(세 폴더 × 두 번)
        inject = ("import os as _o; _r=_o.replace; _n=[0]\n"
                  "def _rep(a, b):\n    _r(a, b); _n[0]+=1\n    if _n[0]==%d: _o._exit(9)\n"
                  "_o.replace=_rep\n")
        # GPT 70차: 복구 도중 다시 멈추는 경우 — 바꿔치기 한가운데(4번째 이름 바꾸기)에서 멈춘 뒤, recover 를 j번째 이름 바꾸기 직후 다시 멈춘다
        rcode = ("import sys; sys.path.insert(0, %r); sys.path.insert(0, %r); import knowledge_release as kr; from pathlib import Path; "
                 "kr.recover(Path(%r))" % (str(ENGINE), str(Path(__file__).resolve().parent), str(dist)))
        plan = ([("inject", k) for k in range(1, 2 * len(kr.KNOW) + 1)] + [("inject_recover", j) for j in range(1, len(kr.KNOW) + 1)]
                + [("random", None)] * n)
        stats["recover_injected"] = 0
        for i, (mode, k) in enumerate(plan):
            if mode == "inject_recover":
                subprocess.run([sys.executable, "-c", (inject % 4) + code.replace("; ", "\n")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                subprocess.run([sys.executable, "-c", (inject % k) + rcode.replace("; ", "\n")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
                stats["recover_injected"] += 1
            elif mode == "inject":
                p = subprocess.Popen([sys.executable, "-c", (inject % k) + code.replace("; ", "\n")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                p.wait(120)
                stats["injected"] += 1
            else:
                p = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(rnd.uniform(0.05, max_delay))
                done = p.poll() is not None
                if not done:
                    kill(p)
                    stats["killed_mid"] += 1
                else:
                    stats["finished"] += 1
            left = [x for x in (kr.OLD, kr.NEW) if (dist / x).exists()]
            cur = {s: tree(dist / s) for s in kr.KNOW}
            phase = ("흔적 없음" if not left else "+".join(sorted(left)))
            stats["phases"][phase] = stats["phases"].get(phase, 0) + 1
            if left:
                stats["leftover_seen"] += 1
                if not release_leftover(dist):
                    stats["violations"].append(f"{i}: 흔적이 있는데 앱 기동 거부 글이 없음")
            else:
                kinds = {("old" if cur[s] == old[s] else "new" if cur[s] == new[s] else "broken") for s in kr.KNOW}
                if "broken" in kinds or len(kinds) > 1:
                    stats["violations"].append(f"{i}: 흔적 없이 섞임·깨짐 {kinds}")
                    if not release_leftover(dist):
                        stats["violations"].append(f"{i}: 섞였는데 앱 기동 거부 글이 없음")
            kr.recover(dist)
            after = {s: tree(dist / s) for s in kr.KNOW}
            if after != old or any((dist / x).exists() for x in (kr.OLD, kr.NEW)):
                stats["violations"].append(f"{i}: recover 뒤 구판이 아님")
                for s in kr.KNOW:   # 다음 회를 위해 구판으로 다시 맞춘다(위반은 이미 기록)
                    pass
        stats["ok"] = not stats["violations"]
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if out:
        out.write_text(json.dumps(stats, ensure_ascii=False, indent=1), encoding="utf-8")
    return stats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-delay", type=float, default=3.0)
    a = ap.parse_args(argv)
    out = ENGINE / "deploy" / "local" / "지식검증" / "출시강제종료시험.json"
    s = run(a.n, a.seed, a.max_delay, out)
    print(f"강제 종료 {s['killed_mid']}회 · 끝까지 감 {s['finished']}회 · 흔적 본 회 {s['leftover_seen']} · 상태 {s['phases']} · 위반 {len(s['violations'])} {s['violations'][:3]}")
    return 0 if s["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
