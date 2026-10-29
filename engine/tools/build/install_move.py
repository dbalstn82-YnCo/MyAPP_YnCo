"""이동 설치(9차 아이디어 ⑥·⑩) — 포장본 점검(검증도구/exe_all.py)이 **그 exe 해시로 전부 통과**한 빌드만 배포 폴더로 옮긴다.
V3 가 새 exe 복사본을 막으므로 복사하지 않고 이동만 한다. 옮긴 뒤 배포 폴더에 install-stamp.json(설치한 exe 해시)을 남겨
앱이 기동 때 자기 해시와 대조한다(다르면 화면 띠 — 손으로 바꿔 넣었거나 V3 복구 등으로 판이 바뀐 것). 실수 방지용이지 보안 경계가 아니다.

  1) exe_checks.json 의 ok·gui_sha·cli_sha 가 빌드 폴더 exe 해시와 같아야 함
  2) 배포 폴더의 LogTriage 가 돌고 있으면 멈춤
  3) dist/LogTriage.exe.이전판 → backup/LogTriage.exe.<--retire 이름>, dist/LogTriage.exe → dist/LogTriage.exe.이전판,
     dist/logtriage-cli.exe → backup/logtriage-cli.exe.<--cli-retire 이름>, 빌드 폴더 exe 둘 → dist (backup 에 같은 이름이 있으면 멈춤)
  4) install-stamp.json 쓰기 · 해시 재확인 — 이동이 중간에 실패하면 이미 한 이동을 거꾸로 되돌린다(GPT 70차)
  한계: exe_checks.json 은 이 PC 의 점검 도구가 쓴 기록이라 같은 PC 에서 고쳐 쓰면 막지 못한다(위조 방어가 아니라 '점검 안 한 판을 실수로 옮기지 않게').
        해시는 '같은 파일'의 근거일 뿐 서명·점검 결과의 진위 증명이 아니다.
사용: python tools/build/install_move.py <빌드 폴더 run> --retire 지식7차 --cli-retire 지식8차 [--dist deploy/local/dist]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
LOCAL = ENGINE / "deploy" / "local"
CHECKS = LOCAL / "build" / "exe_checks.json"
STAMP = "install-stamp.json"
PENDING = ".lt-install-pending"   # 이동 설치 일지(server.release_leftover 도 본다 — 있으면 앱이 뜨지 않음)
EXE_NAMES = ("logtriage.exe", "logtriage-cli.exe")   # 일지가 옮길 수 있는 이름의 머리(대소문자 무시) — 그 밖은 일지에 있어도 옮기지 않는다


def sha(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def running_from(root: Path) -> list:
    if os.name != "nt":
        return []
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith('"
          + str(root).replace("'", "''") + "', 'OrdinalIgnoreCase') } | ForEach-Object { $_.ProcessId }")
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True, encoding="utf-8", errors="replace")
    return [l.strip() for l in r.stdout.splitlines() if l.strip()]


def gate(run: Path, checks: Path | None = None) -> tuple[bool, str]:
    try:
        c = json.loads((checks or CHECKS).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False, "포장본 점검 기록이 없습니다 — 검증도구/exe_all.py 를 먼저 돌리십시오"
    if not c.get("ok"):
        bad = [k for k, v in (c.get("results") or {}).items() if not v.get("ok")]
        return False, f"포장본 점검이 통과하지 않았습니다: {bad}"
    g, l = sha(run / "LogTriage.exe"), sha(run / "logtriage-cli.exe") if (run / "logtriage-cli.exe").is_file() else ""
    if c.get("gui_sha") != g or c.get("cli_sha") != l:
        return False, "포장본 점검 기록의 exe 해시가 지금 빌드 폴더 exe 와 다릅니다 — 점검 뒤 바뀐 판입니다"
    return True, f"포장본 점검 {len(c.get('results') or {})}종 통과({c.get('at')})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--retire", required=True, help="밀려나는 되돌리기 판을 backup 에 둘 이름 꼬리(예: 지식7차)")
    ap.add_argument("--cli-retire", required=True, help="밀려나는 CLI 를 backup 에 둘 이름 꼬리(예: 지식8차)")
    ap.add_argument("--dist", default=str(LOCAL / "dist"))
    a = ap.parse_args(argv)
    run, dist, bk = Path(a.run).resolve(), Path(a.dist).resolve(), LOCAL / "backup"
    pend = dist / PENDING
    if pend.exists():   # GPT 71차 P0: 지난 설치가 강제 종료·정전으로 중간에 멈춤 — 예외 처리가 못 돌았으니 일지로 되돌린다
        msg = undo_pending(pend)
        print(f"[설치] 지난 설치가 중간에 멈춘 흔적 → {msg} — 확인한 뒤 다시 실행하십시오")
        return 1
    ok, why = gate(run)
    print("[설치] 관문:", why)
    if not ok:
        return 1
    busy = running_from(dist)
    if busy:
        print("[설치] 멈춤 — 배포 폴더의 LogTriage 가 돌고 있습니다", busy)
        return 1
    moves = []
    if (dist / "LogTriage.exe.이전판").exists():
        moves.append((dist / "LogTriage.exe.이전판", bk / f"LogTriage.exe.{a.retire}"))
    if (dist / "LogTriage.exe").exists():
        moves.append((dist / "LogTriage.exe", dist / "LogTriage.exe.이전판"))
    if (dist / "logtriage-cli.exe").exists():
        moves.append((dist / "logtriage-cli.exe", bk / f"logtriage-cli.exe.{a.cli_retire}"))
    moves += [(run / "LogTriage.exe", dist / "LogTriage.exe"), (run / "logtriage-cli.exe", dist / "logtriage-cli.exe")]
    for s, d in moves:
        if d.exists() and d.parent == bk:
            print("[설치] 멈춤 — backup 에 같은 이름이 있습니다:", d.name)
            return 1
    want = {"gui": sha(run / "LogTriage.exe"), "cli": sha(run / "logtriage-cli.exe")}
    with open(pend, "w", encoding="utf-8") as f:   # 이동 계획을 먼저 디스크에 — 도중에 죽으면 다음 실행이 되돌린다(앱도 이 흔적이 있으면 뜨지 않음)
        old_stamp = (dist / STAMP).read_text(encoding="utf-8") if (dist / STAMP).is_file() else None   # 도장 쓴 뒤 죽어도 되돌릴 때 옛 도장으로
        # GPT 72차 P0-02: 존재 여부만으로는 '안 옮김/옮김/누가 바꿈'을 못 가른다 — 이동마다 그 파일의 sha, 설치 전 dist exe 상태를 함께 적는다
        f.write(json.dumps({"at": time.strftime("%Y-%m-%d %H:%M:%S"), "dist": str(dist), "backup": str(bk), "run": str(run),
                            "moves": [[str(s), str(d), sha(s)] for s, d in moves],
                            # GPT 73차 P0: 관련 경로 전체(출발지·목적지)의 설치 전 상태 — 되돌린 결과가 이것과 같아야 복구 완료(backup 에 낯선 파일 등)
                            "pre": {str(q): (sha(q) if q.is_file() else None) for s, d in moves for q in (s, d)},
                            "before": {p.name: sha(p) for p in dist.iterdir() if p.is_file() and p.name.lower().startswith(EXE_NAMES)},
                            "stamp": old_stamp}, ensure_ascii=False))
        f.flush()
        os.fsync(f.fileno())
    done = []
    try:
        for s, d in moves:
            os.replace(s, d)       # 같은 볼륨 이동(이름 바꾸기) — 복사본을 만들지 않는다
            done.append((s, d))
            print(f"[설치] 이동 {s.name} → {d.relative_to(LOCAL) if d.is_relative_to(LOCAL) else d}")
    except OSError as e:
        # GPT 70차 P0: 중간에 실패하면 신구가 섞인 배포 폴더가 남는다 — 한 이동을 거꾸로 되돌려 설치 전 상태로
        bad = []
        for s, d in reversed(done):
            try:
                os.replace(d, s)
            except OSError as e2:
                bad.append(f"{d.name}: {e2}")
        print(f"[설치] 실패 — {e} · 이미 옮긴 {len(done)}개를 되돌림" + (f" · **되돌리지 못함 {bad} — 배포 폴더를 손으로 확인하십시오**" if bad else " · 배포 폴더는 설치 전 그대로"))
        if not bad:
            pend.unlink(missing_ok=True)
        return 1
    got = {"gui": sha(dist / "LogTriage.exe"), "cli": sha(dist / "logtriage-cli.exe")}
    if got != want:
        print("[설치] 실패 — 옮긴 뒤 해시가 다릅니다", got, want)
        return 1
    (dist / STAMP).write_text(json.dumps({"at": time.strftime("%Y-%m-%d %H:%M:%S"), "gui_sha": got["gui"], "cli_sha": got["cli"],
                                          "rollback_sha": sha(dist / "LogTriage.exe.이전판") if (dist / "LogTriage.exe.이전판").exists() else "",
                                          "note": "설치 기록 — 앱이 기동 때 자기 exe 해시와 대조한다(실수 방지용, 보안 경계 아님)"},
                                         ensure_ascii=False, indent=1), encoding="utf-8")
    pend.unlink(missing_ok=True)   # 기록까지 끝난 뒤에만 흔적을 지운다
    print(f"[설치] 완료 — GUI {got['gui'][:16]} · CLI {got['cli'][:16]} · {STAMP}")
    return 0


def _plain(p: Path) -> bool:
    """링크·정션(재분석 지점)이 아닌 보통 파일이거나 아직 없는 이름 — 일지가 링크를 따라 엉뚱한 곳을 옮기지 않게(GPT 72차 P0-03)."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return True
    if p.is_symlink() or getattr(st, "st_file_attributes", 0) & 0x400:   # FILE_ATTRIBUTE_REPARSE_POINT
        return False
    return p.is_file()


def undo_pending(pend: Path) -> str:
    """일지의 이동을 거꾸로(GPT 72차 P0-02·03). 이동마다 네 상태를 가른다 —
      출발지 있음·sha 같음 → 안 옮김(그대로)   출발지 없음·목적지 sha 같음 → 옮김(되돌림)
      그 밖(둘 다 없음, sha 다름, 출발지·목적지 둘 다 우리 파일) → 누가 바꿨거나 유실 → **아무것도 옮기지 않고** 흔적 유지
    일지의 경로는 믿지 않는다: 일지 위치의 dist · 일지에 적힌 backup·run 폴더 안, exe 이름만, 링크·정션 거부.
    다 되돌린 뒤 dist exe 상태가 설치 전 기록과 같아야 흔적을 지운다."""
    try:
        j = json.loads(pend.read_text(encoding="utf-8"))
        moves = [(Path(s), Path(d), h) for s, d, h in j["moves"]]
        before = dict(j["before"])
        pre = dict(j["pre"])
        roots = {pend.parent.resolve(), Path(j["backup"]).resolve(), Path(j["run"]).resolve()}
    except (OSError, ValueError, KeyError, TypeError):
        return "일지를 읽지 못함(또는 옛 형식) — 배포 폴더를 손으로 확인하십시오(흔적은 남겨 둠)"
    for s, d, _ in moves:
        for p in (s, d):
            if p.parent.resolve() not in roots or not p.name.lower().startswith(EXE_NAMES) or not _plain(p):
                return f"일지 경로가 설치 계획 밖입니다({p}) — 아무것도 옮기지 않음(흔적은 남겨 둠)"
    virt = {}                                          # 경로 → sha(없으면 None) — 뒤 이동을 되돌린 뒤의 상태로 앞 이동을 판정
    for s, d, _ in moves:
        for q in (s, d):
            virt.setdefault(q, sha(q) if q.is_file() else None)
    plan = []
    for s, d, h in reversed(moves):
        if virt[s] == h:
            continue                                   # 아직 안 옮김
        if virt[s] is None and virt[d] == h:
            plan.append((d, s))                        # 옮김 → 되돌릴 것
            virt[s], virt[d] = h, None
            continue
        return f"{s.name} → {d.name} 상태가 일지와 다릅니다(파일이 없거나 내용이 바뀜) — 아무것도 옮기지 않음(흔적은 남겨 둠)"
    # GPT 73차 P0: 옮기기 '전에' 계획대로 되돌린 결과를 설치 전 상태와 대조 — 다르면 하나도 옮기지 않는다
    if set(pre) != {str(q) for q in virt}:
        return "일지의 설치 전 상태 목록이 이동 계획과 맞지 않습니다 — 아무것도 옮기지 않음(흔적은 남겨 둠)"
    off = sorted(q.name for q in virt if virt[q] != pre[str(q)])
    if off:
        return f"계획대로 되돌려도 설치 전과 다릅니다({off[:4]} — 낯선 파일이 생겼거나 바뀜) — 아무것도 옮기지 않음(흔적은 남겨 둠)"
    dist = pend.parent
    predicted = {p.name: sha(p) for p in dist.iterdir() if p.is_file() and p.name.lower().startswith(EXE_NAMES)}
    for q, h in virt.items():
        if q.parent.resolve() == dist.resolve():
            if h is None:
                predicted.pop(q.name, None)
            else:
                predicted[q.name] = h
    if predicted != before:
        return (f"계획대로 되돌려도 배포 폴더 exe 가 설치 전과 다릅니다({sorted(set(predicted.items()) ^ set(before.items()))[:4]}) "
                "— 아무것도 옮기지 않음(흔적은 남겨 둠)")
    back, bad = 0, []
    for d, s in plan:
        try:
            if s.exists():                             # 확인과 이동 사이 누가 만들었으면 덮어쓰지 않는다
                raise OSError("되돌릴 자리에 파일이 생겼습니다")
            os.replace(d, s)
            back += 1
        except OSError as e:
            bad.append(f"{d.name}: {e}")
    if bad:
        return f"되돌리지 못함 {bad} — 흔적은 남겨 둠"
    now = {p.name: sha(p) for p in dist.iterdir() if p.is_file() and p.name.lower().startswith(EXE_NAMES)}
    real = {q: (sha(Path(q)) if Path(q).is_file() else None) for q in pre}
    if now != before or real != pre:   # 옮긴 사이 누가 바꿨는지 실제로 한 번 더
        return f"되돌린 뒤 설치 전과 다릅니다({sorted(set(now.items()) ^ set(before.items()))[:4]}) — 흔적은 남겨 둠"
    st = pend.parent / STAMP   # 72차 자체 발견: 도장까지 쓰고 죽었으면 신판 도장이 남아 구판 exe 에 거짓 '불일치' 띠 — 옛 도장으로
    if j.get("stamp") is None:
        st.unlink(missing_ok=True)
    else:
        st.write_text(j["stamp"], encoding="utf-8")
    pend.unlink(missing_ok=True)
    return f"{back}개 이동을 되돌려 설치 전 상태로"


if __name__ == "__main__":
    sys.exit(main())
