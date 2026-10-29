"""내장 지식 펼치기(10차 · 2026-10-19 마스터 보고 "단독 실행용 exe 로는 로그 분석이 전혀 안 된다").

원인(실측): exe 가 판정 지식(rules·errorcodes·manuals)과 보고서 서식(report-template)을 옆 폴더에서만 읽었다 — exe 하나만 옮겨 실행하면
룰 0개로 '알려진 장애 패턴 미검출' 리포트가 나왔다. 이제 빌드가 지식을 exe 안(_MEIPASS/knowledge)에 넣고, 기동 때 exe 옆에
판정 지식이 **하나도 없으면** 내장 지식을 펼친 뒤 세대 기록(knowledge-gen.json)을 쓴다.

  · 이미 지식이 있으면(설치 폴더·룰팩으로 갱신된 사이트) 건드리지 않는다 — 내장 지식이 더 오래됐을 수 있다.
  · 일부만 있으면 펼치지 않는다(섞임) — 세대 기록 검사(knowledge_gen)·진단이 알린다.
  · 펼치는 도중 끊기면 작업 폴더(.lt-seed-new)와 그 안 일지(plan.json: 펼치기 전 세 폴더 지문·내장본 지문)가 남는다.
    다음 기동은 — 세대 기록이 이미 유효하면 작업 폴더만 치우고, 아니면 **세 폴더가 각각 '펼치기 전 상태' 또는 '내장본'일 때만** 다시 펼친다.
    그 밖(누가 그 사이 지식을 넣음)이면 덮어쓰지 않고 기동을 멈춘다(GPT 77차 P0-02).
  · 여러 프로세스(창·CLI·서버)가 동시에 처음 뜨면 잠금 파일(.lt-seed.lock)로 하나만 펼치고, 나머지는 기다렸다가 다시 판단한다(GPT 77차 P0-03).
  · 링크·정션인 지식 폴더는 지우거나 바꾸지 않는다. 쓰기가 안 되면 만든 작업 폴더를 지우고 멈춘다.
  · 보고서 서식은 판정 지식이 아니어서 없을 때마다 채운다.
개발 실행(소스)은 엔진 폴더에 지식이 그대로 있어 펼칠 것이 없다.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

KNOW = ("rules", "errorcodes", "manuals")
FORMS = "report-template"
STAGE = ".lt-seed-new"
LOCK = ".lt-seed.lock"
LOCK_WAIT = 120     # 다른 프로세스가 펼치는 동안 기다리는 최대 초



def bundled_root() -> Path | None:
    if getattr(sys, "frozen", False):
        p = Path(getattr(sys, "_MEIPASS", "")) / "knowledge"
        return p if (p / "rules").is_dir() else None
    return None


def _has_yaml(d: Path) -> bool:
    return d.is_dir() and any(d.rglob("*.y*ml"))


def _linky(p: Path) -> bool:
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    return p.is_symlink() or bool(getattr(st, "st_file_attributes", 0) & 0x400)   # 재분석 지점(정션 등)


def _proc_start(pid: int):
    """그 프로세스의 생성 시각(Windows FILETIME 정수) — 알 수 없으면 None. pid 가 다른 프로세스로 재사용됐는지 가리는 데 쓴다(GPT 78차 P1)."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32
        h = k.OpenProcess(0x1000, False, int(pid))        # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return None
        try:
            c, e, kt, ut = (wintypes.FILETIME() for _ in range(4))
            if not k.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt), ctypes.byref(ut)):
                return None
            return (c.dwHighDateTime << 32) | c.dwLowDateTime
        finally:
            k.CloseHandle(h)
    except Exception:   # noqa: BLE001
        return None


def _owner_gone(lk: Path) -> bool:
    """잠금 주인이 끝났다는 것이 **입증**될 때만 True — 죽은 프로세스이거나, 같은 pid 가 다른(생성 시각이 다른) 프로세스로 재사용됨.
    확인할 수 없으면 False(빼앗지 않는다 — GPT 78차 잠재 P0-02)."""
    from .safe_backup import _alive
    try:
        rec = json.loads(lk.read_text(encoding="utf-8"))
        pid, start = int(rec["pid"]), rec.get("start")
    except (OSError, ValueError, KeyError, TypeError):
        return False
    if not _alive(pid):
        return True
    now = _proc_start(pid)
    return start is not None and now is not None and now != start


def _lock(base: Path):
    lk = base / LOCK
    t0 = time.monotonic()
    me = {"pid": os.getpid(), "start": _proc_start(os.getpid()), "token": os.urandom(8).hex()}
    while True:
        try:
            fd = os.open(lk, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            try:
                os.write(fd, json.dumps(me).encode())
                os.fsync(fd)
            finally:
                os.close(fd)
            return lk
        except FileExistsError:
            try:
                if _owner_gone(lk):                     # 펼치다 강제 종료된 프로세스의 잠금 — 기다리지 않고 치운다
                    lk.unlink(missing_ok=True)
                    continue
            except OSError:
                continue
            if time.monotonic() - t0 > LOCK_WAIT:
                raise TimeoutError(f"다른 LogTriage 가 지식을 펼치는 중이거나 주인을 확인할 수 없는 잠금({LOCK})이 있습니다 — "
                                   "LogTriage 를 모두 끈 뒤에도 남아 있으면 그 파일을 지우고 다시 실행하십시오")
            time.sleep(0.3)


USER_HOME_MARK = ".lt-user-home"   # gui.app.base_dir 가 사용자 자리(%LOCALAPPDATA%\LogTriage\home)를 고를 때 남기는 표시


def refresh_user_home(base: Path, src: Path | None = None) -> str:
    """14차: 사용자 자리(앱이 만든 곳)의 지식이 예전 exe 내장본을 펼친 것이고 지금 exe 내장본과 다르면(판 올림) 옛 지식을
    backups/knowledge-before-<시각>/ 으로 옮긴다 — 이어서 seed 가 빈 자리로 보고 새 내장본을 펼친다. 옮긴 곳을 돌려준다('' = 할 일 없음).
    exe 옆 자리는 건드리지 않는다(사람이 지식을 둔 곳). 내장본이 아닌 지식(룰팩·출시)·세대 기록과 내용이 다른 것(섞임)도 건드리지 않는다.
    옮기다 끊겨도 다음 기동이 .moving 표시로 마저 옮긴다."""
    base, src = Path(base), (src or bundled_root())
    if not src or not (base / USER_HOME_MARK).exists():
        return ""
    from .knowledge_gen import FILE as GEN, check_gen, dir_hash
    bk = base / "backups"
    pend = sorted(bk.glob("knowledge-before-*/.moving")) if bk.is_dir() else []
    if pend:
        dst = pend[-1].parent
    else:
        try:
            rec = json.loads((base / GEN).read_text(encoding="utf-8"))
            have = rec["dirs"]
        except (OSError, ValueError, KeyError, TypeError):
            return ""
        if not str(rec.get("source", "")).startswith("내장 지식") or check_gen(base):
            return ""
        if all(have.get(d) == dir_hash(src / d) for d in KNOW):
            return ""
        dst = bk / ("knowledge-before-" + time.strftime("%Y%m%d-%H%M%S"))
        dst.mkdir(parents=True)
        (dst / ".moving").write_text("", encoding="utf-8")
    for n in (*KNOW, GEN):   # 세대 기록을 마지막에 — 끊기면 남은 것이 .moving 으로 이어진다
        if (base / n).exists() and not _linky(base / n):
            os.replace(base / n, dst / n)
    (dst / ".moving").unlink()
    return str(dst)


def seed(base: Path, src: Path | None = None) -> dict:
    """반환: {"seeded": [폴더…], "source": 내장 위치, "error": 글} — 펼친 것이 없으면 seeded 가 빈 목록."""
    base, src = Path(base), (src or bundled_root())
    out: dict = {"seeded": [], "source": str(src or "")}
    if not src:
        return out
    stage = base / STAGE
    lk = None
    made_stage = moving = False
    try:
        from .knowledge_gen import FILE as GEN, check_gen, dir_hash, write_gen
        empty_now = not any(_has_yaml(base / d) for d in KNOW) and not (base / GEN).exists()
        if not stage.exists() and not empty_now:
            has = [d for d in KNOW if _has_yaml(base / d)]
            if 0 < len(has) < len(KNOW) and not (base / GEN).exists():   # GPT 78차 잠재 P0-01: 세대 기록 없는 일부 지식 — 섞임·덜 복사됨
                miss = [d for d in KNOW if d not in has]
                raise OSError(f"판정 지식이 일부만 있습니다({', '.join(has)} 있음 · {', '.join(miss)} 없음) — 덜 복사됐거나 섞인 설치라 분석하지 않습니다. "
                              f"설치 폴더를 통째로 다시 복사하십시오. 사이트에서 고친 지식이 없다면, 남은 폴더({', '.join(has)})를 지우지 말고 "
                              "다른 곳으로 옮겨 보관한 뒤 다시 실행하면 exe 안 내장 지식으로 펼칩니다(GPT 79차: 삭제 유도 금지)")
            # 흔한 경우(지식이 다 있음) — 잠금 없이 바로 지나간다
        else:
            lk = _lock(base)
            for d in KNOW:
                if _linky(base / d):
                    raise OSError(f"{d} 폴더가 링크·정션입니다 — 지우거나 바꾸지 않습니다")
            if _linky(stage):
                raise OSError(f"{STAGE} 가 링크·정션입니다")
            interrupted = stage.exists()
            empty = not any(_has_yaml(base / d) for d in KNOW) and not (base / GEN).exists()   # 잠금 뒤 다시 판단
            want = {d: dir_hash(src / d) for d in KNOW}
            if interrupted and (base / GEN).exists() and check_gen(base) == "" and \
                    all(dir_hash(base / d) == want[d] for d in KNOW):
                shutil.rmtree(stage, ignore_errors=True)       # 세대까지 끝나고 작업 폴더만 남았던 것
                interrupted = False
            elif interrupted:
                try:
                    plan = json.loads((stage / "plan.json").read_text(encoding="utf-8"))
                    pre = plan["pre"]
                except (OSError, ValueError, KeyError, TypeError):
                    raise OSError("끊긴 펼침의 일지(plan.json)를 읽지 못했습니다 — 지식 폴더를 손으로 확인하십시오(덮어쓰지 않음)")
                odd = [d for d in KNOW if dir_hash(base / d) not in (pre.get(d), want[d])]
                if odd:
                    raise OSError(f"끊긴 펼침 뒤 {', '.join(odd)} 폴더 내용이 펼치기 전·내장본 어느 것과도 다릅니다 — "
                                  "누가 지식을 넣은 것으로 보여 덮어쓰지 않습니다. 확인 뒤 .lt-seed-new 를 지우십시오")
            if interrupted or empty:
                pre = {d: dir_hash(base / d) for d in KNOW} if not interrupted else pre
                shutil.rmtree(stage, ignore_errors=True)
                stage.mkdir(parents=True)
                made_stage = True
                tmp = stage / "plan.json.new"   # GPT 78차 P1: 일지는 임시 파일 → fsync → 교체(깨진 일지면 덮어쓰지 않고 멈춤)
                with open(tmp, "w", encoding="utf-8") as f:
                    f.write(json.dumps({"pre": pre, "want": want}, ensure_ascii=False))
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, stage / "plan.json")
                for d in KNOW:
                    shutil.copytree(src / d, stage / d)
                moving = True    # 여기부터는 실패해도 작업 폴더를 남긴다(다음 기동이 일지로 복구)
                for d in KNOW:   # 세 폴더 모두 내장본으로(끊긴 펼침이면 앞서 펼친 것도 다시)
                    if (base / d).exists():
                        shutil.rmtree(base / d)
                    os.replace(stage / d, base / d)
                from . import __version__
                write_gen(base, f"내장 지식(LogTriage {__version__} exe 안)")
                shutil.rmtree(stage, ignore_errors=True)   # 마지막에 지운다 — 남아 있으면 끊긴 펼침
                made_stage = False
                out["seeded"] += list(KNOW)
        forms_empty = not (base / FORMS).is_dir() or not any((base / FORMS).iterdir())
        if (src / FORMS).is_dir() and forms_empty and not _linky(base / FORMS):
            shutil.copytree(src / FORMS, base / FORMS, dirs_exist_ok=True)
            out["seeded"].append(FORMS)
        (base / "rules-local").mkdir(exist_ok=True)
    except (OSError, TimeoutError) as e:
        if made_stage and not moving:
            shutil.rmtree(stage, ignore_errors=True)            # 옮기기 전에 실패(쓰기 불가 등) — 만든 작업 폴더를 남기지 않는다
        out["error"] = (f"내장 지식을 펼치지 못했습니다({type(e).__name__}: {e}) — exe 를 쓰기 가능한 폴더로 옮겨 실행하십시오. "
                        f"위치: {base}")
    finally:
        if lk:
            try:
                lk.unlink(missing_ok=True)
            except OSError:
                pass
    return out
