# -*- coding: utf-8 -*-
"""본사 연동 관리 — 서버 콘솔에서만 쓰는 명령.

왜 만들었나. 지금까지 두 가지를 **파일을 손으로 지우는 것**으로 안내하고 있었다.

  · 사이트 신원 잠금을 풀려면  data/hub_identity.json 을 지우십시오
  · 멈춤 표식을 풀려면          data/hub_recovery_required 를 지우십시오

이것이 정식 절차가 되면 안 된다(GPT 지적).
  ① 신원 파일 지우기는 **실제로 송신했던 서버에서도 똑같이 잠금을 무력화한다.**
     파일 권한이 있는 관리자는 원래 강한 권한을 갖지만, 정상 절차 자체가 보안 불변식을
     손으로 지우도록 가르치는 것은 다른 문제다.
  ② 멈춤 표식이 생겼다는 것은 설정·신원·실행 중인 전송기·감사 기록의 아귀가 맞지
     않았다는 뜻이다. **표식만 지운다고 설정이 맞다는 보장이 없다.**

그래서 지울 수 있는 길을 없애는 대신, **검사를 지나야 지워지는 길**을 둔다.
무엇을 확인했는지 보여 주고, 누가 언제 풀었는지 감사 기록에 남긴다.

쓰는 법:
  python3 -m logtriage.hubadmin --base <설치경로> status
  python3 -m logtriage.hubadmin --base <설치경로> recover --confirm
  python3 -m logtriage.hubadmin --base <설치경로> identity-reset --new-site BUSAN --confirm
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from . import hub as hubmod
from . import runlock

NL = chr(10)
OK, BAD, WARN = "  OK ", "  !! ", "  .. "


def _say(msg: str) -> None:
    """콘솔이 못 찍는 글자가 있어도 **안내가 통째로 사라지지 않게** 한다.

    cp949 콘솔에서 줄표 하나 때문에 UnicodeEncodeError 가 나면서 안내가 전부 날아간 일이
    있었다. 복구 명령이 바로 그 자리에서 입을 다물면 안 된다.
    """
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = (getattr(sys.stdout, "encoding", "") or "utf-8")
        print(msg.encode(enc, "replace").decode(enc, "replace"))


# ── 검사 ─────────────────────────────────────────────────────────────
def inspect(base: Path) -> dict:
    """검사는 **서버와 같은 코드**를 쓴다 — 두 벌로 두면 한쪽만 고치게 된다."""
    d = hubmod.state_report(base)
    d["base"] = str(base)
    return d


def show(base: Path) -> int:
    d = inspect(base)
    _say(f"[본사 연동 상태]  {d['base']}")
    _pid = runlock.running(base)
    if _pid:
        _say(f"  서버가 돌고 있습니다(프로세스 {_pid if _pid > 0 else '?'}) —"
             " 보기는 되지만 바꾸려면 서비스를 내려야 합니다.")
    _say(f"  역할: {d['role']}   사이트 ID: {d['site_id'] or '(없음)'}"
         f"   못 박은 신원: {d['locked_site_id'] or '(없음)'}")
    if d["role"] == "site":
        _say(f"  본사 주소: {d['hub_url']}   사이트 토큰: {'설정됨' if d['token_set'] else '없음'}")
    rec = d.get("recovery") or {}
    if rec:
        at = time.strftime("%Y-%m-%d %H:%M", time.localtime(rec.get("at") or 0)) if rec.get("at") else "(시각 없음)"
        _say(f"  멈춤 표식: {rec.get('reason', '?')} — {rec.get('why', '')}  ({at})")
        if rec.get("detail"):
            _say(f"            {rec['detail'][:160]}")
    else:
        _say("  멈춤 표식: 없음")
    _say("")
    for c in d["checks"]:
        _say(("  OK  " if c["ok"] else "  !!  ") + c["name"] + (f" — {c['note']}" if c["note"] else ""))
    _say("")
    if rec:
        _say("  푸는 법:  python3 -m logtriage.hubadmin --base <설치경로> recover --confirm"
             + ("   (위 !! 를 먼저 고치십시오)" if not d["ok"] else ""))
    return 0 if d["ok"] else 1


# ── 멈춤 표식 풀기 ───────────────────────────────────────────────────
def _hold_or_refuse(base: Path):
    """**자물쇠를 쥔 채로** 고친다 — 쥐지 못하면 거절한다.

    전에는 "서버가 돌고 있나" 를 묻고 아니면 고쳤다. 묻고 고치는 사이에 서버가 뜨면
    그대로 겹친다(GPT 9차). 확인과 변경 사이에 틈을 두지 않는다.
    프로세스가 죽으면 OS 가 자물쇠를 풀어 주므로 멈춘 흔적 때문에 막히는 일은 없다.
    """
    held = runlock.acquire(base)
    if held:
        return held
    pid = runlock.running(base)
    _say(BAD + f"LogTriage 서버가 돌고 있습니다(프로세스 {pid if pid > 0 else '?'}).")
    _say("     보기(status)는 돌고 있어도 되지만, **바꾸는 것은 서버가 합니다** —")
    _say("     [통합 현황] 화면에서 하십시오. 서비스를 다시 시작할 필요가 없습니다.")
    _say("     이 명령은 **서버가 아예 못 떠서 화면을 열 수 없을 때**를 위한 것입니다.")
    return None


def _refuse_while_running(base: Path) -> bool:
    """서버가 돌고 있으면 **바꾸는 명령을 거절한다**(GPT 8차).

    이 명령은 서버와 다른 프로세스다. 동시에 고치면 돌고 있는 것과 디스크가 어긋난다 —
    서버 메모리는 BUSAN 인데 파일은 SEOUL 이 된다(실제로 재현했다). 감사 기록도 둘이
    동시에 쓴다. 서비스를 잠깐 내리는 불편을 택한다.
    """
    pid = runlock.running(base)
    if not pid:
        return False
    _say(BAD + f"LogTriage 서버가 돌고 있습니다(프로세스 {pid if pid > 0 else '?'}).")
    _say("     보기(status)는 돌고 있어도 되지만, **바꾸는 것은 서비스를 내린 뒤**에 합니다 —")
    _say("     돌고 있는 것과 파일이 어긋나면 더 고치기 어려워집니다.")
    _say("")
    _say("       systemctl stop logtriage-server")
    _say("       python3 -m logtriage.hubadmin --base <설치경로> ...")
    _say("       systemctl start logtriage-server")
    return True


def recover(base: Path, confirm: bool, actor: str) -> int:
    held = None
    if confirm:
        held = _hold_or_refuse(base)
        if not held:
            return 2
    try:
        return _recover(base, confirm, actor)
    finally:
        if held:
            held.release()


def _recover(base: Path, confirm: bool, actor: str) -> int:
    d = inspect(base)
    rec = d.get("recovery") or {}
    if not rec:
        _say("멈춤 표식이 없습니다 — 풀 것이 없습니다.")
        return 0
    if not d["ok"]:
        _say("아직 풀 수 없습니다 — 아래가 맞지 않습니다.")
        for c in d["checks"]:
            if not c["ok"]:
                _say(BAD + c["name"] + (f" — {c['note']}" if c["note"] else ""))
        _say("")
        _say("설정을 고친 뒤 다시 하십시오. **표식만 지우는 것은 같은 일을 또 겪는 길입니다.**")
        return 2
    if d.get("config_changed") is False:
        _say("설정이 멈출 때와 **똑같습니다.** 고치지 않고 풀면 같은 일이 또 생깁니다.")
        _say("정말 그대로 두고 풀어야 한다면 설정을 먼저 확인하십시오.")
        return 2
    if not confirm:
        _say("검사는 모두 지났습니다. 실제로 풀려면 --confirm 을 붙이십시오.")
        return 0
    (Path(base) / "data" / hubmod.RECOVERY_FILE).unlink(missing_ok=True)
    _audit(base, actor, "hub.recovery.cleared",
           f"{rec.get('reason', '?')} (설정 지문 {rec.get('config_hash', '')} -> {hubmod.conf_fingerprint(base)})")
    _say("멈춤 표식을 풀었습니다. 서비스를 다시 시작하면 본사 전송이 시작됩니다.")
    return 0


# ── 사이트 신원 바꾸기 ───────────────────────────────────────────────
def identity_reset(base: Path, new_site: str, confirm: bool, actor: str) -> int:
    held = None
    if confirm:
        held = _hold_or_refuse(base)
        if not held:
            return 2
    try:
        return _identity_reset(base, new_site, confirm, actor)
    finally:
        if held:
            held.release()


def _identity_reset(base: Path, new_site: str, confirm: bool, actor: str) -> int:
    locked = hubmod.locked_site(base)
    if not locked:
        _say("못 박은 신원이 없습니다 — 바꿀 것이 없습니다.")
        return 0
    if not hubmod.SITE_RE.match(new_site or ""):
        _say("새 사이트 ID 는 영문·숫자·_- 1~32자입니다.")
        return 2
    if new_site == locked:
        _say(f"이미 '{locked}' 입니다.")
        return 0
    _say(f"[사이트 신원 바꾸기]  '{locked}'  ->  '{new_site}'")
    _say("")
    _say("  이 서버에 쌓인 자료와 본사에 쌓인 자료는 **옛 이름으로 묶여 있습니다.**")
    _say("  바꾸면 본사에서 다른 사이트로 취급되어 과거 자료와 끊깁니다.")
    _say("  본사 담당자와 **먼저 맞춘 뒤에** 하십시오 — 본사에서도 재등록이 필요합니다.")
    _say("")
    if not confirm:
        _say("정말 바꾸려면 --confirm 을 붙이십시오.")
        return 0
    hubmod.set_identity(base, new_site, previous=locked, actor=actor)
    _audit(base, actor, "hub.identity.reset", f"{locked} -> {new_site}")
    _say(f"바꿨습니다: '{locked}' -> '{new_site}'")
    _say("conf/hub.json 의 site_id 도 같은 값인지 확인한 뒤 서비스를 다시 시작하십시오.")
    return 0


def _audit(base: Path, actor: str, action: str, detail: str) -> None:
    """누가 언제 풀었는지 남긴다 — 콘솔에서 한 일도 기록이 있어야 한다."""
    try:
        from .auth import AuthStore
        AuthStore(Path(base) / "data" / "auth" / "auth.sqlite3").audit(
            actor, "(console)", action, detail)
    except Exception:                            # noqa: BLE001 — 기록 실패가 복구를 막지 않는다
        _say(WARN + "감사 기록을 남기지 못했습니다(계정 저장소가 없을 수 있습니다).")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m logtriage.hubadmin",
        description="본사 연동 관리 — 상태 보기 · 멈춤 표식 풀기 · 사이트 신원 바꾸기")
    ap.add_argument("--base", required=True)
    ap.add_argument("--actor", default="", help="누가 하는지(기록에 남습니다)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="지금 상태와 검사 결과를 봅니다")
    r = sub.add_parser("recover", help="검사를 지나면 멈춤 표식을 풉니다")
    r.add_argument("--confirm", action="store_true")
    i = sub.add_parser("identity-reset", help="사이트 신원을 바꿉니다(본사와 함께 재등록 필요)")
    i.add_argument("--new-site", required=True)
    i.add_argument("--confirm", action="store_true")
    ns = ap.parse_args(argv)
    base = Path(ns.base)
    actor = ns.actor or (os.environ.get("SUDO_USER") or os.environ.get("USER")
                         or os.environ.get("USERNAME") or "(콘솔)")
    if not base.is_dir():
        _say(f"설치 경로가 없습니다: {base}")
        return 2
    try:
        if ns.cmd == "status":
            return show(base)
        if ns.cmd == "recover":
            return recover(base, ns.confirm, actor)
        return identity_reset(base, ns.new_site, ns.confirm, actor)
    except Exception as e:                       # noqa: BLE001 — 콘솔 명령이 역추적으로 끝나지 않게
        _say(f"하지 못했습니다: {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
