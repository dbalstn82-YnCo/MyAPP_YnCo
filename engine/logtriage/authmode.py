# -*- coding: utf-8 -*-
"""로그인 방식 바꾸기 — 서버에서 명령으로 (2026-09-30)

사용자 결정: "현재 메일 인증기능 제거, 추후 도입."
회사 이메일 계정 로그인(mode=local)을 **이번 판에서는 쓰지 않습니다.** 코드는 그대로 두어
나중에 한 줄로 되돌릴 수 있게 합니다 — 지우는 것이 아니라 끄는 것입니다.

**화면에서 바꾸지 않습니다.** 자기 로그인 방식을 웹에서 바꾸면 잘못 눌러 스스로 잠기거나,
반대로 서버를 열어 버릴 수 있습니다. 서버에 들어올 수 있는 사람만 바꾸는 것이 맞습니다.

    python3 -m logtriage.authmode --base /opt/logtriage           # 지금 무엇으로 되어 있나
    python3 -m logtriage.authmode --base /opt/logtriage off       # 로그인 없이(내부망 전용)
    python3 -m logtriage.authmode --base /opt/logtriage local     # 회사 이메일 계정으로(추후)
    python3 -m logtriage.authmode --base /opt/logtriage password  # 단일 비밀번호로

알고 계셔야 하는 것: **off 로 두면 접속할 수 있는 사람이 모두 관리자입니다.**
자산 기준을 바꾸거나 본사 연동을 켜는 것도 막히지 않습니다. 망에서 이 서버에 닿을 수
있는 범위가 곧 권한 범위입니다.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

def _say(msg: str = "") -> None:
    """콘솔 부호(cp949 등)로 못 쓰는 글자가 있어도 **안내가 보여야 한다.**

    줄표 하나 때문에 명령 전체가 역추적을 뱉으면, 사람은 무엇을 해야 하는지 모른다
    (실제로 그렇게 됐다 — 서버 기동 쪽에서 같은 일을 이미 겪었다).
    """
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(msg.encode(enc, "replace").decode(enc, "replace"))


MODES = {
    "off": "로그인 없음 — 접속할 수 있는 사람이 모두 관리자입니다(내부망 전용)",
    "password": "단일 비밀번호 — 실행할 때 --password 로 정합니다. 들어온 사람은 모두 관리자입니다",
    "local": "회사 이메일 계정 — 계정마다 권한이 다릅니다(처음 기동 기본값)",
    "portal": "통합 로그인(LDAP·OIDC·헤더) — conf/auth.json 의 portal 항목을 함께 맞춰야 합니다",
}


def read(base: Path) -> dict:
    p = Path(base) / "conf" / "auth.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8-sig"))


def write(base: Path, mode: str) -> dict:
    """mode 만 바꾼다 — 나머지 설정은 손대지 않는다.

    이전 파일을 auth.json.bak 으로 남기고, 임시 파일에 쓴 뒤 바꿔친다.
    """
    if mode not in MODES:
        raise ValueError("로그인 방식은 " + " · ".join(MODES) + " 중 하나입니다")
    d = Path(base) / "conf"
    d.mkdir(parents=True, exist_ok=True)
    p, bak, tmp = d / "auth.json", d / "auth.json.bak", d / "auth.json.tmp"
    conf = read(base)
    if p.exists():
        bak.write_bytes(p.read_bytes())
    before = conf.get("mode", "(없음)")
    conf["mode"] = mode
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(conf, ensure_ascii=False, indent=2) + "\n")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(p)
    return {"before": before, "after": mode}


def write_local(base: Path, key: str, value) -> None:
    """conf/auth.json 의 local.<key> 한 칸만 고친다 — 나머지는 손대지 않는다.

    가입 방식처럼 **돌고 있는 서버가 화면에서 바꾸는** 값이 있다. 설정 변경 때문에
    서비스를 재기동하는 것은 허용되지 않으므로(사용자 규칙), 파일에 적는 것과 함께
    프로세스가 들고 있는 값도 그 자리에서 바꿔야 한다 — 이 함수는 **파일 쪽만** 한다.
    """
    d = Path(base) / "conf"
    d.mkdir(parents=True, exist_ok=True)
    p, bak, tmp = d / "auth.json", d / "auth.json.bak", d / "auth.json.tmp"
    conf = read(base)
    loc = dict(conf.get("local") or {})
    loc[key] = value
    conf["local"] = loc
    if p.exists():
        bak.write_bytes(p.read_bytes())
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(conf, ensure_ascii=False, indent=2) + "\n")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(p)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LogTriage 로그인 방식 보기·바꾸기")
    ap.add_argument("--base", required=True, help="설치 경로(conf/auth.json 이 있는 곳의 상위)")
    ap.add_argument("mode", nargs="?", choices=sorted(MODES), help="바꿀 방식(없으면 지금 값만 보여 줍니다)")
    a = ap.parse_args(argv)
    base = Path(a.base)

    try:
        conf = read(base)
    except (OSError, ValueError) as e:
        print(f"로그인 설정을 읽지 못했습니다: {e}", file=sys.stderr)
        return 2
    now = conf.get("mode", "(설정 파일 없음)")

    if not a.mode:
        _say(f"지금 로그인 방식: {now}")
        for k, v in MODES.items():
            _say(("  * " if k == now else "    ") + f"{k:9s} {v}")
        _say("\n바꾸려면:  python3 -m logtriage.authmode --base " + str(base) + " <방식>")
        return 0

    if a.mode == now:
        _say(f"이미 {now} 입니다 — 바꾸지 않았습니다")
        return 0
    try:
        r = write(base, a.mode)
    except (OSError, ValueError) as e:
        print(f"바꾸지 못했습니다: {e}", file=sys.stderr)
        return 2
    _say(f"로그인 방식을 바꿨습니다: {r['before']} -> {r['after']}")
    _say("  " + MODES[a.mode])
    if a.mode in ("off", "password"):
        _say("\n[알아 두십시오] 이 방식에서는 **들어온 사람이 모두 관리자**입니다.")
        _say("  자산 기준 바꾸기·본사 연동 켜기도 막히지 않습니다.")
        _say("  망에서 이 서버에 닿을 수 있는 범위가 곧 권한 범위가 됩니다.")
    if a.mode == "off":
        _say("\n[중요] 로그인 없이 **망에 열린 채로는 기동하지 않습니다.**")
        _say("  --host 127.0.0.1 로 이 PC 안에서만 쓰시거나,")
        _say("  --password '<비밀번호>' 로 최소한의 잠금을 걸어 주십시오.")
    _say("\n서비스를 다시 시작해야 반영됩니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
