# -*- coding: utf-8 -*-
"""서버가 돌고 있는지 — **다른 프로세스에서** 알아보는 자물쇠.

왜 필요한가. `hubadmin` 은 서버와 **다른 프로세스**다. 서버 안의 threading.Lock 은 거기에
아무 효과가 없다. 그래서 이런 어긋남이 생겼다(실제로 재현했다).

    서버가 도는 중             디스크
      신원 BUSAN               CLI 가 identity-reset → SEOUL
      전송기는 BUSAN 으로 보냄   hub_identity.json 은 SEOUL

돌고 있는 것과 파일이 다른 상태다. 감사 기록도 두 프로세스가 동시에 쓴다.

이번 판에서는 **가장 안전한 쪽**으로 간다 — 서버가 돌고 있으면 바꾸는 명령을 거절한다.
보기만 하는 것(status)은 돌고 있어도 된다. 무중단으로 바꾸는 길이 정말 필요해지면 그때
서버와 CLI 가 함께 쓰는 관리 통로를 설계한다. 지금 억지로 프로세스 사이 맞물림을 만드는
것보다 서비스를 잠깐 내리라고 하는 편이 훨씬 안전하다(GPT 8차).

운영 절차:
    systemctl stop logtriage
    python3 -m logtriage.hubadmin --base <설치경로> recover --confirm
    systemctl start logtriage

OS 자물쇠를 쓰므로 **서버가 죽어 버려도 자물쇠는 저절로 풀린다** — 멈춘 흔적 파일 때문에
영영 못 고치는 일은 없다.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

LOCK_FILE = "server.lock"


def _path(base) -> Path:
    return Path(base) / "data" / LOCK_FILE


def _lock(fh) -> bool:
    """이 파일을 나 혼자 쥘 수 있는가 — 쥐었으면 참.

    **반드시 맨 앞으로 옮긴 뒤 쥔다.** 윈도에서 msvcrt 는 '지금 자리' 에서 한 바이트를
    쥐는데, 열기를 a+b 로 하면 자리가 파일 끝이다. 그러면 쥐는 자리가 서로 달라
    **둘 다 쥐어지고 아무도 막히지 않는다** — 실제로 그렇게 서버가 돌고 있는데도
    '안 돌고 있다' 로 나왔다.
    """
    try:
        fh.seek(0)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


class Held:
    """서버가 사는 동안 쥐고 있는 자물쇠. 프로세스가 죽으면 OS 가 풀어 준다."""

    def __init__(self, fh):
        self._fh = fh

    def release(self) -> None:
        try:
            self._fh.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            self._fh.close()
        except OSError:
            pass


def acquire(base) -> Held | None:
    """서버가 기동하며 쥔다. 못 쥐면 None — 이미 다른 서버가 돌고 있다는 뜻이다."""
    f = _path(base)
    try:
        f.parent.mkdir(parents=True, exist_ok=True)
        fh = open(f, "a+b")
    except OSError:
        return None                       # 자물쇠를 못 만들어도 서버가 못 뜨는 일은 없게
    if not _lock(fh):
        fh.close()
        return None
    # 맨 앞 한 바이트는 **자물쇠 자리**다 — 거기를 덮어쓰지 않고 그 뒤에 프로세스 번호를 적는다
    try:
        fh.seek(1)
        fh.truncate(1)
        fh.write(f" {os.getpid()}".encode("ascii"))
        fh.flush()
    except OSError:
        pass
    return Held(fh)


def running(base) -> int:
    """서버가 돌고 있으면 그 프로세스 번호(모르면 -1), 아니면 0.

    **쥐어 보고 바로 놓는 것**으로 판별한다. 흔적 파일이 남았는지로 보면, 서버가 죽어 버린
    뒤에 영영 '돌고 있다' 가 된다.
    """
    f = _path(base)
    if not f.exists():
        return 0
    try:
        fh = open(f, "a+b")
    except OSError:
        return -1                         # 열 수 없으면 모른다 — 돌고 있다고 본다(fail-closed)
    try:
        if _lock(fh):                     # 내가 쥐었다 = 아무도 안 쥐고 있었다
            try:
                fh.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            except OSError:
                pass
            return 0
        try:
            fh.seek(1)
            return int(fh.read(16).decode("ascii", "replace").strip() or -1)
        except (OSError, ValueError):
            return -1
    finally:
        try:
            fh.close()
        except OSError:
            pass


if __name__ == "__main__":              # 손으로 확인할 때
    print(running(sys.argv[1] if len(sys.argv) > 1 else "."))
