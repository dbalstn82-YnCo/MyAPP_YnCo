# -*- coding: utf-8 -*-
"""판 지문(Build ID) — **코드가 실제로 바뀌었는지** 가리는 값.

왜 필요한가. 제품 판 표시를 `1.0.0` 하나로 고정하기로 했다(사용자 결정). 사람에게 보여 줄
이름으로는 그것이 맞지만, 그 값만으로는 **"패치했는데 화면이 그대로"** 를 가려낼 수 없다 —
패치를 해도 `1.0.0` 이고 안 해도 `1.0.0` 이기 때문이다. 전에는 날짜-r번호가 그 일을 했다.

그래서 둘을 나눈다.

    제품 판   1.0.0          사람이 보는 이름. 완전히 새로워지기 전까지 바뀌지 않는다.
    판 지문   8f31c0a72d4e   코드 내용에서 뽑는다. 한 줄만 고쳐도 달라진다.

만드는 법: 돌아가는 코드 파일마다 **상대 경로 + 내용 SHA-256** 을 적고, 정렬해 한 줄로
이어 붙인 뒤 다시 SHA-256 을 떠서 앞 12자를 쓴다. 경로를 함께 넣는 것은 파일이 옮겨지거나
이름이 바뀐 것도 바뀜으로 보기 위해서다.

**무엇을 넣지 않는가**가 중요하다.
  · data/ · conf/ · uploads/ · reports/  — 운영 자료다. 바뀐다고 코드가 바뀐 것이 아니다.
  · rules/ · errorcodes/ · manuals/      — 룰팩으로 따로 갱신된다. 함께 넣으면 룰팩만 올려도
                                            지문이 달라져 "코드가 바뀌었다" 고 잘못 말한다.
  · __pycache__ · *.pyc                  — 같은 소스에서도 달라진다.

**/healthz 는 디스크를 다시 읽지 않는다.** 기동할 때 메모리에 담아 둔 값을 돌려준다.
옛 프로세스가 그대로 떠 있는데 새 파일만 덮어쓴 상황에서 디스크를 읽으면, 돌고 있는 것은
옛 코드인데 새 지문을 돌려주는 **거짓 성공**이 된다. 그것이 바로 이 값으로 잡으려는 상황이다.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

# 지문에 넣는 파일 — **꾸러미 안의 것은 전부**.
#
# 전에는 확장자 목록으로 걸렀다. 그래서 글자가 아닌 화면 자산(.svg·.png·.woff·.xlsx 등)이
# 지문에서 빠졌다 — 화면 그림만 바꾼 패치는 '코드가 안 바뀌었다' 가 되어, 이 판에서 반복해서
# 겪은 "고쳤는데 화면이 그대로" 를 또 놓쳤을 것이다(GPT 21차).
# 빼는 것은 셋뿐이다: 만들어지는 것(__pycache__·*.pyc), 사용자가 넣는 것(custom),
# 그리고 지문 파일 자신(자기 참조).
SKIP_DIR = {"__pycache__", "custom"}
SKIP_SUFFIX = (".pyc", ".pyo")
LENGTH = 12
STAMP = "_build_id.json"    # 빌드가 만들어 넣는 파일 — 지문 계산에서 뺀다(자기 참조)
#
# 왜 .py 가 아니라 .json 인가. 파이썬 모듈로 두면 `from . import _build_id` 가 꾸러미 객체의
# **속성을 먼저** 본다 — 한 번 읽고 나면 다시 읽히지 않는다. 읽는 규칙이 한 가지뿐인 작은
# 파일이 낫다(pyc 도 속성 캐시도 끼어들지 않는다).


def _files(root: Path):
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIX:
            continue
        if p.name == STAMP:          # 지문을 적어 둔 파일은 지문에 넣지 않는다
            continue
        yield p


def compute_items(items) -> str:
    """(상대 경로, 내용) 목록에서 지문을 만든다 — 지문 계산은 **여기 한 곳**에서만 한다.

    빌드(배포물 전체)와 서버(꾸러미)가 각자 계산하면 둘이 갈라진다.
    """
    h = hashlib.sha256()
    for rel, blob in sorted(items, key=lambda x: x[0]):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(blob).hexdigest().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()[:LENGTH]


def compute(pkg_dir=None) -> str:
    """logtriage 꾸러미의 내용에서 지문을 만든다 — 한 줄만 고쳐도 달라진다."""
    root = Path(pkg_dir) if pkg_dir else Path(__file__).resolve().parent
    return compute_items((p.relative_to(root).as_posix(), p.read_bytes()) for p in _files(root))


def dist_items(stage: Path):
    """배포물 지문에 들어가는 것 — 엔진 꾸러미와 **기동 스크립트**.

    run.sh 만 바뀌어도 실제 기동 동작이 바뀐다. 그때 지문이 그대로면 '패치가 먹었는가' 를
    가릴 수 없다(현장에서 실제로 그렇게 됐다).
    """
    pkg = stage / "engine" / "logtriage"
    for p in _files(pkg):
        yield ("engine/logtriage/" + p.relative_to(pkg).as_posix(), p.read_bytes())
    for name in ("run.sh", "stop.sh"):
        f = stage / name
        if f.exists():
            yield (name, f.read_bytes())


def stamped(pkg_dir=None) -> dict:
    """빌드가 박아 둔 지문 — 없으면 빈 사전(개발 트리에서는 없는 것이 정상)."""
    root = Path(pkg_dir) if pkg_dir else Path(__file__).resolve().parent
    try:
        d = json.loads((root / STAMP).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(d, dict):
        return {}
    return {"id": str(d.get("id", "")), "code": str(d.get("code", "")), "scope": str(d.get("scope", ""))}


_FIXED: list = []
_CODE: list = []


def code() -> str:
    """지금 돌고 있는 **코드**의 지문 — 기동할 때 한 번만 계산한다.

    꾸러미에 지문을 박아 두면 '설치 뒤에 누가 파일을 손댔다' 를 못 잡는다. 이 값은 그
    자리를 지킨다(빌드가 적어 둔 CODE 와 다르면 손댄 것이다).
    """
    if not _CODE:
        import sys as _sys
        st = stamped()
        if getattr(_sys, "frozen", False) and st.get("code"):
            # 12차(PC·리눅스 같은 판 관리): exe 안에는 .py 원본이 없어(압축 아카이브) 원본 지문을 다시 셀 수 없다.
            # 빌드(tools/build/build_pc.py)가 원본에서 센 코드 지문을 넣어 두었다 — 리눅스 묶음의 code 와 같은 값이어야 한다.
            # exe 자체가 바뀌었는지는 exe 해시(설치 기록·빌드 장부)가 지킨다.
            _CODE.append(st["code"])
        else:
            try:
                _CODE.append(compute())
            except OSError:
                _CODE.append("")
    return _CODE[0]


def modified() -> bool:
    st = stamped()
    return bool(st.get("code")) and st["code"] != code()


def current() -> str:
    """이 프로세스의 판 지문 — **처음 부를 때 한 번만** 구하고 그 값을 계속 돌려준다.

    디스크를 다시 읽지 않는 것이 핵심이다. 옛 프로세스가 떠 있는데 새 파일만 덮어쓴 상황에서
    매번 읽으면, 돌고 있는 것은 옛 코드인데 새 지문을 돌려주는 **거짓 성공**이 된다 —
    그것이 바로 이 값으로 잡으려는 상황이다(GPT 8차).
    """
    if not _FIXED:
        st = stamped()
        _FIXED.append(st.get("id") or code())      # 빌드가 박은 값이 있으면 그것이 배포 지문이다
    return _FIXED[0]
