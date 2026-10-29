# -*- coding: utf-8 -*-
"""배포 산출물에 박히는 '빌드 표시'를 한 곳에서만 읽고, 치환이 조용히 실패하지 않게 막는다.

여태 verify.sh·reinstall.sh·apply_patch.sh 에 빌드 표시를 손으로 박아 두어,
엔진만 올리고 확인 스크립트는 옛 값을 들고 나가는 일이 있었다. 이 모듈을 거치면
  ① 빌드 표시는 engine/logtriage/__init__.py 한 곳에서만 나오고
  ② 자리표시자가 없거나 둘 이상이면 빌드가 그 자리에서 멈추고
  ③ 다 만든 zip 을 다시 열어 다른 판의 표시가 섞이지 않았는지 전수로 본다.
assert 를 쓰지 않는다 — python -O 로 돌리면 사라지기 때문이다.
"""
import sys
import re
import zipfile
from pathlib import Path

TOKEN = "@@LOGTRIAGE_BUILD@@"
TOKEN_ID = "@@LOGTRIAGE_BUILDID@@"   # 판 지문 — 코드가 바뀌었는지 가리는 값
_DEF = re.compile(r'(?m)^\s*BUILD\s*=\s*["\']([^"\']+)["\']')
_FMT = re.compile(r"\d+\.\d+\.\d+")          # 제품 버전 하나 — 날짜·r번호를 쓰지 않는다
# 옛 꼴(날짜-r번호)의 판 표시 — 버전 하나로 바꾼 뒤에도 남아 있으면 안 된다.
_OLD = re.compile(rb"\b20\d{2}\.\d{2}\.\d{2}-r\d+\b")
_TEXT = (".sh", ".py", ".txt", ".md", ".json", ".html", ".css", ".cmd", ".ps1",
         ".service", ".conf", ".example", ".yaml", ".yml")


def build_id(engine_dir) -> str:
    """engine/logtriage/__init__.py 의 BUILD 를 읽는다 — 정의가 정확히 하나일 때만."""
    init = Path(engine_dir) / "logtriage" / "__init__.py"
    if not init.is_file():
        raise RuntimeError(f"빌드 표시를 읽을 파일이 없습니다: {init}")
    found = _DEF.findall(init.read_text(encoding="utf-8"))
    if len(found) != 1:
        raise RuntimeError(f"{init} 의 BUILD 정의는 하나여야 합니다 — {len(found)}개 발견: {found}")
    bid = found[0]
    if not _FMT.fullmatch(bid):
        # 이 값은 셸 스크립트의 큰따옴표 사이로 들어간다. 형식을 벗어나면 여기서 멈춘다.
        raise RuntimeError(f"BUILD 형식이 X.Y.Z 가 아닙니다: {bid!r}")
    return bid


def inject_id(text: str, build_id: str, name: str) -> str:
    """판 지문 자리표시자를 바꾼다 — 하나도 없거나 둘 이상이면 중단."""
    n = text.count(TOKEN_ID)
    if n != 1:
        raise RuntimeError(f"{name}: 지문 자리표시자 {TOKEN_ID} 가 하나여야 합니다 — {n}개")
    if not re.fullmatch(r"[0-9a-f]{8,32}", build_id or ""):
        raise RuntimeError(f"{name}: 판 지문 꼴이 아닙니다: {build_id!r}")
    out = text.replace(TOKEN_ID, build_id)
    if out.count(f'WANT_ID="{build_id}"') != 1:
        raise RuntimeError(f'{name}: WANT_ID="{build_id}" 가 하나여야 합니다')
    return out


def inject(text: str, bid: str, name: str) -> str:
    """스크립트 본문의 자리표시자를 빌드 표시로 바꾼다 — 하나도 없거나 둘 이상이면 중단."""
    n = text.count(TOKEN)
    if n != 1:
        raise RuntimeError(f"{name}: 빌드 자리표시자 {TOKEN} 가 하나여야 합니다 — {n}개")
    out = text.replace(TOKEN, bid)
    if TOKEN in out:
        raise RuntimeError(f"{name}: 치환 뒤에도 자리표시자가 남았습니다")
    if out.count(f'WANT="{bid}"') != 1:
        raise RuntimeError(f'{name}: WANT="{bid}" 가 하나여야 합니다')
    return out


# 빌드 도구 자신(이 파일 포함)은 자리표시자를 정당하게 들고 있다 — 검사에서 뺀다
SKIP_DEFAULT = ("tools/build/",)


def audit_zip(zip_path, bid: str, skip=SKIP_DEFAULT) -> None:
    """다 만든 zip 을 다시 열어, 들어 있는 제품 빌드 표시가 이번 판 하나뿐인지 본다."""
    zip_path = Path(zip_path)
    hits, stale = [], {}
    # **맨 글자로 찾지 않는다.** '1.0.0' 은 남의 꾸러미 버전으로도 흔히 나온다 —
    # 실제로 '9.9.9' 로 검사했더니 두 곳이 걸려서, 틀린 판으로도 통과할 뻔했다.
    # 우리가 **박아 넣은 꼴 그대로** 찾는다.
    want = [f'WANT="{bid}"'.encode(),      # 적용 스크립트가 /healthz 와 견주는 값
            f"Version: {bid}".encode(),     # 전체 묶음의 VERSION.txt
            f"LogTriage {bid}".encode()]    # 안내문
    with zipfile.ZipFile(zip_path) as z:
        for zi in z.infolist():
            if zi.is_dir() or not zi.filename.endswith(_TEXT):
                continue
            if any(s in zi.filename for s in skip):
                continue
            data = z.read(zi.filename)
            if TOKEN.encode() in data:
                raise RuntimeError(f"{zip_path.name}: {zi.filename} 에 자리표시자가 그대로 남았습니다")
            if any(w in data for w in want):
                hits.append(zi.filename)
            for m in set(_OLD.findall(data)):   # 옛 꼴이 남아 있으면 그것이 곧 섞인 것이다
                stale.setdefault(m.decode(), []).append(zi.filename)
    if stale:
        raise RuntimeError(f"{zip_path.name}: 옛 꼴의 판 표시가 남아 있습니다 — " +
                           "; ".join(f"{k} ← {chr(44).join(v[:3])}" for k, v in stale.items()))
    # **하나도 못 찾으면 통과시키지 않는다.** 버전 꼴을 바꾸면서 정규식 하나가 안 바뀐 채로
    # 남아, 0곳을 찾고도 "확인 완료" 를 찍은 적이 있다 — 아무것도 지키지 못하는 검사였다.
    if not hits:
        raise RuntimeError(f"{zip_path.name}: 판 표시 {bid} 가 한 곳도 없습니다 —"
                           " 치환이 되지 않았거나 검사가 헛돌고 있습니다")
    _say(f"  판 표시 전수 확인: {zip_path.name} - {bid} ({len(hits)}곳, 옛 꼴 0곳)")


def _say(msg: str) -> None:
    """콘솔이 못 찍는 글자가 있어도 **검사가 무너지지 않게** 한다.

    실제로 cp949 콘솔에서 '\u2014'(줄표) 때문에 UnicodeEncodeError 가 나면서, zip 을 다 만든 뒤의
    빌드 표시 전수 확인이 통째로 건너뛰어졌다. 포장에서 가장 중요한 검사가 글자 하나 때문에
    사라지는 것은 안 된다.
    """
    try:
        print(msg)
    except UnicodeEncodeError:
        enc = (getattr(sys.stdout, "encoding", "") or "utf-8")
        print(msg.encode(enc, "replace").decode(enc, "replace"))


# 패키지에 들어가면 안 되는 것 — **소스 트리가 깨끗한 것과 최종 zip 이 깨끗한 것은 별개다**(GPT).
# 손으로 몇 개만 적어 두면 새 파일이 생길 때마다 빠진다. 그래서 zip 을 열어 전수로 본다.
#
# 조각 맞추기(substring)로 하면 엉뚱한 것이 걸린다 — 처음에 "secret" 으로 했더니
# tests/test_asset_secrets.py 가 걸렸다. 그래서 **파일 이름 전체 · 확장자 · 경로 조각**으로 나눈다.
BAD_NAMES = {                      # 파일 이름이 정확히 이것
    "hub.json": "본사 연동 설정(사이트 토큰이 들어 있다)",
    "hub_identity.json": "설치 신원",
    "hub_client.json": "송신 상태",
    "auth.json": "로그인 설정",
    "secret.key": "금고 열쇠",
    "report_profile.json": "보고서 기본 정보(사내)",
    "trusted_hubs": "본사 허용 목록(운영 설정)",
    "hub_allow.txt": "본사 허용 목록(운영 설정)",
    "rulepack.key": "룰팩 열쇠(따로 전달한다)",
}
BAD_SUFFIX = {                     # 확장자가 이것
    ".sqlite": "데이터베이스", ".sqlite3": "데이터베이스", ".db": "데이터베이스",
    ".key": "열쇠 파일", ".pem": "개인키", ".p12": "개인키", ".pfx": "개인키",
    ".tmp": "중간 파일", ".orig": "중간 파일", ".bak": "중간 파일", ".rej": "중간 파일",
    ".pyc": "파이썬 캐시", ".pyo": "파이썬 캐시",
}
BAD_PARTS = {                      # 경로에 이 폴더가 들어감
    "data": "운영 자료 폴더", "__pycache__": "파이썬 캐시", "custom": "사용자 등록 서식",
}
BAD_PREFIX = {                     # 파일 이름이 이것으로 시작
    "setup_code": "첫 관리자 초대 코드",
}
# 예외 — 이름이 걸리지만 들어가야 하는 것. 예시 파일은 값이 비어 있다.
ALLOW_SUFFIX = (".example",)


def audit_contents(zip_path) -> None:
    """다 만든 zip 을 열어 **들어가면 안 되는 것이 섞이지 않았는지** 전수로 본다."""
    zip_path = Path(zip_path)
    bad = []
    with zipfile.ZipFile(zip_path) as z:
        for n in z.namelist():
            if n.endswith("/"):
                continue
            parts = n.split("/")
            name = parts[-1].lower()
            if name.endswith(ALLOW_SUFFIX):
                continue
            why = BAD_NAMES.get(name)
            if not why:
                why = next((w for suf, w in BAD_SUFFIX.items() if name.endswith(suf)), "")
            if not why:
                why = next((w for pre, w in BAD_PREFIX.items() if name.startswith(pre)), "")
            if not why:
                # 맨 앞(묶음 이름)은 빼고 본다 — 묶음 폴더 이름까지 걸리면 안 된다
                why = next((w for d, w in BAD_PARTS.items() if d in parts[1:-1]), "")
            if why:
                bad.append((n, why))
    if bad:
        raise RuntimeError(f"{zip_path.name}: 들어가면 안 되는 것이 있습니다 — " +
                           "; ".join(f"{n} ({w})" for n, w in bad[:8]) +
                           (f" 외 {len(bad) - 8}개" if len(bad) > 8 else ""))
    _say(f"  반출 금지물 전수 확인: {zip_path.name} - 깨끗합니다")

def retag(text: str, bid: str) -> tuple[str, int]:
    """안내문처럼 사람이 읽는 글에 박혀 있는 옛 빌드 표시를 이번 판으로 바꾼다.

    스크립트와 달리 자리표시자를 넣어 둘 수 없는 글(그대로 열어 보는 안내문)에 쓴다.
    바꾼 자리 수를 함께 돌려주므로, 하나도 없으면 빌드 쪽에서 알아챌 수 있다.
    """
    out, n = _OLD.sub(bid.encode(), text.encode("utf-8")), len(_OLD.findall(text.encode("utf-8")))
    return out.decode("utf-8"), n
