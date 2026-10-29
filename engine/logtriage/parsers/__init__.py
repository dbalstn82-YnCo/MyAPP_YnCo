"""파서 레지스트리 — 제품명으로 파서를 찾는다. 새 제품 지원은 모듈 추가 + 등록."""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from ..schema import Event

Parser = Callable[[Path, str], list[Event]]  # (파일, 호스트명) -> 이벤트 목록

_REGISTRY: dict[str, tuple[str, Parser]] = {}  # product -> (layer, parser)

# ── 12차 성능 ①: 빠른 시각 해석 ─────────────────────────────────────────
# datetime.strptime 은 줄마다 로캘 잠금·정규식 생성 캐시 조회를 거쳐 100MB 로그에서 분석 시간의 약 30% 를 썼다(프로파일 실측).
# 고정 폭 숫자(%Y %m %d %H %M %S %y)·영문 월 약어(%b)·글자 그대로인 구분자만으로 된 형식은 자리로 잘라 읽고,
# 길이·숫자·값이 하나라도 맞지 않거나 지원하지 않는 지시자가 있으면 **원래 strptime 으로** 넘긴다 — 결과·오류가 같다(무작위 대조 시험).
_FW = {"Y": 4, "m": 2, "d": 2, "H": 2, "M": 2, "S": 2, "y": 2, "b": 3}
_MON = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"), 1)}
_FMT_CACHE: dict = {}


def _compile_fmt(fmt: str):
    spec, pos, i = [], 0, 0
    while i < len(fmt):
        c = fmt[i]
        if c == "%":
            if i + 1 >= len(fmt):
                return None
            d = fmt[i + 1]
            if d not in _FW:
                return None                     # %a %f %z %p %j … — 원래 함수로
            spec.append((d, pos, pos + _FW[d]))
            pos += _FW[d]
            i += 2
        else:
            if c.isdigit() or (c.isspace() and c != " "):
                return None
            # 형식의 공백 한 칸: strptime 은 '공백 1개 이상'을 받지만 여기서는 정확히 한 칸일 때만 빠른 길(길이가 다르면 원래 함수로)
            spec.append(("=", pos, c))
            pos += 1
            i += 1
    if not any(d == "Y" or d == "y" for d, *_ in spec) and fmt.count("%") < 3:
        return None
    return spec, pos


def fast_strptime(s: str, fmt: str) -> datetime:
    c = _FMT_CACHE.get(fmt, False)
    if c is False:
        c = _FMT_CACHE[fmt] = _compile_fmt(fmt)
    if c is None or len(s) != c[1]:
        return datetime.strptime(s, fmt)
    v = {"Y": 1900, "m": 1, "d": 1, "H": 0, "M": 0, "S": 0}
    for d, a, b in c[0]:
        if d == "=":
            if s[a] != b:
                return datetime.strptime(s, fmt)
            continue
        t = s[a:b]
        if d == "b":
            mon = _MON.get(t.lower())
            if mon is None:
                return datetime.strptime(s, fmt)
            v["m"] = mon
            continue
        if not t.isdigit() or not t.isascii():
            return datetime.strptime(s, fmt)
        n = int(t)
        if d == "y":
            v["Y"] = n + (2000 if n <= 68 else 1900)
        else:
            v[d] = n
    try:
        return datetime(v["Y"], v["m"], v["d"], v["H"], v["M"], v["S"])
    except ValueError:
        return datetime.strptime(s, fmt)


def register(product: str, layer: str):
    def deco(fn: Parser) -> Parser:
        _REGISTRY[product] = (layer, fn)
        return fn
    return deco


import gzip
import io
import re

# 개인정보 마스킹 — 주민등록번호(13자리, 하이픈 유무) 뒷자리를 가린다. 실로그(연계 전문)에 자주 섞임
_RRN = re.compile(r"(?<!\d)(\d{6})-?(\d{7})(?!\d)")


def mask_pii(line: str) -> str:
    if len(line) >= 13 and _RRN.search(line):
        return _RRN.sub(lambda m: m.group(1) + "-*******", line)
    return line


def detect_encoding(path: Path) -> str:
    """BOM → UTF-16/UTF-8, 아니면 앞부분을 UTF-8 로 엄격 디코딩해 보고 실패하면 CP949(한글 Windows/AIX 로그)."""
    try:
        with open(path, "rb") as fb:
            head = fb.read(65536)
    except OSError:
        return "utf-8"
    if path.suffix.lower() == ".gz":
        try:
            head = gzip.GzipFile(fileobj=io.BytesIO(head)).read(65536)
        except Exception:
            head = head  # 잘린 gzip 은 부분 해제 실패 가능 — 원본 헤더로 판단(대부분 UTF-8)
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "utf-16"
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    # UTF-16 without BOM: NUL 바이트가 규칙적으로 섞임
    if len(head) > 200 and head.count(b"\x00") > len(head) // 4:
        return "utf-16-le"
    sub = head[: len(head) - 4]
    try:
        sub.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as e:
        if e.start >= len(sub) - 4:  # 경계에서 잘린 멀티바이트 문자 — UTF-8 로 간주
            return "utf-8"
        return "cp949"


_EXC = re.compile(r"(?:^|Caused by:\s*|<<__Exception__>>\s*)((?:[a-z][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable))\b", re.M)


def exception_code(text: str) -> str | None:
    """메시지/스택트레이스에서 대표 예외 클래스(FQCN)를 뽑아 코드로 쓴다 — 가장 안쪽(Caused by 마지막) 우선."""
    if len(text) > 6000:  # 앞(최상위 예외)·뒤(Caused by 최하위) 만 검사
        text = text[:3500] + "\n" + text[-2500:]
    found = _EXC.findall(text)
    return found[-1] if found else None


def open_text(path: Path):
    """인코딩 자동 판별(UTF-8/UTF-16/CP949) + .gz 투명 해제 텍스트 스트림."""
    enc = detect_encoding(path)
    if path.suffix.lower() == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding=enc, errors="replace", newline="")
    return open(path, encoding=enc, errors="replace", newline="")


_RANGE = None   # 12차 병렬: 작업자 프로세스가 맡은 조각 (시작 바이트, 끝 바이트, 첫 줄 번호, 인코딩) — None 이면 파일 전체


def set_range(r) -> None:
    global _RANGE
    _RANGE = r


class _RangeRaw(io.RawIOBase):
    """파일의 [start, end) 바이트만 읽는 원시 스트림 — 그 위에 원래와 같은 텍스트 모드(newline='')를 얹는다."""

    def __init__(self, path: Path, start: int, end: int):
        self._f = open(path, "rb")
        self._f.seek(start)
        self._left = end - start

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        if self._left <= 0:
            return 0
        data = self._f.read(min(len(b), self._left))
        n = len(data)
        b[:n] = data
        self._left -= n
        return n

    def close(self) -> None:
        try:
            self._f.close()
        finally:
            super().close()


def iter_lines(path: Path):
    """대용량 대응: 파일 전체를 메모리에 올리지 않고 (행번호, 행) 을 순차 제공. 개인정보(주민번호)는 마스킹.
    12차: 병렬 작업자가 조각을 맡으면(_RANGE) 그 바이트 범위만 같은 규칙으로 읽고 줄 번호를 이어 붙인다."""
    r = _RANGE
    if r is None:
        f, first = open_text(path), 1
    else:
        start, end, first, enc = r
        f = io.TextIOWrapper(io.BufferedReader(_RangeRaw(path, start, end), 1 << 20), encoding=enc, errors="replace", newline="")
    with f:
        for i, line in enumerate(f, first):
            yield i, mask_pii(line.rstrip("\r\n"))


_FILTER = None  # service 가 설정: callable(Event) -> bool (True 면 보관). None 이면 전부 보관


def set_event_filter(fn) -> None:
    global _FILTER
    _FILTER = fn


class EventSink(list):
    """파서가 이벤트를 담는 리스트. 대용량 대응: 필터가 '버려도 됨'이라 하면 객체를 보관하지 않고
    분 단위 건수(dropped)만 남긴다 — 히스토그램·총계는 유지되고 메모리는 크게 줄어든다."""
    __slots__ = ("dropped",)

    def __init__(self):
        super().__init__()
        self.dropped: dict = {}

    def append(self, ev):
        f = _FILTER
        if f is not None and ev.severity == "info" and ev.code is None and not f(ev):
            mk = ev.ts.replace(second=0, microsecond=0)
            self.dropped[mk] = self.dropped.get(mk, 0) + 1
            return
        super().append(ev)

    @property
    def total(self) -> int:
        return len(self) + sum(self.dropped.values())


def get_parser(product: str) -> tuple[str, Parser]:
    p = product.lower()
    if p not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY))
        raise KeyError(f"지원하지 않는 제품 '{product}' (지원: {known})")
    return _REGISTRY[p]


def supported_products() -> list[str]:
    return sorted(_REGISTRY)


from . import (  # noqa: E402,F401  (등록 유발)
    tomcat, nginx, oracle_alert, linux_syslog, windows_event,
    was_logs, apache, iis, db_logs, auditd, log4j, webtob, accesslog, logtypes, tmax_eai,
)
