"""룰 정규식 사전 필터(앵커) — 정규식을 실행하기 전에 "반드시 포함돼야 하는 리터럴" 로 이벤트를 거른다.

anchors(pattern) → ((lit, lit, …), (lit, …), …)
  · 바깥 튜플 = 최상위 대안(|) 하나씩, 안쪽 튜플 = 그 대안이 일치하려면 메시지에 전부 들어 있어야 하는 소문자 리터럴.
  · 이벤트는 어느 한 대안의 리터럴을 모두 포함할 때만 정규식을 실행한다(anchor_hit).
  · 어느 대안에서든 4자 이상 리터럴을 못 뽑으면 빈 튜플 → 필터 없이 정규식만 사용(항상 안전한 방향).
안전 규칙(거짓 음성 방지): 선택 가능(?, *, {0,n})·대안이 여러 개인 그룹·문자 클래스·이스케이프 클래스(\\d \\w \\s …)·
lookaround 은 리터럴을 남기지 않는다. 룰은 모두 IGNORECASE 로 컴파일되므로 양쪽 소문자 비교가 정확하다.
"""
from __future__ import annotations

import re

_QUANT = re.compile(r"\{(\d*)(?:,(\d*))?\}")
_ESC_CLASS = set("dDwWsSbBAZ")
_MIN_RUN = 3     # 이 길이 미만 리터럴은 검사 목록에서 제외(선별력 없음)
_MIN_BEST = 4    # 대안마다 최소 이 길이의 리터럴 하나는 있어야 필터 채택


def anchor_hit(anchors: tuple, text_lower: str) -> bool:
    for br in anchors:
        for a in br:
            if a not in text_lower:
                break
        else:
            return True
    return False


def _quantifier(p: str, i: int) -> tuple[bool | None, int]:
    """p[i:] 가 수량자면 (optional 여부, 다음 위치), 아니면 (None, i)."""
    if i >= len(p):
        return None, i
    ch = p[i]
    if ch in "*?":
        opt, j = True, i + 1
    elif ch == "+":
        opt, j = False, i + 1
    elif ch == "{":
        m = _QUANT.match(p, i)
        if not m:
            return None, i
        lo = int(m.group(1) or 0)
        opt, j = lo == 0, m.end()
    else:
        return None, i
    if j < len(p) and p[j] in "?+":  # lazy / possessive 접미
        j += 1
    return opt, j


def _skip_class(p: str, i: int) -> int:
    """p[i] == '[' 인 문자 클래스의 끝 다음 위치."""
    j = i + 1
    if j < len(p) and p[j] == "^":
        j += 1
    if j < len(p) and p[j] == "]":
        j += 1
    while j < len(p):
        if p[j] == "\\":
            j += 2
            continue
        if p[j] == "]":
            return j + 1
        j += 1
    return len(p)


def _parse(p: str, i: int) -> tuple[list[list[str]], int]:
    """p[i:] 를 ')' 또는 끝까지 파싱 → (대안별 필수 리터럴 목록, 다음 위치)."""
    alts: list[list[str]] = []
    runs: list[str] = []
    cur: list[str] = []

    def flush():
        if cur:
            runs.append("".join(cur))
            cur.clear()

    n = len(p)
    while i < n:
        ch = p[i]
        if ch == "\\" and i + 1 < n:
            nx = p[i + 1]
            if nx in _ESC_CLASS or nx.isdigit() or nx in "ntrfvxu0":
                flush()
                _, i = _quantifier(p, i + 2)
            else:
                lit = nx
                opt, j = _quantifier(p, i + 2)
                if opt is None:
                    cur.append(lit)
                    i += 2
                else:
                    if not opt:
                        cur.append(lit)
                    flush()
                    i = j
            continue
        if ch == "|":
            flush()
            alts.append(runs)
            runs, cur = [], []
            i += 1
            continue
        if ch == ")":
            flush()
            alts.append(runs)
            return alts, i + 1
        if ch == "(":
            flush()
            if p.startswith("(?", i):
                if p.startswith(("(?=", "(?!", "(?<=", "(?<!"), i):
                    _, i = _parse(p, i + (4 if p[i + 2] == "<" else 3))
                    continue
                m = re.match(r"\(\?[aiLmsux-]+\)", p[i:])
                if m:  # 인라인 플래그
                    i += m.end()
                    continue
                m = re.match(r"\(\?P<[^>]+>|\(\?[aiLmsux-]*:", p[i:])
                start = i + (m.end() if m else 2)
            else:
                start = i + 1
            inner, i = _parse(p, start)
            opt, i = _quantifier(p, i)
            if not opt and len(inner) == 1:
                runs.extend(inner[0])
            continue
        if ch == "[":
            flush()
            i = _skip_class(p, i)
            opt, i = _quantifier(p, i)
            continue
        if ch in ".^$":
            flush()
            i += 1
            opt, i = _quantifier(p, i)
            continue
        opt, j = _quantifier(p, i + 1)
        if opt is None:
            cur.append(ch)
            i += 1
        else:
            if not opt:
                cur.append(ch)
            flush()
            i = j
    flush()
    alts.append(runs)
    return alts, i


def anchors(pattern: str) -> tuple[tuple[str, ...], ...]:
    try:
        alts, _ = _parse(pattern, 0)
    except Exception:
        return ()
    out = []
    for runs in alts:
        lits = tuple(dict.fromkeys(r.lower() for r in runs if len(r) >= _MIN_RUN))
        if not lits or max(len(x) for x in lits) < _MIN_BEST:
            return ()
        out.append(lits)
    return tuple(dict.fromkeys(out))
