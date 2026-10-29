"""리눅스 서버 호환 검사(12차) — RHEL 9 의 시스템 python3 는 3.9 다(install.sh 가 그것을 쓴다).

개발 PC 는 3.13 이라 3.10+ 문법·라이브러리를 써도 시험이 다 통과한다 — 리눅스 현장에서 처음 터진다.
이 검사는 엔진 꾸러미(logtriage/)의 모든 .py 를 3.9 기준으로 본다:
  ① 문법: ast.parse(feature_version=(3, 9)) — match 문·괄호 with·except* 등
  ② f-string 안에 바깥과 같은 따옴표(3.12 PEP 701) — 3.9~3.11 에서 SyntaxError
  ③ `X | Y` 타입: `from __future__ import annotations` 없는 모듈의 주석, 그리고 isinstance/issubclass 안(모듈 무관 — 실행 때 평가)
  ④ 3.10+ 표준 라이브러리: zip(strict=)·itertools.pairwise·int.bit_count·datetime.UTC·tomllib·hashlib.file_digest·
     enum.StrEnum·typing.Self/TypeAlias·ExceptionGroup·asyncio.TaskGroup·dataclass(slots=/kw_only=)·re 의 (?>…)
사용: python tools/build/py39_compat.py [꾸러미 폴더]   — 문제 0 이면 종료 코드 0
"""
from __future__ import annotations

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
NEW_ATTR = {("itertools", "pairwise"), ("datetime", "UTC"), ("hashlib", "file_digest"), ("enum", "StrEnum"), ("typing", "Self"),
            ("typing", "TypeAlias"), ("asyncio", "TaskGroup"), ("typing", "ParamSpec"), ("typing", "Concatenate"), ("typing", "TypeGuard")}
NEW_MOD = {"tomllib"}
NEW_NAME = {"ExceptionGroup", "BaseExceptionGroup", "aiter", "anext"}
RE_NEW = re.compile(r"\(\?>")      # 원자 묶음(3.11) — 소유 수량자(*+ 등)는 문자 묶음 안 기호와 구별이 어려워 뺀다(거짓 경보 났음)


def _is_union(n) -> bool:
    return isinstance(n, ast.BinOp) and isinstance(n.op, ast.BitOr)


def _fstring_same_quote(src: str) -> list[int]:
    """f-string 본문({} 안)에 바깥과 같은 따옴표가 있으면(3.12 에서만 허용) 그 줄."""
    bad = []
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
    except (tokenize.TokenError, SyntaxError, IndentationError):
        return bad
    # 3.12+ 의 tokenize 는 f-string 을 FSTRING_START·MIDDLE·END 로 쪼갠다(PEP 701) — STRING 만 보면 f-string 을 하나도 못 본다
    # (시험이 잡은 이 검사기 자신의 구멍). 바깥 f-string 의 따옴표를 쌓아 두고, 그 안의 문자열·f-string 이 같은 따옴표면 표시
    fs_start = getattr(tokenize, "FSTRING_START", None)
    fs_end = getattr(tokenize, "FSTRING_END", None)
    if fs_start is not None:
        stack: list[str] = []
        for t in toks:
            if t.type == fs_start:
                q = re.match(r"(?i)[rbuf]*('''|\"\"\"|'|\")", t.string).group(1)
                if stack and len(stack[-1]) == 1 and q == stack[-1]:
                    bad.append(t.start[0])
                stack.append(q)
            elif t.type == fs_end:
                if stack:
                    stack.pop()
            elif t.type == tokenize.STRING and stack and len(stack[-1]) == 1:
                m = re.match(r"(?i)[rbu]*('''|\"\"\"|'|\")", t.string)
                if m and m.group(1)[0] == stack[-1]:
                    bad.append(t.start[0])
        return sorted(set(bad))
    for t in toks:
        if t.type != tokenize.STRING:
            continue
        s = t.string
        m = re.match(r"(?i)([rbuf]*)('''|\"\"\"|'|\")", s)
        if not m or "f" not in m.group(1).lower():
            continue
        q = m.group(2)
        body = s[len(m.group(0)):-len(q)]
        depth = 0
        i = 0
        while i < len(body):
            c = body[i]
            if c == "{":
                if body[i:i + 2] == "{{" and depth == 0:
                    i += 2
                    continue
                depth += 1
            elif c == "}":
                if body[i:i + 2] == "}}" and depth == 0:
                    i += 2
                    continue
                depth = max(0, depth - 1)
            elif depth and len(q) == 1 and c == q:
                bad.append(t.start[0])
                break
            i += 1
    return bad


def check_file(p: Path, rel: str) -> list[str]:
    src = p.read_text(encoding="utf-8")
    out = []
    try:
        tree = ast.parse(src, feature_version=(3, 9))
    except SyntaxError as e:
        return [f"{rel}:{e.lineno}: 3.9 문법 아님 — {e.msg}"]
    for ln in _fstring_same_quote(src):
        out.append(f"{rel}:{ln}: f-string 안에 바깥과 같은 따옴표(3.12 전용)")
    future = any(isinstance(n, ast.ImportFrom) and n.module == "__future__" and any(a.name == "annotations" for a in n.names)
                 for n in tree.body)
    for n in ast.walk(tree):
        if not future:
            anns = []
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                anns = [a.annotation for a in n.args.args + n.args.kwonlyargs + n.args.posonlyargs] + [n.returns]
            elif isinstance(n, ast.AnnAssign):
                anns = [n.annotation]
            for a in anns:
                if a is not None and any(_is_union(x) for x in ast.walk(a)):
                    out.append(f"{rel}:{a.lineno}: `X | Y` 주석인데 from __future__ import annotations 없음(3.9 에서 import 실패)")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("isinstance", "issubclass") and len(n.args) == 2:
            if any(_is_union(x) for x in ast.walk(n.args[1])):
                out.append(f"{rel}:{n.lineno}: isinstance(…, X | Y) 는 3.10+")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "zip" and any(k.arg == "strict" for k in n.keywords):
            out.append(f"{rel}:{n.lineno}: zip(strict=) 는 3.10+")
        if isinstance(n, ast.Call) and any(k.arg in ("slots", "kw_only") for k in n.keywords) and "dataclass" in ast.dump(n.func):
            out.append(f"{rel}:{n.lineno}: dataclass(slots=/kw_only=) 는 3.10+")
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and (n.value.id, n.attr) in NEW_ATTR:
            out.append(f"{rel}:{n.lineno}: {n.value.id}.{n.attr} 는 3.10+")
        if isinstance(n, ast.Attribute) and n.attr == "bit_count":
            out.append(f"{rel}:{n.lineno}: int.bit_count 는 3.10+")
        # GPT 93차 P0(3.9 실행 관문): 문법은 맞아도 3.9 에서 실행 때 터지는 표준 라이브러리 메서드·인자
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            at, kws = n.func.attr, {k.arg for k in n.keywords}
            owner = n.func.value.id if isinstance(n.func.value, ast.Name) else ""
            if at == "walk" and owner not in ("os", "ast", "snmp", "_snmp", "pkgutil"):   # 자기 모듈의 walk(SNMP)·ast.walk 는 다른 것
                out.append(f"{rel}:{n.lineno}: Path.walk 는 3.12+ (os.walk 를 쓸 것)")
            if at in ("batched", "hardlink_to", "is_junction", "splitroot") or (owner == "sys" and at == "exception"):
                out.append(f"{rel}:{n.lineno}: {owner + '.' if owner else ''}{at} 는 3.10+")
            if at == "from_bytes" and len(n.args) < 2 and "byteorder" not in kws:
                out.append(f"{rel}:{n.lineno}: int.from_bytes 의 byteorder 생략은 3.11+")
            if owner == "bisect" and "key" in kws:
                out.append(f"{rel}:{n.lineno}: bisect(key=) 는 3.10+")
            if owner == "glob" and kws & {"root_dir", "dir_fd", "include_hidden"}:
                out.append(f"{rel}:{n.lineno}: glob(root_dir=/dir_fd=) 는 3.10+")
        if isinstance(n, ast.Call) and any(k.arg == "encoding" and isinstance(k.value, ast.Constant) and k.value.value == "locale" for k in n.keywords):
            out.append(f"{rel}:{n.lineno}: encoding='locale' 은 3.10+")
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            mods = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module or ""]
            for m in mods:
                if m.split(".")[0] in NEW_MOD:
                    out.append(f"{rel}:{n.lineno}: {m} 는 3.11+")
            if isinstance(n, ast.ImportFrom) and n.module in {a for a, _ in NEW_ATTR}:
                for a in n.names:
                    if (n.module, a.name) in NEW_ATTR:
                        out.append(f"{rel}:{n.lineno}: from {n.module} import {a.name} 는 3.10+")
        if isinstance(n, ast.Name) and n.id in NEW_NAME:
            out.append(f"{rel}:{n.lineno}: {n.id} 는 3.10+/3.11+")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "re" \
                and n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) and RE_NEW.search(n.args[0].value):
            out.append(f"{rel}:{n.lineno}: 정규식 원자 묶음·소유 수량자는 3.11+")
    return out


def check(pkg: Path) -> list[str]:
    probs = []
    for p in sorted(pkg.rglob("*.py")):
        if "__pycache__" in p.parts:
            continue
        probs += check_file(p, p.relative_to(pkg.parent).as_posix())
    return probs


def main(argv=None) -> int:
    pkg = Path((argv or sys.argv[1:] or [str(ENGINE / "logtriage")])[0])
    probs = check(pkg)
    for x in probs:
        print(x)
    print(f"[3.9 호환] {pkg} — 문제 {len(probs)}건")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
