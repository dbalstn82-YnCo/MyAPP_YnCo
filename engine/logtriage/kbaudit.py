"""지식 파일(룰·코드) 손상 기록 — 재시작 뒤에도 남는다(2026-10-15, GPT 6차 '③ stderr 만으로는 운영자가 놓친다' 후속).

읽지 못한 파일 목록이 '바뀔 때만' 한 줄씩 남긴다(같은 상태를 화면을 열 때마다 반복해 쓰지 않는다).
  손상 발견 — 새로 읽지 못하게 된 파일(이름·사유·파일 해시 앞 12자)
  복구됨   — 전에 읽지 못하던 파일이 다시 읽힘(또는 지워짐)
내용(룰 문구)은 남기지 않는다 — 파일 이름·사유 유형·해시·시각만. 최근 1,000줄만 보관.
GPT UI 19차: 사유는 예외 글(경로·내용 조각이 섞일 수 있다)을 그대로 남기지 않고 정해진 유형 코드로만 남긴다.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path

LOG = ("data", "kb_damage.jsonl")
STATE = ("data", "kb_damage_state.json")
KEEP = 1000
_lock = threading.Lock()

# 사유 유형 — 기록에는 코드만, 화면에는 한글 이름
REASON_KO = {
    "YAML_SIZE": "파일이 너무 큼(읽기 상한 초과)",
    "YAML_DEPTH": "중첩이 너무 깊음",
    "YAML_ALIAS": "별칭(*)이 너무 많음",
    "YAML_SYNTAX": "YAML 문법 오류",
    "REGEX": "정규식 오류",
    "SCHEMA": "항목 형식이 맞지 않음",
    "ENCODING": "글자 인코딩 오류(UTF-8 아님)",
    "FILE_READ": "파일을 읽을 수 없음(권한·잠금)",
    "OTHER": "기타 읽기 실패",
}


def reason_code(why: str) -> str:
    """rules/codes.unreadable_files 의 'Type: 글' 을 정해진 유형 코드로. 글 자체는 버린다."""
    t, _, msg = str(why or "").partition(":")
    t = t.strip()
    if t == "YamlRejected":
        return "YAML_SIZE" if "큽니다" in msg else "YAML_DEPTH" if "중첩" in msg else "YAML_ALIAS" if "별칭" in msg else "YAML_SYNTAX"
    if t.endswith(("ScannerError", "ParserError", "ComposerError", "ConstructorError", "ReaderError", "YAMLError", "MarkedYAMLError")):
        return "YAML_SYNTAX"
    if t in ("error", "PatternError", "re.error") or "regex" in t.lower():
        return "REGEX"
    if t in ("UnicodeDecodeError", "UnicodeError"):
        return "ENCODING"
    if t in ("OSError", "PermissionError", "FileNotFoundError", "IsADirectoryError", "IOError"):
        return "FILE_READ"
    if t in ("ValueError", "KeyError", "TypeError", "AttributeError", "SchemaError", "ValidationError"):
        return "SCHEMA"
    return "OTHER"


def _sha12(p: Path) -> str:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()[:12]
    except OSError:
        return ""


def sync(base: Path, unreadable: list[dict]) -> list[dict]:
    """지금 읽지 못하는 파일 목록(rules/codes.unreadable_files 결과)을 지난 상태와 비교해 바뀐 것만 기록. 새로 남긴 줄을 돌려준다."""
    base = Path(base)
    now = {str(x.get("file", "")): reason_code(str(x.get("why", ""))) for x in (unreadable or []) if x.get("file") and not str(x["file"]).startswith("(")}
    log, state = base.joinpath(*LOG), base.joinpath(*STATE)
    with _lock:
        try:
            prev = json.loads(state.read_text(encoding="utf-8")) if state.exists() else {}
            if not isinstance(prev, dict):
                prev = {}
        except (OSError, ValueError):
            prev = {}
        at = time.strftime("%Y-%m-%d %H:%M:%S")
        new = []
        for f, why in sorted(now.items()):
            if f not in prev or prev[f] != why:
                new.append({"at": at, "event": "손상 발견", "file": f, "code": why, "sha": _sha12(base / f)})
        for f in sorted(set(prev) - set(now)):
            new.append({"at": at, "event": "복구됨", "file": f, "code": "", "sha": _sha12(base / f)})
        if not new:
            return []
        log.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        if log.exists():
            lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        lines += [json.dumps(x, ensure_ascii=False) for x in new]
        tmp = log.with_suffix(".tmp")
        tmp.write_text("\n".join(lines[-KEEP:]) + "\n", encoding="utf-8")
        os.replace(tmp, log)
        st = state.with_suffix(".tmp")
        st.write_text(json.dumps(now, ensure_ascii=False), encoding="utf-8")
        os.replace(st, state)
        return new


def recent(base: Path, n: int = 30) -> list[dict]:
    """최근 기록(새것 먼저)."""
    log = Path(base).joinpath(*LOG)
    out = []
    try:
        for ln in reversed(log.read_text(encoding="utf-8", errors="replace").splitlines()):
            try:
                x = json.loads(ln)
            except ValueError:
                continue
            if isinstance(x, dict):
                r = {k: str(x.get(k, ""))[:200] for k in ("at", "event", "file", "code", "sha")}
                if r["code"] and r["code"] not in REASON_KO:
                    r["code"] = "OTHER"
                r["why"] = REASON_KO.get(r["code"], "")          # 화면용 한글 이름(기록에는 코드만)
                out.append(r)
            if len(out) >= n:
                break
    except OSError:
        pass
    return out
