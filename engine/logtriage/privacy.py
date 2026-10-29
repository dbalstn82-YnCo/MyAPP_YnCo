# -*- coding: utf-8 -*-
"""분석 이력의 시스템 식별 정보 가리기(2026-09-22).

분석을 등록한 계정 본인에게는 그대로 보여 주고, 다른 계정에게는 장비를 특정할 수 있는 값
(IP 주소·호스트명·MAC 주소)을 `**` 로 가려서 돌려준다.

가리는 기준
  · IPv4 / IPv6 / MAC : 형태로 찾아 가린다(127.0.0.1 등 자기 자신 주소도 동일하게 가림).
  · 호스트명          : 그 분석에 실제로 들어 있던 호스트 값(events.host·분석 이름)만 골라서 가린다.
                        — 제품 파일명(catalina.out)·버전(8.0.32)을 잘못 가리지 않도록 '아는 값'만 지운다.
  · 키 이름이 host/ip/addr/hostname/노드/서버 인 칸은 값 전체를 가린다.
"""
from __future__ import annotations

import re

MASK = "**"
_IPV4 = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:.])")
_MAC = re.compile(r"(?<![\w:-])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})(?![\w:-])")
_HOST_KEYS = ("host", "hostname", "ip", "addr", "address", "node", "server", "target", "장비", "서버", "호스트", "주소")
_KEEP_KEYS = ("id", "incident_id", "raw_ref", "owner", "owner_name", "analyzed_at", "ts", "at")
# 호스트명으로 인정할 형태(영문·숫자·-·_·. 로만 이루어진 2자 이상). 확장자처럼 보이는 값은 호출부에서 걸러낸다.
_HOSTLIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,62}$")
_FILE_EXT = (".log", ".out", ".txt", ".gz", ".zip", ".xml", ".json", ".conf", ".properties", ".jsonl", ".csv", ".hwpx", ".pdf", ".html")


def owner_of(result: dict) -> str:
    return str((result or {}).get("owner") or "")


def _is_host_token(v: str) -> bool:
    if not isinstance(v, str) or not _HOSTLIKE.match(v) or len(v) < 3:
        return False
    low = v.lower()
    if low.endswith(_FILE_EXT):
        return False
    if re.fullmatch(r"[\d.]+", v) and not _IPV4.fullmatch(v):   # 8.0.32 같은 버전은 호스트로 보지 않는다
        return False
    return True


def hosts_of(result: dict) -> set[str]:
    """이 분석에 들어 있던 호스트 값 모으기 — 본문 어디에 섞여 있어도 이 값들만 정확히 가린다."""
    out: set[str] = set()

    def walk(o, key=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, str(k).lower())
        elif isinstance(o, list):
            for v in o:
                walk(v, key)
        elif isinstance(o, str):
            if any(h in key for h in ("host", "node", "장비", "호스트")) and _is_host_token(o):
                out.add(o)

    walk(result or {})
    name = str((result or {}).get("name") or "")
    if _is_host_token(name):
        out.add(name)
    for h in list(out):            # www.a.co 와 www 둘 다 가리도록 앞 라벨도 함께
        head = h.split(".")[0]
        if len(head) >= 3 and _is_host_token(head):
            out.add(head)
    return {h for h in out if len(h) >= 3}


def _ipv6_sub(m) -> str:
    """시각(12:34:56)·Oracle SID 처럼 콜론이 섞인 값을 IPv6 로 잘못 보지 않게 한다."""
    v = m.group(1)
    groups = v.split(":")
    if "::" in v or len(groups) >= 5:
        return MASK
    if any(re.fullmatch(r"[0-9A-Fa-f]{3,4}", g) and re.search(r"[A-Fa-f]", g) for g in groups):
        return MASK
    return v


def mask_text(text: str, hosts: set[str]) -> str:
    if not isinstance(text, str) or not text:
        return text
    out = _IPV4.sub(MASK, text)
    out = _MAC.sub(MASK, out)
    out = _IPV6.sub(_ipv6_sub, out)
    for h in sorted(hosts, key=len, reverse=True):
        out = re.sub(r"(?<![\w.-])" + re.escape(h) + r"(?![\w-])", MASK, out)
    return out


def mask_value(value, hosts: set[str], key: str = ""):
    k = (key or "").lower()
    if isinstance(value, dict):
        return {kk: mask_value(vv, hosts, str(kk)) for kk, vv in value.items()}
    if isinstance(value, list):
        return [mask_value(v, hosts, key) for v in value]
    if isinstance(value, str):
        if k in _KEEP_KEYS:
            return value
        if any(h == k or k.endswith("_" + h) or k.startswith(h + "_") or k == h for h in _HOST_KEYS) and value.strip():
            return MASK
        return mask_text(value, hosts)
    return value


def mask_result(result: dict, hosts: set[str] | None = None) -> dict:
    """분석 결과 한 건을 가린 사본으로 — 원본은 건드리지 않는다."""
    if not isinstance(result, dict):
        return result
    hs = hosts if hosts is not None else hosts_of(result)
    out = mask_value(result, hs)
    out["masked"] = True          # 화면에서 '가려진 이력' 표시에 쓴다
    return out


def mask_for_viewer(data, viewer: str, *, hosts: set[str] | None = None, shares=None):
    """이력 목록·단건·검색 결과 공통 — 등록한 계정이 보면 원본, 다른 계정이 보면 가린 사본.
    15차(마스터: '부서가 같으면 누가 분석하든 공유'): shares(owner) 가 참이면(같은 부서) 원본을 보여 준다."""
    if isinstance(data, list):
        return [mask_for_viewer(x, viewer, shares=shares) for x in data]
    if not isinstance(data, dict):
        return data
    if can_see(owner_of(data), viewer, shares):
        return data
    return mask_result(data, hosts)


def can_see(owner: str, viewer: str, shares=None) -> bool:
    """원본을 볼 수 있는가 — 등록한 본인 또는 같은 부서(shares). 등록자가 없거나 보는 사람이 없으면 가린다.
    이력·전체 현황·홈 목록이 모두 이 한 기준을 쓴다(10-23: 전체 현황 '최근 분석' 만 기준에서 빠져 원본이 나갔다)."""
    return bool(owner and viewer and (owner == viewer or (shares is not None and shares(owner))))
