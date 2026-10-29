"""전사 중앙 수집(본사 허브) — 사이트 서버 → 본사 서버 (2026-09-18 r4).

구성(conf/hub.json)
  {"role": "central" | "site",       central = 본사 서버(다른 사이트 데이터를 받고, 자기 데이터도 '본사' 사이트로 포함)
   "site_id": "HQ", "site_name": "본사",
   "hub_url": "https://logtriage.corp.local",   site 일 때 본사 주소
   "hub_token": "…",                             site 일 때 본사 [사용자·사이트 관리]에서 발급받은 사이트 토큰
   "interval_sec": 60, "send_reports": true, "send_feedback": false, "verify_tls": true, "ca_file": ""}
  send_feedback(7차 아이디어 6, 기본 끔): 1차 명령 현장 피드백 '건수'만 — (판정 ID, 명령 지문 16자, 동작·안 됨·판 다름 수).
  명령 원문·호스트·사람·분석 건은 보내지 않는다. 사이트 것을 통째로 바꿔(누적 재전송 이중 집계 없음) 2,000줄·형식 검사.
  send_exec_reports(8차 아이디어 6, 기본 끔): 현장 읽기 전용 실행 결과 — (판정 키, 명령 지문, 성공·오류 수, 오류 코드별 수)만.
  머리글(칼럼 이름)은 보내지 않는다 — GPT 64차 P0: 칼럼 별칭에 업무 이름·값을 넣을 수 있어 글자 제한이 유출 방지가 아니다.
  값·출력·호스트·사람도 보내지 않는다. 같은 방식(통째 교체·형식 검사·하나라도 틀리면 통째 거부 — 머리글 칸이 오면 거부).
  hub.json 이 없으면 단독 설치(기존과 동일).

사이트가 보내는 것(요약·상태만 — 원본 로그는 사이트에 남는다)
  · 모니터링 항목 전체 상태(가용성·응답·CPU/메모리/디스크 최신값), 최근 장애 이력 200건
  · 새 분석 결과 요약(분석 시각·판정 계층·원인 추정·심각도 건수·파일 이름), 예약 작업 최근 실행 결과
  · 새로 생성된 보고서 파일(HTML·HWPX·DOCX·PDF·JSON, 1개 50MB 이하) — 본사에도 사본 보관
전송은 사이트 → 본사 단방향 HTTPS POST(사이트 토큰). 실패하면 다음 주기에 이어서 보낸다(커서 방식, 유실 없음).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

SITE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
FILE_RE = re.compile(r"^[^\\/:*?\"<>|\x00-\x1f]{1,180}$")
REPORT_EXT = {".html", ".htm", ".hwpx", ".hwp", ".docx", ".pdf", ".json", ".txt", ".xlsx"}
MAX_INGEST = 8 * 1024 * 1024
MAX_FILE = 50 * 1024 * 1024
SITE_QUOTA = 5 * 1024 ** 3        # 사이트별 본사 보고서 사본 총량 한도(5GB)
INGEST_MIN_GAP = 5.0              # 사이트별 요약 수신 최소 간격(초)
STREAM_SWITCH_IDLE = 120.0        # 새 전송 흐름으로 넘어가려면 기존 흐름이 멈춰 있어야 하는 시간(초)
# 본사로 보내는 요청의 시간 제한과, 모드를 바꿀 때 멈추기를 기다리는 시간.
# 두 수가 어긋나면(10초 기다리는데 요청은 60초) 정상 운영에서도 모드 변경이 자주 막힌다 —
# 안전한 쪽으로 실패하는 것은 맞지만, 늘 걸리면 사람은 그 기능을 안 쓰게 된다(GPT 지적).
SEND_TIMEOUT = 15.0               # 요약 한 번 보내기 — 장애난 본사에 오래 매달리지 않는다
FILE_TIMEOUT = 45.0               # 보고서 파일 하나 보내기 — 클 수 있다
STOP_WAIT = 60.0                  # 모드를 바꿀 때 보내기가 끝나기를 기다리는 시간


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """되돌림을 따라가지 않는다 — 목적지가 바뀌면 토큰이 그쪽으로 간다."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code,
            "본사가 다른 주소로 넘기려 합니다 — 따라가지 않습니다(주소를 확인하십시오)",
            headers, fp)


class ReplayError(ValueError):
    pass


class QuotaError(ValueError):
    pass


class ConflictError(ValueError):
    pass


# 설정 틀 번호. **내가 모르는 판이 적어 둔 파일은 손대지 않는다**(GPT 7차).
# 구판 프로그램이 신판 파일을 읽고 '자기가 아는 칸만' 다시 쓰면 새 보안 설정이 조용히
# 사라진다 — 되돌리기·내리기에서 실제로 생기는 일이다.
SCHEMA_VERSION = 3


class FutureConf(ValueError):
    """이 판보다 새 틀로 적힌 설정 — 읽지도 고치지도 않는다."""


def load_conf(base: Path) -> dict | None:
    p = Path(base) / "conf" / "hub.json"
    if not p.exists():
        return None
    c = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(c, dict):
        raise ValueError("conf/hub.json: JSON 객체가 아닙니다")
    got = c.get("schema_version")
    if isinstance(got, int) and got > SCHEMA_VERSION:
        raise FutureConf(
            f"conf/hub.json 은 이 판이 모르는 설정 틀입니다(파일 {got} · 이 판 {SCHEMA_VERSION})"
            " — 잘못 읽어 새 설정을 지우지 않도록 건드리지 않습니다."
            " 더 새 판으로 올리거나, 이 판에 맞는 설정으로 바꿔 주십시오")
    return check_conf(c, base=base, where="conf/hub.json")


NL_ = chr(10)

ALLOW_FILE = "hub_allow.txt"
# 서비스 계정이 **쓸 수 없는** 곳을 먼저 본다. 유닉스에서는 파일이 읽기 전용이어도
# 부모 폴더에 쓸 수 있으면 지우고 새로 만들 수 있다 — conf/ 안에 두면 진짜 기준점이 아니다.
SYSTEM_ALLOW = ("/etc/logtriage/trusted_hubs", "/usr/local/etc/logtriage/trusted_hubs")


DEFAULT_PORT = {"https": 443, "http": 80}


def origin_of(url: str) -> str:
    """scheme + 호스트 + 포트 를 한 꼴로 — 기본 포트는 적지 않는다.

    호스트만 비교하면 :443 · :8443 · :9443 을 다 고를 수 있다. 같은 호스트에 다른 서비스가
    떠 있을 수 있으므로 신뢰 단위는 **출처**다(GPT 판정).
    """
    u = urllib.parse.urlsplit(str(url or "").strip())
    if not u.hostname:
        return ""
    scheme, host = (u.scheme or "").lower(), u.hostname.lower()
    if ":" in host:                       # IPv6 은 대괄호를 되살린다
        host = "[" + host + "]"
    try:
        port = u.port
    except ValueError:
        return ""
    tail = "" if (port or DEFAULT_PORT.get(scheme)) == DEFAULT_PORT.get(scheme) else f":{port}"
    return f"{scheme}://{host}{tail}"


def trusted(base) -> list:
    """보낼 수 있는 본사 주소 목록 — **화면에서는 만들 수 없는 파일**에서만 읽는다.

    웹 관리자 한 사람이 목적지를 정할 수 있으면, 그 계정을 얻은 사람이 우리 자료의 목적지를
    정할 수 있다는 뜻이다(GPT 판정). 그래서 목록은 서버 파일에 두고 화면은 읽기만 한다.

    파일이 없으면 제한하지 않는다 — 있으면 목록 밖으로는 못 보낸다. 화면이 그 사실을 말한다.
    """
    # 서비스가 못 쓰는 곳이 있으면 그것만 쓴다 — conf/ 쪽은 보지 않는다(섞으면 약한 쪽이 이긴다)
    src = None
    for sp in SYSTEM_ALLOW:
        if Path(sp).exists():
            src = Path(sp)
            break
    p = src or (Path(base) / "conf" / ALLOW_FILE)
    try:
        out = []
        for line in p.read_text(encoding="utf-8-sig").splitlines():
            t = line.split("#", 1)[0].strip()
            if not t:
                continue
            # 호스트만 적어도 받아 준다 — 그때는 https 기본 포트로 읽는다
            out.append(origin_of(t if "://" in t else "https://" + t) or t.lower())
        return out
    except OSError:
        return []


def check_url(url: str, base=None, where: str = "운영 모드") -> str:
    """본사 주소를 **파서로** 본다 — 정규식으로 보면 이상한 꼴이 빠져나간다."""
    u = urllib.parse.urlsplit(str(url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError(f"{where}: 본사 주소는 https://주소 형식이어야 합니다")
    if u.username or u.password:
        # 그 값이 설정 파일·화면·로그에 그대로 남는다
        raise ValueError(f"{where}: 본사 주소에 아이디·비밀번호를 넣을 수 없습니다")
    if u.fragment or u.query:
        raise ValueError(f"{where}: 본사 주소에 ? 나 # 뒤의 글자를 넣을 수 없습니다")
    if u.path not in ("", "/"):
        raise ValueError(f"{where}: 본사 주소는 호스트까지만 적습니다(예: https://hq.corp.local)")
    host = u.hostname.lower()
    if u.scheme == "http" and host not in ("127.0.0.1", "localhost", "::1"):
        # 평문 허용 스위치는 없앴다 — 사이트 토큰과 보고서를 평문으로 보내는 기능을
        # 남길 근거가 없다(지시: 안전하게 못 만들 기능은 없앤다)
        raise ValueError(f"{where}: 본사 주소는 https:// 여야 합니다"
                         " — 사이트 토큰과 보고서가 평문으로 나갑니다."
                         " 같은 PC(127.0.0.1) 시험만 예외입니다")
    origin = origin_of(url)
    ok = trusted(base) if base is not None else []
    if ok and origin not in ok:
        raise ValueError(f"{where}: '{origin}' 는 이 서버가 보낼 수 있는 본사 목록에 없습니다 —"
                         f" 서버의 conf/{ALLOW_FILE} 에 적힌 곳으로만 보낼 수 있습니다"
                         f" (지금 목록: {', '.join(ok)})")
    return origin


def check_conf(c: dict, base=None, where: str = "운영 모드") -> dict:
    """설정 한 벌이 쓸 수 있는 것인지 본다 — **파일로 들어오든 화면으로 들어오든 같은 검사.**

    따로 두면 파일로는 막히는 값이 화면으로는 들어온다. 검사는 한 곳에만 있어야 한다.
    """
    if not isinstance(c, dict):
        raise ValueError(f"{where}: 설정이 올바르지 않습니다")
    c = {k: v for k, v in c.items() if not k.startswith("_")}
    c.setdefault("role", "site")
    c.setdefault("interval_sec", 60)
    c.setdefault("send_reports", True)
    c.setdefault("send_feedback", False)
    c.setdefault("send_exec_reports", False)
    if c["role"] not in ("central", "site"):
        raise ValueError(f"{where}: 운영 모드는 본사(central) 또는 사이트(site) 여야 합니다")
    if not SITE_RE.match(str(c.get("site_id", ""))):
        raise ValueError(f"{where}: 사이트 ID 는 영문·숫자·_- 1~32자입니다")
    c.setdefault("site_name", c["site_id"])
    if c["role"] == "site" and (not c.get("hub_url") or not c.get("hub_token")):
        raise ValueError(f"{where}: 사이트 서버는 본사 주소와 사이트 토큰이 필요합니다")
    c["interval_sec"] = max(15, min(int(c.get("interval_sec") or 60), 3600))
    c["send_reports"] = bool(c.get("send_reports", True))
    c["send_feedback"] = c.get("send_feedback") is True   # 명시적으로 켠 것만
    c["send_exec_reports"] = c.get("send_exec_reports") is True
    c.pop("allow_http", None)     # 없앤 기능 — 옛 설정 파일에 남아 있어도 무시한다
    c["verify_tls"] = True        # 인증서 검사를 끄는 길은 두지 않는다
    c["schema_version"] = SCHEMA_VERSION
    if c["role"] == "site":       # 사이트 토큰·보고서는 암호화 구간으로만
        c["hub_url"] = check_url(c["hub_url"], base, where)
    return c


def save_conf(base: Path, conf: dict | None) -> dict | None:
    """운영 모드를 파일로 남긴다. conf 가 None 이면 **단독 설치**로 되돌린다.

    · 쓰기 전에 같은 검사를 지난다.
    · 이전 설정을 conf/hub.json.bak 으로 남긴다 — 잘못 바꿨을 때 되돌릴 수 있게.
    · 임시 파일에 쓰고 바꿔치운다 — 쓰다가 죽어도 반쪽짜리 설정이 남지 않게.
    """
    import os
    d = Path(base) / "conf"
    d.mkdir(parents=True, exist_ok=True)
    p, bak = d / "hub.json", d / "hub.json.bak"
    if p.exists():
        try:
            # 되돌릴 수 있게 남기되 **토큰 원문은 넣지 않는다** —
            # 남기면 토큰이 있는 자리가 두 배가 된다(GPT 판정)
            old = json.loads(p.read_text(encoding="utf-8-sig"))
            old.pop("hub_token", None)
            old["_token"] = "따로 보관 — 이 파일에는 남기지 않습니다"
            bak.write_text(json.dumps(old, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except (OSError, ValueError):
            pass
    if conf is None:
        if p.exists():
            p.unlink()
        return None
    c = check_conf(conf, base=base)
    tmp = d / "hub.json.tmp"
    # **만들 때부터** 0600 — 쓰는 동안 잠깐 남이 읽을 수 있는 틈을 두지 않는다
    if tmp.exists():
        tmp.unlink()
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(c, ensure_ascii=False, indent=2) + "\n")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    tmp.replace(p)
    return c


IDENTITY_FILE = "hub_identity.json"


def locked_site(base) -> str:
    """한 번 본사로 보낸 뒤 고정된 사이트 ID — **모드를 오가도 남는다.**

    단독으로 되돌렸다가 다시 사이트로 오면서 다른 ID 를 넣으면, 본사에서는 새 사이트로 보이고
    과거 자료와 관계가 끊긴다. 잠금이 단독 경유로 풀리면 잠근 뜻이 없다(GPT 판정).
    """
    try:
        d = json.loads((Path(base) / "data" / IDENTITY_FILE).read_text(encoding="utf-8"))
        return str(d.get("site_id") or "")
    except (OSError, ValueError, TypeError):
        return ""


STATE_FILE = "hub_client.json"


RECOVERY_FILE = "hub_recovery_required"
# 멈춘 까닭. **하나로 뭉뚱그리면 복구 명령이 틀린 절차를 고른다**(GPT 7차).
REASONS = {
    "config_invalid": "설정을 읽을 수 없습니다",
    "config_future": "이 판이 모르는 설정 틀입니다",
    "identity_conflict": "못 박은 신원과 설정이 다릅니다",
    "rollback_failed": "모드를 바꾸다 되돌리기까지 실패했습니다",
}


def _canon(c: dict) -> str:
    """설정을 **뜻만 남긴 한 꼴**로 — 공백·키 차례가 달라도 같은 글자가 나오게."""
    keep = ("role", "site_id", "site_name", "interval_sec", "send_reports", "send_feedback", "send_exec_reports",
            "verify_tls", "schema_version")
    d = {k: c.get(k) for k in keep if k in c}
    if c.get("hub_url"):
        d["hub_origin"] = origin_of(c["hub_url"])      # 주소는 출처로 고른다
    # 토큰 **원문은 넣지 않는다.** 넣으면 서버 열쇠로 덮어야 하는데, 열쇠가 생기거나 바뀌면
    # 아무도 손대지 않아도 지문이 달라진다(실제로 첫 기동 때 그랬다). 토큰은 따로 본다.
    d["token_set"] = bool(c.get("hub_token"))
    return json.dumps(d, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def conf_fingerprint(base) -> str:
    """지금 설정의 지문 — **뜻을 보고** 만든다. 비밀은 남기지 않는다.

    처음엔 파일 바이트를 그대로 해시했는데, 그러면 **공백만 바꿔도 지문이 달라진다**(GPT 8차).
    "설정을 고쳤습니까" 를 묻는 자리에서 들여쓰기만 바꾸고 빠져나갈 수 있었다.
    그래서 뜻만 남긴 한 꼴로 고른 뒤 해시한다.

    토큰이 바뀐 것도 **고친 것**이다(새 토큰을 받아 복구하는 일이 흔하다). 다만 토큰의 해시를
    표식에 그대로 남기면 그것이 또 하나의 단서가 되므로, 서버 열쇠로 HMAC 을 떠서 남긴다 —
    열쇠가 없는 사람에게는 아무 뜻이 없는 값이다.
    """
    p = Path(base) / "conf" / "hub.json"
    try:
        raw = p.read_bytes()
    except OSError:
        return ""
    try:
        c = json.loads(raw.decode("utf-8-sig"))
        if not isinstance(c, dict):
            raise ValueError("객체가 아님")
        # **우리가 고른 꼴로 맞춘 뒤** 지문을 뜬다. 그러지 않으면 서버가 기동하며 옛 항목을
        # 정리한 것(schema_version·site_name·verify_tls 채우기)만으로 지문이 달라져,
        # **운영자가 고친 것처럼 보인다** — 실제로 그래서 고치지 않은 설정이 풀렸다.
        try:
            c = check_conf(dict(c), base=base, where="지문")
        except Exception:                      # noqa: BLE001 — 못 고르면 있는 그대로 본다
            pass
        body = _canon(c)
    except ValueError:
        # 읽을 수 없는 설정은 뜻을 고를 수 없다 — 그때는 원문으로 본다(그래도 바뀌면 달라진다)
        body = "raw:" + hashlib.sha256(raw).hexdigest()
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def key_id(base) -> str:
    """지금 서버 열쇠가 **어느 것인지**만 가리키는 값(열쇠 자체는 드러내지 않는다).

    토큰 지문은 열쇠로 덮는다. 그래서 열쇠를 갈아 끼우면 토큰이 그대로인데도 지문이
    달라진다 — 그것을 '토큰이 바뀌었다' 로 세면 **열쇠만 바꾸고 복구를 풀 수 있다**(GPT 9차).
    어느 열쇠로 떴는지 함께 적어 두고, 열쇠가 다르면 견주지 않는다.
    """
    k = _server_key(base)
    return hashlib.sha256(b"logtriage-key-id" + k).hexdigest()[:8] if k else ""


def token_fingerprint(base) -> str:
    """사이트 토큰만의 지문 — **서버 열쇠가 있을 때만** 만든다(없으면 빈 글자).

    토큰이 바뀐 것도 '고친 것' 이다(새 토큰을 받아 복구하는 일이 흔하다). 다만 토큰의 해시를
    그대로 남기면 그것이 또 하나의 단서가 되므로 열쇠로 덮는다. 열쇠가 없거나 바뀌었으면
    견줄 수 없는 값이니 **아예 비워 두고 견주지 않는다** — 모르는 것을 '달라졌다' 로 세면
    손대지 않은 설정이 고쳐진 것처럼 보인다.
    """
    key = _server_key(base)
    if not key:
        return ""
    try:
        c = json.loads((Path(base) / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
        tok = str((c or {}).get("hub_token") or "") if isinstance(c, dict) else ""
    except (OSError, ValueError):
        return ""
    if not tok:
        return ""
    return hmac.new(key, tok.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def _server_key(base) -> bytes:
    """서버 열쇠 — 있으면 지문을 그것으로 덮는다(없으면 그냥 해시)."""
    try:
        return (Path(base) / "conf" / "secret.key").read_bytes()
    except OSError:
        return b""


def mark_recovery(base, reason: str, detail: str = "") -> None:
    """보내기를 멈추고 **왜 멈췄는지** 남긴다. 이미 있으면 덮어쓰지 않는다 — 첫 까닭이 진짜다."""
    d = Path(base) / "data"
    f = d / RECOVERY_FILE
    if f.exists():
        return
    d.mkdir(parents=True, exist_ok=True)
    body = {"reason": reason, "why": REASONS.get(reason, reason),
            "detail": str(detail)[:400], "at": time.time(),
            "config_hash": conf_fingerprint(base),
            "token_fp": token_fingerprint(base),
            "token_fp_key": key_id(base)}
    f.write_text(json.dumps(body, ensure_ascii=False, indent=2) + NL_, encoding="utf-8")


def read_recovery(base) -> dict:
    """멈춤 표식을 읽는다 — 옛 판이 남긴 글자만 있는 파일도 받아 준다."""
    try:
        raw = (Path(base) / "data" / RECOVERY_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        return {}
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            d.setdefault("why", REASONS.get(str(d.get("reason")), "본사 연동이 멈춰 있습니다"))
            return d
    except ValueError:
        pass
    return {"reason": "unknown", "why": raw.splitlines()[0], "detail": "", "at": 0,
            "config_hash": ""}


def set_identity(base, site_id: str, previous: str = "", actor: str = "") -> None:
    """사이트 신원을 **바꿔 적는다** — lock_site 는 한 번만 적지만 이쪽은 덮어쓴다.

    본사와 함께 재등록한 뒤에 쓰는 길이다. 옛 이름과 바꾼 사람을 함께 남겨, 나중에
    "이 서버가 전에 무엇이었나" 를 되짚을 수 있게 한다. 적는 방식은 lock_site 와 같다 —
    보안 경계이므로 원자적으로 적는다.
    """
    d = Path(base) / "data"
    d.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"site_id": site_id, "locked_at": time.time(),
                       "previous": previous, "changed_by": actor,
                       "_설명": "이 서버의 사이트 ID 입니다. 바꾸려면 본사와 함께 재등록해야 합니다."},
                      ensure_ascii=False, indent=2) + NL_
    tmp = d / (IDENTITY_FILE + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, d / IDENTITY_FILE)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def state_report(base) -> dict:
    """지금 연동 상태와 검사 결과 — **서버와 콘솔 명령이 같은 것을 본다.**

    두 벌로 두면 한쪽만 고치게 되고, 그것이 곧 "화면은 막는데 서버는 받는" 어긋남이 된다.
    비밀은 담지 않는다 — 토큰은 **있는지 여부**만 적는다.
    """
    base = Path(base)
    out: dict = {"checks": [], "ok": True}

    def check(name, ok, note=""):
        out["checks"].append({"name": name, "ok": bool(ok), "note": str(note)})
        if not ok:
            out["ok"] = False

    conf, err = None, ""
    try:
        conf = load_conf(base)
        check("설정을 읽을 수 있습니다", True,
              "본사 연동을 쓰지 않습니다" if conf is None else f"역할 {conf['role']}")
    except Exception as e:                      # noqa: BLE001 — 까닭을 그대로 보여 준다
        err = f"{type(e).__name__}: {e}"
        check("설정을 읽을 수 있습니다", False, err)
    out["role"] = (conf or {}).get("role", "none")
    out["site_id"] = (conf or {}).get("site_id", "")
    out["hub_url"] = (conf or {}).get("hub_url", "")
    out["token_set"] = bool((conf or {}).get("hub_token"))

    locked = locked_site(base)
    out["locked_site_id"] = locked
    clash = identity_conflict(base, conf)
    check("신원과 설정이 맞습니다", not clash,
          clash or (f"신원 {locked}" if locked else "못 박은 신원 없음"))

    allow = trusted(base)
    out["allow_list"] = allow
    if (conf or {}).get("role") == "site":
        inside = (not allow) or origin_of(conf["hub_url"]) in [origin_of(a) for a in allow]
        check("보낼 수 있는 본사 목록과 맞습니다", inside,
              ", ".join(allow) if allow else "목록이 없습니다 — 제한하지 않습니다")
        check("사이트 토큰이 들어 있습니다", bool(conf.get("hub_token")))
        check("본사 주소가 https 입니다", str(conf.get("hub_url", "")).startswith("https://"),
              conf.get("hub_url", ""))
        check("인증서 검사가 켜져 있습니다", conf.get("verify_tls") is True)
    else:
        check("보낼 수 있는 본사 목록", True, ", ".join(allow) if allow else "목록이 없습니다")

    rec = read_recovery(base)
    out["recovery"] = rec
    if rec:
        # 뜻이 그대로이고 **토큰도 그대로일 때만** '안 고쳤다' 로 본다.
        # 토큰 지문은 양쪽에 다 있을 때만 견준다 — 열쇠가 없던 때 적힌 표식과는 견줄 수 없다.
        same = bool(rec.get("config_hash")) and rec["config_hash"] == conf_fingerprint(base)
        # 토큰 지문은 **같은 열쇠로 뜬 것끼리만** 견준다. 열쇠가 바뀌었으면 토큰이 바뀐
        # 것인지 알 수 없고, 모르는 것을 '바뀌었다' 로 세면 열쇠만 갈아 끼우고 풀 수 있다.
        was_tok, now_tok = str(rec.get("token_fp") or ""), token_fingerprint(base)
        was_key, now_key = str(rec.get("token_fp_key") or ""), key_id(base)
        if same and was_tok and now_tok and was_key and was_key == now_key and was_tok != now_tok:
            same = False
        out["config_changed"] = not same
        check("멈춘 뒤 설정을 고쳤습니다", not same,
              "설정이 그때와 **같습니다** — 고치지 않고 푸는 것은 같은 일을 또 겪는 길입니다"
              if same else "그때와 다른 설정입니다")
    return out


def migrate_identity(base, conf: dict | None) -> str:
    """옛 설치를 올릴 때 사이트 신원을 승계한다 — 승계했으면 그 ID 를 돌려준다.

    **없으면 업그레이드 한 번으로 잠금이 풀린다(GPT 상 후보).** 구버전에는 신원 파일이
    없었으므로, 이미 본사로 보내 오던 서버가 새 코드에서는 '잠기지 않은 새 설치' 로 보인다.
    그 상태에서 사이트 ID 를 바꾸면 본사에 쌓인 자료와 끊기고, 보내는 곳까지 바꿀 수 있다.

    **'보낸 적이 있는가' 를 묻지 않는다.** 처음에는 송신 기록(data/hub_client.json)이 비어
    있을 때만 열어 두게 짰는데, 그 파일은 서비스 계정이 **쓸 수도** 있다. 지우는 것뿐 아니라
    0 으로 채워 넣는 것도 된다 — 열어 두는 쪽이 똑같이 위조되므로 경계가 아니다(GPT 5차).
    그래서 **설정에 사이트 ID 가 있으면 보내기 전이라도 잠근다.**

    설치하면서 잘못 적었다면 서버에서 conf/hub.json 을 고치고 신원 파일을 지우십시오 —
    화면에서 바꾸는 길은 두지 않습니다. 한 사람이 화면에서 바꿀 수 있으면 잠근 뜻이 없습니다.
    """
    if not isinstance(conf, dict):
        return ""
    # **역할이 뜻을 가질 때만 잠근다.** 옛 설정에 역할을 바꾸면서 지우지 않은 사이트 ID 가
    # 남아 있을 수 있다(GPT 5차). role=none 에 남은 'OLD-BUSAN' 을 진짜 신원으로 못 박으면,
    # 그 뒤로 이 서버는 쓴 적도 없는 이름에 묶인다. 지금은 load_conf 가 그런 설정을 거절하지만,
    # 이 함수가 **스스로** 따지지 않으면 다음에 누가 검증 안 한 사전을 넘기는 순간 뚫린다.
    if str(conf.get("role") or "") not in ("central", "site"):
        return ""
    sid = str(conf.get("site_id") or "")
    if not sid or locked_site(base):
        return ""
    lock_site(base, sid)
    return locked_site(base)


def identity_conflict(base, conf: dict | None) -> str:
    """못 박은 신원과 지금 설정이 어긋나는가 — 어긋나면 그 까닭을 돌려준다.

    서로 다른 증거가 부딪히면 **자동으로 정하지 않는다**(GPT 5차). 어느 쪽이 맞는지는
    본사에 무엇이 쌓여 있는지를 봐야 알 수 있고, 그것은 이 서버가 알 수 없다.
    """
    if not conf:
        return ""
    locked, sid = locked_site(base), str(conf.get("site_id") or "")
    if locked and sid and locked != sid:
        return (f"못 박은 사이트 신원('{locked}')과 설정의 사이트 ID('{sid}')가 다릅니다 —"
                " 어느 쪽이 맞는지는 본사에 무엇이 쌓여 있는지를 봐야 알 수 있어"
                " 서버가 혼자 정하지 않습니다.")
    return ""


def lock_site(base, site_id: str) -> None:
    """첫 전송이 성공한 뒤 사이트 신원을 못 박는다 — 한 번만 적고 덮어쓰지 않는다."""
    if not site_id or locked_site(base):
        return
    d = Path(base) / "data"
    d.mkdir(parents=True, exist_ok=True)
    body = json.dumps({"site_id": site_id, "locked_at": time.time(),
                       "_설명": "이 서버의 사이트 ID 입니다. 바꾸려면 본사와 함께 재등록해야 합니다."},
                      ensure_ascii=False, indent=2) + NL_
    # **보안 경계를 평범한 쓰기로 적지 않는다**(GPT 5차). 반쪽 JSON 이 남으면 다음 기동에서
    # 신원이 없는 것으로 읽혀 잠금이 풀린다. 다음 기동에서 보이는 것은 **온전한 신원이거나
    # 신원이 아예 없거나** 둘 중 하나여야 한다.
    tmp = d / (IDENTITY_FILE + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, d / IDENTITY_FILE)
        try:                                  # 폴더 항목까지 디스크에 내린다(가능한 곳에서만)
            dfd = os.open(d, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except (OSError, AttributeError):
            pass
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def same_target(a: dict | None, b: dict) -> bool:
    """옛 설정과 새 설정이 **같은 곳**을 가리키는가.

    빈칸을 '토큰 그대로' 로 읽는 것은 같은 곳일 때만 맞다. 주소가 바뀌었는데 물려주면
    옛 토큰이 새 주소로 그대로 나간다(GPT 상 등급). 사이트 이름이 바뀌어도 마찬가지다 —
    본사 쪽에서 다른 사이트로 취급되므로 그 토큰이 맞는다는 보장이 없다.
    """
    if not a or a.get("role") != b.get("role") or a.get("role") != "site":
        return False
    if str(a.get("site_id") or "") != str(b.get("site_id") or ""):
        return False
    try:
        pa, pb = urllib.parse.urlsplit(str(a.get("hub_url") or "")), urllib.parse.urlsplit(str(b.get("hub_url") or ""))
    except ValueError:
        return False
    return (pa.scheme.lower(), (pa.hostname or "").lower(), pa.port) == \
           (pb.scheme.lower(), (pb.hostname or "").lower(), pb.port)


def public_conf(c: dict | None, allow: list | None = None) -> dict:
    """화면에 내려보낼 수 있는 꼴 — **사이트 토큰은 절대 돌려주지 않는다.**

    한 번 넣은 토큰을 되돌려 주면, 화면을 볼 수 있는 사람이 곧 본사에 쓸 수 있는 사람이 된다.
    설정되어 있는지만 말한다.
    """
    if not c:
        return {"role": "none", "site_id": "", "site_name": "", "hub_url": "",
                "token_set": False, "interval_sec": 60, "send_reports": True, "send_feedback": False, "send_exec_reports": False,
                "allow_list": list(allow or [])}
    return {"role": c["role"], "site_id": c["site_id"], "site_name": c.get("site_name", ""),
            "hub_url": c.get("hub_url", ""), "token_set": bool(c.get("hub_token")),
            "interval_sec": c.get("interval_sec", 60), "send_reports": bool(c.get("send_reports", True)),
            "send_feedback": c.get("send_feedback") is True,
            "send_exec_reports": c.get("send_exec_reports") is True,
            # 화면이 "아무 데나 보낼 수 있는 상태" 인지 말할 수 있게 목록을 함께 준다
            "allow_list": list(allow or [])}


def _th(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def _num(v, lo=None, hi=None):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    if v != v:   # NaN
        return None
    if lo is not None and v < lo or hi is not None and v > hi:
        return None
    return float(v)


def _txt(v, n):
    return v[:n] if isinstance(v, str) else ("" if v is None else str(v)[:n])


# ── 본사 저장소 ───────────────────────────────────────────────────────────
class HubStore:
    def __init__(self, base: Path):
        self.dir = Path(base) / "data" / "hub"
        self.files = self.dir / "files"
        self.files.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "hub.sqlite3"
        self._lock = threading.Lock()
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS sites(
              id TEXT PRIMARY KEY, name TEXT, token_hash TEXT, created REAL, last_seen REAL, last_ip TEXT,
              version TEXT DEFAULT '', interval INTEGER DEFAULT 60, info TEXT DEFAULT '{}', disabled INTEGER DEFAULT 0,
              local INTEGER DEFAULT 0, stream TEXT DEFAULT '', seq INTEGER DEFAULT 0, retired TEXT DEFAULT '[]', stream_seen REAL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS targets(
              site_id TEXT, tid TEXT, name TEXT, address TEXT, kind TEXT, group_name TEXT, status TEXT,
              latency REAL, last_check REAL, enabled INTEGER, stale INTEGER, cpu REAL, mem REAL, disk REAL,
              usage_at REAL, detail TEXT, updated REAL, PRIMARY KEY(site_id, tid));
            CREATE TABLE IF NOT EXISTS alerts(
              site_id TEXT, aid INTEGER, tid TEXT, name TEXT, address TEXT, kind TEXT, opened REAL, closed REAL,
              reason TEXT, acknowledged INTEGER, PRIMARY KEY(site_id, aid));
            CREATE INDEX IF NOT EXISTS alerts_open ON alerts(site_id, closed);
            CREATE TABLE IF NOT EXISTS incidents(
              site_id TEXT, iid TEXT, analyzed_at TEXT, name TEXT, layer TEXT, verdict TEXT, critical INTEGER,
              sev TEXT, files TEXT, events INTEGER, received REAL, PRIMARY KEY(site_id, iid));
            CREATE INDEX IF NOT EXISTS incidents_at ON incidents(analyzed_at);
            CREATE TABLE IF NOT EXISTS runs(
              site_id TEXT, rid TEXT, name TEXT, kind TEXT, state TEXT, started REAL, finished REAL, message TEXT,
              PRIMARY KEY(site_id, rid));
            CREATE TABLE IF NOT EXISTS reports(
              site_id TEXT, name TEXT, size INTEGER, mtime REAL, sha256 TEXT, received REAL, PRIMARY KEY(site_id, name));
            CREATE TABLE IF NOT EXISTS forms(
              site_id TEXT, kind TEXT, name TEXT, sha256 TEXT, received REAL, PRIMARY KEY(site_id, kind, name));
            CREATE TABLE IF NOT EXISTS kbfb(
              site_id TEXT, rule_id TEXT, cmd_hash TEXT, ok INTEGER, fail INTEGER, version INTEGER, received REAL,
              PRIMARY KEY(site_id, rule_id, cmd_hash));
            CREATE TABLE IF NOT EXISTS xrep(
              site_id TEXT, vkey TEXT, cmd_hash TEXT, ok INTEGER, error INTEGER, codes TEXT, headers TEXT, received REAL,
              PRIMARY KEY(site_id, vkey, cmd_hash));
            """)
            cols = {r[1] for r in db.execute("PRAGMA table_info(sites)")}
            for c, ddl in (("stream", "TEXT DEFAULT ''"), ("seq", "INTEGER DEFAULT 0"), ("retired", "TEXT DEFAULT '[]'"), ("stream_seen", "REAL DEFAULT 0")):
                if c not in cols:
                    db.execute(f"ALTER TABLE sites ADD COLUMN {c} {ddl}")
        self._site_locks: dict[str, threading.Lock] = {}

    @contextmanager
    def db(self):
        c = sqlite3.connect(str(self.path), timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # 사이트 관리
    def sites(self) -> list[dict]:
        with self.db() as db:
            rows = [dict(r) for r in db.execute("SELECT * FROM sites ORDER BY local DESC, id")]
        for r in rows:
            r.pop("token_hash", None)
            try:
                r["info"] = json.loads(r.get("info") or "{}")
            except ValueError:
                r["info"] = {}
        return rows

    def add_site(self, sid: str, name: str, local: bool = False) -> str | None:
        if not SITE_RE.match(sid or ""):
            raise ValueError("사이트 ID 는 영문·숫자·_- 1~32자")
        name = _txt(name or sid, 60)
        tok = None if local else secrets.token_urlsafe(32)
        with self._lock, self.db() as db:
            if db.execute("SELECT 1 FROM sites WHERE id=?", (sid,)).fetchone():
                if local:
                    db.execute("UPDATE sites SET name=?, local=1 WHERE id=?", (name, sid))
                    return None
                raise ValueError("이미 등록된 사이트 ID 입니다")
            db.execute("INSERT INTO sites(id,name,token_hash,created,local) VALUES(?,?,?,?,?)",
                       (sid, name, _th(tok) if tok else "", time.time(), 1 if local else 0))
        return tok

    def reset_token(self, sid: str) -> str:
        tok = secrets.token_urlsafe(32)
        with self._lock, self.db() as db:
            if not db.execute("UPDATE sites SET token_hash=? WHERE id=? AND local=0", (_th(tok), sid)).rowcount:
                raise ValueError("없는 사이트이거나 본사 자체 사이트입니다")
        return tok

    def update_site(self, sid: str, value: dict) -> None:
        upd = {}
        if "name" in value:
            upd["name"] = _txt(value["name"], 60)
        if "disabled" in value:
            if not isinstance(value["disabled"], bool):
                raise ValueError("disabled 는 true/false")
            upd["disabled"] = 1 if value["disabled"] else 0
        if not upd:
            raise ValueError("바꿀 항목이 없습니다")
        with self._lock, self.db() as db:
            if not db.execute("UPDATE sites SET " + ",".join(f"{k}=?" for k in upd) + " WHERE id=?", (*upd.values(), sid)).rowcount:
                raise ValueError("없는 사이트입니다")

    def delete_site(self, sid: str) -> None:
        with self._lock, self.db() as db:
            r = db.execute("SELECT local FROM sites WHERE id=?", (sid,)).fetchone()
            if not r:
                raise ValueError("없는 사이트입니다")
            if r["local"]:
                raise ValueError("본사 자체 사이트는 삭제할 수 없습니다(conf/hub.json)")
            for t in ("sites", "targets", "alerts", "incidents", "runs", "reports"):
                db.execute(f"DELETE FROM {t} WHERE {'id' if t == 'sites' else 'site_id'}=?", (sid,))
        d = self.files / sid
        if d.exists():
            for f in d.iterdir():
                f.unlink(missing_ok=True)
            d.rmdir()

    def site_by_token(self, tok: str) -> dict | None:
        if not tok or len(tok) > 200:
            return None
        h = _th(tok)
        with self.db() as db:
            for r in db.execute("SELECT id,name,token_hash,disabled FROM sites WHERE local=0"):
                if r["token_hash"] and hmac.compare_digest(r["token_hash"], h):
                    return None if r["disabled"] else dict(r)
        return None

    # 수신
    def ingest(self, sid: str, payload: dict, ip: str = "") -> dict:
        if not isinstance(payload, dict):
            raise ValueError("JSON 객체 필요")
        site = payload.get("site") or {}
        now = time.time()
        tgt = payload.get("targets")
        if tgt is not None and (not isinstance(tgt, list) or len(tgt) > 5000):
            raise ValueError("targets: 5,000개 이하 목록")
        alerts = payload.get("alerts") or []
        incs = payload.get("incidents") or []
        runs = payload.get("runs") or []
        for nm, v, lim in (("alerts", alerts, 2000), ("incidents", incs, 2000), ("runs", runs, 500)):
            if not isinstance(v, list) or len(v) > lim:
                raise ValueError(f"{nm}: {lim:,}개 이하 목록")
        n = {"targets": 0, "alerts": 0, "incidents": 0, "runs": 0}
        stream, seq = payload.get("stream"), payload.get("seq")
        with self._lock, self.db() as db:
            # 재전송 방지(r4 검토 2차): 같은 stream 은 seq 가 늘어나야 한다. 새 stream(재설치로 상태 파일이 없어진 경우)은
            # 현재 stream 이 2분 이상 멈췄을 때만 받아들이고, 이전 stream 은 영구 폐기 — 폐기된 stream 의 패킷은 다시 받지 않는다.
            cur = db.execute("SELECT stream, seq, retired, stream_seen FROM sites WHERE id=?", (sid,)).fetchone()
            if isinstance(stream, str) and re.fullmatch(r"[0-9a-f]{16,64}", stream) and isinstance(seq, int) and not isinstance(seq, bool) and seq > 0:
                try:
                    retired = json.loads(cur["retired"] or "[]") if cur else []
                except ValueError:
                    retired = []
                if stream in retired:
                    raise ReplayError("폐기된 전송 흐름입니다(재생 거절)")
                if cur and cur["stream"] == stream:
                    if seq <= (cur["seq"] or 0):
                        raise ReplayError("이미 받은 전송입니다(순번 중복)")
                elif cur and cur["stream"]:
                    if now - (cur["stream_seen"] or 0) < STREAM_SWITCH_IDLE:
                        raise ReplayError("다른 전송 흐름이 아직 동작 중입니다 — 이전 사이트 서버를 멈추면 2분 뒤 자동으로 넘어갑니다")
                    retired = (retired + [cur["stream"]])[-50:]
                db.execute("UPDATE sites SET stream=?, seq=?, retired=?, stream_seen=? WHERE id=?", (stream, seq, json.dumps(retired), now, sid))
            else:
                raise ValueError("전송 순번(stream·seq)이 없습니다 — 사이트 서버를 r4 이상으로 갱신하십시오")
            info = {"collector": bool(site.get("collector")), "automation": bool(site.get("automation")),
                    "hostname": _txt(site.get("hostname"), 80), "os": _txt(site.get("os"), 40), "db": _txt(site.get("db"), 40)}
            db.execute("UPDATE sites SET last_seen=?, last_ip=?, version=?, interval=?, info=? WHERE id=?",
                       (now, _txt(ip, 60), _txt(site.get("version"), 40), int(_num(site.get("interval"), 15, 3600) or 60),
                        json.dumps(info, ensure_ascii=False), sid))
            if tgt is not None:
                seen = []
                for t in tgt:
                    if not isinstance(t, dict) or not _txt(t.get("id"), 64):
                        continue
                    u = t.get("usage") if isinstance(t.get("usage"), dict) else {}
                    row = (sid, _txt(t["id"], 64), _txt(t.get("name"), 100), _txt(t.get("address"), 255), _txt(t.get("kind"), 20),
                           _txt(t.get("group_name"), 80), _txt(t.get("status"), 16), _num(t.get("latency"), 0, 1e6),
                           _num(t.get("last_check"), 0), 1 if t.get("enabled") else 0, 1 if t.get("stale") else 0,
                           _num(u.get("cpu"), 0, 100), _num(u.get("mem"), 0, 100), _num(u.get("disk"), 0, 100), _num(u.get("at"), 0),
                           _txt(t.get("detail"), 200), now)
                    db.execute("INSERT OR REPLACE INTO targets VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", row)
                    seen.append(row[1])
                    n["targets"] += 1
                if payload.get("full_targets", True):   # 사이트에서 지운 항목은 본사에서도 지운다
                    db.execute("CREATE TEMP TABLE IF NOT EXISTS _seen(tid TEXT PRIMARY KEY)")
                    db.execute("DELETE FROM _seen")
                    db.executemany("INSERT OR IGNORE INTO _seen VALUES(?)", [(s,) for s in seen])
                    db.execute("DELETE FROM targets WHERE site_id=? AND tid NOT IN (SELECT tid FROM _seen)", (sid,))
            for a in alerts:
                if not isinstance(a, dict) or not isinstance(a.get("id"), int) or isinstance(a.get("id"), bool):
                    continue
                db.execute("INSERT OR REPLACE INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (sid, a["id"], _txt(a.get("target_id"), 64), _txt(a.get("name"), 100), _txt(a.get("address"), 255),
                            _txt(a.get("kind"), 20), _num(a.get("opened"), 0), _num(a.get("closed"), 0),
                            _txt(a.get("close_reason"), 60), 1 if a.get("acknowledged") else 0))
                n["alerts"] += 1
            for i in incs:
                if not isinstance(i, dict) or not _txt(i.get("id"), 80):
                    continue
                sev = i.get("sev_totals") if isinstance(i.get("sev_totals"), dict) else {}
                sev = {k: int(_num(sev.get(k), 0, 1e9) or 0) for k in ("critical", "error", "warn", "info")}
                files = [_txt(f, 180) for f in (i.get("files") or [])[:50]] if isinstance(i.get("files"), list) else []
                db.execute("INSERT OR REPLACE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (sid, _txt(i["id"], 80), _txt(i.get("analyzed_at"), 25), _txt(i.get("name"), 200), _txt(i.get("layer"), 40),
                            _txt(i.get("verdict"), 300), 1 if sev["critical"] else 0, json.dumps(sev), json.dumps(files, ensure_ascii=False),
                            int(_num(i.get("events_total"), 0, 1e12) or 0), now))
                n["incidents"] += 1
            forms = payload.get("forms")   # 3차 아이디어 6: 서식 원장(이름·지문만) — 보낸 때마다 그 사이트 것을 통째로 바꾼다
            if forms is not None:
                # GPT 37차: 한 줄이라도 형식이 틀렸거나 200줄을 넘으면 '통째로 거부'(예전 원장 유지) — 일부만 바뀐 원장으로 오판하지 않게.
                # 보낸 사이트는 토큰으로 정해지고(전송값 아님) 같은 전송의 순번(stream·seq) 재생 방지를 그대로 받는다. 지우기·넣기는 한 거래.
                rows = []
                if isinstance(forms, list) and len(forms) <= 200:
                    for f in forms:
                        sha = str(f.get("sha256", "")).lower() if isinstance(f, dict) else ""
                        nm = _txt(f.get("name"), 60) if isinstance(f, dict) else ""
                        if not (re.fullmatch(r"[0-9a-f]{64}", sha) and nm):
                            rows = None
                            break
                        rows.append((sid, "builtin" if f.get("kind") == "builtin" else "custom", nm, sha, now))
                else:
                    rows = None
                if rows is None:
                    n["forms_rejected"] = 1
                else:
                    db.execute("DELETE FROM forms WHERE site_id=?", (sid,))
                    db.executemany("INSERT OR REPLACE INTO forms VALUES(?,?,?,?,?)", rows)
                    n["forms"] = len(rows)
            fb = payload.get("kbfb")   # 7차 아이디어 6: 현장 피드백 건수 — 사이트 것을 통째로 바꾼다(이중 집계 없음), 하나라도 틀리면 통째 거부
            if fb is not None:
                rows = []
                if isinstance(fb, list) and len(fb) <= 2000:
                    for f in fb:
                        if not isinstance(f, dict):
                            rows = None
                            break
                        rid, h = str(f.get("rule_id", "")), str(f.get("cmd_hash", ""))
                        cnt = [f.get(k) for k in ("ok", "fail", "version")]
                        if not (re.fullmatch(r"[A-Za-z0-9_.:$-]{1,120}", rid) and re.fullmatch(r"[0-9a-f]{16}", h)
                                and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 1_000_000 for x in cnt)):
                            rows = None
                            break
                        if any(r[1] == rid and r[2] == h for r in rows):   # GPT 61차: 같은 짝이 두 번 — 모호하니 통째 거부
                            rows = None
                            break
                        rows.append((sid, rid, h, cnt[0], cnt[1], cnt[2], now))
                else:
                    rows = None
                if rows is None:
                    n["kbfb_rejected"] = 1
                else:
                    db.execute("DELETE FROM kbfb WHERE site_id=?", (sid,))
                    db.executemany("INSERT OR REPLACE INTO kbfb VALUES(?,?,?,?,?,?,?)", rows)
                    n["kbfb"] = len(rows)
            xr = payload.get("xrep")   # 8차 아이디어 6: 현장 실행 결과 — 통째 교체, 하나라도 틀리면 통째 거부
            if xr is not None:
                rows = _xrep_rows(sid, xr, now)
                if rows is None:
                    n["xrep_rejected"] = 1
                else:
                    db.execute("DELETE FROM xrep WHERE site_id=?", (sid,))
                    db.executemany("INSERT OR REPLACE INTO xrep VALUES(?,?,?,?,?,?,?,?)", rows)
                    n["xrep"] = len(rows)
            for r in runs:
                if not isinstance(r, dict) or not _txt(r.get("id"), 80):
                    continue
                db.execute("INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?,?)",
                           (sid, _txt(r["id"], 80), _txt(r.get("name"), 100), _txt(r.get("kind"), 30), _txt(r.get("state"), 20),
                            _num(r.get("started"), 0), _num(r.get("finished"), 0), _txt(r.get("message"), 300)))
                n["runs"] += 1
            # 보관 한도: 사이트별 분석 요약 2,000건 · 닫힌 장애 90일 · 실행 이력 1,000건
            db.execute("""DELETE FROM incidents WHERE site_id=? AND iid NOT IN
                          (SELECT iid FROM incidents WHERE site_id=? ORDER BY analyzed_at DESC LIMIT 2000)""", (sid, sid))
            db.execute("DELETE FROM alerts WHERE site_id=? AND closed IS NOT NULL AND closed<?", (sid, now - 90 * 86400))
            db.execute("""DELETE FROM runs WHERE site_id=? AND rid NOT IN
                          (SELECT rid FROM runs WHERE site_id=? ORDER BY started DESC LIMIT 1000)""", (sid, sid))
        return {"ok": True, "received": n, "at": now}

    def site_lock(self, sid: str) -> threading.Lock:
        with self._lock:
            return self._site_locks.setdefault(sid, threading.Lock())

    def save_file(self, sid: str, name: str, mtime: float, stream, length: int) -> dict:
        name = Path(name).name
        if not FILE_RE.match(name) or Path(name).suffix.lower() not in REPORT_EXT:
            raise ValueError("보고서 파일 이름·형식 오류")
        if not 0 < length <= MAX_FILE:
            raise ValueError("보고서 파일 크기 오류(50MB 이하)")
        with self.db() as db:
            used = db.execute("SELECT coalesce(sum(size),0) FROM reports WHERE site_id=?", (sid,)).fetchone()[0]
            prev = db.execute("SELECT sha256 FROM reports WHERE site_id=? AND name=?", (sid, name)).fetchone()
        if used + length > SITE_QUOTA:
            raise QuotaError("사이트 보고서 사본 저장 한도(5GB)를 넘습니다 — 본사 관리자가 오래된 사본을 정리해야 합니다")
        d = self.files / sid
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / f".{secrets.token_hex(4)}.part"
        h = hashlib.sha256()
        left = length
        try:
            with open(tmp, "wb") as f:
                while left > 0:
                    chunk = stream.read(min(1 << 20, left))
                    if not chunk:
                        raise ValueError("전송이 중간에 끊겼습니다")
                    f.write(chunk); h.update(chunk); left -= len(chunk)
            if prev and prev["sha256"] == h.hexdigest():   # 같은 내용 재전송 — 그대로 성공
                return {"ok": True, "sha256": h.hexdigest(), "stored_as": name, "duplicate": True}
            if prev:   # 이미 받은 보고서는 덮어쓰지 않고 새 판(~r2, ~r3 …)으로 따로 보관(감사용 불변성 + 재생성본 전달)
                stem, suf = Path(name).stem, Path(name).suffix
                with self.db() as db:
                    k = 2
                    while db.execute("SELECT 1 FROM reports WHERE site_id=? AND name=?", (sid, f"{stem}~r{k}{suf}")).fetchone() or (d / f"{stem}~r{k}{suf}").exists():
                        k += 1
                        if k > 999:
                            raise ConflictError("같은 이름의 보고서 판이 너무 많습니다")
                name = f"{stem}~r{k}{suf}"
            tmp.replace(d / name)
        finally:
            tmp.unlink(missing_ok=True)
        with self._lock, self.db() as db:
            db.execute("INSERT OR REPLACE INTO reports VALUES(?,?,?,?,?,?)", (sid, name, length, float(mtime or time.time()), h.hexdigest(), time.time()))
            # 사이트별 보고서 최근 500개 보관
            old = [r[0] for r in db.execute("SELECT name FROM reports WHERE site_id=? ORDER BY mtime DESC LIMIT -1 OFFSET 500", (sid,))]
            for o in old:
                db.execute("DELETE FROM reports WHERE site_id=? AND name=?", (sid, o))
                (d / o).unlink(missing_ok=True)
        return {"ok": True, "sha256": h.hexdigest(), "stored_as": name}

    def file_path(self, sid: str, name: str) -> Path | None:
        name = Path(name).name
        if not SITE_RE.match(sid or "") or not FILE_RE.match(name):
            return None
        with self.db() as db:
            if not db.execute("SELECT 1 FROM reports WHERE site_id=? AND name=?", (sid, name)).fetchone():
                return None
        p = self.files / sid / name
        return p if p.exists() else None

    # 조회(사용자 사이트 범위로 거른다)
    def _scope(self, allowed) -> tuple[str, list]:
        if allowed is None or "*" in allowed:
            return "", []
        ids = [s for s in allowed if SITE_RE.match(s)]
        if not ids:
            return " AND 1=0", []
        return f" AND site_id IN ({','.join('?' * len(ids))})", ids

    def overview(self, allowed=None) -> dict:
        now = time.time()
        sc, sa = self._scope(allowed)
        with self.db() as db:
            sites = []
            for s in self.sites():
                if allowed is not None and "*" not in allowed and s["id"] not in allowed:
                    continue
                # 신선한 관측(stale=0)만 지금 상태로 센다 — 사이트가 '오래된 측정'이라고 표시한 장비는 확인 불가(GPT 16차 P1-02)
                c = {(r["status"] or "unknown", bool(r["st"])): r["n"] for r in db.execute(
                    "SELECT status, coalesce(stale,0) st, count(*) n FROM targets WHERE site_id=? AND enabled=1 GROUP BY status, st", (s["id"],))}
                s["targets"] = sum(c.values())
                s["up"] = c.get(("up", False), 0)
                s["down"] = c.get(("down", False), 0) + c.get(("suspect", False), 0)
                s["down_stale"] = c.get(("down", True), 0) + c.get(("suspect", True), 0)
                s["stale_targets"] = sum(v for (st, old), v in c.items() if old)
                s["open_alerts"] = db.execute("SELECT count(*) FROM alerts WHERE site_id=? AND closed IS NULL", (s["id"],)).fetchone()[0]
                s["hot"] = db.execute("""SELECT count(*) FROM targets WHERE site_id=? AND enabled=1 AND usage_at>? AND
                                         (cpu>=90 OR mem>=90 OR disk>=90)""", (s["id"], now - 300)).fetchone()[0]
                day = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 86400))
                s["incidents_24h"] = db.execute("SELECT count(*) FROM incidents WHERE site_id=? AND analyzed_at>=?", (s["id"], day)).fetchone()[0]
                s["reports"] = db.execute("SELECT count(*) FROM reports WHERE site_id=?", (s["id"],)).fetchone()[0]
                s["failed_runs_24h"] = db.execute("SELECT count(*) FROM runs WHERE site_id=? AND state='failed' AND started>?",
                                                  (s["id"], now - 86400)).fetchone()[0]
                lim = max(90, (s.get("interval") or 60) * 3)
                s["online"] = bool(s.get("last_seen") and now - s["last_seen"] <= lim)
                s["state"] = "disabled" if s["disabled"] else ("online" if s["online"] else ("never" if not s.get("last_seen") else "offline"))
                sites.append(s)
            down = [dict(r) for r in db.execute(
                "SELECT * FROM targets WHERE enabled=1 AND status IN ('down','suspect')" + sc + " ORDER BY site_id, name LIMIT 500", sa)]
            hot = [dict(r) for r in db.execute(
                "SELECT * FROM targets WHERE enabled=1 AND usage_at>? AND (cpu>=90 OR mem>=90 OR disk>=90)" + sc +
                " ORDER BY max(coalesce(cpu,0),coalesce(mem,0),coalesce(disk,0)) DESC LIMIT 200", [now - 300] + sa)]
            alerts = [dict(r) for r in db.execute(
                "SELECT * FROM alerts WHERE 1=1" + sc + " ORDER BY opened DESC LIMIT 100", sa)]
            incs = [dict(r) for r in db.execute(
                "SELECT * FROM incidents WHERE 1=1" + sc + " ORDER BY analyzed_at DESC LIMIT 100", sa)]
            reports = [dict(r) for r in db.execute(
                "SELECT * FROM reports WHERE 1=1" + sc + " ORDER BY mtime DESC LIMIT 100", sa)]
            runs = [dict(r) for r in db.execute(
                "SELECT * FROM runs WHERE 1=1" + sc + " ORDER BY started DESC LIMIT 60", sa)]
            forms = [dict(r) for r in db.execute("SELECT site_id, kind, name, sha256 FROM forms WHERE 1=1" + sc + " ORDER BY kind, name", sa)]
            # 7차 아이디어 6: 사이트를 합친 현장 피드백 — '안 됨·판 다름'이 많은 명령부터(사이트 수와 함께)
            kbfb = [dict(r) for r in db.execute(
                "SELECT rule_id, cmd_hash, SUM(ok) AS ok, SUM(fail) AS fail, SUM(version) AS version, COUNT(DISTINCT site_id) AS sites "
                "FROM kbfb WHERE 1=1" + sc + " GROUP BY rule_id, cmd_hash HAVING SUM(fail)+SUM(version) > 0 "
                "ORDER BY SUM(fail)+SUM(version) DESC LIMIT 50", sa)]
            # 8차 아이디어 6: 사이트를 합친 현장 실행 결과 — 사이트 수와 함께, 오류가 많은 것부터
            xrep = []
            for r in db.execute("SELECT vkey, cmd_hash, SUM(ok) AS ok, SUM(error) AS error, COUNT(DISTINCT site_id) AS sites, "
                                "GROUP_CONCAT(codes, '\x1f') AS codes, GROUP_CONCAT(headers, '\x1f') AS headers "
                                "FROM xrep WHERE 1=1" + sc + " GROUP BY vkey, cmd_hash ORDER BY SUM(error) DESC, SUM(ok) DESC LIMIT 50", sa):
                d = dict(r)
                cs: dict = {}
                for blob in str(d.pop("codes") or "").split("\x1f"):
                    try:
                        for k, v in (json.loads(blob or "{}") or {}).items():
                            cs[k] = cs.get(k, 0) + int(v)
                    except (ValueError, TypeError):
                        continue
                d["codes"] = dict(sorted(cs.items(), key=lambda kv: -kv[1])[:5])
                d.pop("headers", None)
                xrep.append(d)
        for i in incs:
            for k in ("sev", "files"):
                try:
                    i[k] = json.loads(i[k] or "null")
                except ValueError:
                    i[k] = None
        names = {s["id"]: s["name"] for s in sites}
        live_ids = {s["id"] for s in sites if s["state"] == "online"}
        for r in down:   # 지난 장애 표시 — 끊긴 사이트이거나 사이트가 오래된 측정이라고 표시한 장비
            r["past"] = bool(r.get("stale")) or r["site_id"] not in live_ids
        for lst in (down, hot, alerts, incs, reports, runs):
            for r in lst:
                r["site_name"] = names.get(r["site_id"], r["site_id"])
        tot = {k: sum(s[k] for s in sites) for k in ("targets", "up", "down", "open_alerts", "hot", "incidents_24h", "reports")}
        # '지금' 숫자는 수신 중인 사이트의 신선한 관측만(GPT 16차 P1-01). 끊긴 사이트·오래된 측정의 장애는 지우지 않고 '지난 장애'로 따로
        live = [s for s in sites if s["state"] == "online"]
        gone = [s for s in sites if s["state"] in ("offline", "never")]
        tot["up"] = sum(s["up"] for s in live)
        tot["down"] = sum(s["down"] for s in live)
        tot["down_past"] = sum(s["down"] + s["down_stale"] for s in gone) + sum(s["down_stale"] for s in live)
        tot["nochk"] = sum(s["targets"] for s in gone) + sum(s["stale_targets"] for s in live)
        tot["sites"] = len(sites)
        tot["online"] = sum(1 for s in sites if s["state"] == "online")
        return {"at": now, "sites": sites, "total": tot, "down": down, "hot": hot, "alerts": alerts,
                "incidents": incs, "reports": reports, "runs": runs, "forms": forms, "kbfb": kbfb, "xrep": xrep}

    def site_targets(self, sid: str) -> list[dict]:
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM targets WHERE site_id=? ORDER BY kind, name", (sid,))]


# ── 사이트 → 본사 전송기 ──────────────────────────────────────────────────
class HubClient:
    """사이트 서버(또는 본사 자체)의 데이터를 주기적으로 모아 본사 저장소로 보낸다.
    central 이면 HTTP 없이 같은 프로세스의 HubStore 에 직접 넣는다."""

    def __init__(self, api, conf: dict, hub_store: HubStore | None = None):
        self.api = api
        self.conf = conf
        self.hub = hub_store
        self.state_file = Path(api._base) / "data" / "hub_client.json"
        self.state = {"inc_after": "", "run_after": 0.0, "rep_after": 0.0, "last_ok": 0.0, "last_error": "", "last_try": 0.0,
                      "sent": {"incidents": 0, "reports": 0, "cycles": 0}, "stream": secrets.token_hex(16), "seq": 0}
        try:
            self.state.update(json.loads(self.state_file.read_text(encoding="utf-8")))
        except (OSError, ValueError):
            pass
        self._stop = threading.Event()
        self._wake = threading.Event()
        # 모드가 바뀌어 버려진 전송기인가 — 그러면 다시는 아무것도 내보내지 않는다
        self.abandoned = False
        # 보내는 동안 잡는 자물쇠. 모드를 바꾸는 쪽이 이것을 기다리면, 동시에 보낼 수 있는
        # 전송기가 언제나 정확히 하나가 된다 — 버렸다 되살리는 어정쩡한 상태를 없앤다(GPT 판정).
        self.sending = threading.Lock()
        self.thread: threading.Thread | None = None

    # 공개 상태(화면 표시)
    def status(self) -> dict:
        now = time.time()
        return {"role": self.conf["role"], "site_id": self.conf["site_id"], "site_name": self.conf.get("site_name"),
                "hub_url": self.conf.get("hub_url", "") if self.conf["role"] == "site" else "(본사 자체)",
                "interval": self.conf["interval_sec"], "running": bool(self.thread and self.thread.is_alive()),
                "last_ok": self.state["last_ok"], "last_try": self.state["last_try"], "last_error": self.state["last_error"],
                "healthy": bool(self.state["last_ok"] and now - self.state["last_ok"] <= self.conf["interval_sec"] * 3),
                "sent": self.state["sent"]}

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self._stop.clear()
        self.thread = threading.Thread(target=self._loop, name="hub-client", daemon=True)
        self.thread.start()

    def stop(self, abandon: bool = False) -> bool:
        """멈춘다. abandon=True 면 **다시는 아무것도 내보내지 않는다.**

        스레드가 마침 본사로 요청을 보내는 중이면(요청 시간 제한 60초) join(10) 이 시간 안에
        안 끝난다. 표시가 없으면 옛 전송기가 살아서 옛 주소로 한 번 더 보낸다 —
        모드를 바꾼다는 것은 대개 "저기로 보내지 마라" 는 뜻이므로 그 한 번이 뜻을 깨뜨린다.
        """
        if abandon:
            self.abandoned = True
        self._stop.set(); self._wake.set()
        if self.thread:
            self.thread.join(timeout=STOP_WAIT)
        # 스레드가 남아 있어도 **보내는 중이 아니면** 더 내보내지 않는다(버려졌으므로).
        # 자물쇠를 잡아 보는 것으로 "지금 보내는 중인가" 를 확인한다.
        if self.thread and self.thread.is_alive():
            if not self.sending.acquire(timeout=1.0):
                return False        # 아직 보내는 중이다 — 모드를 바꾸지 않는다
            self.sending.release()
            return bool(abandon)    # 버렸으면 더 못 내보내므로 바꿔도 된다
        return True

    def kick(self):
        self._wake.set()

    def _loop(self):
        self._stop.wait(5)   # 기동 직후 수집기 첫 결과를 기다림
        while not self._stop.is_set():
            try:
                self.cycle()
            except Exception as e:   # 전송 실패는 상태로만 남기고 다음 주기에 다시
                self.state["last_error"] = f"{type(e).__name__}: {e}"[:300]
                self._save()
            self._wake.wait(self.conf["interval_sec"])
            self._wake.clear()

    def _save(self):
        try:
            tmp = self.state_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state, ensure_ascii=False), encoding="utf-8")
            tmp.replace(self.state_file)
        except OSError:
            pass

    # 수집
    def collect(self) -> tuple[dict, str, float]:
        import platform
        from . import __version__
        api = self.api
        snap = api.nms.snapshot()
        targets = []
        for t in snap["targets"]:
            u = t.get("usage") or {}
            targets.append({k: t.get(k) for k in ("id", "name", "address", "kind", "group_name", "status", "latency", "last_check",
                                                   "enabled", "stale", "detail")}
                           | {"usage": {k: u.get(k) for k in ("cpu", "mem", "disk", "at")} if u else {}})
        alerts = [{k: a.get(k) for k in ("id", "target_id", "name", "address", "kind", "opened", "closed", "close_reason", "acknowledged")}
                  for a in snap["alerts"]]
        incs, newest = [], self.state["inc_after"]
        try:
            hist = api.store.history(200)
        except Exception:
            hist = []
        for h in sorted(hist, key=lambda x: str(x.get("analyzed_at") or "")):
            at = str(h.get("analyzed_at") or "")
            if at <= self.state["inc_after"]:
                continue
            f = h.get("first") or {}
            files = [Path(str(x.get("name") if isinstance(x, dict) else x)).name for x in (h.get("files") or [])][:50]
            incs.append({"id": h.get("id"), "analyzed_at": at, "name": h.get("name") or ", ".join(files[:3]),
                         "layer": f.get("layer_ko", "CLEAR"), "verdict": f.get("verdict", ""), "sev_totals": h.get("sev_totals") or {},
                         "files": files, "events_total": h.get("events_total") or 0})
            newest = max(newest, at)
        runs, run_after = [], self.state["run_after"]
        try:
            st = api.automation.status()
            kinds = {j["id"]: j.get("kind") for j in st.get("jobs", [])}
            for r in st.get("runs", [])[:100]:
                fin = r.get("ended") or 0
                if r.get("state") != "running" and fin and fin > self.state["run_after"]:
                    run_after = max(run_after, fin)
                    if r.get("state") == "success" and kinds.get(r.get("job_id")) == "log_watch" and '"analyzed": []' in (r.get("output") or ""):
                        continue   # 1분마다 도는 반입 폴더 감시의 '처리할 파일 없음' 성공은 본사로 보내지 않음(목록 잡음)
                    msg = r.get("error") or ""
                    if not msg and r.get("output"):
                        try:
                            o = json.loads(r["output"]); msg = str(o.get("summary") or o.get("message") or "")[:300] if isinstance(o, dict) else ""
                        except ValueError:
                            msg = ""
                    runs.append({"id": str(r.get("id")), "name": r.get("name"), "kind": kinds.get(r.get("job_id"), ""), "state": r.get("state"),
                                 "started": r.get("started"), "finished": fin, "message": msg})
                    run_after = max(run_after, fin)
        except Exception:
            pass
        payload = {"site": {"id": self.conf["site_id"], "name": self.conf.get("site_name"), "version": __version__,
                            "interval": self.conf["interval_sec"], "hostname": platform.node(), "os": platform.system(),
                            "db": getattr(api.store, "kind", ""), "collector": bool(api.collector.thread.is_alive()) if getattr(api, "collector", None) else False,
                            "automation": True},
                   "targets": targets, "full_targets": True, "alerts": alerts, "incidents": incs, "runs": runs}
        if self.conf.get("send_feedback") is True:   # 7차 아이디어 6: 켠 사이트만 — 건수만(원문·호스트·사람 없음)
            try:
                fb = api.store.feedback_summary()
                payload["kbfb"] = [{"rule_id": rid, "cmd_hash": h, "ok": int(v.get("ok", 0)), "fail": int(v.get("fail", 0)),
                                    "version": int(v.get("version", 0))}
                                   for rid, per in sorted(fb.items()) for h, v in sorted(per.items())][:2000]
            except Exception:   # noqa: BLE001 — 피드백 실패가 상태 전송을 막지 않는다
                pass
        if self.conf.get("send_exec_reports") is True:   # 8차 아이디어 6: 켠 사이트만 — 성공·오류·코드·머리글 이름(값 없음)
            try:
                payload["xrep"] = xrep_payload(api.store)
            except Exception:   # noqa: BLE001 — 실행 결과 실패가 상태 전송을 막지 않는다
                pass
        try:   # 3차 아이디어 6: 서식 원장(이름·지문만, 서식 파일·매핑 내용 없음)
            from .report_custom import ledger_export
            payload["forms"] = [{k: f.get(k) for k in ("kind", "name", "sha256")}
                                for f in ledger_export(Path(api._base) / "report-template")["forms"]][:200]
        except Exception:   # noqa: BLE001 — 원장 실패가 상태 전송을 막지 않는다
            pass
        return payload, newest, run_after

    def _post(self, path: str, data: bytes, ctype: str, query: str = "") -> dict:
        # 자료가 실제로 이 서버 밖으로 나가는 **단 한 곳**이다. 버려진 전송기면 여기서 끝낸다 —
        # 스레드가 이미 요청을 만들던 중이어도 이 문을 지나야 나간다.
        if self.abandoned:
            raise RuntimeError("운영 모드가 바뀌어 이 전송은 취소되었습니다")
        url = self.conf["hub_url"].rstrip("/") + path + (("?" + query) if query else "")
        req = urllib.request.Request(url, data=data, method="POST" if path.endswith("ingest") else "PUT",
                                     headers={"Content-Type": ctype, "X-Site-Token": self.conf["hub_token"], "X-Site-Id": self.conf["site_id"]})
        # 되돌림(redirect)을 따라가지 않는 여는 쪽을 만든다 — 허용된 본사가 302 로 다른 곳을
        # 가리키면 토큰과 보고서가 그쪽으로 간다. 그러면 신뢰 목록이 무의미해진다(GPT 판정).
        handlers = [_NoRedirect]
        if url.lower().startswith("https://"):
            # 인증서 검사를 끄는 길은 두지 않는다 — 끄면 중간에서 가로채도 알 수 없다
            ctx = ssl.create_default_context(cafile=self.conf.get("ca_file") or None)
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        # 보내는 동안 자물쇠를 잡는다 — 모드를 바꾸는 쪽이 이것을 기다리면 동시에 보낼 수 있는
        # 전송기가 언제나 정확히 하나가 된다(GPT 판정: 버렸다 되살리는 상태를 없앤다).
        with self.sending:
            if self.abandoned:      # 기다리는 사이에 버려졌을 수 있다
                raise RuntimeError("운영 모드가 바뀌어 이 전송은 취소되었습니다")
            try:
                # 파일을 보낼 때는 더 기다린다 — 크기 때문이다
                with opener.open(req, timeout=(FILE_TIMEOUT if path.endswith("file") else SEND_TIMEOUT)) as r:
                    return json.loads(r.read(1 << 20) or b"{}")
            except urllib.error.HTTPError as e:
                try:
                    msg = json.loads(e.read(4096)).get("error", "")
                except Exception:
                    msg = ""
                raise RuntimeError(f"본사 응답 {e.code} {msg}".strip()) from None
            except urllib.error.URLError as e:
                raise RuntimeError(f"본사 접속 실패: {e.reason}") from None

    def cycle(self) -> dict:
        if self.abandoned:
            return {}      # 모드가 바뀌어 버려진 전송기다 — 모으지도 보내지도 않는다
        self.state["last_try"] = time.time()
        payload, newest, run_after = self.collect()
        self.state["seq"] = int(self.state.get("seq") or 0) + 1
        payload["stream"], payload["seq"] = self.state["stream"], self.state["seq"]
        self._save()
        if self.conf["role"] == "central":
            res = self.hub.ingest(self.conf["site_id"], payload, "local")
        else:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            if len(body) > MAX_INGEST:
                raise RuntimeError("전송 자료가 8MB 를 넘습니다")
            res = self._post("/api/hub/ingest", body, "application/json")
        # 여기까지 왔으면 본사가 받아 준 것이다 — 사이트 신원을 못 박는다(모드를 오가도 남는다)
        lock_site(self.api._base, self.conf["site_id"])
        self.state["inc_after"] = newest
        self.state["run_after"] = run_after
        self.state["sent"]["incidents"] += len(payload["incidents"])
        self.state["sent"]["cycles"] += 1
        if self.conf.get("send_reports", True):
            self._send_reports()
        self.state["last_ok"] = time.time()
        self.state["last_error"] = ""
        self._save()
        return res

    def _send_reports(self, per_cycle: int = 20):
        dirs = [Path(self.api._base) / "reports"]
        try:   # 예약 작업 산출물 경로를 따로 지정했으면 그곳도(r4)
            od = self.api.automation.output_dir()
            if od.resolve() not in [d.resolve() for d in dirs]:
                dirs.append(od)
        except Exception:
            pass
        files = sorted((p for rep in dirs if rep.is_dir() for p in rep.iterdir() if p.is_file() and p.suffix.lower() in REPORT_EXT
                        and not p.name.startswith(".") and p.stat().st_mtime > self.state["rep_after"]
                        and 0 < p.stat().st_size <= MAX_FILE and FILE_RE.match(p.name)),
                       key=lambda p: p.stat().st_mtime)
        for p in files[:per_cycle]:
            if time.time() - p.stat().st_mtime < 5:   # 쓰는 중인 파일은 다음 주기에
                break
            mt = p.stat().st_mtime
            if self.conf["role"] == "central":
                try:
                    with open(p, "rb") as f:
                        self.hub.save_file(self.conf["site_id"], p.name, mt, f, p.stat().st_size)
                except ConflictError:
                    pass
            else:
                try:
                    self._post("/api/hub/file", p.read_bytes(), "application/octet-stream",
                               urllib.parse.urlencode({"name": p.name, "mtime": f"{mt:.3f}"}))
                except RuntimeError as e:
                    if "409" not in str(e):   # 같은 이름이 이미 본사에 있으면 건너뜀(재전송·이름 충돌)
                        raise
            self.state["rep_after"] = mt
            self.state["sent"]["reports"] += 1
            self._save()


_XR_KEY = re.compile(r"[A-Za-z0-9_.:$#-]{1,160}")
_XR_CODE = re.compile(r"[A-Za-z]{0,8}-?[0-9A-Za-z]{1,8}")


def xrep_payload(store) -> list:
    """사이트가 본사로 보내는 현장 보고 — (판정 키, 명령 지문, 성공·오류 수, 오류 코드 상위 5)만. 머리글은 넣지 않는다(GPT 64차 P0)."""
    xs = store.exec_report_summary()
    return [{"vkey": k, "cmd_hash": h, "ok": int(v.get("ok", 0)), "error": int(v.get("error", 0)),
             "codes": dict(sorted((v.get("codes") or {}).items(), key=lambda kv: -kv[1])[:5])}
            for k, per in sorted(xs.items()) for h, v in sorted(per.items())][:2000]


def _xrep_rows(sid: str, xr, now: float):
    """8차 아이디어 6: 사이트가 보낸 현장 실행 결과 검사 — 2,000줄·형식·같은 짝 두 번이면 None(통째 거부)."""
    if not isinstance(xr, list) or len(xr) > 2000:
        return None
    rows, seen = [], set()
    for f in xr:
        if not isinstance(f, dict):
            return None
        k, h = str(f.get("vkey", "")), str(f.get("cmd_hash", ""))
        cnt = [f.get("ok"), f.get("error")]
        codes = f.get("codes") or {}
        if f.get("headers") or set(f) - {"vkey", "cmd_hash", "ok", "error", "codes"}:   # GPT 64차 P0: 머리글·모르는 칸은 받지 않는다
            return None
        if not (_XR_KEY.fullmatch(k) and re.fullmatch(r"[0-9a-f]{16}", h)
                and all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 1_000_000 for x in cnt)):
            return None
        if not isinstance(codes, dict) or len(codes) > 5 or not all(
                _XR_CODE.fullmatch(str(c)) and isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 1_000_000 for c, v in codes.items()):
            return None
        if (k, h) in seen:
            return None
        seen.add((k, h))
        rows.append((sid, k, h, cnt[0], cnt[1], json.dumps(codes, ensure_ascii=False), "", now))
    return rows
