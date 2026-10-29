"""전사 배포용 인증·권한·감사(2026-09-18 r4).

· 통합 계정(SSO)으로 로그인 — 방식은 conf/auth.json 의 portal.method 로 고른다(모두 표준 라이브러리만 사용, 인터넷 없는 환경에서도 설치 가능).
    ldap   : 포털과 같은 디렉터리(AD/LDAP)에 포털 ID·비밀번호로 단순 바인드(LDAPS 권장). 이름·부서·소속 그룹을 읽어 권한 자동 매핑.
    oidc   : 포털이 OpenID Connect(Keycloak·사내 IdP 등)를 제공할 때 — 인가 코드 흐름, id_token RS256 서명·iss·aud·exp·nonce 검증.
    header : 포털 SSO 에이전트가 설치된 앞단 웹서버(nginx/Apache)가 인증 후 사용자 ID 를 헤더로 넘길 때 — 신뢰 프록시 IP 에서 온 요청만 인정.
    link   : 포털 메뉴 링크가 서명된 파라미터(사용자·시각·nonce·HMAC-SHA256)로 넘어올 때 — 2분 유효, 재사용 차단.
· 사내 이메일 계정 로그인(mode=local): ID 는 회사 도메인 이메일만, 비밀번호는 페퍼(HMAC)+scrypt+ChaCha20-Poly1305 3중 저장 — accounts.py
· 비상용 로컬 관리자(통합 로그인 장애·초기 설정): PBKDF2-SHA256 비밀번호, /login?local=1.
· 권한: viewer(조회) < operator(분석·등록·예약 실행) < admin(사용자·사이트·룰팩·인증 설정). 사용자별 접근 사이트 목록('*' = 전체).
· 자산 조회 사이트(asset_sites): 사이트별 자산 현황(자산 관리 문서·장비 주소 목록)은 이 목록에 '하나씩' 지정된 사이트만 볼 수 있다.
  '전체(*)'는 허용하지 않고 관리자 권한도 이 제한을 넘지 못한다 — 해당 사이트 담당자만 조회(지정·변경은 감사 기록).
· 세션: 서버 DB 에 해시로 저장(재기동해도 유지), 유휴 만료·최대 수명. 감사 기록: 로그인·로그아웃·모든 변경 요청·보고서 내려받기.
· conf/auth.json 이 없으면 기존 방식(--password 단일 비밀번호 또는 인증 없음)을 그대로 쓴다 — 기존 설치와 호환.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import unicodedata
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

ROLES = {"viewer": 1, "operator": 2, "admin": 3}
ROLE_KO = {"viewer": "조회", "operator": "운영", "admin": "관리자"}
LOGIN_RE = re.compile(r"^[A-Za-z0-9._@\-]{1,64}$")
SITE_RE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
NL_ = chr(10)

PBKDF2_ROUNDS = 240_000

DEFAULT_CONF = {
    "mode": "portal",                 # local(사내 이메일 계정) | portal(통합 로그인) | password(기존 단일 비밀번호) | off
    "session_idle_min": 60,
    "session_max_hours": 12,
    "default_role": "viewer",         # 포털 첫 로그인 사용자에게 줄 권한
    "default_sites": [],              # 포털 첫 로그인 사용자에게 줄 사이트('*' 전체)
    "auto_create": True,              # False 면 관리자가 미리 등록한 사용자만 로그인
    "require_https": "auto",          # auto=사내망·VPN·같은 PC 는 평문 허용, 인터넷 구간은 HTTPS 필수 / True=항상 / False=검사 안 함
    "first_admin": "",                # 첫 관리자로 예약한 ID — 초기 설정 화면에서 비밀번호만 정하면 등록된다(빈 값이면 아무 ID 나)
    # 2026-10-02: 웹으로 첫 계정을 만드는 길에는 **예외가 없다** — 설정과 무관하게 1회용
    # 코드를 받는다. 이 값은 옛 설정 파일을 읽기 위해 남겨 두고(기동할 때 '이제 쓰지 않습니다'
    # 라고 알린다), 더는 아무것도 열지 않는다.
    "setup_scope": "token",
    "admin_allow": [],                # [사용자 · 권한] 화면·API 를 허용할 대역(CIDR 목록). 비우면 제한 없음
    "portal": {"method": "ldap", "label": "통합 계정"},
}


class AuthError(ValueError):
    """로그인·계정 오류 — 메시지는 화면에 그대로 보여도 되는 문장만(API 는 400/401 로 응답)."""


def load_conf(base: Path) -> dict | None:
    p = Path(base) / "conf" / "auth.json"
    if not p.exists():
        return None
    conf = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(conf, dict):
        raise ValueError("conf/auth.json: JSON 객체가 아닙니다")
    out = json.loads(json.dumps(DEFAULT_CONF))
    for k, v in conf.items():
        if k.startswith("_"):
            continue
        if k == "portal" and isinstance(v, dict):
            out["portal"].update(v)
        else:
            out[k] = v
    if out["mode"] not in ("local", "portal", "password", "off"):
        raise ValueError("conf/auth.json: mode 는 local|portal|password|off")
    if out["mode"] == "portal" and out["portal"].get("method") not in ("ldap", "oidc", "header", "link"):
        raise ValueError("conf/auth.json: portal.method 는 ldap|oidc|header|link")
    if out["mode"] == "local":
        from .accounts import conf_of
        out["local"] = conf_of(out)   # 값 검사·기본값 채움(도메인·비밀번호 규칙)
    if out["default_role"] not in ROLES:
        raise ValueError("conf/auth.json: default_role 은 viewer|operator|admin")
    out["setup_scope"] = str(out.get("setup_scope") or "private").strip().lower()
    if out["setup_scope"] not in ("loopback", "private", "token"):
        raise ValueError("conf/auth.json: setup_scope 는 loopback|private|token")
    out["first_admin"] = unicodedata.normalize("NFKC", str(out.get("first_admin") or "")).strip().lower()
    return out


FIRST_RUN_CONF = {
    "_설명": "처음 기동할 때 자동으로 만든 설정입니다. 회사 이메일 계정으로 로그인합니다(mode=local).",
    "_바꾸려면": "mode 를 portal(통합 로그인) 또는 off(로그인 없음)로 바꾸고 서버를 다시 시작하십시오.",
    "_직접가입": ("local.signup 기본값 approve: 누구나 [계정 만들기] 로 신청하고 **관리자가 승인하면** 씁니다. "
               "off=가입 받지 않음(관리자 발급만), code=관리자가 발급한 가입 코드를 아는 사람만 승인 없이, "
               "open=신청하면 바로. 이 값은 관리자 화면 [계정 · 가입] 에서 **서비스를 멈추지 않고** 바꿉니다."),
    "_HTTPS": ("require_https 기본값 auto: 사내망·VPN·같은 PC 접속은 평문(HTTP)도 허용하고, 그 밖의 주소(인터넷 구간)는 "
               "HTTPS 로만 받습니다. 운영에서는 conf/tls.json 으로 서버에 인증서를 달거나 앞단(nginx)에 TLS 를 두고 "
               "true 로 고정하십시오. 시험용으로 모두 허용하려면 false."),
    "_HTTP_예고": ("평문(HTTP) 접속은 시험 단계 편의를 위해 당분간 허용합니다. 추후 패치에서 기본값이 true 로 바뀌어 "
                 "평문 접속이 차단될 예정이니, 그 전에 conf/tls.json 에 인증서를 달거나 앞단에 TLS 를 두십시오."),
    "_첫관리자": ("first_admin 이 비어 있으면(기본값) 1회용 코드로 [관리자 계정 만들기] 화면을 연 사람이 **ID 를 직접 적어** 첫 관리자를 "
                "만듭니다. 특정 ID 로 못 박아 두려면 여기에 그 ID 를 적고 다시 기동하십시오(그때는 화면에서 비밀번호만 정합니다)."),
    "_초기설정범위": ("setup_scope 는 2026-10-02 부터 **쓰지 않습니다.** 웹으로 첫 계정을 만들 때는 설정과 무관하게 "
                  "기동할 때 출력된 1회용 코드를 받습니다(같은 PC 에서 열어도 마찬가지 — 앞단 프록시 뒤에서는 접속 "
                  "주소로 '서버에 앉은 사람' 을 가려낼 수 없기 때문입니다). 코드 없이 만들려면 서버 콘솔에서 "
                  "python3 -m logtriage.accounts --base <경로> add --email ○○@회사 --role admin 을 쓰십시오."),
    # 2026-09-30 에는 "메일 인증기능 제거" 지시로 off(로그인 없음)였습니다.
    # 2026-10-01 사용자 지시로 **계정 로그인을 기본으로** 되돌립니다 — "페이지를 열고 계정 로그인".
    # 메일을 보내는 기능은 여전히 없습니다(인증 메일·비밀번호 메일 발송 없음). 처음 열면
    # [관리자 계정 만들기] 가 뜨고, 그 뒤부터는 사람들이 [계정 만들기] 로 직접 가입합니다.
    # 로그인을 내리려면 한 줄입니다:  python3 -m logtriage.authmode --base <설치경로> off
    "mode": "local",
    "require_https": "auto",
    # 2026-10-22 마스터: 첫 관리자가 개발자 개인 계정으로 박혀 있어 배포하면 받은 곳에서 관리자를 만들 수 없었다 —
    # 기본값은 비워 두고, 1회용 코드를 넣은 사람이 ID 를 직접 적는다(코드가 첫 관리자 자리를 지킨다).
    "first_admin": "",
    # 첫 관리자 자리를 **먼저 누른 사람이 가져가지 못하게** 한다(GPT 21차). 서버에 앉아서
    # 만드는 것은 그대로이고, 그 밖에서는 기동할 때 나온 1회용 코드가 필요하다.
    "setup_scope": "token",
    "local": {"domain": "solideos.com", "signup": "approve"},
}


def _say(msg: str) -> None:
    """콘솔 부호(cp949 등)로 못 쓰는 글자가 있어도 기동을 막지 않는다."""
    try:
        print(msg, flush=True)
    except (UnicodeEncodeError, OSError, ValueError):
        try:
            enc = (getattr(sys.stdout, "encoding", None) or "utf-8")
            print(msg.encode(enc, "replace").decode(enc, "replace"), flush=True)
        except Exception:
            pass


# 옛 판이 처음 기동 때 **저절로** 적어 넣던 첫 관리자 ID(개발자 개인 계정)의 SHA-256 — 배포 코드에 그 주소를 글자로 남기지 않는다
_AUTO_FIRST_ADMIN_SHA = "bf30f0e13ba581cb740f2711daea1d69e2d1968ed10d1c747cdd72c294356815"
_AUTO_MARK = ("처음 기동할 때 자동으로 만든 설정입니다", "사내 이메일 계정 로그인. 이 파일을")   # 자동 생성본 · 예시 파일을 복사한 것


def _unpin_auto_first_admin(p: Path) -> bool:
    """2026-10-22: 옛 판이 자동으로 만든 conf/auth.json 에 박힌 개인 계정 first_admin 을 비운다 — 사람이 고른 값이 아니라
    프로그램이 적은 값이다(설명 칸이 자동 생성 문구 그대로이고 값이 그 계정일 때만). 사람이 다른 ID 를 적었으면 손대지 않는다.
    계정이 이미 있는 서버는 초기 설정 화면이 닫혀 있어 이 값이 쓰이지 않는다 — 비워도 동작이 바뀌지 않는다."""
    try:
        raw = json.loads(p.read_text(encoding="utf-8-sig"))
        fa = unicodedata.normalize("NFKC", str(raw.get("first_admin") or "")).strip().lower()
        if not fa or hashlib.sha256(fa.encode("utf-8")).hexdigest() != _AUTO_FIRST_ADMIN_SHA \
                or not str(raw.get("_설명", "")).startswith(_AUTO_MARK):
            return False
        bak = p.with_name("auth.json.before-first-admin-unpin")   # GPT 102차 P1-01: 일부러 그 ID 를 골랐던 경우를 위해 원본을 남긴다
        if not bak.exists():
            bak.write_bytes(p.read_bytes())
        raw["first_admin"] = ""
        raw["_first_admin" if "_first_admin" in raw else "_첫관리자"] = FIRST_RUN_CONF["_첫관리자"]
        tmp = p.with_suffix(".json.new")
        tmp.write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, p)
        _say("[LogTriage] 자동으로 정해져 있던 첫 관리자 ID 를 비웠습니다 — [관리자 계정 만들기] 화면에서 ID 를 직접 적습니다")
        return True
    except (OSError, ValueError, AttributeError, TypeError):
        return False


def ensure_conf(base: Path) -> dict:
    """설정이 없으면 만들어 준다 — 처음 기동해도 바로 쓸 수 있게(2026-09-22).

    2026-10-01 부터 처음 기동 기본값은 **회사 이메일 계정 로그인**입니다(사용자 지시).
    처음 열면 [관리자 계정 만들기] 가 뜨고, 그 뒤부터 사람들이 [계정 만들기] 로 직접
    가입합니다. 이미 conf/auth.json 이 있으면 손대지 않으므로, 로그인 없이 쓰고 있던
    서버는 **그대로 유지됩니다** — 바꾸려면 authmode 명령을 씁니다.

    이미 conf/auth.json 이 있으면 손대지 않는다. 파일이 상하거나 권한이 없으면 메모리 기본값으로 계속 진행한다.
    """
    p = Path(base) / "conf" / "auth.json"
    if p.exists():
        _unpin_auto_first_admin(p)
    if not p.exists():
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".json.new")
            tmp.write_text(json.dumps(FIRST_RUN_CONF, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, p)
            _say(f"[LogTriage] 처음 기동 - 로그인 설정을 만들었습니다: {p}")
            _say("           회사 이메일 계정으로 로그인합니다 — 처음 열면 [관리자 계정 만들기] 가 뜹니다.")
            _say("           그 화면은 **1회용 코드**로만 열립니다 — 기동할 때 화면에 나오고")
            _say("           conf/setup-code.txt 에도 적힙니다(첫 관리자 자리를 남이 먼저 차지하지 못하게).")
            _say("           그 뒤부터 사람들은 로그인 화면의 [계정 만들기] 로 직접 가입하고,")
            _say("           관리자가 [계정 · 가입] 화면에서 승인합니다(기본값: 승인 뒤 사용).")
            _say(f"           로그인을 내리려면:  python3 -m logtriage.authmode --base {Path(base)} off")
        except OSError as e:
            _say(f"[LogTriage] 로그인 설정 파일을 만들지 못했습니다({e}) - 이번 기동에만 기본값(계정 로그인)을 적용합니다")
            conf = json.loads(json.dumps(DEFAULT_CONF))
            conf.update({k: v for k, v in FIRST_RUN_CONF.items() if not k.startswith("_")})
            from .accounts import conf_of
            conf["local"] = conf_of(conf)
            return conf
    return load_conf(base)


def public_conf(conf: dict | None) -> dict:
    """화면 표시용 — 비밀값(secret·client_secret·비밀번호)은 가린다."""
    if not conf:
        return {"mode": "legacy"}
    c = json.loads(json.dumps(conf))

    def mask(d):
        for k in list(d):
            if isinstance(d[k], dict):
                mask(d[k])
            elif re.search(r"secret|password|token", k, re.I) and d[k]:
                d[k] = "●●●● (설정됨)"
    mask(c)
    return c


# ── 비밀번호 해시(로컬 관리자) ─────────────────────────────────────────────
def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def check_pw(pw: str, stored: str | None) -> bool:
    try:
        algo, rounds, salt, dk = (stored or "").split("$")
        if algo != "pbkdf2_sha256":
            return False
        got = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(got.hex(), dk)
    except (ValueError, TypeError):
        return False


_DUMMY_HASH = hash_pw(secrets.token_hex(8))


def _th(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── 저장소 ────────────────────────────────────────────────────────────────
class AuthStore:
    """사용자·세션·감사 저장소.

    2026-09-22: 신원(로그인 ID·이름·부서·메일)을 DB 에 평문으로 두지 않는다.
      · 조회 키   = HMAC-SHA256(서버 키, 소문자 ID)  ← 서버 키 없이는 누가 등록돼 있는지 알 수 없다
      · 표시 값   = ChaCha20-Poly1305 로 암호화해 한 칸(enc)에 보관, 화면에 보일 때만 복호화
      · 세션·감사 기록도 같은 조회 키로만 사람을 가리킨다
    """

    def __init__(self, path: Path, base: Path | None = None):
        self.path = Path(path)
        # 서버 키(conf/secret.key)를 찾을 설치 경로 — 표준 위치(<설치경로>/data/auth/auth.sqlite3)가 아니면 DB 가 있는 폴더를 쓴다
        if base is not None:
            self.base = Path(base)
        elif len(self.path.parents) >= 3 and self.path.parent.name == "auth" and self.path.parents[1].name == "data":
            self.base = self.path.parents[2]
        else:
            self.base = self.path.parent
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        from .crypto import derive
        self._ikey = derive(self.base, "identity-index")
        self._ekey = derive(self.base, "identity-enc")
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users(
              login TEXT PRIMARY KEY, name TEXT DEFAULT '', dept TEXT DEFAULT '', email TEXT DEFAULT '',
              role TEXT DEFAULT 'viewer', sites TEXT DEFAULT '[]', source TEXT DEFAULT 'portal',
              pw_hash TEXT, created REAL, last_login REAL, disabled INTEGER DEFAULT 0, managed INTEGER DEFAULT 0,
              asset_sites TEXT DEFAULT '[]');
            CREATE TABLE IF NOT EXISTS access_req(
              id INTEGER PRIMARY KEY AUTOINCREMENT, login TEXT NOT NULL, kind TEXT NOT NULL, want TEXT NOT NULL,
              enc BLOB, status TEXT DEFAULT 'pending', created REAL, decided REAL DEFAULT 0,
              decider TEXT DEFAULT '', note TEXT DEFAULT '', UNIQUE(login,kind,want));
            CREATE TABLE IF NOT EXISTS sessions(
              th TEXT PRIMARY KEY, login TEXT, created REAL, seen REAL, ip TEXT);
            CREATE TABLE IF NOT EXISTS audit(
              id INTEGER PRIMARY KEY, at REAL, login TEXT, ip TEXT, action TEXT, target TEXT, detail TEXT, ok INTEGER);
            CREATE INDEX IF NOT EXISTS audit_at ON audit(at);
            CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, at REAL);
            """)
            if "asset_sites" not in {r[1] for r in db.execute("PRAGMA table_info(users)")}:
                db.execute("ALTER TABLE users ADD COLUMN asset_sites TEXT DEFAULT '[]'")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS kicked(th TEXT PRIMARY KEY, at REAL, reason TEXT);
            """)
            for tbl, col in (("users", "enc"), ("audit", "enc"), ("audit", "chain")):
                if col not in {r[1] for r in db.execute(f"PRAGMA table_info({tbl})")}:
                    db.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {'TEXT' if col == 'chain' else 'BLOB'}")
        self._migrate_identity()

    # ── 신원 보호(색인 + 암호화) ──
    @staticmethod
    def canon(login: str) -> str:
        """조회 키·암호문 결박에 쓰는 표준형 — 유니코드 정규화 + 앞뒤 공백 제거 + 소문자."""
        return unicodedata.normalize("NFKC", (login or "")).strip().lower()

    def _idx(self, login: str) -> str:
        return hmac.new(self._ikey, self.canon(login).encode("utf-8"), hashlib.sha256).hexdigest()

    def _enc(self, value: dict | str, table: str = "users", column: str = "enc", row: str = "") -> bytes:
        """암호문을 '표·칸·행' 에 묶어 저장한다 — 다른 사람 행으로 옮겨 붙이는 변조를 막는다."""
        from .crypto import KEY_VERSION, aad, chacha20_poly1305_encrypt
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        return bytes([KEY_VERSION]) + nonce + chacha20_poly1305_encrypt(self._ekey, nonce, raw, aad(table, column, row))

    def _dec(self, blob, table: str = "users", column: str = "enc", row: str = ""):
        from .crypto import AeadError, aad, chacha20_poly1305_decrypt
        if not blob:
            return None
        b = bytes(blob)
        tries = [(b[1:13], b[13:], aad(table, column, row))] if b and b[0] == 1 else []
        tries.append((b[:12], b[12:], b"identity"))     # 2026-09-22 이전 방식(고정 AAD)도 읽어 준다
        for nonce, body, ad in tries:
            try:
                return json.loads(chacha20_poly1305_decrypt(self._ekey, nonce, body, ad))
            except (AeadError, ValueError, TypeError, IndexError):
                continue
        return None

    def _migrate_identity(self) -> None:
        """예전 DB(평문 ID·이름) → 색인·암호화 방식으로 한 번만 옮긴다."""
        with self._lock, self.db() as db:
            rows = [r for r in db.execute("SELECT * FROM users") if not r["enc"]]
            for r in rows:
                db.execute("UPDATE users SET login=?, enc=?, name='', dept='', email='' WHERE login=?",
                           (self._idx(r["login"]), self._enc({"login": r["login"], "name": r["name"] or "",
                                                              "dept": r["dept"] or "", "email": r["email"] or ""},
                                                             "users", "enc", self._idx(r["login"])), r["login"]))
                db.execute("UPDATE sessions SET login=? WHERE login=?", (self._idx(r["login"]), r["login"]))
            arows = [r for r in db.execute("SELECT id, at, login, target FROM audit WHERE enc IS NULL")] if rows else []
            for r in arows:
                db.execute("UPDATE audit SET login=?, target='', enc=? WHERE id=?",
                           (self._idx(r["login"] or ""),
                            self._enc({"login": r["login"] or "", "target": r["target"] or ""},
                                      "audit", "enc", f"{r['at'] or 0:.6f}"), r["id"]))
        if rows:
            print(f"[LogTriage] 사용자 {len(rows)}명의 신원 정보를 암호화 방식으로 옮겼습니다", flush=True)

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

    # 사용자
    def _user(self, r) -> dict | None:
        if not r:
            return None
        d = dict(r)
        d.pop("pw_hash", None)
        ident = self._dec(d.pop("enc", None), "users", "enc", str(d.get("login", "")))
        if isinstance(ident, dict):          # 암호화 보관분 → 화면·권한 판단에는 예전과 같은 모양으로 돌려준다
            d["login"] = ident.get("login", d.get("login", ""))
            d["name"] = ident.get("name", "")
            d["dept"] = ident.get("dept", "")
            d["email"] = ident.get("email", "")
            if ident.get("dept_self"):       # 16차: 직접 가입 때 스스로 적은 부서 — 관리자가 확인하기 전엔 공유 기준이 아니다
                d["dept_self"] = True
        for k in ("sites", "asset_sites"):
            try:
                d[k] = json.loads(d.get(k) or "[]")
            except ValueError:
                d[k] = []
        return d

    def get_user(self, login: str) -> dict | None:
        with self.db() as db:
            return self._user(db.execute("SELECT * FROM users WHERE login=?", (self._idx(login),)).fetchone())

    def users(self) -> list[dict]:
        with self.db() as db:
            return [self._user(r) for r in db.execute(
                "SELECT * FROM users ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'operator' THEN 1 ELSE 2 END, created")]

    def count_admins(self) -> int:
        with self.db() as db:
            return db.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]

    def set_local(self, login: str, password: str, role: str = "admin", name: str = "") -> None:
        if not LOGIN_RE.match(login):
            raise ValueError("계정은 영문·숫자·._@- 1~64자")
        if len(password) < 10:
            raise ValueError("비밀번호는 10자 이상")
        with self._lock, self.db() as db:
            db.execute("""INSERT INTO users(login,enc,role,sites,source,pw_hash,created,managed) VALUES(?,?,?,?,?,?,?,1)
                          ON CONFLICT(login) DO UPDATE SET pw_hash=excluded.pw_hash, source='local', role=excluded.role, disabled=0""",
                       (self._idx(login), self._enc({"login": login, "name": name or login, "dept": "", "email": ""},
                                                    "users", "enc", self._idx(login)),
                        role, json.dumps(["*"]), "local", hash_pw(password), time.time()))
            db.execute("DELETE FROM sessions WHERE login=?", (self._idx(login),))

    def verify_local(self, login: str, password: str) -> dict | None:
        with self.db() as db:
            r = db.execute("SELECT * FROM users WHERE login=? AND source='local' AND disabled=0", (self._idx(login),)).fetchone()
        if r and check_pw(password, r["pw_hash"]):
            return self._user(r)
        if not r:
            check_pw(password, _DUMMY_HASH)  # 계정 유무를 응답 시간으로 드러내지 않도록 같은 비용
        return None

    def portal_user(self, login: str, conf: dict, name="", dept="", email="", groups=(), source="portal") -> dict:
        """포털 인증을 통과한 사용자 → 등록/갱신. 중지·미등록(auto_create=False)이면 AuthError."""
        login = (login or "").strip()
        if not LOGIN_RE.match(login):
            raise AuthError("계정 ID 형식을 인식할 수 없습니다")
        name, dept, email = str(name or "")[:80], str(dept or "")[:80], str(email or "")[:120]
        mapped = _map_groups(conf, groups)
        now = time.time()
        idx = self._idx(login)
        with self._lock, self.db() as db:
            r = db.execute("SELECT * FROM users WHERE login=?", (idx,)).fetchone()
            if r is None:
                if not conf.get("auto_create", True) and not mapped:
                    raise AuthError("LogTriage 사용 등록이 안 된 계정입니다 — 관리자에게 등록을 요청하십시오")
                role = (mapped or {}).get("role") or conf.get("default_role", "viewer")
                sites = (mapped or {}).get("sites") or list(conf.get("default_sites") or [])
                assets = [x for x in ((mapped or {}).get("asset_sites") or []) if SITE_RE.match(str(x))]
                db.execute("INSERT INTO users(login,enc,role,sites,source,created,last_login,asset_sites) VALUES(?,?,?,?,?,?,?,?)",
                           (idx, self._enc({"login": login, "name": name, "dept": dept, "email": email}, "users", "enc", idx),
                            role, json.dumps(sites), source, now, now, json.dumps(assets)))
            else:
                if r["disabled"]:
                    raise AuthError("사용이 중지된 계정입니다 — 관리자에게 문의하십시오")
                if r["source"] == "local":
                    raise AuthError("비상용 로컬 계정과 같은 ID 입니다 — 관리자에게 문의하십시오")
                old = self._dec(r["enc"], "users", "enc", idx) or {"login": login, "name": "", "dept": "", "email": ""}
                upd = {"enc": self._enc({"login": login, "name": name or old.get("name", ""),
                                         "dept": dept or old.get("dept", ""), "email": email or old.get("email", "")},
                                        "users", "enc", idx),
                       "last_login": now}
                if mapped and not r["managed"]:   # 관리자가 화면에서 정한 권한(managed=1)은 그룹 매핑이 덮어쓰지 않음
                    upd["role"] = mapped.get("role") or r["role"]
                    if mapped.get("sites"):
                        upd["sites"] = json.dumps(mapped["sites"])
                    if mapped.get("asset_sites"):
                        upd["asset_sites"] = json.dumps([x for x in mapped["asset_sites"] if SITE_RE.match(str(x))])
                db.execute("UPDATE users SET " + ",".join(f"{k}=?" for k in upd) + " WHERE login=?", (*upd.values(), idx))
            return self._user(db.execute("SELECT * FROM users WHERE login=?", (idx,)).fetchone())

    def update_user(self, login: str, value: dict, actor: str) -> dict:
        if not isinstance(value, dict):
            raise ValueError("JSON 객체 필요")
        allowed = {"role", "sites", "asset_sites", "disabled", "name", "dept", "dept_confirm"}
        upd = {}
        for k, v in value.items():
            if k not in allowed:
                continue
            if k == "role":
                if v not in ROLES:
                    raise ValueError("권한은 viewer|operator|admin")
            elif k == "sites":
                if not isinstance(v, list) or len(v) > 200 or not all(isinstance(s, str) and (s == "*" or SITE_RE.match(s)) for s in v):
                    raise ValueError("사이트 목록 형식 오류(영문·숫자·_- 1~32자, 전체는 *)")
                v = json.dumps(sorted(set(v)))
            elif k == "asset_sites":
                if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and SITE_RE.match(x) for x in v):
                    raise ValueError("자산 조회 사이트는 사이트를 하나씩 지정합니다(전체 * 는 허용하지 않음)")
                v = json.dumps(sorted(set(v)))
            elif k == "disabled":
                if not isinstance(v, bool):
                    raise ValueError("disabled 는 true/false")
                v = 1 if v else 0
            elif k == "dept_confirm":
                if not isinstance(v, bool):
                    raise ValueError("dept_confirm 은 true/false")
            else:
                if not isinstance(v, str) or len(v) > 80:
                    raise ValueError(f"{k}: 80자 이하 문자열")
            upd[k] = v
        if not upd:
            raise ValueError("바꿀 항목이 없습니다")
        idx = self._idx(login)
        with self._lock, self.db() as db:
            r = db.execute("SELECT * FROM users WHERE login=?", (idx,)).fetchone()
            if not r:
                raise ValueError("없는 사용자입니다")
            confirm = bool(upd.pop("dept_confirm", False))
            if "name" in upd or "dept" in upd or confirm:          # 신원 항목은 암호화 칸(enc)으로 모아 둔다
                old = self._dec(r["enc"], "users", "enc", idx) or {"login": login, "name": "", "dept": "", "email": ""}
                new_dept = str(upd.pop("dept", old.get("dept", "")))
                # 16차(GPT 107 P0-01): 신청 부서(dept_self)는 관리자가 [부서 확인]을 체크하거나 부서 값을 직접 바꿨을 때만 확인된 것으로 본다.
                # 이름·권한만 고쳐 저장했다고 확인된 것으로 바뀌지 않는다.
                keep_self = bool(old.get("dept_self")) and not confirm and new_dept.strip() == str(old.get("dept", "")).strip()
                upd["enc"] = self._enc({"login": login, "name": upd.pop("name", old.get("name", "")),
                                        "dept": new_dept, "email": old.get("email", ""),
                                        **({"dept_self": True} if keep_self and new_dept.strip() else {})},
                                       "users", "enc", idx)
            if login == actor and ("role" in upd or "disabled" in upd):
                raise ValueError("자기 자신의 권한·중지는 바꿀 수 없습니다")
            demote = r["role"] == "admin" and not r["disabled"] and (upd.get("role", "admin") != "admin" or upd.get("disabled"))
            if demote and db.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0] <= 1:
                raise ValueError("마지막 관리자는 권한을 낮추거나 중지할 수 없습니다")
            upd["managed"] = 1
            db.execute("UPDATE users SET " + ",".join(f"{k}=?" for k in upd) + " WHERE login=?", (*upd.values(), idx))
            if upd.get("disabled") or "role" in upd or "sites" in upd or "asset_sites" in upd:
                db.execute("DELETE FROM sessions WHERE login=?", (idx,))   # 권한 변경은 다음 로그인부터 — 기존 세션 종료
            return self._user(db.execute("SELECT * FROM users WHERE login=?", (idx,)).fetchone())

    def add_user(self, value: dict, actor: str) -> dict:
        if not isinstance(value, dict):
            raise ValueError("JSON 객체 필요")
        login = str(value.get("login", "")).strip()
        if not LOGIN_RE.match(login):
            raise ValueError("계정은 영문·숫자·._@- 1~64자(포털 ID 그대로)")
        with self._lock, self.db() as db:
            if db.execute("SELECT 1 FROM users WHERE login=?", (self._idx(login),)).fetchone():
                raise ValueError("이미 등록된 계정입니다")
            db.execute("INSERT INTO users(login,enc,role,sites,source,created,managed) VALUES(?,?,?,?,?,?,1)",
                       (self._idx(login), self._enc({"login": login, "name": str(value.get("name", ""))[:80],
                                                     "dept": str(value.get("dept", ""))[:80], "email": ""},
                                                    "users", "enc", self._idx(login)),
                        "viewer", "[]", "portal", time.time()))
        rest = {k: v for k, v in value.items() if k in ("role", "sites", "asset_sites")}
        return self.update_user(login, rest, actor=actor) if rest else self.get_user(login)

    # ── 막힌 명령의 승인 요청(2026-10-01) ─────────────────────────────────
    REQ_KINDS = ("role", "site", "asset")
    REQ_KO = {"role": "권한", "site": "사이트 접근", "asset": "자산 조회"}
    # 요청으로 올릴 수 있는 가장 높은 권한. **관리자는 요청으로 주지 않는다**(GPT 20차) —
    # 관리자 임명은 [계정 · 가입] 의 계정 관리에서 사람을 보고 하는 일이다. 요청 줄에 섞여
    # 있으면 바쁜 관리자가 줄줄이 누르다 함께 누른다.
    REQ_MAX_ROLE = "operator"

    def request_access(self, login: str, kind: str, want: str, action: str = "", reason: str = "",
                       ip: str = "") -> dict:
        """막힌 사람이 **그 자리에서** 승인을 요청한다.

        같은 사람이 같은 것을 또 요청하면 **쌓지 않고 덮어쓴다**(UNIQUE) — 관리자 화면이
        같은 줄로 가득 차면 아무도 보지 않는다. 거절당한 뒤 다시 요청하는 것은 허용한다.
        """
        if kind not in self.REQ_KINDS:
            raise ValueError("요청 종류는 role|site|asset")
        want = str(want or "").strip()
        if kind == "role":
            if want not in ROLES:
                raise ValueError("권한은 viewer|operator|admin")
            if ROLES[want] > ROLES[self.REQ_MAX_ROLE]:
                raise ValueError(
                    f"{ROLE_KO.get(want, want)} 권한은 요청으로 드리지 않습니다 — "
                    "관리자 임명은 [사용자 · 권한] 화면의 [계정 · 가입] 에서 따로 합니다. "
                    f"필요한 일이 {ROLE_KO[self.REQ_MAX_ROLE]} 권한으로 되는지 먼저 확인하십시오")
        elif not SITE_RE.match(want):
            raise ValueError("사이트 ID 형식 오류(영문·숫자·_- 1~32자)")
        if not self.get_user(login):
            raise ValueError("등록되지 않은 계정입니다")
        idx = self._idx(login)
        body = {"login": login, "action": str(action or "").strip()[:200],
                "reason": str(reason or "").strip()[:300]}
        now = time.time()
        with self._lock, self.db() as db:
            db.execute("""INSERT INTO access_req(login,kind,want,enc,status,created,decided,decider,note)
                          VALUES(?,?,?,?, 'pending', ?, 0, '', '')
                          ON CONFLICT(login,kind,want) DO UPDATE SET enc=excluded.enc, status='pending',
                              created=excluded.created, decided=0, decider='', note=''""",
                       (idx, kind, want, self._enc(body, "access_req", "enc", idx), now))
        # 감사 기록의 detail 은 평문 칸이다 — **사유는 넣지 않는다.** 사람이 쓴 글에는 장비
        # 주소·호스트명이 섞일 수 있고, 분석 이력에서는 그것을 가리고 있다(privacy.py).
        # 남기는 것은 '무엇을 요청했고 어디서 막혔는지' 까지다.
        self.audit(login, ip, "access.request", f"{kind}:{want}", body["action"])
        return {"ok": True, "kind": kind, "want": want, "status": "pending"}

    def _req_row(self, r) -> dict:
        d = self._dec(r["enc"], "access_req", "enc", r["login"]) or {}
        if not isinstance(d, dict):
            d = {}
        return {"id": r["id"], "login": d.get("login", "(읽을 수 없음)"), "kind": r["kind"], "want": r["want"],
                "kind_ko": self.REQ_KO.get(r["kind"], r["kind"]), "action": d.get("action", ""),
                "reason": d.get("reason", ""), "status": r["status"], "created": r["created"],
                # 거절 사유도 암호화 칸에 둔다. note 칸은 2026-10-01 전 줄을 읽기 위해서만 본다.
                "decided": r["decided"], "decider": r["decider"], "note": d.get("note", "") or (r["note"] or "")}

    def my_requests(self, login: str) -> list[dict]:
        with self.db() as db:
            rows = db.execute("SELECT * FROM access_req WHERE login=? ORDER BY created DESC",
                              (self._idx(login),)).fetchall()
        return [self._req_row(r) for r in rows]

    def access_requests(self, status: str = "") -> list[dict]:
        with self.db() as db:
            rows = (db.execute("SELECT * FROM access_req WHERE status=? ORDER BY created DESC LIMIT 500", (status,))
                    if status else
                    db.execute("SELECT * FROM access_req ORDER BY created DESC LIMIT 500")).fetchall()
        return [self._req_row(r) for r in rows]

    def decide_request(self, rid: int, approve: bool, actor: str, note: str = "") -> dict:
        """승인하면 **권한을 실제로 올려 준다** — 표시만 바꾸고 끝나면 요청한 사람은 또 막힌다."""
        with self.db() as db:
            r = db.execute("SELECT * FROM access_req WHERE id=?", (int(rid),)).fetchone()
        if not r:
            raise ValueError("없는 요청입니다")
        if r["status"] != "pending":
            raise ValueError("이미 처리한 요청입니다 — 화면을 새로 고치십시오")
        req = self._req_row(r)
        who = req["login"]
        if approve:
            u = self.get_user(who)
            if not u:
                raise ValueError("요청한 계정이 없습니다(삭제되었습니다)")
            if req["kind"] == "role":
                val = {"role": req["want"]}
            elif req["kind"] == "site":
                val = {"sites": sorted(set(list(u.get("sites") or []) + [req["want"]]))}
            else:
                val = {"asset_sites": sorted(set(list(u.get("asset_sites") or []) + [req["want"]]))}
            # 마지막 관리자·자기 자신 규칙은 update_user 가 그대로 건다(여기서 우회하지 않는다).
            self.update_user(who, val, actor)
        idx = self._idx(who)
        blob = self._enc({"login": who, "action": req["action"], "reason": req["reason"],
                          "note": str(note or "").strip()[:200]}, "access_req", "enc", idx)
        with self._lock, self.db() as db:
            db.execute("UPDATE access_req SET status=?, decided=?, decider=?, note='', enc=? WHERE id=?",
                       ("approved" if approve else "denied", time.time(), (actor or "")[:80], blob, int(rid)))
        self.audit(actor or "(admin)", "", "access." + ("approve" if approve else "deny"),
                   f"{who} {req['kind']}:{req['want']}", "")
        return {"ok": True, "id": int(rid), "status": "approved" if approve else "denied",
                "login": who, "kind": req["kind"], "want": req["want"]}

    def delete_user(self, login: str, actor: str) -> None:
        if login == actor:
            raise ValueError("자기 자신은 삭제할 수 없습니다")
        with self._lock, self.db() as db:
            r = db.execute("SELECT role,disabled FROM users WHERE login=?", (self._idx(login),)).fetchone()
            if not r:
                raise ValueError("없는 사용자입니다")
            if r["role"] == "admin" and not r["disabled"] and \
               db.execute("SELECT count(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0] <= 1:
                raise ValueError("마지막 관리자는 삭제할 수 없습니다")
            db.execute("DELETE FROM users WHERE login=?", (self._idx(login),))
            db.execute("DELETE FROM sessions WHERE login=?", (self._idx(login),))

    # 세션
    def new_session(self, login: str, ip: str, single: bool = True) -> str:
        """로그인마다 새 토큰을 발급한다(세션 고정 방지). single=True 면 같은 ID 의 기존 접속을 모두 끊는다(중복 로그인 금지)."""
        tok = secrets.token_hex(32)
        now = time.time()
        idx = self._idx(login)
        with self._lock, self.db() as db:
            if single:
                for old in db.execute("SELECT th FROM sessions WHERE login=?", (idx,)).fetchall():
                    db.execute("INSERT OR REPLACE INTO kicked(th,at,reason) VALUES(?,?,?)",
                               (old["th"], now, "다른 곳에서 같은 계정으로 로그인"))
                db.execute("DELETE FROM sessions WHERE login=?", (idx,))
                db.execute("DELETE FROM kicked WHERE at<?", (now - 86400,))
            db.execute("INSERT INTO sessions(th,login,created,seen,ip) VALUES(?,?,?,?,?)", (_th(tok), idx, now, now, ip))
            db.execute("DELETE FROM sessions WHERE seen<?", (now - 86400 * 2,))
            db.execute("UPDATE users SET last_login=? WHERE login=?", (now, self._idx(login)))
        return tok

    def session_user(self, tok: str, idle_min: float, max_hours: float) -> dict | None:
        if not tok or not re.fullmatch(r"[0-9a-f]{64}", tok):
            return None
        now = time.time()
        th = _th(tok)
        with self.db() as db:
            s = db.execute("SELECT * FROM sessions WHERE th=?", (th,)).fetchone()
            if not s:
                return None
            if now - s["seen"] > idle_min * 60 or now - s["created"] > max_hours * 3600:
                db.execute("DELETE FROM sessions WHERE th=?", (th,))
                return None
            u = db.execute("SELECT * FROM users WHERE login=? AND disabled=0", (s["login"],)).fetchone()
            if not u:
                return None
            if now - s["seen"] > 30:   # 매 요청 쓰기 방지
                db.execute("UPDATE sessions SET seen=? WHERE th=?", (now, th))
            return self._user(u)

    def was_kicked(self, tok: str) -> bool:
        """이 접속이 '다른 곳 로그인' 때문에 끊겼는지 — 로그인 화면에 이유를 보여 주기 위해."""
        if not tok or not re.fullmatch(r"[0-9a-f]{64}", tok or ""):
            return False
        with self.db() as db:
            return bool(db.execute("SELECT 1 FROM kicked WHERE th=?", (_th(tok),)).fetchone())

    def drop_session(self, tok: str) -> None:
        with self._lock, self.db() as db:
            db.execute("DELETE FROM sessions WHERE th=?", (_th(tok or ""),))

    # 쿠키 정책을 바꾸면 **이미 발급된 쿠키는 그대로 남는다.**
    # SameSite 를 Lax 에서 Strict 로 올려도, 브라우저가 들고 있는 옛 쿠키는 Lax 다(GPT 지적).
    # 그래서 정책을 바꾼 판으로 처음 올라올 때 세션을 한 번 비운다 — 모두 다시 로그인한다.
    # 불편하지만, 바꾼 보호가 실제로 걸리는 유일한 길이다.
    COOKIE_POLICY = "samesite-strict-1"

    def drop_all_sessions(self) -> int:
        """세션을 모두 비운다 — 몇 개를 비웠는지 돌려준다."""
        with self._lock, self.db() as db:
            n = db.execute("SELECT count(*) FROM sessions").fetchone()[0]
            db.execute("DELETE FROM sessions")
            return int(n)

    def apply_cookie_policy(self, base) -> int:
        """쿠키 정책이 바뀐 판으로 올라왔으면 세션을 한 번 비운다(한 번만).

        표식을 data/ 에 적는다. 같은 정책이면 아무것도 하지 않으므로, 다시 시작할 때마다
        로그아웃되는 일은 없다.
        """
        mark = Path(base) / "data" / "cookie_policy"
        try:
            if mark.read_text(encoding="utf-8").strip() == self.COOKIE_POLICY:
                return 0
        except OSError:
            pass
        n = self.drop_all_sessions()
        mark.parent.mkdir(parents=True, exist_ok=True)
        mark.write_text(self.COOKIE_POLICY + NL_, encoding="utf-8")
        return n

    def sessions_count(self) -> int:
        with self.db() as db:
            return db.execute("SELECT count(DISTINCT login) FROM sessions WHERE seen>?", (time.time() - 3600,)).fetchone()[0]

    def use_nonce(self, nonce: str, ttl: float = 600) -> bool:
        now = time.time()
        with self._lock, self.db() as db:
            db.execute("DELETE FROM nonces WHERE at<?", (now - ttl,))
            try:
                db.execute("INSERT INTO nonces(nonce,at) VALUES(?,?)", (nonce, now))
                return True
            except sqlite3.IntegrityError:
                return False

    # 감사 — 누가(login)·무엇을(target) 은 암호화해 남기고, 화면에 볼 때만 푼다
    def audit(self, login: str, ip: str, action: str, target: str = "", detail: str = "", ok: bool = True) -> None:
        try:
            who = (login or "-")[:120]
            what = str(target)[:200]
            now = time.time()
            with self._lock, self.db() as db:
                prev = db.execute("SELECT chain FROM audit ORDER BY id DESC LIMIT 1").fetchone()
                blob = self._enc({"login": who, "target": what}, "audit", "enc", f"{now:.6f}")
                chain = hmac.new(self._ikey, ((prev["chain"] if prev and prev["chain"] else "")
                                              + f"|{now:.6f}|{action[:60]}|{ip or ''}|{1 if ok else 0}|"
                                              ).encode("utf-8") + blob, hashlib.sha256).hexdigest()
                db.execute("INSERT INTO audit(at,login,ip,action,target,detail,ok,enc,chain) VALUES(?,?,?,?,?,?,?,?,?)",
                           (now, self._idx(who), ip or "", action[:60], "", str(detail)[:500],
                            1 if ok else 0, blob, chain))
        except sqlite3.Error:
            pass

    def audit_list(self, limit: int = 300, login: str = "", action: str = "", days: int = 30) -> list[dict]:
        q, a = "SELECT * FROM audit WHERE at>=?", [time.time() - max(1, min(int(days), 400)) * 86400]
        if login:
            q += " AND login=?"; a.append(self._idx(login))
        if action:
            q += " AND action LIKE ?"; a.append(action + "%")
        q += " ORDER BY id DESC LIMIT ?"; a.append(max(1, min(int(limit), 2000)))
        out = []
        with self.db() as db:
            for r in db.execute(q, a):
                d = dict(r)
                ident = self._dec(d.pop("enc", None), "audit", "enc", f"{d.get('at', 0):.6f}")
                if isinstance(ident, dict):
                    d["login"], d["target"] = ident.get("login", ""), ident.get("target", "")
                out.append(d)
        return out

    def audit_verify(self, limit: int = 100000) -> dict:
        """감사 기록이 지워지거나 순서가 바뀌지 않았는지 사슬로 확인한다(2026-09-22)."""
        prev, checked, bad = "", 0, None
        with self.db() as db:
            for r in db.execute("SELECT id,at,action,ip,ok,enc,chain FROM audit ORDER BY id LIMIT ?", (limit,)):
                if not r["chain"]:
                    prev = ""; continue        # 예전 판에서 쌓인 기록은 사슬이 없다
                want = hmac.new(self._ikey, (prev + f"|{r['at']:.6f}|{r['action']}|{r['ip'] or ''}|{r['ok']}|").encode("utf-8")
                                + bytes(r["enc"] or b""), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(want, r["chain"]):
                    bad = r["id"]; break
                prev = r["chain"]; checked += 1
        return {"ok": bad is None, "checked": checked, "broken_at": bad}

    def prune(self, keep_days: int = 400) -> None:
        with self._lock, self.db() as db:
            db.execute("DELETE FROM audit WHERE at<?", (time.time() - keep_days * 86400,))


def _map_groups(conf: dict, groups) -> dict | None:
    """portal.group_map: [{"group": "CN=IT운영,OU=…"(또는 부분 문자열), "role": "operator", "sites": ["SITE1"]}] — 가장 높은 권한 1건"""
    best = None
    gl = [str(g).lower() for g in (groups or [])]
    for m in (conf.get("portal") or {}).get("group_map") or []:
        g = str(m.get("group", "")).lower()
        if g and any(g == x or g in x for x in gl) and m.get("role") in ROLES:
            if best is None or ROLES[m["role"]] > ROLES[best["role"]]:
                best = {"role": m["role"], "sites": list(m.get("sites") or []), "asset_sites": list(m.get("asset_sites") or [])}
    return best


def asset_allowed(user: dict | None, site_id: str) -> bool:
    """사이트 자산 현황 조회: 이 사이트가 asset_sites 에 명시된 사용자만(관리자·전체 사이트 권한도 예외 없음).
    포털 인증을 쓰지 않는 기존 단독 설치(공용 접속·이 PC)는 사용자 구분이 없으므로 허용."""
    if not user:
        return False
    if user.get("source") == "legacy":
        return True
    return site_id in (user.get("asset_sites") or [])


def site_allowed(user: dict | None, site_id: str) -> bool:
    if not user:
        return False
    s = user.get("sites") or []
    return "*" in s or site_id in s


# ── LDAP 단순 바인드(표준 라이브러리 BER 구현) ───────────────────────────────
def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(content)) + content


def _int(v: int, tag: int = 0x02) -> bytes:
    return _tlv(tag, v.to_bytes(max(1, (v.bit_length() + 8) // 8), "big", signed=True))


def _read_tlv(buf: bytes, i: int):
    tag = buf[i]; i += 1
    ln = buf[i]; i += 1
    if ln & 0x80:
        k = ln & 0x7F
        ln = int.from_bytes(buf[i:i + k], "big"); i += k
    if i + ln > len(buf):
        raise ValueError("BER 길이 초과")
    return tag, buf[i:i + ln], i + ln


def _children(content: bytes):
    i, out = 0, []
    while i < len(content):
        t, v, i = _read_tlv(content, i)
        out.append((t, v))
    return out


class _LdapConn:
    def __init__(self, url: str, timeout: float, verify: bool, ca_file: str):
        u = urllib.parse.urlsplit(url)
        if u.scheme not in ("ldap", "ldaps") or not u.hostname:
            raise AuthError("LDAP 주소 설정 오류(ldap:// 또는 ldaps://) — 관리자에게 문의")
        port = u.port or (636 if u.scheme == "ldaps" else 389)
        raw = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "ldaps":
            ctx = ssl.create_default_context(cafile=ca_file or None)
            if not verify:
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=u.hostname)
        raw.settimeout(timeout)
        self.s = raw
        self.buf = b""
        self.mid = 0

    def _send(self, op: bytes) -> int:
        self.mid += 1
        self.s.sendall(_tlv(0x30, _int(self.mid) + op))
        return self.mid

    def _recv(self):
        while True:
            if len(self.buf) >= 2:
                ln, hl = self.buf[1], 2
                if ln & 0x80:
                    k = ln & 0x7F
                    ln = int.from_bytes(self.buf[2:2 + k], "big") if len(self.buf) >= 2 + k else None
                    hl = 2 + k
                if ln is not None:
                    if hl + ln > 1 << 20:
                        raise AuthError("LDAP 응답이 너무 큽니다")
                    if len(self.buf) >= hl + ln:
                        msg, self.buf = self.buf[:hl + ln], self.buf[hl + ln:]
                        _, body, _ = _read_tlv(msg, 0)
                        return _children(body)[1]   # (protocolOp tag, content)
            chunk = self.s.recv(65536)
            if not chunk:
                raise AuthError("인증 서버가 연결을 끊었습니다")
            self.buf += chunk

    def bind(self, dn: str, pw: str) -> int:
        self._send(_tlv(0x60, _int(3) + _tlv(0x04, dn.encode("utf-8")) + _tlv(0x80, pw.encode("utf-8"))))
        tag, content = self._recv()
        if tag != 0x61:
            raise AuthError("LDAP 응답 형식 오류")
        return int.from_bytes(_children(content)[0][1], "big")

    def search_one(self, base: str, attr: str, value: str, attrs: list[str]) -> dict:
        val = re.sub(r"([*()\\\x00])", lambda m: "\\%02x" % ord(m.group(1)), value)   # RFC 4515 이스케이프(동등 비교라 필수는 아님)
        flt = _tlv(0xA3, _tlv(0x04, attr.encode()) + _tlv(0x04, val.encode("utf-8")))
        req = (_tlv(0x04, base.encode("utf-8")) + _int(2, 0x0A) + _int(0, 0x0A) + _int(2) + _int(5) + _tlv(0x01, b"\x00")
               + flt + _tlv(0x30, b"".join(_tlv(0x04, a.encode()) for a in attrs)))
        self._send(_tlv(0x63, req))
        found: dict = {}
        for _ in range(100):
            tag, content = self._recv()
            if tag == 0x64 and not found:
                kids = _children(content)
                for _, pa in _children(kids[1][1]):
                    t, vals = _children(pa)
                    found[t[1].decode("utf-8", "replace").lower()] = [v.decode("utf-8", "replace") for _, v in _children(vals[1])]
            elif tag == 0x65:
                break
        return found

    def close(self):
        try:
            self.s.sendall(_tlv(0x30, _int(self.mid + 1) + _tlv(0x42, b"")))   # unbind
            self.s.close()
        except OSError:
            pass


def _ldap_dn_escape(s: str) -> str:
    return re.sub(r'([,\\#+<>;"=])', r"\\\1", s)


def ldap_login(conf: dict, login: str, password: str) -> dict:
    lc = (conf.get("portal") or {}).get("ldap") or {}
    if not password:   # 빈 비밀번호는 LDAP 에서 '인증 없는 바인드 성공'이 되므로 반드시 거절(RFC 4513 5.1.2)
        raise AuthError("비밀번호를 입력하십시오")
    if not LOGIN_RE.match(login or ""):
        raise AuthError("계정 ID 형식이 올바르지 않습니다")
    fmt = lc.get("bind_dn_format") or "{login}"
    try:
        c = _LdapConn(lc.get("url", ""), float(lc.get("timeout", 5)), lc.get("verify_tls", True) is not False, lc.get("ca_file", ""))
    except (OSError, ssl.SSLError) as e:
        raise AuthError(f"인증 서버에 연결하지 못했습니다({type(e).__name__}) — 관리자에게 문의하십시오") from e
    try:
        rc = c.bind(fmt.replace("{login}", _ldap_dn_escape(login)), password)
        if rc == 49:
            raise AuthError("계정 ID 또는 비밀번호가 맞지 않습니다")
        if rc != 0:
            raise AuthError(f"인증 서버가 로그인을 거절했습니다(코드 {rc})")
        info = {"name": "", "dept": "", "email": "", "groups": []}
        if lc.get("search_base"):
            attrs = [lc.get("name_attr", "displayName"), lc.get("dept_attr", "department"), lc.get("mail_attr", "mail"), lc.get("group_attr", "memberOf")]
            f = c.search_one(lc["search_base"], lc.get("login_attr", "sAMAccountName"), login, attrs)
            g = lambda a: (f.get(a.lower()) or [""])[0]
            info.update(name=g(attrs[0]), dept=g(attrs[1]), email=g(attrs[2]), groups=f.get(attrs[3].lower()) or [])
        return info
    except AuthError:
        raise                       # 로그인 실패 메시지는 그대로 전달(AuthError 는 ValueError 계열)
    except (OSError, ssl.SSLError, IndexError, ValueError) as e:
        raise AuthError(f"인증 서버 통신 오류({type(e).__name__})") from e
    finally:
        c.close()


# ── OIDC(인가 코드) + RS256 검증(순수 파이썬 RSA) ─────────────────────────
_DIGESTINFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def rs256_verify(n: int, e: int, signing_input: bytes, sig: bytes) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k or k < 256:   # 2048비트 미만 키 거절
        return False
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    h = _DIGESTINFO_SHA256 + hashlib.sha256(signing_input).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(h) - 3) + b"\x00" + h
    return hmac.compare_digest(em, expected)


class Oidc:
    def __init__(self, conf: dict):
        self.c = (conf.get("portal") or {}).get("oidc") or {}
        for k in ("authorize_url", "token_url", "client_id", "redirect_uri"):
            if not self.c.get(k):
                raise ValueError(f"conf/auth.json: portal.oidc.{k} 가 필요합니다")
        self._pending: dict[str, tuple[float, str]] = {}   # state → (시각, nonce)
        self._jwks: tuple[float, dict] | None = None
        self._lock = threading.Lock()

    def _ctx(self):
        ctx = ssl.create_default_context(cafile=self.c.get("ca_file") or None)
        if self.c.get("verify_tls") is False:
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def authorize_url(self) -> str:
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            for k in [k for k, (t, _) in self._pending.items() if now - t > 600]:
                self._pending.pop(k, None)
            if len(self._pending) > 5000:
                raise AuthError("로그인 요청이 너무 많습니다 — 잠시 후 다시 시도하십시오")
            self._pending[state] = (now, nonce)
        q = {"response_type": "code", "client_id": self.c["client_id"], "redirect_uri": self.c["redirect_uri"],
             "scope": self.c.get("scope", "openid profile"), "state": state, "nonce": nonce}
        return self.c["authorize_url"] + ("&" if "?" in self.c["authorize_url"] else "?") + urllib.parse.urlencode(q)

    def callback(self, query: dict) -> dict:
        state = (query.get("state") or [""])[0]
        code = (query.get("code") or [""])[0]
        with self._lock:
            pend = self._pending.pop(state, None)
        if not pend or time.time() - pend[0] > 600:
            raise AuthError("로그인 요청이 만료되었습니다 — 다시 로그인하십시오")
        if not code:
            raise AuthError("통합 로그인이 완료되지 않았습니다: " + (query.get("error") or ["unknown"])[0][:80])
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": self.c["redirect_uri"],
                                       "client_id": self.c["client_id"], "client_secret": self.c.get("client_secret", "")}).encode()
        req = urllib.request.Request(self.c["token_url"], data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ctx()) as r:
                tok = json.loads(r.read(1 << 20))
        except (OSError, ValueError) as e:
            raise AuthError(f"인증 토큰 발급 실패({type(e).__name__})") from e
        claims = self.verify_id_token(tok.get("id_token", ""), pend[1])
        c = self.c
        groups = claims.get(c.get("groups_claim", "groups")) or []
        return {"login": str(claims.get(c.get("login_claim", "preferred_username")) or claims.get("sub") or ""),
                "name": str(claims.get(c.get("name_claim", "name")) or ""), "dept": str(claims.get(c.get("dept_claim", "department")) or ""),
                "email": str(claims.get("email") or ""), "groups": groups if isinstance(groups, list) else [str(groups)]}

    def _keys(self) -> dict:
        now = time.time()
        if self._jwks and now - self._jwks[0] < 3600:
            return self._jwks[1]
        with urllib.request.urlopen(self.c["jwks_url"], timeout=10, context=self._ctx()) as r:
            data = json.loads(r.read(1 << 20))
        keys = {k.get("kid", ""): (int.from_bytes(_b64u(k["n"]), "big"), int.from_bytes(_b64u(k["e"]), "big"))
                for k in data.get("keys", []) if k.get("kty") == "RSA"}
        self._jwks = (now, keys)
        return keys

    def verify_id_token(self, jwt: str, nonce: str) -> dict:
        try:
            h64, p64, s64 = jwt.split(".")
            head, claims = json.loads(_b64u(h64)), json.loads(_b64u(p64))
        except ValueError as e:
            raise AuthError("ID 토큰 형식 오류") from e
        if self.c.get("jwks_url"):
            if head.get("alg") != "RS256":
                raise AuthError("지원하지 않는 서명 방식입니다(RS256 만)")
            try:
                keys = self._keys()
            except (OSError, ValueError, KeyError) as e:
                raise AuthError(f"인증 서명 키를 가져오지 못했습니다({type(e).__name__})") from e
            key = keys.get(head.get("kid", "")) or (next(iter(keys.values())) if len(keys) == 1 else None)
            if not key or not rs256_verify(key[0], key[1], f"{h64}.{p64}".encode(), _b64u(s64)):
                raise AuthError("ID 토큰 서명 검증 실패")
        elif not self.c.get("token_url", "").lower().startswith("https://") and self.c.get("allow_unsigned") is not True:
            raise AuthError("OIDC 는 jwks_url(서명 검증) 또는 https 토큰 주소가 필요합니다")
        now = time.time()
        aud = claims.get("aud")
        if (self.c.get("issuer") and claims.get("iss") != self.c["issuer"]) or \
           (self.c["client_id"] not in (aud if isinstance(aud, list) else [aud])) or \
           float(claims.get("exp", 0)) < now - 60 or claims.get("nonce") != nonce:
            raise AuthError("ID 토큰 검증 실패(발급자·대상·만료·nonce)")
        return claims


# ── 포털 링크 서명(link) ─────────────────────────────────────────────────
def link_sign(secret: str, login: str, ts: int, nonce: str, name: str = "", dept: str = "") -> str:
    msg = "|".join([login, str(ts), nonce, name, dept]).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def secret_ok(secret: str) -> bool:
    """link 비밀키: 32자 이상 + 서로 다른 글자 12종 이상(사전형·반복형 차단). gen-secret 으로 만든 값을 권장."""
    return len(secret) >= 32 and len(set(secret)) >= 12


def link_secret(conf: dict) -> str:
    return ((conf.get("portal") or {}).get("link") or {}).get("secret") or os.environ.get("LOGTRIAGE_PORTAL_SECRET", "")


def link_login(conf: dict, query: dict, store: AuthStore) -> dict:
    lc = (conf.get("portal") or {}).get("link") or {}
    secret = link_secret(conf)
    if not secret_ok(secret):
        raise AuthError("로그인 링크 연동 비밀키가 없거나 약합니다(32자 이상 무작위 값) — 관리자에게 문의하십시오")
    g = lambda k: (query.get(k) or [""])[0]
    login, ts, nonce, sig, name, dept = g("u"), g("t"), g("n"), g("sig"), g("name"), g("dept")
    try:
        t = int(ts)
    except ValueError:
        raise AuthError("로그인 링크 형식 오류") from None
    if abs(time.time() - t) > float(lc.get("max_skew_sec", 120)):
        raise AuthError("로그인 링크가 만료되었습니다 — 로그인 메뉴를 다시 눌러 주십시오(서버 시각 확인)")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{8,64}", nonce):
        raise AuthError("로그인 링크 형식 오류")
    if not hmac.compare_digest(sig.lower(), link_sign(secret, login, t, nonce, name, dept)):
        raise AuthError("로그인 링크 서명이 맞지 않습니다")
    if not store.use_nonce("link:" + nonce, ttl=float(lc.get("max_skew_sec", 120)) * 2 + 60):
        raise AuthError("이미 사용된 로그인 링크입니다 — 로그인 메뉴를 다시 눌러 주십시오")
    return {"login": login, "name": name, "dept": dept, "email": "", "groups": []}


def header_login(conf: dict, peer_ip: str, headers) -> dict:
    hc = (conf.get("portal") or {}).get("header") or {}
    trusted = hc.get("trusted_proxies") or []   # 기본값 없음(r4 검토): 같은 서버의 임의 프로세스가 사칭하지 못하도록 명시한 앞단만
    if not trusted:
        raise AuthError("통합 로그인(SSO) 앞단 주소(trusted_proxies)가 설정되지 않았습니다 — 관리자에게 문의하십시오")
    if peer_ip not in trusted:
        raise AuthError("통합 로그인(SSO) 앞단을 거치지 않은 접속입니다 — 지정된 접속 주소를 사용하십시오")
    ps = hc.get("proxy_secret") or ""
    if ps and not hmac.compare_digest((headers.get("X-Proxy-Secret") or "").encode(), ps.encode()):
        raise AuthError("통합 로그인(SSO) 앞단 확인값이 맞지 않습니다 — 지정된 접속 주소를 사용하십시오")
    login = (headers.get(hc.get("user_header", "X-Portal-User")) or "").strip()
    if not login:
        raise AuthError("통합 로그인(SSO) 사용자 정보가 전달되지 않았습니다 — 다시 접속하십시오")
    dec = lambda v: urllib.parse.unquote(v or "")
    groups = [g.strip() for g in dec(headers.get(hc.get("groups_header", "X-Portal-Groups"))).split(";") if g.strip()]
    return {"login": login, "name": dec(headers.get(hc.get("name_header", "X-Portal-Name"))),
            "dept": dec(headers.get(hc.get("dept_header", "X-Portal-Dept"))), "email": "", "groups": groups}


# ── 관리 CLI ─────────────────────────────────────────────────────────────
def main(argv=None) -> int:
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="python -m logtriage.auth", description="LogTriage 인증 관리 — 비상용 로컬 관리자·포털 링크 시험")
    ap.add_argument("--base", required=True, help="설치 경로(데이터 폴더)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a1 = sub.add_parser("set-admin", help="비상용 로컬 관리자 생성/비밀번호 변경")
    a1.add_argument("--login", default="admin")
    a1.add_argument("--password", default=os.environ.get("LOGTRIAGE_ADMIN_PASSWORD", ""))
    a2 = sub.add_parser("sign-link", help="포털 링크(link 방식) 시험 URL 생성")
    a2.add_argument("--user", required=True)
    a2.add_argument("--url", default="http://127.0.0.1:8088")
    sub.add_parser("users", help="사용자 목록")
    sub.add_parser("gen-secret", help="link 방식 비밀키(무작위 48자) 생성 — auth.json 의 portal.link.secret 과 연동 시스템에 같은 값을 넣음")
    a = ap.parse_args(argv)
    base = Path(a.base)
    store = AuthStore(base / "data" / "auth" / "auth.sqlite3")
    if a.cmd == "set-admin":
        pw = a.password or getpass.getpass("새 비밀번호(10자 이상): ")
        store.set_local(a.login, pw, "admin", "비상 관리자")
        store.audit("cli", "", "user.local_admin", a.login)
        print(f"로컬 관리자 '{a.login}' 설정 완료 — 브라우저에서 /login?local=1 로 로그인")
    elif a.cmd == "gen-secret":
        print(secrets.token_urlsafe(36))
    elif a.cmd == "sign-link":
        conf = load_conf(base) or {}
        secret = link_secret(conf)
        if not secret_ok(secret):
            print("conf/auth.json 의 portal.link.secret 이 없거나 약합니다(32자 이상 무작위 — gen-secret 사용)")
            return 2
        ts, nonce = int(time.time()), secrets.token_hex(12)
        print(f"{a.url.rstrip('/')}/sso/link?" + urllib.parse.urlencode({"u": a.user, "t": ts, "n": nonce, "sig": link_sign(secret, a.user, ts, nonce)}))
    else:
        for u in store.users():
            print(f"{u['login']:<24} {u['role']:<9} {','.join(u['sites']) or '-':<20} {u['source']:<7} {'중지' if u['disabled'] else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
