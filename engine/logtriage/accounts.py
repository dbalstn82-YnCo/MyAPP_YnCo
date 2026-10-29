"""사내 이메일 계정 로그인(2026-09-21) — ID 는 회사 도메인 이메일만, 비밀번호는 3중으로 보호해 저장한다.

비밀번호 저장(세 겹)
  ① 페퍼(HMAC-SHA256): 입력 비밀번호를 서버 키 파일(conf/secret.key)에서 뽑은 키로 먼저 HMAC 한다.
     → DB 만 빠져나가면 사전·무차별 대입을 아예 시작할 수 없다(키가 파일에 따로 있음).
  ② scrypt(메모리 하드 해시, 기본 N=16384·r=8·p=1, 계정마다 다른 16바이트 소금):
     → GPU·ASIC 대량 대입에 강하다. scrypt 를 못 쓰는 파이썬이면 PBKDF2-HMAC-SHA512 600,000회로 자동 대체.
  ③ ChaCha20-Poly1305 저장 암호화: ①②로 만든 검증값을 다시 암호화해 저장(추가 데이터로 이메일을 묶어 다른 계정 값으로 바꿔치기 불가).
  전송 구간은 HTTPS 강제(require_https)로 보호한다.

계정 규칙
  · ID 형식: <아이디>@<회사 도메인> (기본 solideos.com). 다른 도메인 이메일은 등록·로그인 모두 거부.
  · 비밀번호: 10자 이상(설정 가능), 영문 대·소문자·숫자·기호 중 3종 이상, 아이디·회사명·흔한 비밀번호 사용 금지, 최근 5개 재사용 금지.
  · 처음 발급 비밀번호와 관리자 초기화 비밀번호는 첫 로그인 때 반드시 변경.
  · 연속 실패 5회 → 10분 잠금(관리자가 즉시 해제 가능). 비밀번호 유효기간 기본 90일(0이면 사용 안 함).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import unicodedata
import sqlite3
import time
from pathlib import Path

from .auth import ROLES, AuthError, AuthStore
from .crypto import KEY_VERSION, AeadError, aad, chacha20_poly1305_decrypt, chacha20_poly1305_encrypt, derive

DEFAULT = {
    "domain": "solideos.com",
    "min_length": 10,
    "classes": 3,               # 대문자·소문자·숫자·기호 중 최소 종류 수
    "history": 5,               # 최근 N개 재사용 금지
    "expire_days": 90,          # 0 이면 사용 안 함
    "max_fails": 5,
    "lock_minutes": 10,
    "scrypt_n": 15,             # 2**15 = 32,768 (메모리 약 32MB) — 2026-09-22 상향
    "signup": "approve",        # 직접 가입 방식 — 아래 SIGNUP 참조(기본: 관리자 승인 뒤 사용)
}

# 직접 가입(2026-10-01) — 사람이 자기 계정을 스스로 만든다.
#
# 가입을 아무 제한 없이 열면 **이 서버에 닿을 수 있는 사람이 모두 사용자**가 된다
# (회사 이메일 형식은 밖에서도 짐작할 수 있다). 그래서 기본은 '승인 뒤 사용' 이다.
# 즉시 쓰게 하는 것도 한 번 눌러 바꿀 수 있게 두되, 그 대가를 화면에 적는다.
SIGNUP = {
    "off": "가입 받지 않음 — 관리자가 발급한 계정만 씁니다",
    "approve": "누구나 신청하고 **관리자 승인 뒤** 사용합니다(권장)",
    "code": "관리자가 발급한 **가입 코드**를 아는 사람만 — 승인 없이 바로 씁니다",
    "open": "신청하면 바로 씁니다 — 이 서버에 닿는 사람은 누구나 들어옵니다",
}
SIGNUP_KEY = "(signup)"      # 가입 코드를 저장할 때 쓰는 자리표(계정 이메일이 아니다)
# 화면에서 고를 수 있는 방식. **'즉시 사용'(open)은 빠진다**(GPT 20차) — 이 서버에 닿는
# 사람이 모두 사용자가 되는 길이라, 서버에 들어올 수 있는 사람만 conf/auth.json 으로 켠다.
# 사이트 ID·로그인 방식과 같은 대우다.
SIGNUP_FROM_SCREEN = ("off", "approve", "code")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"
WEAK = {"password", "passw0rd", "qwerty", "asdf", "1q2w3e4r", "1qaz2wsx", "admin", "letmein", "welcome",
        "solideos", "logtriage", "abcd1234", "12345678", "87654321", "iloveyou", "zxcvbnm"}


def conf_of(conf: dict | None) -> dict:
    c = dict(DEFAULT)
    c.update(((conf or {}).get("local") or {}))
    c["domain"] = str(c["domain"]).strip().lower().lstrip("@")
    if not re.fullmatch(r"[a-z0-9.\-]{3,60}\.[a-z]{2,10}", c["domain"]):
        raise ValueError("conf/auth.json: local.domain 형식 오류(예: solideos.com)")
    c["min_length"] = max(8, min(int(c["min_length"]), 64))
    c["classes"] = max(2, min(int(c["classes"]), 4))
    c["history"] = max(0, min(int(c["history"]), 24))
    c["expire_days"] = max(0, min(int(c["expire_days"]), 3650))
    c["max_fails"] = max(3, min(int(c["max_fails"]), 20))
    c["lock_minutes"] = max(1, min(int(c["lock_minutes"]), 1440))
    c["scrypt_n"] = max(12, min(int(c["scrypt_n"]), 20))
    c["signup"] = str(c.get("signup") or "approve").strip().lower()
    if c["signup"] not in SIGNUP:
        raise ValueError("conf/auth.json: local.signup 은 " + "|".join(SIGNUP) + " 중 하나입니다")
    return c


def normalize_email(value: str, domain: str) -> str:
    """ID 는 회사 도메인 이메일만 — 다른 도메인·형식은 받지 않는다."""
    e = unicodedata.normalize("NFKC", (value or "")).strip().lower()
    if not e:
        raise AuthError("이메일 주소를 입력하십시오")
    if len(e) > 100 or e.count("@") != 1:
        raise AuthError(f"ID 는 회사 이메일 형식이어야 합니다 (예: hong123@{domain})")
    local, dom = e.split("@")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9._%+\-]{0,62}[a-z0-9])?", local):
        raise AuthError(f"ID 형식이 올바르지 않습니다 (예: hong123@{domain})")
    if dom != domain:
        raise AuthError(f"@{domain} 계정만 사용할 수 있습니다 — 다른 이메일 주소는 등록·로그인할 수 없습니다")
    return e


def classes_of(pw: str) -> int:
    return sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])


def check_policy(pw: str, email: str, conf: dict) -> None:
    c = conf
    if not isinstance(pw, str) or not (c["min_length"] <= len(pw) <= 128):
        raise AuthError(f"비밀번호는 {c['min_length']}자 이상 128자 이하로 정하십시오")
    if classes_of(pw) < c["classes"]:
        raise AuthError(f"비밀번호에 영문 대문자·소문자·숫자·기호 중 {c['classes']}종류 이상을 섞으십시오")
    if pw.strip() != pw or " " in pw:
        raise AuthError("비밀번호 앞뒤 공백과 띄어쓰기는 쓸 수 없습니다")
    low = pw.lower()
    local = email.split("@")[0]
    if len(local) >= 4 and local in low:
        raise AuthError("비밀번호에 ID(이메일 앞부분)를 넣을 수 없습니다")
    if any(w in low for w in WEAK):
        raise AuthError("흔히 쓰이는 문자열(회사명·제품명·연속 문자 등)은 비밀번호로 쓸 수 없습니다")
    if re.search(r"(.)\1{3,}", pw) or re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf|zxcv)", low):
        raise AuthError("같은 글자 반복이나 키보드 연속 문자는 쓸 수 없습니다")


def temp_password(n: int = 14) -> str:
    """발급용 임시 비밀번호 — 헷갈리는 글자(0/O, 1/l/I)는 빼고 4종류를 모두 넣는다."""
    lo, up, di, sy = "abcdefghijkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*?-+"
    pools = [lo, up, di, sy]
    while True:
        pw = [secrets.choice(p) for p in pools] + [secrets.choice(lo + up + di + sy) for _ in range(n - 4)]
        secrets.SystemRandom().shuffle(pw)
        out = "".join(pw)
        low = out.lower()
        if not any(w in low for w in WEAK) and not re.search(r"(.)\1{3,}", out):
            return out


def recovery_code() -> str:
    """비밀번호 재설정 코드 — 헷갈리는 글자(0·O·1·I)를 뺀 32자 집합에서 12자리(약 60비트), 4자씩 끊어 읽기 쉽게."""
    abc = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw = "".join(secrets.choice(abc) for _ in range(12))
    return "-".join(raw[i:i + 4] for i in range(0, 12, 4))


class Accounts:
    """이메일 계정 저장소 — 권한(역할·사이트)은 기존 users 표를 그대로 쓰고, 여기서는 비밀번호만 다룬다."""

    def __init__(self, store: AuthStore, base: Path, conf: dict | None = None):
        self.store = store
        self.base = Path(base)
        self.conf = conf_of(conf)
        self._pepper = derive(self.base, "password-pepper")
        self._enc = derive(self.base, "verifier-enc")
        self._idxkey = derive(self.base, "email-index")     # ID(이메일)를 평문으로 저장하지 않기 위한 블라인드 인덱스 키
        with self.store.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS accounts(
              idx TEXT PRIMARY KEY, email_enc BLOB, verifier BLOB NOT NULL, history TEXT DEFAULT '[]',
              created REAL, pw_changed REAL, must_change INTEGER DEFAULT 1,
              fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, last_login REAL DEFAULT 0,
              pending INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS recovery(
              idx TEXT PRIMARY KEY, code BLOB, created REAL, expires REAL, tries INTEGER DEFAULT 0, issuer TEXT);
            CREATE TABLE IF NOT EXISTS signup_code(
              id INTEGER PRIMARY KEY CHECK(id=1), code BLOB, created REAL, expires REAL,
              max_uses INTEGER DEFAULT 0, uses INTEGER DEFAULT 0, issuer TEXT);
            """)
        self._migrate_v2()
        self._add_pending()

    # ── ID(이메일) 저장: 블라인드 인덱스 + 암호화 ──
    def _idx(self, email: str) -> str:
        """조회용 색인 — 서버 키가 있어야만 이메일에서 만들 수 있다(DB 만으로는 누구 계정인지 알 수 없음)."""
        return hmac.new(self._idxkey, email.encode("utf-8"), hashlib.sha256).hexdigest()

    def _enc_email(self, email: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return bytes([KEY_VERSION]) + nonce + chacha20_poly1305_encrypt(
            self._enc, nonce, email.encode("utf-8"), aad("accounts", "email", self._idx(email)))

    def _dec_email(self, blob, row_key: str = "") -> str:
        b = bytes(blob or b"")
        if b[:1] == bytes([KEY_VERSION]):
            try:
                return chacha20_poly1305_decrypt(self._enc, b[1:13], b[13:],
                                                 aad("accounts", "email", row_key)).decode("utf-8")
            except (AeadError, TypeError, ValueError):
                pass
        try:                                   # 2026-09-22 이전 방식(고정 AAD)
            return chacha20_poly1305_decrypt(self._enc, b[:12], b[12:], b"email").decode("utf-8")
        except (AeadError, TypeError, ValueError):
            return "(읽을 수 없음)"

    def _migrate_v2(self) -> None:
        """예전 표(평문 이메일 PK) → 색인·암호화 표로 한 번만 옮긴다."""
        with self.store._lock, self.store.db() as db:
            cols = {r[1] for r in db.execute("PRAGMA table_info(accounts)")}
            if "email" not in cols:
                return
            rows = db.execute("SELECT * FROM accounts").fetchall()
            db.execute("ALTER TABLE accounts RENAME TO accounts_v1")
            db.executescript("""
            CREATE TABLE accounts(
              idx TEXT PRIMARY KEY, email_enc BLOB, verifier BLOB NOT NULL, history TEXT DEFAULT '[]',
              created REAL, pw_changed REAL, must_change INTEGER DEFAULT 1,
              fails INTEGER DEFAULT 0, locked_until REAL DEFAULT 0, last_login REAL DEFAULT 0);
            """)
            for r in rows:
                db.execute("""INSERT INTO accounts(idx,email_enc,verifier,history,created,pw_changed,must_change,fails,locked_until,last_login)
                              VALUES(?,?,?,?,?,?,?,?,?,?)""",
                           (self._idx(r["email"]), self._enc_email(r["email"]), r["verifier"], r["history"],
                            r["created"], r["pw_changed"], r["must_change"], r["fails"], r["locked_until"], r["last_login"]))
            db.execute("DROP TABLE accounts_v1")
        print(f"[LogTriage] 계정 {len(rows)}건의 ID 저장 방식을 암호화 방식으로 옮겼습니다", flush=True)

    def _add_pending(self) -> None:
        """예전 설치에 '승인 대기' 칸을 더한다 — 이미 쓰고 있던 계정은 **승인된 것으로** 둔다.

        _migrate_v2 가 표를 다시 만드는 경우에도 이 칸이 빠지므로 마지막에 한 번 더 본다.
        """
        with self.store._lock, self.store.db() as db:
            cols = {r[1] for r in db.execute("PRAGMA table_info(accounts)")}
            if "pending" not in cols:
                db.execute("ALTER TABLE accounts ADD COLUMN pending INTEGER DEFAULT 0")

    # ── 비밀번호 검증값 만들기·확인하기 ──
    def _verifier(self, email: str, password: str, params: dict | None = None) -> bytes:
        p = params or {"v": 2, "algo": "scrypt", "n": 2 ** self.conf["scrypt_n"], "r": 8, "p": 1,
                       "pep": "sha512", "salt": secrets.token_hex(16)}
        pep = hashlib.sha512 if p.get("pep") == "sha512" else hashlib.sha256   # 예전(v1) 값은 SHA-256 으로 그대로 확인
        pre = hmac.new(self._pepper, (email + "\x00" + password).encode("utf-8"), pep).digest()             # ① 페퍼
        salt = bytes.fromhex(p["salt"])
        if p["algo"] == "scrypt":                                                                            # ② 메모리 하드 해시
            dk = hashlib.scrypt(pre, salt=salt, n=int(p["n"]), r=int(p["r"]), p=int(p["p"]), dklen=32, maxmem=1 << 27)
        elif p["algo"] == "pbkdf2_sha512":
            dk = hashlib.pbkdf2_hmac("sha512", pre, salt, int(p["n"]), dklen=32)
        else:
            raise ValueError("알 수 없는 비밀번호 저장 방식: " + str(p.get("algo")))
        blob = json.dumps({**p, "hash": dk.hex()}, separators=(",", ":")).encode()
        nonce = secrets.token_bytes(12)                                                                      # ③ 저장 암호화
        return bytes([KEY_VERSION]) + nonce + chacha20_poly1305_encrypt(
            self._enc, nonce, blob, aad("accounts", "verifier", self._idx(email)))

    def _params(self, email: str, verifier: bytes) -> dict:
        b = bytes(verifier)
        tries = ([(b[1:13], b[13:], aad("accounts", "verifier", self._idx(email)))] if b[:1] == bytes([KEY_VERSION]) else [])
        tries.append((b[:12], b[12:], email.encode()))          # 2026-09-22 이전 방식(AAD=이메일)
        for nonce, body, ad in tries:
            try:
                return json.loads(chacha20_poly1305_decrypt(self._enc, nonce, body, ad))
            except (AeadError, ValueError):
                continue
        raise AuthError("계정 정보를 읽을 수 없습니다 — 서버 키 파일(conf/secret.key)을 확인하십시오")

    def _matches(self, email: str, password: str, verifier: bytes) -> bool:
        p = self._params(email, verifier)
        want = p.pop("hash")
        got = self._verifier(email, password, p)
        return hmac.compare_digest(self._params(email, got)["hash"], want)

    def _make(self, email: str, password: str) -> bytes:
        try:
            return self._verifier(email, password)
        except (ValueError, MemoryError):   # scrypt 를 쓸 수 없는 환경
            return self._verifier(email, password, {"v": 2, "algo": "pbkdf2_sha512", "n": 600000, "r": 0, "p": 0,
                                                    "pep": "sha512", "salt": secrets.token_hex(16)})

    # ── 계정 관리 ──
    def exists(self, email: str) -> bool:
        with self.store.db() as db:
            return bool(db.execute("SELECT 1 FROM accounts WHERE idx=?", (self._idx(email),)).fetchone())

    def create(self, email: str, password: str | None = None, role: str = "viewer", sites=None, asset_sites=None,
               name: str = "", dept: str = "", actor: str = "", must_change: bool | None = None,
               pending: bool = False, dept_self: bool = False) -> dict:
        email = normalize_email(email, self.conf["domain"])
        if role not in ROLES:
            raise ValueError("권한은 viewer|operator|admin")
        issued = None
        if password is None:   # 임시 비밀번호 발급 → 첫 로그인 때 반드시 변경
            password = issued = temp_password()
        else:
            check_policy(password, email, self.conf)
        if must_change is None:
            must_change = issued is not None
        if self.exists(email):
            raise ValueError("이미 등록된 계정입니다")
        now = time.time()
        ver = self._make(email, password)
        with self.store._lock, self.store.db() as db:
            uidx = self.store._idx(email)
            u = db.execute("SELECT source FROM users WHERE login=?", (uidx,)).fetchone()
            if u and u["source"] not in ("email", "local"):
                raise ValueError("다른 로그인 방식으로 이미 등록된 ID 입니다")
            # 승인 대기 계정은 users.disabled=1 로 둔다 — 로그인 길목이 이미 그 값을 보므로,
            # 승인 절차를 **새 관문 하나 더 만드는 대신** 이미 막는 자리에 얹는다.
            db.execute("""INSERT INTO users(login,enc,role,sites,asset_sites,source,created,managed,disabled)
                          VALUES(?,?,?,?,?, 'email', ?, 1, ?)
                          ON CONFLICT(login) DO UPDATE SET role=excluded.role, sites=excluded.sites,
                              asset_sites=excluded.asset_sites, enc=excluded.enc, source='email',
                              disabled=excluded.disabled""",
                       (uidx, self.store._enc({"login": email, "name": name[:80], "dept": dept[:80], "email": email,
                                               **({"dept_self": True} if dept_self and dept.strip() else {})},
                                              "users", "enc", uidx),
                        role, json.dumps(sorted(set(sites or []))), json.dumps(sorted(set(asset_sites or []))), now,
                        1 if pending else 0))
            db.execute("INSERT INTO accounts(idx,email_enc,verifier,history,created,pw_changed,must_change,pending) "
                       "VALUES(?,?,?,?,?,?,?,?)",
                       (self._idx(email), self._enc_email(email), ver, "[]", now, now,
                        1 if must_change else 0, 1 if pending else 0))
        self.store.audit(actor or "cli", "", "account.create", email,
                         f"role={role}" + (" 승인대기" if pending else ""))
        return {"email": email, "password": issued, "must_change": bool(must_change), "pending": bool(pending)}

    def set_password(self, email: str, new: str, *, old: str | None = None, by_admin: bool = False, actor: str = "") -> None:
        email = normalize_email(email, self.conf["domain"])
        with self.store.db() as db:
            row = db.execute("SELECT * FROM accounts WHERE idx=?", (self._idx(email),)).fetchone()
        if not row:
            raise AuthError("등록되지 않은 계정입니다")
        if not by_admin:
            if old is None or not self._matches(email, old, row["verifier"]):
                raise AuthError("현재 비밀번호가 맞지 않습니다")
            if old == new:
                raise AuthError("이전과 다른 비밀번호로 정하십시오")
        check_policy(new, email, self.conf)
        try:
            hist = json.loads(row["history"] or "[]")
        except ValueError:
            hist = []
        for h in [row["verifier"]] + [bytes.fromhex(x) for x in hist]:
            try:
                same = self._matches(email, new, h)
            except AuthError:
                continue   # 예전 서버 키로 만든 이력은 비교를 건너뛴다(현재 비밀번호는 위에서 이미 확인)
            if same:
                raise AuthError(f"최근에 쓴 비밀번호 {self.conf['history']}개는 다시 쓸 수 없습니다")
        keep = self.conf["history"]
        hist = ([bytes(row["verifier"]).hex()] + hist)[:keep] if keep else []
        now = time.time()
        with self.store._lock, self.store.db() as db:
            db.execute("UPDATE accounts SET verifier=?, history=?, pw_changed=?, must_change=0, fails=0, locked_until=0 WHERE idx=?",
                       (self._make(email, new), json.dumps(hist), now, self._idx(email)))
            db.execute("DELETE FROM sessions WHERE login=?", (self.store._idx(email),))   # 비밀번호를 바꾸면 기존 접속은 모두 끊는다
        self.store.audit(actor or email, "", "account.password", email, "관리자 초기화" if by_admin else "본인 변경")

    def reset(self, email: str, actor: str = "") -> str:
        """관리자 초기화 — 임시 비밀번호를 돌려주고 첫 로그인 때 변경하게 한다."""
        email = normalize_email(email, self.conf["domain"])
        if not self.exists(email):
            raise ValueError("등록되지 않은 계정입니다")
        pw = temp_password()
        with self.store._lock, self.store.db() as db:
            db.execute("UPDATE accounts SET verifier=?, pw_changed=?, must_change=1, fails=0, locked_until=0 WHERE idx=?",
                       (self._make(email, pw), time.time(), self._idx(email)))
            db.execute("DELETE FROM sessions WHERE login=?", (self.store._idx(email),))
        self.store.audit(actor or "cli", "", "account.reset", email)
        return pw

    def unlock(self, email: str, actor: str = "") -> None:
        with self.store._lock, self.store.db() as db:
            if not db.execute("UPDATE accounts SET fails=0, locked_until=0 WHERE idx=?", (self._idx(email),)).rowcount:
                raise ValueError("등록되지 않은 계정입니다")
        self.store.audit(actor or "cli", "", "account.unlock", email)

    def delete(self, email: str, actor: str = "") -> None:
        with self.store._lock, self.store.db() as db:
            db.execute("DELETE FROM accounts WHERE idx=?", (self._idx(email),))
            db.execute("DELETE FROM recovery WHERE idx=?", (self._idx(email),))
        self.store.delete_user(email, actor or "cli")
        self.store.audit(actor or "cli", "", "account.delete", email)

    def list(self) -> list[dict]:
        users = {u["login"]: u for u in self.store.users()}
        now = time.time()
        out = []
        with self.store.db() as db:
            for r in db.execute("SELECT * FROM accounts ORDER BY created"):
                email = self._dec_email(r["email_enc"], r["idx"])
                u = users.get(email, {})
                exp = self.conf["expire_days"]
                out.append({"email": email, "name": u.get("name", ""), "dept": u.get("dept", ""), "dept_self": bool(u.get("dept_self")),
                            "role": u.get("role", "viewer"), "sites": u.get("sites", []), "asset_sites": u.get("asset_sites", []),
                            "disabled": bool(u.get("disabled")), "must_change": bool(r["must_change"]),
                            "pending": bool(r["pending"]),
                            "locked": r["locked_until"] > now, "locked_until": r["locked_until"], "fails": r["fails"],
                            "created": r["created"], "pw_changed": r["pw_changed"], "last_login": r["last_login"],
                            "expires_in": (None if not exp else round((r["pw_changed"] + exp * 86400 - now) / 86400, 1))})
        return out

    def count(self) -> int:
        with self.store.db() as db:
            return db.execute("SELECT count(*) FROM accounts").fetchone()[0]

    def list_one(self, email: str) -> dict | None:
        return next((a for a in self.list() if a["email"] == (email or "").lower()), None)

    # ── 비밀번호 분실: 재설정 코드 ──
    CODE_MINUTES = 30        # 코드 유효 시간
    CODE_TRIES = 5           # 코드 입력 허용 횟수

    @staticmethod
    def _clean_code(code: str) -> str:
        """입력 편의 — 대소문자·붙임표·공백은 무시하고 비교한다."""
        return re.sub(r"[^A-Za-z0-9]", "", code or "").upper()

    def issue_code(self, email: str, actor: str = "", minutes: int | None = None) -> dict:
        """관리자가 본인 확인 후 발급하는 1회용 재설정 코드. 코드는 비밀번호와 같은 방식(페퍼·scrypt·암호화)으로만 저장한다."""
        email = normalize_email(email, self.conf["domain"])
        if not self.exists(email):
            raise ValueError("등록되지 않은 계정입니다")
        mins = max(5, min(int(minutes or self.CODE_MINUTES), 1440))
        plain = recovery_code()
        now = time.time()
        with self.store._lock, self.store.db() as db:
            db.execute("INSERT INTO recovery(idx,code,created,expires,tries,issuer) VALUES(?,?,?,?,0,?) "
                       "ON CONFLICT(idx) DO UPDATE SET code=excluded.code, created=excluded.created, "
                       "expires=excluded.expires, tries=0, issuer=excluded.issuer",
                       (self._idx(email), self._make(email, "code:" + self._clean_code(plain)), now, now + mins * 60, (actor or "cli")[:80]))
        self.store.audit(actor or "cli", "", "account.code", email, f"유효 {mins}분")
        return {"email": email, "code": plain, "minutes": mins, "expires": now + mins * 60}

    def code_status(self, email: str) -> dict | None:
        with self.store.db() as db:
            r = db.execute("SELECT created,expires,tries,issuer FROM recovery WHERE idx=?", (self._idx(email),)).fetchone()
        if not r:
            return None
        return {"created": r["created"], "expires": r["expires"], "tries": r["tries"], "issuer": r["issuer"],
                "valid": r["expires"] > time.time() and r["tries"] < self.CODE_TRIES}

    def cancel_code(self, email: str, actor: str = "") -> None:
        with self.store._lock, self.store.db() as db:
            db.execute("DELETE FROM recovery WHERE idx=?", (self._idx(email),))
        self.store.audit(actor or "cli", "", "account.code.cancel", email)

    def reset_with_code(self, email_in: str, code: str, new_password: str, ip: str = "") -> None:
        """코드로 본인 확인 후 새 비밀번호를 정한다 — 성공하면 코드는 즉시 폐기되고 기존 접속도 모두 끊긴다."""
        email = normalize_email(email_in, self.conf["domain"])
        idx = self._idx(email)
        now = time.time()
        clean = self._clean_code(code)
        with self.store._lock, self.store.db() as db:   # 확인과 시도 증가를 한 번에(동시 요청이 겹쳐도 횟수가 새지 않게)
            db.execute("BEGIN IMMEDIATE")
            r = db.execute("SELECT * FROM recovery WHERE idx=?", (idx,)).fetchone()
            ok = bool(r) and r["expires"] > now and r["tries"] < self.CODE_TRIES and clean                 and self._matches(email, "code:" + clean, r["code"])
            if r and not ok:
                db.execute("UPDATE recovery SET tries=tries+1 WHERE idx=?", (idx,))
        if not r or r["expires"] <= now or r["tries"] >= self.CODE_TRIES:
            self._make(email, "code:" + (clean or "x"))    # 코드 유무를 응답 시간으로 알 수 없게 같은 비용을 치른다
            self.store.audit(email, ip, "account.code.fail", email, "코드 없음·만료·시도 초과", ok=False)
            raise AuthError("재설정 코드가 없거나 만료되었습니다 — 관리자에게 코드를 다시 요청하십시오")
        if not ok:
            left = self.CODE_TRIES - (r["tries"] + 1)
            self.store.audit(email, ip, "account.code.fail", email, f"코드 불일치(남은 시도 {max(left, 0)}회)", ok=False)
            if left <= 0:
                raise AuthError("코드 입력 횟수를 초과했습니다 — 관리자에게 코드를 다시 요청하십시오")
            raise AuthError(f"재설정 코드가 맞지 않습니다 (남은 시도 {left}회)")
        self.set_password(email, new_password, by_admin=True, actor=email)   # 정책 검사·이력·세션 정리는 기존 경로 그대로
        with self.store._lock, self.store.db() as db:
            db.execute("DELETE FROM recovery WHERE idx=?", (idx,))
            db.execute("UPDATE accounts SET must_change=0 WHERE idx=?", (idx,))
        self.store.audit(email, ip, "account.recover", email, "재설정 코드로 비밀번호 변경")

    # ── 직접 가입(2026-10-01) ──
    def signup_mode(self) -> str:
        return self.conf["signup"]

    def issue_signup_code(self, actor: str = "", minutes: int = 0, max_uses: int = 0) -> dict:
        """가입 코드 발급 — 하나를 여러 사람이 씁니다(쓴 횟수를 세고, 기한이 지나면 죽습니다).

        코드는 비밀번호와 같은 세 겹(페퍼·scrypt·저장 암호화)으로만 남깁니다 — DB 만 빠져나가도
        코드를 되돌릴 수 없습니다. 그래서 **발급한 그 자리에서만** 평문을 보여 줍니다.
        """
        mins = max(10, min(int(minutes or 1440), 43200))     # 10분 ~ 30일
        uses = max(0, min(int(max_uses or 0), 999))          # 0 = 횟수 제한 없음
        plain = recovery_code()
        now = time.time()
        with self.store._lock, self.store.db() as db:
            db.execute("INSERT INTO signup_code(id,code,created,expires,max_uses,uses,issuer) VALUES(1,?,?,?,?,0,?) "
                       "ON CONFLICT(id) DO UPDATE SET code=excluded.code, created=excluded.created, "
                       "expires=excluded.expires, max_uses=excluded.max_uses, uses=0, issuer=excluded.issuer",
                       (self._make(SIGNUP_KEY, "code:" + self._clean_code(plain)), now, now + mins * 60,
                        uses, (actor or "cli")[:80]))
        self.store.audit(actor or "cli", "", "signup.code", "",
                         f"유효 {mins}분" + (f" · {uses}회" if uses else " · 횟수 제한 없음"))
        return {"code": plain, "minutes": mins, "max_uses": uses, "expires": now + mins * 60}

    def cancel_signup_code(self, actor: str = "") -> None:
        with self.store._lock, self.store.db() as db:
            db.execute("DELETE FROM signup_code WHERE id=1")
        self.store.audit(actor or "cli", "", "signup.code.cancel", "")

    def signup_code_status(self) -> dict | None:
        with self.store.db() as db:
            r = db.execute("SELECT created,expires,max_uses,uses,issuer FROM signup_code WHERE id=1").fetchone()
        if not r:
            return None
        left = None if not r["max_uses"] else max(r["max_uses"] - r["uses"], 0)
        return {"created": r["created"], "expires": r["expires"], "max_uses": r["max_uses"], "uses": r["uses"],
                "issuer": r["issuer"], "left": left,
                "valid": r["expires"] > time.time() and (left is None or left > 0)}

    def _use_signup_code(self, code: str) -> None:
        """가입 코드 확인 — 확인과 '쓴 횟수 늘리기'를 **한 트랜잭션에서** 한다.

        따로 하면 같은 코드로 동시에 들어온 신청이 횟수 제한을 넘겨 버린다.
        """
        clean = self._clean_code(code)
        now = time.time()
        with self.store._lock, self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            r = db.execute("SELECT * FROM signup_code WHERE id=1").fetchone()
            alive = bool(r) and r["expires"] > now and (not r["max_uses"] or r["uses"] < r["max_uses"])
            ok = alive and bool(clean) and self._matches(SIGNUP_KEY, "code:" + clean, r["code"])
            if ok:
                db.execute("UPDATE signup_code SET uses=uses+1 WHERE id=1")
        if not r or not alive:
            self._make(SIGNUP_KEY, "code:" + (clean or "x"))    # 코드 유무를 응답 시간으로 알 수 없게
            raise AuthError("가입 코드가 없거나 기한이 지났습니다 — 관리자에게 코드를 다시 요청하십시오")
        if not ok:
            raise AuthError("가입 코드가 맞지 않습니다")

    def signup(self, email_in: str, password: str, name: str = "", dept: str = "", code: str = "",
               ip: str = "") -> dict:
        """사람이 자기 계정을 직접 만든다 — 권한은 **조회(viewer)** 로 고정한다.

        권한을 고르게 하지 않는다. 신청하는 사람이 자기 권한을 적어 내면 그것은 권한 체계가
        아니다 — 운영·관리자 권한은 관리자가 화면에서 올려 준다.
        """
        mode = self.conf["signup"]
        if mode == "off":
            raise AuthError("이 서버는 직접 가입을 받지 않습니다 — 관리자에게 계정 발급을 요청하십시오")
        email = normalize_email(email_in, self.conf["domain"])
        check_policy(password, email, self.conf)
        if self.exists(email):
            # 이미 있는 ID 라고 알려 주면 '누가 쓰는 서버인지' 가 조금 새 나간다. 그래도 가입
            # 화면에서는 알려 준다 — 모르면 같은 신청을 반복하고 관리자에게 전화가 간다.
            # 대신 시도 횟수 제한(서버 쪽 _too_many)으로 훑는 것을 막는다.
            raise AuthError("이미 등록된 ID 입니다 — 로그인하거나 [비밀번호를 잊으셨나요?] 를 이용하십시오")
        if mode == "code":
            self._use_signup_code(code)
        pending = mode == "approve"
        # 16차: 스스로 적은 부서는 '신청 부서' — 같은 부서 공유(원본·보고서)는 관리자가 승인하거나 사용자 편집에서
        # 저장해 확인한 뒤에만 켜진다. 아무 부서나 적어 그 부서 분석 원본을 보는 길을 막는다.
        r = self.create(email, password, "viewer", [], [], name, dept,
                        actor="(직접 가입)", must_change=False, pending=pending, dept_self=True)
        self.store.audit(email, ip, "signup", email, SIGNUP[mode])
        return {"email": email, "pending": pending, "mode": mode}

    def pending_list(self) -> list[dict]:
        return [a for a in self.list() if a["pending"]]

    def approve(self, email_in: str, actor: str = "", role: str = "viewer", sites=None, asset_sites=None) -> dict:
        """가입 신청 받아 주기 — 권한·사이트는 이때 관리자가 정한다."""
        email = normalize_email(email_in, self.conf["domain"])
        if role not in ROLES:
            raise ValueError("권한은 viewer|operator|admin")
        with self.store.db() as db:
            row = db.execute("SELECT pending FROM accounts WHERE idx=?", (self._idx(email),)).fetchone()
        if not row:
            raise ValueError("등록되지 않은 계정입니다")
        if not row["pending"]:
            raise ValueError("이미 승인된 계정입니다")
        with self.store._lock, self.store.db() as db:
            db.execute("UPDATE accounts SET pending=0 WHERE idx=?", (self._idx(email),))
            db.execute("UPDATE users SET disabled=0, role=?, sites=?, asset_sites=? WHERE login=?",
                       (role, json.dumps(sorted(set(sites or []))), json.dumps(sorted(set(asset_sites or []))),
                        self.store._idx(email)))
        self.store.audit(actor or "cli", "", "account.approve", email, f"role={role}")
        return {"ok": True, "email": email, "role": role}

    def reject(self, email_in: str, actor: str = "", why: str = "") -> None:
        """가입 신청 거절 — 승인 **대기 중인 것만** 지운다(쓰고 있던 계정을 실수로 지우지 않게)."""
        email = normalize_email(email_in, self.conf["domain"])
        with self.store.db() as db:
            row = db.execute("SELECT pending FROM accounts WHERE idx=?", (self._idx(email),)).fetchone()
        if not row:
            raise ValueError("등록되지 않은 계정입니다")
        if not row["pending"]:
            raise ValueError("이미 승인된 계정입니다 — 거절이 아니라 [사용 중지]·[삭제] 를 쓰십시오")
        self.delete(email, actor=actor)
        self.store.audit(actor or "cli", "", "account.reject", email, why[:120])

    # ── 로그인 ──
    def verify(self, email_in: str, password: str, ip: str = "") -> dict:
        email = normalize_email(email_in, self.conf["domain"])
        now = time.time()
        with self.store.db() as db:
            row = db.execute("SELECT * FROM accounts WHERE idx=?", (self._idx(email),)).fetchone()
            user = db.execute("SELECT * FROM users WHERE login=?", (self.store._idx(email),)).fetchone()
        if not row or not user:
            self._make(email, password)   # 계정 유무를 응답 시간으로 알 수 없게 같은 비용을 치른다
            raise AuthError("ID 또는 비밀번호가 맞지 않습니다")
        if user["disabled"] and not row["pending"]:
            raise AuthError("사용이 중지된 계정입니다 — 관리자에게 문의하십시오")
        if row["locked_until"] > now:
            raise AuthError(f"연속 실패로 잠긴 계정입니다 — {int((row['locked_until'] - now) / 60) + 1}분 뒤 다시 시도하거나 관리자에게 잠금 해제를 요청하십시오")
        if not self._matches(email, password, row["verifier"]):
            left = self.conf["max_fails"] - (row["fails"] + 1)
            with self.store._lock, self.store.db() as db:
                lock = now + self.conf["lock_minutes"] * 60 if left <= 0 else 0
                db.execute("UPDATE accounts SET fails=fails+1, locked_until=? WHERE idx=?", (lock, self._idx(email)))
            self.store.audit(email, ip, "login.fail", "email", f"연속 실패 {row['fails'] + 1}회", ok=False)
            if left <= 0:
                raise AuthError(f"연속 {self.conf['max_fails']}회 실패로 계정을 {self.conf['lock_minutes']}분간 잠갔습니다")
            raise AuthError(f"ID 또는 비밀번호가 맞지 않습니다 (남은 시도 {left}회)")
        if row["pending"]:
            # 비밀번호가 맞은 **뒤에** 알려 준다 — 남의 ID 로 '승인 대기인지' 를 떠볼 수 없게.
            with self.store._lock, self.store.db() as db:
                db.execute("UPDATE accounts SET fails=0, locked_until=0 WHERE idx=?", (self._idx(email),))
            self.store.audit(email, ip, "login.pending", "email", "승인 대기", ok=False)
            raise AuthError("가입 신청이 아직 승인되지 않았습니다 — 관리자 승인을 기다리고 있습니다")
        expired = bool(self.conf["expire_days"]) and now - (row["pw_changed"] or 0) > self.conf["expire_days"] * 86400
        with self.store._lock, self.store.db() as db:
            db.execute("UPDATE accounts SET fails=0, locked_until=0, last_login=? WHERE idx=?", (now, self._idx(email)))
            try:    # 옛 방식(v1 페퍼·낮은 비용)으로 저장된 값은 로그인에 성공한 이 순간 최신 방식으로 바꿔 둔다
                pr = self._params(email, row["verifier"])
                if pr.get("pep") != "sha512" or (pr.get("algo") == "scrypt" and int(pr.get("n", 0)) < 2 ** self.conf["scrypt_n"]):
                    db.execute("UPDATE accounts SET verifier=? WHERE idx=?", (self._make(email, password), self._idx(email)))
            except (AuthError, ValueError):
                pass
        u = self.store._user(user)
        u["must_change"] = bool(row["must_change"]) or expired
        u["change_reason"] = "처음 로그인" if row["must_change"] else ("비밀번호 사용 기간이 지났습니다" if expired else "")
        return u


def main(argv=None) -> int:
    """계정 관리 CLI — python -m logtriage.accounts --base <설치경로> <명령>"""
    import argparse
    import getpass
    ap = argparse.ArgumentParser(prog="python -m logtriage.accounts", description="LogTriage 이메일 계정 관리")
    ap.add_argument("--base", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="계정 등록(임시 비밀번호 발급)")
    a.add_argument("--email", required=True); a.add_argument("--role", default="viewer", choices=list(ROLES))
    a.add_argument("--name", default=""); a.add_argument("--dept", default="")
    a.add_argument("--sites", default=""); a.add_argument("--asset-sites", default="")
    a.add_argument("--password", default="", help="직접 정할 때(비우면 임시 비밀번호 발급)")
    for name, help_ in (("reset", "비밀번호 초기화(임시 발급)"), ("unlock", "잠금 해제"), ("delete", "계정 삭제"),
                        ("code", "비밀번호 분실 - 재설정 코드 발급"), ("code-cancel", "발급한 재설정 코드 취소")):
        s = sub.add_parser(name, help=help_); s.add_argument("--email", required=True)
        if name == "code":
            s.add_argument("--minutes", type=int, default=0, help="유효 시간(분, 기본 30)")
    sub.add_parser("list", help="계정 목록")
    sub.add_parser("pending", help="가입 신청(승인 대기) 목록")
    ap_ok = sub.add_parser("approve", help="가입 신청 승인")
    ap_ok.add_argument("--email", required=True)
    ap_ok.add_argument("--role", default="viewer", choices=list(ROLES))
    ap_ok.add_argument("--sites", default=""); ap_ok.add_argument("--asset-sites", default="")
    ap_no = sub.add_parser("reject", help="가입 신청 거절(계정 삭제)")
    ap_no.add_argument("--email", required=True); ap_no.add_argument("--why", default="")
    ap_sc = sub.add_parser("signup-code", help="가입 코드 발급")
    ap_sc.add_argument("--minutes", type=int, default=0, help="유효 시간(분, 기본 1440)")
    ap_sc.add_argument("--max-uses", type=int, default=0, help="쓸 수 있는 횟수(0=제한 없음)")
    sub.add_parser("signup-code-cancel", help="발급한 가입 코드 취소")
    ns = ap.parse_args(argv)
    try:
        return _run(ns)
    except (AuthError, ValueError) as e:   # 사용자에게는 한 줄 메시지만
        print("오류:", e)
        return 2


def _run(ns) -> int:
    from .auth import load_conf
    base = Path(ns.base)
    conf = load_conf(base) or {}
    store = AuthStore(base / "data" / "auth" / "auth.sqlite3")
    acc = Accounts(store, base, conf)
    if ns.cmd == "add":
        pw = ns.password or None
        if pw == "-":
            pw = getpass.getpass("비밀번호: ")
        r = acc.create(ns.email, pw, ns.role, [x for x in ns.sites.split(",") if x],
                       [x for x in ns.asset_sites.split(",") if x], ns.name, ns.dept)
        print(f"등록 완료: {r['email']} ({ns.role})")
        if r["password"]:
            print(f"임시 비밀번호: {r['password']}   ← 본인에게 안전하게 전달하고 첫 로그인 때 바꾸게 하십시오")
    elif ns.cmd == "reset":
        print("임시 비밀번호:", acc.reset(ns.email))
    elif ns.cmd == "unlock":
        acc.unlock(ns.email); print("잠금을 해제했습니다:", ns.email)
    elif ns.cmd == "delete":
        acc.delete(ns.email); print("삭제했습니다:", ns.email)
    elif ns.cmd == "code":
        r = acc.issue_code(ns.email, minutes=(ns.minutes or None))
        print(f"재설정 코드: {r['code']}   ({r['minutes']}분 안에 사용, 1회용)")
        print(f"  사용 방법: 로그인 화면 > [비밀번호 재설정] > {r['email']} 와 위 코드를 입력하고 새 비밀번호 지정")
        print("  본인 확인 후 전화·사내 메신저 등으로 직접 전달하십시오(메일 자동 발송 없음).")
    elif ns.cmd == "code-cancel":
        acc.cancel_code(ns.email); print("발급한 재설정 코드를 취소했습니다:", ns.email)
    elif ns.cmd == "pending":
        rows = acc.pending_list()
        if not rows:
            print("승인을 기다리는 가입 신청이 없습니다")
        for r in rows:
            print(f"{r['email']:<32} {r['name'] or '-':<10} {r['dept'] or '-':<14} 신청 {time.strftime('%Y-%m-%d %H:%M', time.localtime(r['created']))}")
        print(f"가입 방식: {acc.signup_mode()} — {SIGNUP[acc.signup_mode()]}")
    elif ns.cmd == "approve":
        r = acc.approve(ns.email, role=ns.role, sites=[x for x in ns.sites.split(",") if x],
                        asset_sites=[x for x in ns.asset_sites.split(",") if x])
        print(f"승인했습니다: {r['email']} ({r['role']})")
    elif ns.cmd == "reject":
        acc.reject(ns.email, why=ns.why); print("거절했습니다(계정 삭제):", ns.email)
    elif ns.cmd == "signup-code":
        r = acc.issue_signup_code(minutes=ns.minutes, max_uses=ns.max_uses)
        print(f"가입 코드: {r['code']}   ({r['minutes']}분 안에 사용"
              + (f", {r['max_uses']}명까지)" if r["max_uses"] else ", 횟수 제한 없음)"))
        print("  사용 방법: 로그인 화면 > [계정 만들기] 에서 이 코드를 함께 적습니다.")
        print("  가입 방식이 code 가 아니면 코드를 묻지 않습니다 — python -m logtriage.accounts 로는 방식을 바꿀 수 없고,")
        print("  관리자 화면 [계정] 탭에서 바꿉니다.")
    elif ns.cmd == "signup-code-cancel":
        acc.cancel_signup_code(); print("발급한 가입 코드를 취소했습니다")
    else:
        for r in acc.list():
            flags = " ".join(x for x in ("중지" if r["disabled"] else "", "잠김" if r["locked"] else "",
                                         "변경필요" if r["must_change"] else "") if x)
            print(f"{r['email']:<32} {r['role']:<9} {','.join(r['sites']) or '-':<14} 자산 {','.join(r['asset_sites']) or '-':<10} {flags}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
