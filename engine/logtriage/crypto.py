"""표준 라이브러리만으로 만든 암호 도구(2026-09-21) — 인터넷이 없는 설치 환경에서도 추가 패키지가 필요 없다.

· ChaCha20-Poly1305 AEAD (RFC 8439) 순수 파이썬 구현 — 계정 비밀번호 검증값을 '파일에 저장하기 전에' 한 번 더 암호화한다.
  (DB 파일만 빠져나가도 서버 키 파일이 없으면 비밀번호 대입 시도 자체가 불가능하다.)
· HKDF-SHA256 — 서버 키 파일 하나에서 용도별 키(페퍼용·암호화용)를 갈라 쓴다.
· 서버 키 파일(conf/secret.key): 처음 기동할 때 32바이트 무작위로 만들고 소유자만 읽도록 권한을 좁힌다. 백업·이전 시 반드시 함께 옮겨야 한다.

성능: 검증값(100바이트 남짓)만 암호화하므로 순수 파이썬으로도 로그인 1회당 1밀리초 미만이다.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
import struct
from pathlib import Path

__all__ = ["chacha20_poly1305_encrypt", "chacha20_poly1305_decrypt", "hkdf", "server_key", "derive", "AeadError",
           "KEY_VERSION", "aad", "backend"]

KEY_VERSION = 1      # 서버 키 세대 — 나중에 키를 바꿀 때 예전 자료를 구분해 풀기 위해 암호문마다 함께 적는다

# 설치 환경에 검증된 암호 라이브러리가 있으면 그것을 쓰고, 없으면 아래 순수 파이썬 구현(RFC 8439 시험값 통과)을 쓴다.
try:   # pragma: no cover - 설치 환경에 따라 갈림
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as _LibAead
except Exception:   # noqa: BLE001
    _LibAead = None


def backend() -> str:
    return "cryptography" if _LibAead else "stdlib"


def aad(table: str, column: str, row_key: str = "", version: int = 2) -> bytes:
    """암호문을 '어느 표·어느 칸·어느 행' 에 묶는 추가 인증 자료 —
    다른 사람 행으로 암호문을 옮겨 붙이는 공격을 막는다(GPT 교차 검토 2026-09-22)."""
    return f"lt/v{version}/{table}.{column}/{row_key}".encode("utf-8")

_MASK = 0xFFFFFFFF


class AeadError(ValueError):
    """복호화 실패(키가 다르거나 자료가 변조됨)."""


# ── ChaCha20 (RFC 8439 §2.3) ──────────────────────────────────────────────
def _rotl(v: int, n: int) -> int:
    v &= _MASK
    return ((v << n) | (v >> (32 - n))) & _MASK


def _quarter(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK; s[b] = _rotl(s[b] ^ s[c], 7)


def _block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
             *struct.unpack("<8I", key), counter & _MASK, *struct.unpack("<3I", nonce)]
    w = list(state)
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13); _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12); _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & _MASK for i in range(16)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20: 키 32바이트·nonce 12바이트")
    out = bytearray(len(data))
    for i in range(0, len(data), 64):
        ks = _block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out[i:i + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


# ── Poly1305 (RFC 8439 §2.5) ──────────────────────────────────────────────
def poly1305(key: bytes, msg: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305: 키 32바이트")
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        acc = (acc + int.from_bytes(chunk + b"\x01", "little")) % p
        acc = (acc * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * (-len(b) % 16)


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AEAD 암호화 — 결과는 암호문 + 16바이트 인증 태그. nonce 는 레코드마다 새로 뽑은 12바이트 난수를 쓴다(재사용 금지)."""
    if _LibAead is not None:
        return _LibAead(key).encrypt(nonce, plaintext, aad or None)
    otk = _block(key, 0, nonce)[:32]
    ct = chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct + poly1305(otk, mac_data)


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(data) < 16:
        raise AeadError("암호문이 너무 짧습니다")
    if _LibAead is not None:
        try:
            return _LibAead(key).decrypt(nonce, data, aad or None)
        except Exception as e:   # noqa: BLE001
            raise AeadError("복호화 실패 — 서버 키가 다르거나 자료가 변조되었습니다") from e
    ct, tag = data[:-16], data[-16:]
    otk = _block(key, 0, nonce)[:32]
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    if not hmac.compare_digest(poly1305(otk, mac_data), tag):
        raise AeadError("복호화 실패 — 서버 키가 다르거나 자료가 변조되었습니다")
    return chacha20(key, 1, nonce, ct)


# ── 키 관리 ───────────────────────────────────────────────────────────────
def hkdf(ikm: bytes, info: bytes, length: int = 32, salt: bytes = b"") -> bytes:
    """HKDF-SHA256 (RFC 5869) — 서버 키 하나에서 용도별 키를 갈라낸다."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out, t = b"", b""
    for i in range(1, (length + 31) // 32 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
    return out[:length]


def server_key(base: Path) -> bytes:
    """conf/secret.key (32바이트). 없으면 만들고 소유자만 읽도록 권한을 좁힌다."""
    p = Path(base) / "conf" / "secret.key"
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        tmp = p.with_suffix(".key.new")
        with open(tmp, "wb") as f:
            f.write(secrets.token_bytes(32))
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
        os.replace(tmp, p)
    key = p.read_bytes()   # 공백 제거 금지: 무작위 키는 앞뒤에 공백 바이트(0x20·0x0a 등)가 올 수 있다
    if len(key) < 32:
        raise ValueError(f"서버 키 파일이 손상되었습니다: {p} (32바이트 이상) — 백업본으로 되돌리십시오")
    try:
        if os.name != "nt" and (p.stat().st_mode & 0o077):
            os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def derive(base: Path, purpose: str, length: int = 32) -> bytes:
    return hkdf(server_key(base), b"logtriage/" + purpose.encode(), length)
