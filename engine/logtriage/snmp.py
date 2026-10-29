"""SNMP v2c GET / GETNEXT 클라이언트 — 표준 라이브러리만(BER 직접 부호화). net-snmp 설치 없이 방화벽·스위치의
sysUpTime·CPU·메모리·인터페이스 카운터(IF-MIB)를 읽기 위한 최소 구현. v3(인증·암호화)는 미지원 — 장비 쪽에서 v2c 를 켜고
LogTriage 서버 IP 만 허용 호스트로 제한할 것. community 는 평문으로 전송되므로 관리망에서만 사용."""
from __future__ import annotations
import hmac
import os
import socket
import struct
import time

INTEGER, OCTET_STRING, NULL, OID, SEQUENCE = 0x02, 0x04, 0x05, 0x06, 0x30
IPADDRESS, COUNTER32, GAUGE32, TIMETICKS, OPAQUE, COUNTER64 = 0x40, 0x41, 0x42, 0x43, 0x44, 0x46
NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB = 0x80, 0x81, 0x82
GET_REQUEST, GET_NEXT, GET_RESPONSE = 0xA0, 0xA1, 0xA2
MAX_PACKET = 65535
WALK_MAX = 300           # OID 찾기(walk) 최대 항목
MAX_RATE = 1.25e9        # 10 Gbps — 이보다 큰 증가분은 카운터 리셋으로 간주

SYS_DESCR, SYS_UPTIME, SYS_NAME = '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0', '1.3.6.1.2.1.1.5.0'
IF_DESCR, IF_IN_OCTETS, IF_OUT_OCTETS = '1.3.6.1.2.1.2.2.1.2', '1.3.6.1.2.1.2.2.1.10', '1.3.6.1.2.1.2.2.1.16'
IF_NAME, IF_HC_IN, IF_HC_OUT = '1.3.6.1.2.1.31.1.1.1.1', '1.3.6.1.2.1.31.1.1.1.6', '1.3.6.1.2.1.31.1.1.1.10'


class SnmpError(Exception):
    pass


# ── BER 부호화 ──
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _len(len(payload)) + payload


def enc_int(v: int, tag: int = INTEGER) -> bytes:
    if v == 0:
        return tlv(tag, b'\x00')
    n = (v.bit_length() + 8) // 8
    return tlv(tag, v.to_bytes(n, 'big', signed=True))


def enc_uint(v: int, tag: int) -> bytes:  # Counter/Gauge/TimeTicks: 부호 없는 값(최상위 비트 1 이면 0x00 앞에 붙임)
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')
    if b[0] & 0x80:
        b = b'\x00' + b
    return tlv(tag, b)


def enc_str(s, tag: int = OCTET_STRING) -> bytes:
    return tlv(tag, s if isinstance(s, bytes) else str(s).encode('utf-8'))


def enc_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip().strip('.').split('.') if x != '']
    if len(parts) < 2 or parts[0] > 2 or parts[1] > 39:
        raise SnmpError(f'OID 형식 오류: {oid}')
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p < 0:
            raise SnmpError(f'OID 형식 오류: {oid}')
        chunk = [p & 0x7F]; p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F)); p >>= 7
        out.extend(reversed(chunk))
    return tlv(OID, bytes(out))


def enc_value(tag: int, v) -> bytes:
    if tag in (INTEGER,):
        return enc_int(int(v))
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return enc_uint(int(v), tag)
    if tag == OCTET_STRING:
        return enc_str(v)
    if tag == OID:
        return enc_oid(v)
    if tag == IPADDRESS:
        return tlv(IPADDRESS, socket.inet_aton(v))
    return tlv(tag, b'')   # NULL / noSuch*


def build_pdu(kind: int, community: str, reqid: int, varbinds) -> bytes:
    """varbinds: [(oid, (tag, value))...]; GET 요청은 값이 NULL"""
    vb = b''.join(tlv(SEQUENCE, enc_oid(oid) + enc_value(tag, val)) for oid, (tag, val) in varbinds)
    pdu = tlv(kind, enc_int(reqid) + enc_int(0) + enc_int(0) + tlv(SEQUENCE, vb))
    return tlv(SEQUENCE, enc_int(1) + enc_str(community) + pdu)


def build_get(community: str, oids, reqid: int, kind: int = GET_REQUEST) -> bytes:
    return build_pdu(kind, community, reqid, [(o, (NULL, None)) for o in oids])


def build_response(community: str, reqid: int, varbinds) -> bytes:  # 시험용 가짜 에이전트
    return build_pdu(GET_RESPONSE, community, reqid, varbinds)


# ── BER 복호화 ──
def _read_tlv(data: bytes, pos: int):
    if pos >= len(data):
        raise SnmpError('응답이 잘렸습니다')
    tag = data[pos]; pos += 1
    if pos >= len(data):
        raise SnmpError('응답이 잘렸습니다')
    ln = data[pos]; pos += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise SnmpError('길이 필드 오류')
        ln = int.from_bytes(data[pos:pos + n], 'big'); pos += n
    if pos + ln > len(data):
        raise SnmpError('응답이 잘렸습니다')
    return tag, data[pos:pos + ln], pos + ln


def dec_oid(b: bytes) -> str:
    if not b:
        return ''
    first = b[0]
    parts = [first // 40, first % 40] if first < 128 else [2, first - 80]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(v); v = 0
    return '.'.join(str(p) for p in parts)


def dec_value(tag: int, b: bytes):
    if tag == INTEGER:
        return int.from_bytes(b, 'big', signed=True) if b else 0
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return int.from_bytes(b, 'big', signed=False) if b else 0
    if tag == OCTET_STRING:
        try:
            s = b.decode('utf-8')
            if all(ch.isprintable() or ch in '\r\n\t' for ch in s):
                return s
        except UnicodeDecodeError:
            pass
        return '0x' + b.hex()
    if tag == OID:
        return dec_oid(b)
    if tag == IPADDRESS and len(b) == 4:
        return '.'.join(str(x) for x in b)
    if tag in (NULL, NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB):
        return None
    return '0x' + b.hex()


def parse_message(data: bytes):
    """→ (version, community, pdu_kind, reqid, errstat, erridx, [(oid, tag, value)...])"""
    tag, body, _ = _read_tlv(data, 0)
    if tag != SEQUENCE:
        raise SnmpError('SNMP 메시지가 아닙니다')
    pos = 0
    t, ver, pos = _read_tlv(body, pos); version = dec_value(t, ver)
    t, comm, pos = _read_tlv(body, pos); community = comm.decode('utf-8', 'replace')
    kind, pdu, pos = _read_tlv(body, pos)
    p = 0
    t, rid, p = _read_tlv(pdu, p); reqid = dec_value(t, rid)
    t, es, p = _read_tlv(pdu, p); errstat = dec_value(t, es)
    t, ei, p = _read_tlv(pdu, p); erridx = dec_value(t, ei)
    t, vbs, p = _read_tlv(pdu, p)
    out = []; q = 0
    while q < len(vbs):
        t, one, q = _read_tlv(vbs, q)
        a = 0
        t1, o, a = _read_tlv(one, a); t2, v, a = _read_tlv(one, a)
        out.append((dec_oid(o), t2, dec_value(t2, v)))
    return version, community, kind, reqid, errstat, erridx, out


ERRORS = {1: 'tooBig', 2: 'noSuchName', 3: 'badValue', 4: 'readOnly', 5: 'genErr', 6: 'noAccess', 13: 'resourceUnavailable', 16: 'authorizationError'}


def _exchange(host: str, port: int, community: str, oids, timeout: float, retries: int, kind: int = GET_REQUEST):
    fam = socket.AF_INET6 if ':' in host else socket.AF_INET
    last = 'timeout'; want = community.encode('utf-8')
    for _ in range(retries + 1):
        reqid = int.from_bytes(os.urandom(3), 'big') + 1
        pkt = build_get(community, oids, reqid, kind)
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            try:
                s.connect((host, port))          # 응답은 이 장비(주소·포트)에서 온 것만 받는다
                s.send(pkt)
                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise socket.timeout()
                    s.settimeout(remaining)
                    data = s.recv(MAX_PACKET)
                    try:
                        ver, comm, pk, rid, errstat, erridx, vbs = parse_message(data)
                    except SnmpError:
                        continue
                    if ver != 1 or pk != GET_RESPONSE or rid != reqid or not hmac.compare_digest(comm.encode('utf-8', 'replace'), want):
                        continue                 # 버전·community·요청 ID 가 모두 맞는 응답만 수락
                    if errstat:
                        raise SnmpError(f'장비 응답 오류: {ERRORS.get(errstat, errstat)} (항목 {erridx})')
                    return vbs
            except socket.timeout:
                last = f'응답 없음({timeout:.0f}s) — SNMP 미설정·community 불일치·허용 호스트 미등록·UDP {port} 차단 여부 확인'
            except ConnectionResetError:
                last = f'응답 없음 — UDP {port} 포트가 닫혀 있음(ICMP unreachable): 장비의 SNMP 서비스 상태 확인'
            except OSError as e:
                last = f'전송 오류: {e}'
    raise SnmpError(last)


def get(host: str, oids, community: str = 'public', port: int = 161, timeout: float = 2.0, retries: int = 1) -> dict:
    """여러 OID 를 한 번에 GET → {oid: value}(없는 항목은 None)"""
    oids = [o.strip().strip('.') for o in oids if o and o.strip()]
    if not oids:
        return {}
    if len(oids) > 32:
        raise SnmpError('한 번에 32개 OID 까지')
    return {o: v for o, _t, v in _exchange(host, port, community, oids, timeout, retries)}


def walk(host: str, base: str, community: str = 'public', port: int = 161, timeout: float = 2.0, max_entries: int = WALK_MAX, budget: float = 20.0) -> list:
    """GETNEXT 로 base 아래를 순회 → [(oid, value)...]. OID 가 커지지 않으면(순환·역행) 즉시 중단, 전체 budget 초 안에 끝낸다."""
    base = base.strip().strip('.'); cur = base; out = []; t0 = time.monotonic()
    def key(o): return tuple(int(x) for x in o.split('.'))
    while len(out) < max_entries:
        remaining = budget - (time.monotonic() - t0)
        if remaining <= 0.05:
            break
        vbs = _exchange(host, port, community, [cur], min(timeout, remaining), 0, GET_NEXT)
        if not vbs:
            break
        oid, tag, val = vbs[0]
        try:
            if tag == END_OF_MIB or not (oid == base or oid.startswith(base + '.')) or key(oid) <= key(cur):
                break
        except ValueError:
            break
        out.append((oid, val)); cur = oid
    return out
