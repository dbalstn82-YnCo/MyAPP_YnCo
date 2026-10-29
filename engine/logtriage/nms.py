"""인프라 감시(NMS) — 등록한 IP 의 ICMP/TCP 가용성 수집기·저장소. 분석 DB(storage.py)와는 별도 SQLite."""
from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import unicodedata
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

LOG = logging.getLogger(__name__)
KINDS = ('server', 'network', 'security', 'storage', 'other')


def validate(value):
    if not isinstance(value, dict):
        raise ValueError('장비 설정은 객체여야 합니다')
    out = {}
    for name, limit in (('name', 100), ('group_name', 80), ('notes', 500)):
        text = value.get(name, '')
        if not isinstance(text, str) or len(text) > limit:
            raise ValueError(f'{name}: 최대 {limit}자')
        out[name] = text.strip()
    if not out['name']:
        raise ValueError('장비 이름이 필요합니다')
    try:
        address = ipaddress.ip_address(value.get('address', ''))
    except ValueError:
        raise ValueError('IPv4 또는 IPv6 주소를 입력하십시오 (호스트명 미지원)') from None
    if address.is_unspecified or address.is_multicast or str(address)=='255.255.255.255' or '%' in str(address):
        raise ValueError('단일 장비의 유효한 IP 주소가 필요합니다')
    out['address'] = str(address)
    for key, allowed in (('kind', KINDS), ('method', ('tcp','icmp'))):
        if value.get(key) not in allowed:
            raise ValueError(f'{key}: 허용되지 않은 값')
        out[key] = value[key]
    for key, default, low, high in (('port',443,1,65535),('interval',30,10,86400),
                                  ('timeout',3,1,10),('fail_limit',3,1,20),('recover_limit',2,1,20)):
        n = value.get(key, default)
        if type(n) is not int or not low <= n <= high:
            raise ValueError(f'{key}: {low}~{high} 정수')
        out[key] = n
    if type(value.get('enabled', True)) is not bool:
        raise ValueError('enabled는 boolean이어야 합니다')
    out['enabled'] = int(value.get('enabled',True))
    if value.get('metrics', 'none') not in METRICS:
        raise ValueError('metrics: none / local / agent / snmp 중 하나')
    out['metrics'] = value.get('metrics', 'none')
    if value.get('procs', 'top') not in PROCS_LEVELS:
        raise ValueError('procs: none / users / top 중 하나')
    out['procs'] = value.get('procs', 'top')   # 계정별 프로세스: none(안 함) / users(계정별 집계만) / top(집계 + 상위 프로세스)
    out['metrics_interval'] = metrics_interval(value.get('metrics_interval', 0))
    # SNMP v2c 조회 설정(방화벽·스위치 등 에이전트를 설치할 수 없는 장비) — metrics='snmp' 일 때만 의미
    comm = value.get('snmp_community', '')
    if not isinstance(comm, str) or len(comm) > 64 or any(ord(c) < 32 for c in comm):
        raise ValueError('snmp_community: 64자 이내 문자열')
    out['snmp_community'] = comm
    sp = value.get('snmp_port', 161)
    if type(sp) is not int or not 1 <= sp <= 65535:
        raise ValueError('snmp_port: 1~65535')
    out['snmp_port'] = sp
    for key in ('snmp_oid_cpu', 'snmp_oid_mem', 'snmp_oid_mem2'):
        o = value.get(key, '')
        if not isinstance(o, str) or len(o) > 128 or (o.strip() and not OID_RE.fullmatch(o.strip())):
            raise ValueError(f'{key}: 숫자와 점으로 된 OID (예: 1.3.6.1.4.1.2021.11.11.0)')
        out[key] = o.strip().strip('.')
    for key, allowed in (('snmp_cpu_mode', ('value', 'idle')), ('snmp_mem_mode', ('value', 'idle', 'used', 'avail'))):
        m = value.get(key, allowed[0])
        if m not in allowed:
            raise ValueError(f'{key}: {"/".join(allowed)} 중 하나')
        out[key] = m
    if out['snmp_mem_mode'] in ('used', 'avail') and out['snmp_oid_mem'] and not out['snmp_oid_mem2']:
        raise ValueError('메모리 해석이 used/avail 이면 전체(total) OID 도 필요합니다')
    ifx = value.get('snmp_ifindex', 0)
    if type(ifx) is not int or not 0 <= ifx <= 100000000:
        raise ValueError('snmp_ifindex: 0(사용 안 함) 또는 인터페이스 번호')
    out['snmp_ifindex'] = ifx
    if out['metrics'] == 'snmp' and not comm and not value.get('id'):
        raise ValueError('SNMP community 를 입력하십시오')
    return out


# ── 자원 사용률(CPU·메모리·디스크) 수집 — 이 서버 자체(표준 라이브러리만) ──
METRICS = ('none', 'local', 'agent', 'snmp')
METRICS_DEFAULT_SEC = {'local': 10, 'agent': 30, 'snmp': 30}   # metrics_interval=0(기본)일 때


def metrics_interval(n):
    """14차(마스터: '자원 사용률 수집을 설정할 수 있게'): 사용률 수집 주기(초). 0 = 기본, 그 밖은 5~3600.
    SNMP 는 장비 부하를 생각해 10초 미만을 받지 않는다(set_usage·Collector 에서 10 으로 올림)."""
    if type(n) is not int or not (n == 0 or 5 <= n <= 3600):
        raise ValueError('metrics_interval: 0(기본) 또는 5~3600 초')
    return n


def metrics_every(metrics, n):
    """실제 수집 주기(초) — 0 이면 방식별 기본값, SNMP 는 10초 이상."""
    sec = n or METRICS_DEFAULT_SEC.get(metrics, 30)
    return max(10, sec) if metrics == 'snmp' else sec
PROCS_LEVELS = ('none', 'users', 'top')
PROCS_MAX_JSON = 40000
OID_RE = re.compile(r'\.?\d+(\.\d+){1,60}')
SKIP_FSTYPES = {'tmpfs', 'devtmpfs', 'squashfs', 'overlay', 'proc', 'sysfs', 'cgroup', 'cgroup2', 'devpts', 'efivarfs', 'autofs', 'mqueue',
                'debugfs', 'tracefs', 'securityfs', 'pstore', 'bpf', 'configfs', 'fusectl', 'hugetlbfs', 'binfmt_misc', 'ramfs', 'rpc_pipefs',
                'nsfs', 'selinuxfs', 'iso9660', 'fuse.gvfsd-fuse', 'fuse.portal', 'fuse.lxcfs'}
_cpu_prev = {}


def _unescape_mount(s: str) -> str:
    """/proc/mounts 의 \\040(공백)·\\011(탭)·\\134(역슬래시) 등 8진 이스케이프 해제"""
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), s)


def _statvfs_usage(path: str):
    """df 와 같은 산식: used=(blocks-bfree), avail=bavail, pct=used/(used+avail). → (pct, used_gb, total_gb) 또는 None"""
    st = os.statvfs(path)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize; avail = st.f_bavail * st.f_frsize; total = st.f_blocks * st.f_frsize
    if used + avail <= 0 or total <= 0:
        return None
    return round(100.0 * used / (used + avail), 1), round(used / 2**30, 1), round(total / 2**30, 1)


def local_disks():
    """이 서버의 모든 고정 디스크 볼륨 사용률 → [{'path','pct','used_gb','total_gb'}]
    Linux: /proc/mounts 에서 /dev 장치·실제 파일시스템만(같은 장치는 첫 마운트만, 에이전트와 같은 규칙·df 와 같은 산식), Windows: 고정 드라이브 전부."""
    out = []; seen = set()
    try:
        if os.name == 'nt':
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if not mask & (1 << i):
                    continue
                root = f'{chr(65 + i)}:\\'
                if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:   # DRIVE_FIXED
                    continue
                try:
                    du = shutil.disk_usage(root)
                except OSError:
                    continue
                if du.total:
                    out.append({'path': root[:2], 'pct': round(100.0 * du.used / du.total, 1), 'used_gb': round(du.used / 2**30, 1), 'total_gb': round(du.total / 2**30, 1)})
        else:
            with open('/proc/mounts') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    dev, mp, fst = _unescape_mount(parts[0]), _unescape_mount(parts[1]), parts[2]
                    if not dev.startswith('/dev/') or fst in SKIP_FSTYPES or fst.startswith('fuse.') or mp.startswith(('/snap/', '/var/lib/docker/', '/run/', '/sys/', '/proc/', '/dev/')):
                        continue
                    if dev in seen:   # 같은 장치의 bind mount 는 첫 마운트만
                        continue
                    seen.add(dev)
                    try:
                        u = _statvfs_usage(mp)
                    except OSError:
                        continue
                    if u:
                        out.append({'path': mp, 'pct': u[0], 'used_gb': u[1], 'total_gb': u[2]})
                    if len(out) >= 32:
                        break
    except Exception:
        pass
    return out[:32]


def _cpu_times():
    """(busy, total) 누적 시간. Linux /proc/stat, Windows GetSystemTimes."""
    if os.name == 'nt':
        import ctypes
        idle, kern, user = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
        total = kern.value + user.value
        return total - idle.value, total
    with open('/proc/stat') as f:
        parts = f.readline().split()[1:]
    vals = [int(x) for x in parts][:8]  # user nice system idle iowait irq softirq steal (guest·guest_nice 는 user·nice 에 포함 → 제외)
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
    return sum(vals) - idle, sum(vals)


def local_metrics():
    """이 서버의 사용률(%) — cpu, mem, disk(루트/시스템 드라이브), load1(Linux). 첫 호출은 CPU 기준값만 잡는다."""
    out = {'cpu': None, 'mem': None, 'disk': None, 'load1': None, 'rx': None, 'tx': None, 'disks': None}
    try:
        busy, total = _cpu_times()
        prev = _cpu_prev.get('t')
        _cpu_prev['t'] = (busy, total)
        if prev and total > prev[1]:
            out['cpu'] = round(100.0 * (busy - prev[0]) / (total - prev[1]), 1)
    except Exception:
        pass
    try:
        if os.name == 'nt':
            import ctypes
            class MS(ctypes.Structure):
                _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong), ('ullTotalPhys', ctypes.c_ulonglong),
                            ('ullAvailPhys', ctypes.c_ulonglong), ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                            ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong), ('ullAvailExtendedVirtual', ctypes.c_ulonglong)]
            m = MS(); m.dwLength = ctypes.sizeof(MS); ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            out['mem'] = round(100.0 * (m.ullTotalPhys - m.ullAvailPhys) / max(1, m.ullTotalPhys), 1)
        else:
            info = {}
            with open('/proc/meminfo') as f:
                for line in f:
                    k, _, v = line.partition(':'); info[k] = int(v.split()[0])
            avail = info.get('MemAvailable', info.get('MemFree', 0) + info.get('Buffers', 0) + info.get('Cached', 0))
            out['mem'] = round(100.0 * (info['MemTotal'] - avail) / max(1, info['MemTotal']), 1)
    except Exception:
        pass
    try:  # 디스크: 모든 고정 볼륨 — disk 는 가장 높은 볼륨(임계치 판단 기준), disks 는 볼륨별 상세
        disks = local_disks()
        if disks:
            out['disk'] = max(d['pct'] for d in disks); out['disks'] = json.dumps(disks, ensure_ascii=False)
        else:
            root = os.environ.get('SystemDrive', 'C:') + '\\' if os.name == 'nt' else '/'
            du = shutil.disk_usage(root)
            out['disk'] = round(100.0 * du.used / max(1, du.total), 1)
    except Exception:
        pass
    try:
        if hasattr(os, 'getloadavg'):
            out['load1'] = round(os.getloadavg()[0], 2)
    except Exception:
        pass
    try:  # 계정별 프로세스(이 서버) — procs 모듈(Linux /proc · Windows API)
        from .procs import local_procs
        out['procs'] = local_procs(); out['pcount'] = out['procs']['total'] if out['procs'] else None
    except Exception:
        out['procs'] = None; out['pcount'] = None
    try:  # 네트워크 트래픽(bytes/s) — Linux: lo 제외 전체 인터페이스 합계의 증가분
        if os.name != 'nt':
            rx = tx = 0
            with open('/proc/net/dev') as f:
                for line in f.readlines()[2:]:
                    name, _, rest = line.partition(':')
                    if name.strip() == 'lo':
                        continue
                    v = rest.split(); rx += int(v[0]); tx += int(v[8])
            now = time.monotonic(); prev = _cpu_prev.get('net')
            _cpu_prev['net'] = (rx, tx, now)
            if prev and now > prev[2]:
                out['rx'] = round(max(0, rx - prev[0]) / (now - prev[2]), 1)
                out['tx'] = round(max(0, tx - prev[1]) / (now - prev[2]), 1)
    except Exception:
        pass
    return out


def validate_metrics(value):
    """에이전트 푸시 본문 검증 → {'cpu','mem','disk','load1','extra'}"""
    if not isinstance(value, dict):
        raise ValueError('객체 형식이 필요합니다')
    out = {}
    for k in ('cpu', 'mem', 'disk'):
        v = value.get(k)
        if v is None:
            out[k] = None; continue
        if type(v) not in (int, float) or not 0 <= v <= 100:
            raise ValueError(f'{k}: 0~100 숫자')
        out[k] = round(float(v), 1)
    v = value.get('load1')
    out['load1'] = round(float(v), 2) if type(v) in (int, float) and 0 <= v < 10000 else None
    for k in ('rx', 'tx'):  # bytes/s
        v = value.get(k)
        out[k] = round(float(v), 1) if type(v) in (int, float) and 0 <= v < 1e12 else None
    extra = {k: value[k] for k in ('hostname', 'os', 'disk_path', 'uptime') if isinstance(value.get(k), (str, int, float))}
    out['extra'] = json.dumps(extra, ensure_ascii=False)[:500]
    out['disks'] = None
    ds = value.get('disks')
    if isinstance(ds, list) and ds:   # 볼륨별 [{path,pct,used_gb,total_gb}] — 최대 32개
        clean = []
        for d in ds[:32]:
            if not isinstance(d, dict) or type(d.get('pct')) not in (int, float) or not 0 <= d['pct'] <= 100:
                raise ValueError('disks: [{path, pct(0~100), used_gb, total_gb}] 형식')
            item = {'path': str(d.get('path', ''))[:80], 'pct': round(float(d['pct']), 1)}
            for k in ('used_gb', 'total_gb'):
                if type(d.get(k)) in (int, float) and 0 <= d[k] < 1e9:
                    item[k] = round(float(d[k]), 1)
            clean.append(item)
        out['disks'] = json.dumps(clean, ensure_ascii=False)[:12000]   # 32 볼륨 × 긴 경로도 잘리지 않게
        if out.get('disk') is None:
            out['disk'] = max(d['pct'] for d in clean)
    out['procs'] = clean_procs(value.get('procs'))
    out['pcount'] = out['procs']['total'] if out['procs'] else None
    return out


def clean_procs(p):
    """에이전트 procs 객체 정제 — 계정 40개·상위 20개·이름 48자, 정수/유한값/범위 검사, 제어문자·bidi 문자 제거. 형식이 아니면 None(사용률 저장은 계속)."""
    import math, re
    if not isinstance(p, dict):
        return None
    def uint(v, hi):   # bool 제외 정수(정수값 float 허용), 0 이상
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v != int(v) or not 0 <= v <= hi:
            return None
        return int(v)
    def num(v, hi):
        return round(float(v), 1) if not isinstance(v, bool) and isinstance(v, (int, float)) and math.isfinite(v) and 0 <= v < hi else 0.0
    def txt(v, n):
        return re.sub(r'[\x00-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]', ' ', str(v))[:n].strip() or '?'
    total = uint(p.get('total'), 10 ** 7)
    if total is None:
        return None
    users = []
    for u in (p.get('users') or [])[:41]:
        if isinstance(u, dict) and isinstance(u.get('user'), str):
            c = uint(u.get('count'), 10 ** 7)
            if c is not None:
                users.append({'user': txt(u['user'], 64), 'count': c, 'cpu': num(u.get('cpu'), 100000), 'mem_mb': num(u.get('mem_mb'), 10 ** 9)})
    top = []
    for r in (p.get('top') or [])[:20]:
        if isinstance(r, dict) and isinstance(r.get('name'), str):
            pid = uint(r.get('pid'), 2 ** 31)
            if pid is not None:
                top.append({'pid': pid, 'user': txt(r.get('user', '?'), 64), 'name': txt(r['name'], 48), 'cpu': num(r.get('cpu'), 100000), 'mem_mb': num(r.get('mem_mb'), 10 ** 9)})
    return {'total': total, 'known': uint(p.get('known'), 10 ** 7), 'failed': uint(p.get('failed'), 10 ** 7) or 0,
            'ncpu': uint(p.get('ncpu'), 4096), 'users': users, 'top': top}


# ── SNMP v2c 조회(방화벽·스위치 등) ──
def snmp_metrics(target: dict, prev: dict) -> dict:
    """target 의 SNMP 설정으로 cpu/mem/rx/tx 를 읽는다. prev 는 {'rx','tx','at'} 이전 카운터(트래픽 증가분 계산).
    실패 시 SnmpError. 값이 없는 OID 는 None."""
    from . import snmp
    oids = [snmp.SYS_UPTIME]
    cpu_o, mem_o, mem2_o = target.get('snmp_oid_cpu') or '', target.get('snmp_oid_mem') or '', target.get('snmp_oid_mem2') or ''
    ifx = int(target.get('snmp_ifindex') or 0)
    for o in (cpu_o, mem_o, mem2_o):
        if o:
            oids.append(o)
    if ifx:
        oids += [f'{snmp.IF_HC_IN}.{ifx}', f'{snmp.IF_HC_OUT}.{ifx}', f'{snmp.IF_IN_OCTETS}.{ifx}', f'{snmp.IF_OUT_OCTETS}.{ifx}', f'{snmp.IF_DESCR}.{ifx}']
    vals = snmp.get(target['address'], oids, target.get('snmp_community') or 'public', int(target.get('snmp_port') or 161), timeout=2.0, retries=1)
    out = {'cpu': None, 'mem': None, 'disk': None, 'load1': None, 'rx': None, 'tx': None, 'disks': None}
    def num(o):
        v = vals.get(o)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, str):
            try:
                return float(v.strip().rstrip('%'))
            except ValueError:
                return None
        return None
    if cpu_o:
        v = num(cpu_o)
        if v is not None:
            v = 100.0 - v if target.get('snmp_cpu_mode') == 'idle' else v
            out['cpu'] = round(max(0.0, min(100.0, v)), 1)
    if mem_o:
        v = num(mem_o); mode = target.get('snmp_mem_mode') or 'value'
        if v is not None:
            if mode in ('used', 'avail'):
                total = num(mem2_o) if mem2_o else None
                v = (100.0 * v / total if mode == 'used' else 100.0 * (1 - v / total)) if total else None
            elif mode == 'idle':
                v = 100.0 - v
            if v is not None:
                out['mem'] = round(max(0.0, min(100.0, v)), 1)
    now = time.monotonic(); extra = {'snmp': 'ok'}
    up = vals.get(snmp.SYS_UPTIME)
    if isinstance(up, int):
        extra['uptime'] = up // 100
    if ifx:
        rx = vals.get(f'{snmp.IF_HC_IN}.{ifx}'); tx = vals.get(f'{snmp.IF_HC_OUT}.{ifx}'); wrap = 2**64
        if not isinstance(rx, int) or not isinstance(tx, int):
            rx = vals.get(f'{snmp.IF_IN_OCTETS}.{ifx}'); tx = vals.get(f'{snmp.IF_OUT_OCTETS}.{ifx}'); wrap = 2**32
        ifname = vals.get(f'{snmp.IF_DESCR}.{ifx}')
        if isinstance(ifname, str):
            extra['ifname'] = ifname[:60]
        if isinstance(rx, int) and isinstance(tx, int):
            reset = not prev or prev.get('wrap') != wrap
            if prev and isinstance(up, int) and isinstance(prev.get('up'), int) and up < prev['up']:
                reset = True   # 장비 재기동 → 카운터 기준 다시 잡음
            if prev and isinstance(ifname, str) and prev.get('ifname') not in (None, ifname):
                reset = True   # ifIndex 가 다른 인터페이스를 가리키게 됨
                extra['if_error'] = f'ifIndex {ifx} 인터페이스가 {prev.get("ifname")} → {ifname} 로 바뀜'
            if not reset and now > prev['at']:
                dt = now - prev['at']
                if wrap == 2**32:   # 32비트 카운터는 한 번의 wrap 을 보정
                    drx = (rx - prev['rx']) % wrap; dtx = (tx - prev['tx']) % wrap
                else:
                    drx = rx - prev['rx']; dtx = tx - prev['tx']
                if drx >= 0 and dtx >= 0 and drx / dt <= snmp.MAX_RATE and dtx / dt <= snmp.MAX_RATE:
                    out['rx'] = round(drx / dt, 1); out['tx'] = round(dtx / dt, 1)
            prev.clear(); prev.update({'rx': rx, 'tx': tx, 'at': now, 'wrap': wrap, 'up': up if isinstance(up, int) else None, 'ifname': ifname if isinstance(ifname, str) else None})
        else:
            extra['if_error'] = f'ifIndex {ifx} 카운터 없음'
    out['extra'] = json.dumps(extra, ensure_ascii=False)[:500]
    return out


def probe(target):
    start = time.monotonic()
    if target['method']=='tcp':
        try:
            with socket.create_connection((target['address'],target['port']),target['timeout']):
                return 'up', round((time.monotonic()-start)*1000,2), 'TCP 연결 성공'
        except (TimeoutError,ConnectionError,OSError) as exc:
            return 'down', None, f'TCP 연결 실패: {type(exc).__name__}'
    ping = shutil.which('ping')
    if not ping:
        return 'error',None,'수집기 설정 오류: ping 실행 파일 없음'
    if os.name=='nt':
        args=[ping,'-n','1','-w',str(target['timeout']*1000),target['address']]
    else:
        args=[ping,'-n','-c','1','-W',str(target['timeout']),target['address']]
    try:
        result=subprocess.run(args,capture_output=True,timeout=target['timeout']+2,
                              env={**os.environ,'LC_ALL':'C'},
                              creationflags=0x08000000 if os.name=='nt' else 0)
        raw=result.stdout+result.stderr
        try:
            output=raw.decode('utf-8')
        except UnicodeDecodeError:  # Windows 한국어 콘솔(cp949) — '시간<1ms'
            import locale
            output=raw.decode(locale.getpreferredencoding(False) or 'cp949','replace')
        if result.returncode==0:
            rtt=re.search(r'(?:time|시간)[=<]\s*([\d.]+)\s*ms',output,re.I)  # Linux(LC_ALL=C) 'time=' / Windows 한국어 '시간='
            return 'up',float(rtt[1]) if rtt else None,'ICMP 응답 수신'
        if os.name!='nt' and result.returncode!=1:
            return 'error',None,'수집기 오류: ping 권한/실행 환경 확인'
        return 'down',None,'ICMP 응답 없음 (차단 또는 경로 장애 가능)'
    except subprocess.TimeoutExpired:
        return 'error',None,'수집기 오류: ping 프로세스 실행 시간 초과'
    except OSError:
        return 'error',None,'수집기 오류: ping 실행 실패'


class Store:
    # SNMP community 는 장비 접속 비밀값이다 — DB 에 평문으로 두지 않고 서버 키로 암호화해 보관한다(2026-09-22).
    SEC_PREFIX = 'enc1:'

    def __init__(self,path):
        self.path=Path(path)
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self._ckey=None
        try:      # <설치경로>/data/nms/nms.sqlite3 → 설치경로
            from .crypto import derive
            base=self.path.parents[2] if len(self.path.parents)>2 else self.path.parent
            self._ckey=derive(base,'nms-secret')
        except Exception as e:      # 키를 못 만들면 기능은 살리고 평문으로 둔다(기동 실패보다 낫다)
            LOG.warning('NMS 비밀값 암호화 키를 준비하지 못했습니다(%s) — community 가 평문으로 저장됩니다',e)

        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS targets(
              id TEXT PRIMARY KEY,name TEXT,address TEXT,kind TEXT,group_name TEXT,notes TEXT,
              method TEXT,port INTEGER,interval INTEGER,timeout INTEGER,fail_limit INTEGER,recover_limit INTEGER,
              enabled INTEGER,revision INTEGER DEFAULT 1,status TEXT DEFAULT 'unknown',
              failures INTEGER DEFAULT 0,successes INTEGER DEFAULT 0,last_check REAL,
              latency REAL,detail TEXT DEFAULT '',next_due REAL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS samples(
              id INTEGER PRIMARY KEY, target_id TEXT,at REAL,result TEXT,latency REAL,detail TEXT,
              FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS sample_time ON samples(target_id,at);
            CREATE TABLE IF NOT EXISTS alerts(
              id INTEGER PRIMARY KEY,target_id TEXT,opened REAL,closed REAL,close_reason TEXT,
              acknowledged INTEGER DEFAULT 0,
              FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
            CREATE UNIQUE INDEX IF NOT EXISTS active_alert ON alerts(target_id) WHERE closed IS NULL;
            CREATE TABLE IF NOT EXISTS metrics(
              id INTEGER PRIMARY KEY,target_id TEXT,at REAL,cpu REAL,mem REAL,disk REAL,load1 REAL,extra TEXT,rx REAL,tx REAL,
              FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS metrics_time ON metrics(target_id,at);
            CREATE INDEX IF NOT EXISTS sample_at ON samples(at);
            CREATE INDEX IF NOT EXISTS metrics_at ON metrics(at);
            ''')
            cols = {r[1] for r in db.execute('PRAGMA table_info(targets)')}
            if 'metrics' not in cols:  # 2026-09-14 이전 DB
                db.execute("ALTER TABLE targets ADD COLUMN metrics TEXT DEFAULT 'none'")
            mcols = {r[1] for r in db.execute('PRAGMA table_info(metrics)')}
            for c, ddl in (('rx', 'REAL'), ('tx', 'REAL'), ('disks', 'TEXT'), ('pcount', 'INTEGER')):
                if c not in mcols:
                    db.execute(f'ALTER TABLE metrics ADD COLUMN {c} {ddl}')
            db.execute('''CREATE TABLE IF NOT EXISTS procs(target_id TEXT PRIMARY KEY, at REAL, data TEXT,
                          FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE)''')   # 항목별 최신 프로세스 상세 1건(이력은 metrics.pcount 만)
            for c, ddl in (('snmp_community', "TEXT DEFAULT ''"), ('snmp_port', 'INTEGER DEFAULT 161'), ('snmp_oid_cpu', "TEXT DEFAULT ''"),
                           ('snmp_oid_mem', "TEXT DEFAULT ''"), ('snmp_oid_mem2', "TEXT DEFAULT ''"), ('snmp_cpu_mode', "TEXT DEFAULT 'value'"),
                           ('snmp_mem_mode', "TEXT DEFAULT 'value'"), ('snmp_ifindex', 'INTEGER DEFAULT 0'), ('procs', "TEXT DEFAULT 'top'"),
                           ('metrics_interval', 'INTEGER DEFAULT 0')):   # 14차: 사용률 수집 주기(초) — 0 = 기본(자체 10 · 에이전트/SNMP 30)
                if c not in cols:
                    db.execute(f'ALTER TABLE targets ADD COLUMN {c} {ddl}')
            db.execute('CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)')
            db.execute('''CREATE TABLE IF NOT EXISTS agent_tokens(
                          th TEXT PRIMARY KEY, target_id TEXT, label TEXT, created REAL, expires REAL,
                          last_used REAL, uses INTEGER DEFAULT 0, revoked INTEGER DEFAULT 0, created_by TEXT,
                          FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE)''')
            db.execute('CREATE INDEX IF NOT EXISTS agent_tok_target ON agent_tokens(target_id)')
            # 19차 간편 설치: 1회용 등록 코드(원문은 저장하지 않음 — 해시만). 대상 하나에 묶이고 30분·1회·틀린 시도 5번이면 폐기
            db.execute('''CREATE TABLE IF NOT EXISTS agent_enroll(
                          ch TEXT PRIMARY KEY, target_id TEXT, created REAL, expires REAL, used REAL, used_from TEXT,
                          fails INTEGER DEFAULT 0, created_by TEXT,
                          FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE)''')
        tok = self.path.with_name('agent_token.txt')
        if not tok.exists():
            tok.write_text(secrets.token_hex(16), encoding='utf-8')
        try:
            os.chmod(tok, 0o600)  # 토큰 파일은 서비스 계정만 읽기
        except OSError:
            pass
        self.agent_token = tok.read_text(encoding='utf-8').strip()
        with self.db() as db:      # 공용 토큰을 폐기했으면 더 이상 받지 않는다
            r = db.execute("SELECT value FROM settings WHERE key='legacy_token_off'").fetchone()
        if r and r['value'] == '1':
            self.agent_token = ''
        self._last_push = {}
        self.agent_rejects = {}   # 14차: 거절한 에이전트 보고(출발 주소·호스트명별 최신 1건, 메모리에만) — '자원 사용률이 안 들어온다'의 원인을 화면에

    REJECTS_MAX = 30

    def note_reject(self, address, hostname, reason, target_id='', authed=True):
        """14차(마스터: '응답 시간만 수집되고 자원 사용률이 안 된다'): 에이전트가 보냈는데 받지 않은 보고를 기억한다 — 토큰 불일치·
        주소/호스트명이 등록 항목과 다름 등. 화면이 '어디서 온 보고를 왜 거절했는지·무엇을 고치면 되는지'를 보여 준다.
        GPT 105차: 토큰이 맞지 않는 요청(출처 확인 안 됨)은 authed=False — 호스트명을 싣지 않고, 개수가 넘치면 이것부터 버린다
        (토큰 없이 31곳을 보내 진짜 원인을 밀어내지 못하게). 글자는 제어·방향 제어 문자를 지운다(화면 이름 위조 방지)."""
        def clean(v, n):
            return ''.join(c for c in str(v or '') if unicodedata.category(c) not in ('Cc', 'Cf'))[:n]
        k = (clean(address, 64), clean(hostname, 64) if authed else '')
        self.agent_rejects.pop(k, None)
        self.agent_rejects[k] = {'at': time.time(), 'address': k[0], 'hostname': k[1], 'reason': clean(reason, 240),
                                 'target_id': clean(target_id, 64), 'authed': bool(authed)}
        while len(self.agent_rejects) > self.REJECTS_MAX:
            drop = next((kk for kk, v in self.agent_rejects.items() if not v['authed']), None) or next(iter(self.agent_rejects))
            self.agent_rejects.pop(drop)

    def recent_rejects(self, seconds=3600):
        lo = time.time() - seconds
        return sorted((dict(v) for v in list(self.agent_rejects.values()) if v['at'] >= lo), key=lambda v: -v['at'])

    def clear_reject(self, address, hostname):
        self.agent_rejects.pop((str(address or '')[:64], str(hostname or '')[:64]), None)

    @staticmethod
    def _sc_aad(target_id):
        """암호문을 '어느 대상의 community 인지' 까지 묶는다 — 다른 행으로 옮겨 붙이지 못하게."""
        return ('lt/nms/community/' + str(target_id or '-')).encode('utf-8')

    def _sc_enc(self,text,target_id=''):
        """community 평문 → 저장형.

        암호화할 수 없으면 평문으로 되돌아가지 않고 거절한다 — 한 번 평문으로 새면 DB 에 계속 쌓인다."""
        if not text or str(text).startswith(self.SEC_PREFIX):
            return text or ''
        if not self._ckey:
            raise ValueError('서버 키를 준비하지 못해 SNMP community 를 안전하게 저장할 수 없습니다 '
                             '— conf/secret.key 권한·경로를 확인한 뒤 다시 시도하십시오')
        try:
            from .crypto import chacha20_poly1305_encrypt
            n=secrets.token_bytes(12)     # 레코드마다 새 난수 — 절대 재사용하지 않는다
            blob=n+chacha20_poly1305_encrypt(self._ckey,n,str(text).encode('utf-8'),self._sc_aad(target_id))
            return self.SEC_PREFIX+base64.b64encode(blob).decode('ascii')
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f'SNMP community 암호화에 실패했습니다({e}) — 평문으로 저장하지 않습니다') from None

    def _sc_dec(self,stored,target_id=''):
        """저장형 → community 평문. 예전에 평문으로 들어간 값도 읽되, 읽는 김에 암호문으로 바꿔 둔다."""
        if not stored:
            return ''
        if not str(stored).startswith(self.SEC_PREFIX):
            self._sc_migrate(target_id,str(stored))    # 예전 평문 — 이번 기회에 암호문으로
            return stored
        if not self._ckey:
            return ''
        try:
            from .crypto import chacha20_poly1305_decrypt
            blob=base64.b64decode(str(stored)[len(self.SEC_PREFIX):])
            out=chacha20_poly1305_decrypt(self._ckey,blob[:12],blob[12:],self._sc_aad(target_id))
            if out is None and target_id:      # 예전 판(대상 정보를 묶지 않은 암호문)도 읽어 준다
                out=chacha20_poly1305_decrypt(self._ckey,blob[:12],blob[12:],b'lt/nms/community')
                if out is not None:
                    self._sc_migrate(target_id,out.decode('utf-8'))
            return out.decode('utf-8') if out is not None else ''
        except Exception as e:
            LOG.warning('community 복호 실패(%s) — 서버 키(conf/secret.key)가 바뀌었는지 확인하십시오',e); return ''

    def _sc_migrate(self,target_id,plain):
        """평문·예전 형식으로 남아 있던 community 를 조용히 지금 형식으로 바꿔 저장한다."""
        if not target_id or not plain or not self._ckey:
            return
        try:
            enc=self._sc_enc(plain,target_id)
            with self.db() as db:
                db.execute('UPDATE targets SET snmp_community=? WHERE id=?',(enc,target_id))
            LOG.info('SNMP community 를 암호화 형식으로 옮겼습니다 (대상 %s)',target_id)
        except Exception as e:
            LOG.warning('community 이관 실패(%s)',e)

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.row_factory=sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self,value):
        data=validate(value)
        id=value.get('id')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if id:
                if not isinstance(id,str) or not db.execute('SELECT 1 FROM targets WHERE id=?',(id,)).fetchone():
                    raise ValueError('장비가 없습니다')
                if not data['snmp_community']:   # 편집 시 community 를 비워 두면 기존 값 유지(화면에는 노출하지 않음)
                    data['snmp_community']=db.execute('SELECT snmp_community FROM targets WHERE id=?',(id,)).fetchone()[0] or ''
                if data['metrics']=='snmp' and not data['snmp_community']:
                    raise ValueError('SNMP community 를 입력하십시오')
                data['snmp_community']=self._sc_enc(data['snmp_community'],id)
                fields=','.join(k+'=?' for k in data)
                db.execute(f'UPDATE targets SET {fields},revision=revision+1,status=?,failures=0,successes=0,next_due=0,last_check=NULL,latency=NULL,detail=? WHERE id=?',
                           (*data.values(),'unknown' if data['enabled'] else 'paused','설정 변경 후 재확인 대기',id))
                db.execute("UPDATE alerts SET closed=?,close_reason='configuration changed' WHERE target_id=? AND closed IS NULL",(time.time(),id))
            else:
                if db.execute('SELECT count(*) FROM targets').fetchone()[0]>=500:
                    raise ValueError('시험 버전 등록 한도: 500개 감시 항목')
                if data['metrics']=='snmp' and not data['snmp_community']:
                    raise ValueError('SNMP community 를 입력하십시오')
                id=uuid.uuid4().hex
                data['snmp_community']=self._sc_enc(data['snmp_community'],id)
                fields=','.join(data)
                placeholders=','.join('?' for _ in data)
                db.execute(f'INSERT INTO targets(id,{fields},status) VALUES(?,{placeholders},?)',
                           (id,*data.values(),'unknown' if data['enabled'] else 'paused'))
        return {'id':id}

    def delete(self,id):
        with self.db() as db:
            db.execute('DELETE FROM targets WHERE id=?',(id,))

    def record(self,target,result,latency,detail,now=None):
        now=time.time() if now is None else now
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM targets WHERE id=?',(target['id'],)).fetchone()
            if not current or not current['enabled'] or current['revision']!=target['revision']:
                return
            status=current['status']
            failures=current['failures']+1 if result=='down' else 0
            successes=current['successes']+1 if result=='up' else 0
            active=db.execute('SELECT id FROM alerts WHERE target_id=? AND closed IS NULL',(target['id'],)).fetchone()
            if result=='error':
                status='unknown'  # collector error does not prove device failure/recovery
            elif result=='down':
                status='down' if active or failures>=current['fail_limit'] else 'suspect'
                if status=='down' and not active:
                    db.execute('INSERT INTO alerts(target_id,opened) VALUES(?,?)',(target['id'],now))
            elif active and successes<current['recover_limit']:
                status='recovering'
            else:
                status='up'
                if active:
                    db.execute("UPDATE alerts SET closed=?,close_reason='recovered' WHERE id=?",(now,active['id']))
            db.execute('UPDATE targets SET status=?,failures=?,successes=?,last_check=?,latency=?,detail=?,next_due=? WHERE id=?',
                       (status,failures,successes,now,latency,detail,now+current['interval'],target['id']))
            db.execute('INSERT INTO samples(target_id,at,result,latency,detail) VALUES(?,?,?,?,?)',
                       (target['id'],now,result,latency,detail))

    def due(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT * FROM targets WHERE enabled=1 AND next_due<=? ORDER BY next_due LIMIT 500',(time.time(),))]

    def snapshot(self):
        with self.db() as db:
            targets=[dict(r) for r in db.execute('SELECT * FROM targets ORDER BY kind,name')]
            alerts=[dict(r) for r in db.execute('SELECT a.*,t.name,t.address,t.kind FROM alerts a JOIN targets t ON t.id=a.target_id ORDER BY a.opened DESC LIMIT 200')]
            active=db.execute('SELECT count(*) FROM alerts WHERE closed IS NULL').fetchone()[0]
        now=time.time()
        latest=self.latest_metrics(); settings=self.get_settings(); alarms=[]; psum=self.procs_summary()
        for t in targets:
            t['stale']=bool(t['enabled'] and t['last_check'] and now-t['last_check']>max(t['interval']*3,60))
            t['snmp_has_community']=bool(t.get('snmp_community')); t['snmp_community']=''   # 비밀값은 화면에 내보내지 않음
            m=latest.get(t['id'])
            u=None
            if m:
                u={'at':m['at'],'cpu':m['cpu'],'mem':m['mem'],'disk':m['disk'],'load1':m['load1'],'rx':m['rx'],'tx':m['tx'],'stale':now-m['at']>180,'disks':None,'error':None,
                   'pcount':m.get('pcount'),'pusers':(psum.get(t['id']) or {}).get('users'),'pknown':(psum.get(t['id']) or {}).get('known')}
                try:
                    u['disks']=json.loads(m['disks']) if m.get('disks') else None
                except (TypeError, ValueError):
                    pass
                try:
                    ex=json.loads(m['extra']) if m.get('extra') else {}
                    if isinstance(ex, dict):
                        u['error']=ex.get('error'); u['uptime']=ex.get('uptime'); u['if_error']=ex.get('if_error')
                except (TypeError, ValueError):
                    pass
                if t['enabled'] and not u['stale'] and t.get('metrics')!='none':   # 임계치 초과 → 알림 후보(화면이 팝업·소리·브라우저 알림)
                    for k,label in (('cpu','CPU'),('mem','메모리'),('disk','디스크')):
                        v=u.get(k); th=settings['th_'+k]
                        if v is not None and v>=th-5:   # 임계치-5% 부터 목록에 포함(over=False 는 팝업 유지용 히스테리시스, 새 팝업은 over=True 만)
                            detail=''
                            if k=='disk' and u['disks']:
                                worst=max(u['disks'],key=lambda d:d['pct']); detail=worst.get('path','')
                            alarms.append({'target_id':t['id'],'name':t['name'],'metric':k,'label':label,'value':v,'threshold':th,'over':v>=th,'detail':detail,'at':m['at']})
            t['usage']=u
        return {'targets':targets,'alerts':alerts,'active_alerts':active,'at':now,'settings':settings,'usage_alarms':alarms,
                'agent_rejects':self.recent_rejects()}

    # ── 알림 임계치 설정(서버 공통) ──
    DEFAULT_SETTINGS={'th_cpu':90,'th_mem':90,'th_disk':90,'alarm_down':True,'repeat_min':10}

    def get_settings(self):
        out=dict(self.DEFAULT_SETTINGS)
        with self.db() as db:
            for r in db.execute('SELECT key,value FROM settings'):
                if r['key'] in out:
                    try:
                        out[r['key']]=json.loads(r['value'])
                    except ValueError:
                        pass
        return out

    def set_settings(self,value):
        if not isinstance(value,dict):
            raise ValueError('객체 형식이 필요합니다')
        cur=self.get_settings()
        for k in ('th_cpu','th_mem','th_disk'):
            if k in value:
                v=value[k]
                if type(v) is not int or not 50<=v<=100:
                    raise ValueError(f'{k}: 50~100 정수(%)')
                cur[k]=v
        if 'alarm_down' in value:
            if type(value['alarm_down']) is not bool:
                raise ValueError('alarm_down: true/false')
            cur['alarm_down']=value['alarm_down']
        if 'repeat_min' in value:
            v=value['repeat_min']
            if type(v) is not int or not 1<=v<=1440:
                raise ValueError('repeat_min: 1~1440 분')
            cur['repeat_min']=v
        with self.db() as db:
            for k,v in cur.items():
                db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',(k,json.dumps(v)))
        return cur

    def record_metrics(self,target_id,m,now=None,min_interval=0):
        now=time.time() if now is None else now
        if min_interval and now-self._last_push.get(target_id,0)<min_interval:
            raise ValueError(f'수신 간격 제한: 항목당 {min_interval}초에 1건')
        self._last_push[target_id]=now
        with self.db() as db:
            row=db.execute('SELECT procs FROM targets WHERE id=?',(target_id,)).fetchone()
            if not row:
                raise ValueError('감시 항목이 없습니다')
            level=row[0] or 'top'; procs=m.get('procs') if level!='none' else None
            db.execute('INSERT INTO metrics(target_id,at,cpu,mem,disk,load1,extra,rx,tx,disks,pcount) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                       (target_id,now,m.get('cpu'),m.get('mem'),m.get('disk'),m.get('load1'),m.get('extra',''),m.get('rx'),m.get('tx'),m.get('disks'),
                        procs['total'] if isinstance(procs,dict) else None))
            if isinstance(procs,dict):   # 최신 상세 1건만 보관(항목별) — users 수준이면 상위 프로세스 목록 제외
                data=dict(procs); data['top']=[] if level=='users' else data.get('top',[])
                db.execute('INSERT INTO procs(target_id,at,data) VALUES(?,?,?) ON CONFLICT(target_id) DO UPDATE SET at=excluded.at,data=excluded.data',
                           (target_id,now,json.dumps(data,ensure_ascii=False)[:PROCS_MAX_JSON]))

    def metrics(self,id,seconds=3600):
        """최근 N초 사용률 시계열(오름차순). 3시간 초과면 1분 평균으로 줄여 최대 720점."""
        since=time.time()-max(60,min(int(seconds),7*86400))
        with self.db() as db:
            rows=[dict(r) for r in db.execute('SELECT at,cpu,mem,disk,load1,rx,tx,pcount FROM metrics WHERE target_id=? AND at>=? ORDER BY at',(id,since))]
        if len(rows)>720:
            step=(rows[-1]['at']-rows[0]['at'])/720 or 1; out=[]; bucket=[]; b0=rows[0]['at']
            for r in rows:
                if r['at']-b0>=step and bucket:
                    out.append({k:(sum(x[k] for x in bucket if x[k] is not None)/max(1,sum(1 for x in bucket if x[k] is not None)) if any(x[k] is not None for x in bucket) else None) for k in ('cpu','mem','disk','load1','rx','tx','pcount')}|{'at':bucket[-1]['at']})
                    bucket=[]; b0=r['at']
                bucket.append(r)
            if bucket: out.append({k:(sum(x[k] for x in bucket if x[k] is not None)/max(1,sum(1 for x in bucket if x[k] is not None)) if any(x[k] is not None for x in bucket) else None) for k in ('cpu','mem','disk','load1','rx','tx','pcount')}|{'at':bucket[-1]['at']})
            rows=out
        return rows

    LIVE_SAMPLES_MAX = 4000
    AVAIL_WINDOW = 86400       # 17차: 가용률은 최근 24시간(표본은 7일 보관)
    AVAIL_CACHE_SEC = 30

    def avail24(self):
        """17차(현장 '가용률이 항상 100%'): 예전 게이지는 '지금 정상인 항목 수 / 판정 항목 수'라 지금 장애가 없으면 늘 100% 였다.
        → 항목별 최근 24시간 검사 결과 건수 {항목 id: [성공, 실패, 수집기 오류]} 를 준다. 가용률 계산(항목별 성공/(성공+실패)의
        평균)은 화면이 사용 중 항목만 골라 한다. 수집기 오류(error)는 대상 장비 상태를 알 수 없어 분모에서 뺀다.
        관제 화면이 2초마다 부르므로 30초 동안은 같은 결과를 돌려준다."""
        now = time.time()
        c = getattr(self, '_avail_cache', None)
        if c and now - c[0] < self.AVAIL_CACHE_SEC:
            return c[1]
        with self.db() as db:
            rows = db.execute("SELECT target_id, sum(result='up'), sum(result='down'), sum(result='error') FROM samples "
                              "WHERE at>? GROUP BY target_id", (now - self.AVAIL_WINDOW,)).fetchall()
        out = {'window': self.AVAIL_WINDOW, 'at': now, 'by': {r[0]: [int(r[1] or 0), int(r[2] or 0), int(r[3] or 0)] for r in rows}}
        self._avail_cache = (now, out)
        return out

    def live(self, seconds=600, after=None, since=None):
        """실시간 관제(14차, 2026-10-22 마스터 '제니퍼처럼 액티브한 모니터링') — 전 항목의 최근 검사 표본과 사용률 추이를 한 번에.
        samples: [항목 id, 시각, 결과(up|down|error), 응답 ms] — 응답 시간 분포(X-View 식 산점도)용. 최신 LIVE_SAMPLES_MAX 건까지.
        series : {항목 id: [[시각, cpu, mem, disk], …]} — 이퀄라이저·추이 그래프용(항목당 최근 240점).
        after(표본 행 번호)·since(사용률 시각)를 주면 그 뒤 것만 — 화면이 2초마다 덧붙여 받는다(매번 10분치를 다시 보내지 않게).
        GPT 102차 P1-04: 표본 이어 받기는 시각이 아니라 **행 번호**로(시각을 밀리초로 반올림해 넘기면 사이에 든 표본을 놓친다).
        cursor = 돌려준 표본의 마지막 행 번호, mcursor = 사용률 마지막 시각(원값), truncated = 상한에 걸려 잘림.
        상세 글(detail)은 내보내지 않는다(주소가 섞일 수 있음)."""
        now = time.time()
        seconds = max(60, min(int(seconds), 3600))
        lo = now - seconds
        with self.db() as db:
            if after is not None:
                q = db.execute('SELECT id,target_id,at,result,latency FROM samples WHERE id>? AND at>? ORDER BY id DESC LIMIT ?',
                               (int(after), lo, self.LIVE_SAMPLES_MAX + 1)).fetchall()
            else:
                q = db.execute('SELECT id,target_id,at,result,latency FROM samples WHERE at>? ORDER BY id DESC LIMIT ?',
                               (lo, self.LIVE_SAMPLES_MAX + 1)).fetchall()
            truncated = len(q) > self.LIVE_SAMPLES_MAX
            q = q[:self.LIVE_SAMPLES_MAX][::-1]
            samples = [[r['target_id'], round(r['at'], 3), r['result'], None if r['latency'] is None else round(r['latency'], 2)] for r in q]
            mlo = max(lo, float(since)) if since is not None else lo
            rows = db.execute('SELECT target_id,at,cpu,mem,disk FROM metrics WHERE at>? ORDER BY at', (mlo,)).fetchall()
            cursor = q[-1]['id'] if q else (int(after) if after is not None else
                                             (db.execute('SELECT max(id) FROM samples').fetchone()[0] or 0))
        series = {}
        for r in rows:
            series.setdefault(r['target_id'], []).append([round(r['at'], 1), r['cpu'], r['mem'], r['disk']])
        return {'samples': samples, 'series': {k: v[-240:] for k, v in series.items()}, 'at': now, 'seconds': seconds,
                'partial': after is not None, 'cursor': cursor, 'mcursor': rows[-1]['at'] if rows else (float(since) if since is not None else lo),
                'truncated': truncated, 'avail': self.avail24()}

    def latest_metrics(self):
        """항목별 최신 사용률 1건 {target_id: {...}}"""
        with self.db() as db:
            rows=db.execute('SELECT m.target_id,m.at,m.cpu,m.mem,m.disk,m.load1,m.extra,m.rx,m.tx,m.disks,m.pcount FROM metrics m JOIN (SELECT target_id,max(at) mx FROM metrics GROUP BY target_id) x ON x.target_id=m.target_id AND x.mx=m.at').fetchall()
        return {r['target_id']:dict(r) for r in rows}

    def procs_summary(self):
        """항목별 프로세스 요약 {target_id: {'at','total','users','known'}} (상세는 procs_detail)"""
        out={}
        with self.db() as db:
            for r in db.execute('SELECT target_id,at,data FROM procs'):
                try:
                    d=json.loads(r['data']); out[r['target_id']]={'at':r['at'],'total':d.get('total'),'users':len(d.get('users') or []),'known':d.get('known'),'failed':d.get('failed')}
                except (TypeError, ValueError):
                    pass
        return out

    def procs_detail(self,id):
        with self.db() as db:
            r=db.execute('SELECT at,data FROM procs WHERE target_id=?',(id,)).fetchone()
        if not r:
            return None
        try:
            d=json.loads(r['data']); d['at']=r['at']; return d
        except (TypeError, ValueError):
            return None


    # ── 에이전트 토큰: 대상별 발급 + 유효기간 (2026-09-22) ──────────────────────
    #   원문은 저장하지 않는다(SHA-256 만). 발급 순간에만 원문을 돌려주고, 그 뒤에는 다시 볼 수 없다.
    TOKEN_DAYS_MAX = 3650
    TOKEN_ACTIVE_MAX = 5        # 대상 하나에 살아 있는 토큰 수 — 넘으면 먼저 폐기하게 한다

    @staticmethod
    def _tok_hash(tok: str) -> str:
        return hashlib.sha256(('lt-agent:' + (tok or '')).encode('utf-8')).hexdigest()

    def issue_agent_token(self, target_id: str = '', label: str = '', days: int = 365, by: str = '') -> dict:
        """대상 하나에 쓸 토큰을 발급한다. days=0 이면 기한 없음. 원문은 여기서만 돌려준다."""
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ValueError('유효기간(일)은 숫자여야 합니다') from None
        if not 0 <= days <= self.TOKEN_DAYS_MAX:
            raise ValueError(f'유효기간은 0(무기한)~{self.TOKEN_DAYS_MAX}일 사이로 정하십시오')
        target_id = str(target_id or '').strip()
        if target_id:
            with self.db() as db:
                r = db.execute('SELECT name,metrics FROM targets WHERE id=?', (target_id,)).fetchone()
            if not r:
                raise ValueError('등록되지 않은 감시 대상입니다')
            if r['metrics'] != 'agent':
                raise ValueError(f"'{r['name']}' 은 자원 사용률 수집이 '에이전트'로 설정돼 있지 않습니다")
            label = label or r['name']
        now = time.time()
        if target_id:      # 살아 있는 토큰이 너무 많으면 먼저 정리하게 한다(어느 것을 폐기할지 모르게 되는 상황 방지)
            with self.db() as db:
                alive = db.execute('SELECT count(*) FROM agent_tokens WHERE target_id=? AND revoked=0'
                                   ' AND (expires=0 OR expires>?)', (target_id, now)).fetchone()[0]
            if alive >= self.TOKEN_ACTIVE_MAX:
                raise ValueError(f'이 대상에 살아 있는 토큰이 이미 {alive}개입니다 — '
                                 f'쓰지 않는 토큰을 먼저 폐기한 뒤 발급하십시오(최대 {self.TOKEN_ACTIVE_MAX}개)')
        tok = secrets.token_urlsafe(32)        # 256비트 CSPRNG — 해시만 저장하므로 원문 세기가 중요하다
        with self.db() as db:
            db.execute('INSERT INTO agent_tokens(th,target_id,label,created,expires,created_by) VALUES(?,?,?,?,?,?)',
                       (self._tok_hash(tok), target_id or None, str(label or '')[:60], now,
                        0 if days == 0 else now + days * 86400, str(by or '')[:64]))
        return {'token': tok, 'target_id': target_id, 'label': label,
                'expires': 0 if days == 0 else now + days * 86400, 'days': days}

    # ── 19차 간편 설치: 1회용 등록 코드 → 대상 전용 토큰 ─────────────────────────
    #   화면이 코드를 만들면(로그인한 담당자), 대상 서버의 설치 스크립트가 코드를 내고 토큰을 받는다.
    #   토큰은 그 응답에서 한 번만 나가 설치 파일(권한 600)로 들어간다 — 화면·명령줄·셸 기록에 남지 않는다.
    ENROLL_MINUTES = 30
    ENROLL_FAILS_MAX = 5
    _ENROLL_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'      # 헷갈리는 0·O·1·I 없음
    _ENROLL_RE = re.compile(r'LT-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}')

    @staticmethod
    def _enroll_hash(code: str) -> str:
        return hashlib.sha256(('lt-enroll:' + (code or '')).encode('utf-8')).hexdigest()

    def issue_enroll(self, target_id: str, by: str = '') -> dict:
        target_id = str(target_id or '').strip()
        with self.db() as db:
            r = db.execute('SELECT name,metrics,enabled FROM targets WHERE id=?', (target_id,)).fetchone()
        if not r:
            raise ValueError('등록되지 않은 감시 대상입니다 — 먼저 [저장]하십시오')
        if r['metrics'] != 'agent':
            raise ValueError(f"'{r['name']}' 은 자원 사용률 수집이 '에이전트'가 아닙니다 — 수집 방식을 에이전트로 저장한 뒤 만드십시오")
        a = self._ENROLL_ALPHA
        code = 'LT-' + '-'.join(''.join(secrets.choice(a) for _ in range(4)) for _ in range(3))   # 60비트 · 30분 · 1회 · 틀린 시도 제한
        now = time.time()
        with self.db() as db:
            db.execute('DELETE FROM agent_enroll WHERE expires<?', (now - 86400,))
            db.execute('INSERT INTO agent_enroll(ch,target_id,created,expires,created_by) VALUES(?,?,?,?,?)',
                       (self._enroll_hash(code), target_id, now, now + self.ENROLL_MINUTES * 60, str(by or '')[:64]))
        return {'code': code, 'expires': now + self.ENROLL_MINUTES * 60, 'issued': now, 'name': r['name']}

    def redeem_enroll(self, code: str, addr: str = '', hostname: str = '') -> dict:
        """설치 스크립트가 낸 코드 확인 → 대상 전용 토큰(1년) 발급. 대상 서버에서만: 보낸 곳 IP 가 등록 주소이거나 호스트명이 항목 이름과 같아야 한다."""
        code = str(code or '').strip().upper()
        if not self._ENROLL_RE.fullmatch(code):
            raise PermissionError('등록 코드 형식이 아닙니다')
        now = time.time()
        with self.db() as db:
            e = db.execute('SELECT * FROM agent_enroll WHERE ch=?', (self._enroll_hash(code),)).fetchone()
            if not e:
                raise PermissionError('없는 등록 코드입니다 — LogTriage 화면에서 [설치 명령 만들기]로 새로 만드십시오')
            if e['used']:
                raise PermissionError('이미 쓴 등록 코드입니다(1회용) — 화면에서 새로 만드십시오')
            if e['expires'] < now:
                raise PermissionError(f'등록 코드 유효시간({self.ENROLL_MINUTES}분)이 지났습니다 — 화면에서 새로 만드십시오')
            if e['fails'] >= self.ENROLL_FAILS_MAX:
                raise PermissionError('틀린 시도가 많아 이 등록 코드를 막았습니다 — 화면에서 새로 만드십시오')
            t = db.execute('SELECT id,name,address,metrics,metrics_interval FROM targets WHERE id=?', (e['target_id'],)).fetchone()
            if not t or t['metrics'] != 'agent':
                raise PermissionError('대상 감시 항목이 없거나 에이전트 수집이 아닙니다')
            hn = str(hostname or '').strip().lower()
            wrong = not (addr and addr == t['address']) and not (hn and hn == str(t['name']).strip().lower())
            if not wrong:
                cur = db.execute('UPDATE agent_enroll SET used=?, used_from=? WHERE ch=? AND used IS NULL', (now, f'{addr} {hostname}'[:120], e['ch']))
                if cur.rowcount != 1:
                    raise PermissionError('이미 쓴 등록 코드입니다(1회용) — 화면에서 새로 만드십시오')   # 동시에 두 번 낸 경우
        if wrong:   # 틀린 시도는 따로 적는다 — 위 거래 안에서 예외를 던지면 되돌려져 횟수가 쌓이지 않는다(19차 시험에서 발견)
            with self.db() as db:
                db.execute('UPDATE agent_enroll SET fails=fails+1 WHERE ch=?', (e['ch'],))
            raise PermissionError('이 등록 코드의 대상 서버가 아닙니다 — 보낸 곳 주소와 호스트명이 감시 항목의 주소·이름과 다릅니다'
                                  '(NAT 뒤라면 감시 항목 이름을 이 서버의 hostname 과 같게 하십시오)')
        tok = self.issue_agent_token(t['id'], t['name'], 365, by=(e['created_by'] or '') + ' (간편 설치)')
        return {'token': tok['token'], 'target_id': t['id'], 'name': t['name'], 'expires': tok['expires'],
                'interval': metrics_every('agent', t['metrics_interval'] or 0)}

    def enroll_state(self, target_id: str, since: float) -> dict:
        """화면이 '설치 확인'을 기다릴 때 — 코드가 쓰였는지·첫 보고가 왔는지(값은 없이)."""
        with self.db() as db:
            e = db.execute('SELECT used,used_from FROM agent_enroll WHERE target_id=? AND created>=? ORDER BY created DESC LIMIT 1',
                           (target_id, float(since) - 1)).fetchone()
            m = db.execute('SELECT max(at) FROM metrics WHERE target_id=? AND at>=?', (target_id, float(since))).fetchone()[0]
        return {'used': bool(e and e['used']), 'used_at': e['used'] if e else None, 'first_report': m,
                'used_from': (e['used_from'] or '') if e and e['used'] else ''}   # GPT 119 P1-02: 어디서 등록했는지 담당자가 대조

    def check_agent_token(self, tok: str) -> dict | None:
        """수치를 받을 때 쓰는 확인 — 살아 있으면 {'target_id','label','legacy'}, 아니면 None.

        기한이 지났거나 폐기된 토큰은 None 이 아니라 사유를 담아 돌려준다(화면에 이유를 보여 주기 위함)."""
        if not tok:
            return None
        th = self._tok_hash(tok)
        now = time.time()
        with self.db() as db:
            r = db.execute('SELECT * FROM agent_tokens WHERE th=?', (th,)).fetchone()
            if r:
                if r['revoked']:
                    return {'error': '폐기된 토큰입니다 — [모니터링]에서 새로 발급받으십시오'}
                if r['expires'] and r['expires'] < now:
                    return {'error': '토큰 유효기간이 지났습니다 — [모니터링]에서 새로 발급받으십시오'}
                db.execute('UPDATE agent_tokens SET last_used=?, uses=uses+1 WHERE th=?', (now, th))
                return {'target_id': r['target_id'] or '', 'label': r['label'] or '', 'legacy': False}
        if self.agent_token and hmac.compare_digest(tok, self.agent_token):
            return {'target_id': '', 'label': '(공용)', 'legacy': True}    # 이미 깔린 에이전트 호환
        return None

    def list_agent_tokens(self) -> list:
        now = time.time()
        with self.db() as db:
            rows = [dict(r) for r in db.execute(
                'SELECT a.th,a.target_id,a.label,a.created,a.expires,a.last_used,a.uses,a.revoked,a.created_by,'
                ' t.name AS target_name FROM agent_tokens a LEFT JOIN targets t ON t.id=a.target_id'
                ' ORDER BY a.created DESC')]
        for r in rows:
            r['id'] = r.pop('th')[:16]        # 화면·폐기용 짧은 손잡이(원문은 아님)
            r['expired'] = bool(r['expires']) and r['expires'] < now
            r['days_left'] = None if not r['expires'] else int((r['expires'] - now) // 86400)
        return rows

    def revoke_agent_token(self, short_id: str) -> dict:
        with self.db() as db:
            cur = db.execute('UPDATE agent_tokens SET revoked=1 WHERE substr(th,1,16)=? AND revoked=0',
                             (str(short_id or '')[:16],))
            if not cur.rowcount:
                raise ValueError('없거나 이미 폐기된 토큰입니다')
        return {'ok': True}

    def legacy_token_state(self) -> dict:
        """예전 공용 토큰 — 아직 살아 있는지, 폐기했는지."""
        with self.db() as db:
            r = db.execute("SELECT value FROM settings WHERE key='legacy_token_off'").fetchone()
        return {'active': not (r and r['value'] == '1'), 'token': self.agent_token}

    def disable_legacy_token(self) -> dict:
        """공용 토큰 폐기 — 이걸 쓰는 에이전트는 더 이상 수치를 올리지 못한다."""
        with self.db() as db:
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('legacy_token_off','1')")
        self.agent_token = ''
        return {'ok': True}

    def agent_targets(self,address=None,hostname=None):
        """에이전트 푸시를 받을 항목: metrics='agent' 이고 주소 또는 이름이 일치"""
        with self.db() as db:
            rows=[dict(r) for r in db.execute("SELECT id,name,address FROM targets WHERE metrics='agent'")]
        return [r for r in rows if (address and r['address']==address) or (hostname and r['name'].lower()==str(hostname).lower())]

    def local_targets(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT id,metrics_interval FROM targets WHERE metrics='local' AND enabled=1")]

    def set_usage(self, value):
        """14차: 사용률 수집 방식·주기·프로세스 수준만 바꾼다 — 가용성 상태·장애 이력·검사 주기는 그대로(전체 [편집] 저장은 상태를 새로 시작한다).
        SNMP 로 바꾸려면 커뮤니티가 저장돼 있어야 한다(없으면 [편집]에서 넣도록 거절 — 여기서는 비밀값을 받지 않는다)."""
        if not isinstance(value, dict) or not isinstance(value.get('id'), str):
            raise ValueError('감시 항목 ID 필요')
        with self.db() as db:
            cur = db.execute('SELECT id,metrics,procs,metrics_interval,snmp_community FROM targets WHERE id=?', (value['id'],)).fetchone()
            if not cur:
                raise ValueError('감시 항목이 없습니다')
            m = value.get('metrics', cur['metrics'] or 'none')
            if m not in METRICS:
                raise ValueError('metrics: none / local / agent / snmp 중 하나')
            p = value.get('procs', cur['procs'] or 'top')
            if p not in PROCS_LEVELS:
                raise ValueError('procs: none / users / top 중 하나')
            n = metrics_interval(value.get('metrics_interval', cur['metrics_interval'] or 0))
            if m == 'snmp' and not cur['snmp_community']:
                raise ValueError('SNMP 수집은 커뮤니티가 필요합니다 — 감시 항목 [편집]에서 SNMP 설정을 넣으십시오')
            db.execute('UPDATE targets SET metrics=?,procs=?,metrics_interval=? WHERE id=?', (m, p, n, cur['id']))
        return {'id': cur['id'], 'metrics': m, 'procs': p, 'metrics_interval': n, 'every': metrics_every(m, n)}

    def usage_interval(self, target_id):
        with self.db() as db:
            r = db.execute('SELECT metrics,metrics_interval FROM targets WHERE id=?', (target_id,)).fetchone()
        return metrics_every(r['metrics'], r['metrics_interval'] or 0) if r else 30

    def snmp_targets(self):
        with self.db() as db:
            return [dict(r) for r in db.execute("SELECT * FROM targets WHERE metrics='snmp' AND enabled=1")]

    def history(self,id):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT at,result,latency,detail FROM samples WHERE target_id=? ORDER BY at DESC LIMIT 120',(id,))][::-1]

    def ack(self,id):
        with self.db() as db:
            if not db.execute('UPDATE alerts SET acknowledged=1 WHERE id=?',(id,)).rowcount:
                raise ValueError('장애 이력이 없습니다')

    def prune(self):
        with self.db() as db:
            db.execute('DELETE FROM samples WHERE at<?',(time.time()-7*86400,))
            db.execute('DELETE FROM metrics WHERE at<?',(time.time()-7*86400,))
            db.execute('DELETE FROM alerts WHERE closed IS NOT NULL AND closed<?',(time.time()-90*86400,))


class Collector:
    def __init__(self,store,workers=8):
        self.store=store
        self.stop_event=threading.Event()
        self.pool=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='nms-probe')
        self.workers=workers
        self.thread=threading.Thread(target=self.run,name='nms-scheduler',daemon=True)
        self.heartbeat=0
        self.error=''
        self._snmp_prev={}      # target_id → 이전 인터페이스 카운터
        self._snmp_busy=set()
        self._mnext={}          # 14차: target_id → 다음 사용률 수집 시각(항목별 주기)
        self._force=set()       # 14차: [지금 갱신] — 다음 순회(0.5초 안)에 바로 수집

    def collect_now(self,target_id):
        """[지금 갱신] — 이 서버 자체·SNMP 는 다음 순회에 바로 수집. 에이전트는 원격이 보내는 것이라 당길 수 없다(다음 보고 때)."""
        self._force.add(target_id)

    def start(self):
        self.thread.start()

    def _poll_snmp(self,target):
        try:
            prev=self._snmp_prev.setdefault(target['id'],{})
            tgt=dict(target); tgt['snmp_community']=self.store._sc_dec(target.get('snmp_community'),target['id'])   # 저장은 암호문, 조회 때만 평문
            try:
                m=snmp_metrics(tgt,prev)
            except Exception as e:   # SnmpError·소켓 오류 — 값 없이 오류만 기록해 화면에 표시
                m={'cpu':None,'mem':None,'disk':None,'load1':None,'rx':None,'tx':None,'disks':None,'extra':json.dumps({'error':str(e)[:200]},ensure_ascii=False)}
            self.store.record_metrics(target['id'],m)
        except Exception:
            LOG.exception('SNMP poll failed')
        finally:
            self._snmp_busy.discard(target['id'])

    def run(self):
        active={}
        last_prune=0
        last_scan=0
        local_metrics()  # CPU 기준값
        while not self.stop_event.is_set():
            try:
                now=time.time()
                if self._force or now-last_scan>=1:   # 14차: 항목별 주기(metrics_interval) — 1초마다 훑고, [지금 갱신]은 바로
                    last_scan=now
                    for tg in self.store.snmp_targets():   # SNMP 장비 사용률 — 항목당 동시 1회
                        if tg['id'] in self._snmp_busy or not (tg['id'] in self._force or now>=self._mnext.get(tg['id'],0)):
                            continue
                        self._force.discard(tg['id'])
                        self._mnext[tg['id']]=now+metrics_every('snmp',tg.get('metrics_interval') or 0)
                        self._snmp_busy.add(tg['id']); self.pool.submit(self._poll_snmp,tg)
                    due=[r for r in self.store.local_targets() if r['id'] in self._force or now>=self._mnext.get(r['id'],0)]
                    if due:   # 이 서버 자체 사용률 — 측정은 한 번, 기록은 그때 차례인 항목마다
                        m=local_metrics()
                        if m['cpu'] is not None:
                            for r in due:
                                self.store.record_metrics(r['id'],m)
                                self._force.discard(r['id'])
                                self._mnext[r['id']]=now+metrics_every('local',r.get('metrics_interval') or 0)
                    self._force={x for x in self._force if x in self._snmp_busy}   # 에이전트·없는 항목 요청은 버린다(당길 수 없음)
                for id,(future,target) in list(active.items()):
                    if future.done():
                        del active[id]
                        try:
                            outcome=future.result()
                        except Exception:
                            LOG.exception('NMS probe failed')
                            outcome=('error',None,'수집기 내부 오류: 서버 로그 확인')
                        self.store.record(target,*outcome)
                for target in self.store.due():
                    if len(active)>=self.workers:
                        break
                    if target['id'] not in active:
                        active[target['id']]=(self.pool.submit(probe,target),target)
                if time.time()-last_prune>3600:
                    self.store.prune()
                    last_prune=time.time()
                self.heartbeat=time.time()
                self.error=''
            except Exception:
                LOG.exception('NMS scheduler failed')
                self.error='수집 스케줄러 오류: 서버 로그 확인'
            self.stop_event.wait(.5)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=15)
        self.pool.shutdown(wait=True,cancel_futures=True)
