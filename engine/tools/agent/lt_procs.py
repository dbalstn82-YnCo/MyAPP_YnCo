"""계정별 프로세스 현황 수집 — 표준 라이브러리만(Linux: /proc, Windows: Win32 API via ctypes, 실패 시 tasklist). root/관리자 불필요.
결과: {'total': 전체 수, 'known': 계정을 알아낸 수, 'failed': 읽지 못한 수(권한), 'users': [{'user','count','cpu','mem_mb'}...], 'top': [{'pid','user','name','cpu','mem_mb'}...], 'ncpu': n}
메모리는 RSS(Linux)/작업 집합(Windows) 합계 — 공유 페이지가 중복되므로 계정 합계는 실제 점유보다 클 수 있다.
CPU% 는 직전 호출과의 CPU 시간 증가분으로 계산(첫 호출은 0). 명령행 인자는 수집하지 않는다(비밀번호가 섞일 수 있음) — 프로세스 이름만."""
from __future__ import annotations

import os
import subprocess
import sys
import time

MAX_USERS = 40
MAX_TOP = 20
NAME_LEN = 48


class ProcSampler:
    """호출 사이의 CPU 시간 차이로 프로세스별 CPU% 를 낸다. 인스턴스 하나를 유지하며 collect() 를 반복 호출."""

    def __init__(self):
        self._prev: dict = {}       # (pid, 시작시각) -> cpu_seconds — PID 재사용 시 이전 프로세스와 차분되지 않게
        self._t = None
        self._uid_cache: dict = {}
        self._uid_cache_t = time.monotonic()   # 계정명 캐시는 1시간마다 비움(계정 이름 변경 반영)
        self.failed = 0             # 마지막 수집에서 목록에서 빠진 프로세스 수(Linux: hidepid·종료 등으로 status/stat 를 못 읽음; Windows 는 N/A 로 포함되므로 0)
        self._ncpu = max(1, os.cpu_count() or 1)
        self._clk = None
        self._dbg_tried = False

    # ── 공개 ──
    def collect(self, top_n: int = MAX_TOP, max_users: int = MAX_USERS) -> dict:
        now = time.monotonic()
        if now - self._uid_cache_t > 3600:
            self._uid_cache = {}; self._uid_cache_t = now
        self.failed = 0
        rows = self._win_rows() if os.name == 'nt' else self._linux_rows()
        elapsed = (now - self._t) if self._t else 0.0
        cur = {}
        out_rows = []
        for pid, user, name, cpu_s, mem_mb, ident in rows:
            key = (pid, ident)
            cur[key] = cpu_s
            pct = 0.0
            prev = self._prev.get(key)
            if prev is not None and elapsed > 0 and cpu_s >= prev:
                pct = 100.0 * (cpu_s - prev) / elapsed / self._ncpu
            out_rows.append((pid, user, name, round(min(100.0 * self._ncpu, pct), 1), round(mem_mb, 1)))
        self._prev = cur; self._t = now
        d = summarize(out_rows, top_n, max_users, self._ncpu); d['failed'] = self.failed
        return d

    # ── Linux ──
    def _linux_rows(self):
        rows = []
        if self._clk is None:
            try:
                self._clk = os.sysconf('SC_CLK_TCK')
            except (ValueError, AttributeError, OSError):
                self._clk = 100
        for d in os.listdir('/proc'):
            if not d.isdigit():
                continue
            try:
                name = None; uid = None; rss_kb = 0
                with open(f'/proc/{d}/status', 'rb') as f:
                    for line in f:
                        if line.startswith(b'Name:'):
                            name = line[5:].strip().decode('utf-8', 'replace')
                        elif line.startswith(b'Uid:'):
                            uid = int(line.split()[1])
                        elif line.startswith(b'VmRSS:'):
                            rss_kb = int(line.split()[1])
                        if name is not None and uid is not None and rss_kb and line.startswith(b'VmRSS:'):
                            break
                with open(f'/proc/{d}/stat', 'rb') as f:
                    st = f.read()
                rest = st[st.rfind(b')') + 2:].split()   # 프로세스 이름 뒤 3번째 필드부터
                cpu_s = (int(rest[11]) + int(rest[12])) / float(self._clk)   # utime + stime
                start = int(rest[19]) if len(rest) > 19 else 0              # starttime(field 22) — PID 재사용 구분
                try:   # comm 은 15자로 잘리므로 읽을 수 있으면 실행 파일 이름을 우선(다른 계정 프로세스는 권한상 실패 → Name)
                    exe = os.path.basename(os.readlink(f'/proc/{d}/exe'))
                    if exe and not exe.endswith(' (deleted)'):
                        name = exe
                except OSError:
                    pass
                rows.append((int(d), self._uname(uid), (name or '?')[:NAME_LEN], cpu_s, rss_kb / 1024.0, start))
            except (OSError, ValueError, IndexError):
                self.failed += 1
                continue   # 사이에 종료됐거나 hidepid 로 접근 불가
        return rows

    def _uname(self, uid):
        if uid is None:
            return '?'
        u = self._uid_cache.get(uid)
        if u is None:
            try:
                import pwd
                u = pwd.getpwuid(uid).pw_name
            except (KeyError, ImportError):
                u = str(uid)
            self._uid_cache[uid] = u
        return u

    # ── Windows ──
    def _win_rows(self):
        try:
            return self._win_rows_api()
        except Exception:
            return self._win_rows_tasklist()

    def _win_rows_api(self):
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.windll.kernel32; adv = ctypes.windll.advapi32
        if not self._dbg_tried:   # 관리자로 실행 중이면 SeDebugPrivilege 를 켜 보호 프로세스까지 조회(일반 사용자면 조용히 실패)
            self._dbg_tried = True
            try:
                _enable_debug_privilege()
            except Exception:
                pass

        class PE32(ctypes.Structure):
            _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD), ('th32ProcessID', wintypes.DWORD),
                        ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)), ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                        ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', ctypes.c_long), ('dwFlags', wintypes.DWORD), ('szExeFile', ctypes.c_wchar * 260)]

        class PMC(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD), ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t), ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaNonPagedPoolUsage', ctypes.c_size_t), ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]

        class SID_AND_ATTR(ctypes.Structure):
            _fields_ = [('Sid', ctypes.c_void_p), ('Attributes', wintypes.DWORD)]

        k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE; k32.OpenProcess.restype = wintypes.HANDLE
        snap = k32.CreateToolhelp32Snapshot(0x2, 0)
        if snap == wintypes.HANDLE(-1).value or not snap:
            raise OSError('snapshot')
        rows = []
        try:
            pe = PE32(); pe.dwSize = ctypes.sizeof(PE32)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                pid = pe.th32ProcessID; name = pe.szExeFile[:NAME_LEN] or '?'
                cpu_s = 0.0; mem_mb = 0.0; user = 'N/A'; created = 0
                h = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION(Windows 8.1+ 에서 시간·메모리·토큰 조회에 충분)
                if h:
                    try:
                        ct, et, kt, ut = (wintypes.FILETIME() for _ in range(4))
                        if k32.GetProcessTimes(h, ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)):
                            cpu_s = (_ft(kt) + _ft(ut)) / 1e7; created = _ft(ct)   # 생성 시각 = PID 재사용 구분
                        pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
                        if k32.K32GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                            mem_mb = pmc.WorkingSetSize / 2 ** 20
                        tok = wintypes.HANDLE()
                        if adv.OpenProcessToken(h, 0x8, ctypes.byref(tok)):   # TOKEN_QUERY
                            try:
                                user = self._token_user(adv, tok, SID_AND_ATTR) or 'N/A'
                            finally:
                                k32.CloseHandle(tok)
                    finally:
                        k32.CloseHandle(h)
                elif pid == 0:
                    user = 'SYSTEM'
                rows.append((pid, user, name, cpu_s, mem_mb, created))
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k32.CloseHandle(snap)
        return rows

    def _token_user(self, adv, tok, SID_AND_ATTR):
        import ctypes
        from ctypes import wintypes
        need = wintypes.DWORD()
        adv.GetTokenInformation(tok, 1, None, 0, ctypes.byref(need))   # TokenUser
        buf = ctypes.create_string_buffer(max(need.value, 64))
        if not adv.GetTokenInformation(tok, 1, buf, len(buf), ctypes.byref(need)):
            return None
        sid = ctypes.c_void_p(ctypes.cast(buf, ctypes.POINTER(SID_AND_ATTR)).contents.Sid)   # int 로 풀리면 64비트 포인터가 c_int 로 잘린다
        key = ctypes.string_at(sid, 8)   # 문자열 SID 변환 실패 시의 대체 캐시 키
        try:
            sid_str = wintypes.LPWSTR()
            if adv.ConvertSidToStringSidW(sid, ctypes.byref(sid_str)):
                key = sid_str.value; ctypes.windll.kernel32.LocalFree(sid_str)
        except Exception:
            pass
        u = self._uid_cache.get(key)
        if u is not None:
            return u
        nlen = wintypes.DWORD(256); dlen = wintypes.DWORD(256); use = wintypes.DWORD()
        name = ctypes.create_unicode_buffer(256); dom = ctypes.create_unicode_buffer(256)
        if adv.LookupAccountSidW(None, sid, name, ctypes.byref(nlen), dom, ctypes.byref(dlen), ctypes.byref(use)):
            u = (dom.value + '\\' if dom.value else '') + name.value
        else:
            u = key if isinstance(key, str) else 'N/A'
        self._uid_cache[key] = u
        return u

    def _win_rows_tasklist(self):
        """대안: tasklist /V (사용자·메모리·CPU 시간). 인코딩은 콘솔 코드페이지."""
        import csv, io
        enc = 'cp%d' % ctypes_codepage() if os.name == 'nt' else 'utf-8'
        try:
            out = subprocess.run(['tasklist', '/V', '/FO', 'CSV', '/NH'], capture_output=True, timeout=20, creationflags=0x08000000).stdout.decode(enc, 'replace')
        except Exception:
            return []
        rows = []
        for r in csv.reader(io.StringIO(out)):
            if len(r) < 8:
                continue
            try:
                pid = int(r[1]); mem_mb = float(''.join(ch for ch in r[4] if ch.isdigit()) or 0) / 1024.0
                h, m, s = (r[7].split(':') + ['0', '0'])[:3]; cpu_s = int(h) * 3600 + int(m) * 60 + int(s)
            except ValueError:
                continue
            rows.append((pid, r[6] or 'N/A', r[0][:NAME_LEN], float(cpu_s), mem_mb, 0))   # tasklist 도 CPU Time 누적값 → collect() 에서 차분
        return rows


def _ft(ft) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


def ctypes_codepage() -> int:
    try:
        import ctypes
        return ctypes.windll.kernel32.GetOEMCP() or 949
    except Exception:
        return 949


def _enable_debug_privilege():
    import ctypes
    from ctypes import wintypes
    adv = ctypes.windll.advapi32; k32 = ctypes.windll.kernel32

    class LUID(ctypes.Structure):
        _fields_ = [('LowPart', wintypes.DWORD), ('HighPart', ctypes.c_long)]

    class LUID_AND_ATTR(ctypes.Structure):
        _fields_ = [('Luid', LUID), ('Attributes', wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [('PrivilegeCount', wintypes.DWORD), ('Privileges', LUID_AND_ATTR * 1)]

    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x28, ctypes.byref(tok)):   # ADJUST_PRIVILEGES | QUERY
        return
    try:
        tp = TOKEN_PRIVILEGES(); tp.PrivilegeCount = 1; tp.Privileges[0].Attributes = 0x2   # SE_PRIVILEGE_ENABLED
        if adv.LookupPrivilegeValueW(None, 'SeDebugPrivilege', ctypes.byref(tp.Privileges[0].Luid)):
            adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp), 0, None, None)
    finally:
        k32.CloseHandle(tok)


def summarize(rows, top_n: int = MAX_TOP, max_users: int = MAX_USERS, ncpu: int = 1) -> dict:
    """(pid, user, name, cpu%, mem_mb) 목록 → 계정별 집계 + 상위 프로세스. 계정 수가 많으면 상위 max_users 만 두고 나머지는 '(기타 n계정)'."""
    users: dict = {}
    for pid, user, name, cpu, mem in rows:
        u = users.setdefault(user, {'user': user, 'count': 0, 'cpu': 0.0, 'mem_mb': 0.0})
        u['count'] += 1; u['cpu'] += cpu; u['mem_mb'] += mem
    ulist = sorted(users.values(), key=lambda x: (-x['count'], -x['cpu'], x['user']))
    if len(ulist) > max_users:
        rest = ulist[max_users:]; ulist = ulist[:max_users]
        ulist.append({'user': f'(기타 {len(rest)}계정)', 'count': sum(x['count'] for x in rest), 'cpu': sum(x['cpu'] for x in rest), 'mem_mb': sum(x['mem_mb'] for x in rest)})
    for u in ulist:
        u['cpu'] = round(u['cpu'], 1); u['mem_mb'] = round(u['mem_mb'], 1)
    top = sorted(rows, key=lambda r: (-r[3], -r[4]))[:top_n]
    return {'total': len(rows), 'known': sum(1 for r in rows if r[1] not in ('N/A', '?')), 'ncpu': ncpu, 'users': ulist, 'failed': 0,
            'top': [{'pid': r[0], 'user': r[1], 'name': r[2], 'cpu': r[3], 'mem_mb': r[4]} for r in top]}


_sampler = ProcSampler()


def local_procs() -> dict | None:
    try:
        return _sampler.collect()
    except Exception:
        return None


if __name__ == '__main__':   # 수동 확인: python -m logtriage.procs
    import json
    s = ProcSampler(); s.collect(); time.sleep(1.0)
    print(json.dumps(s.collect(), ensure_ascii=False, indent=1)[:4000])
