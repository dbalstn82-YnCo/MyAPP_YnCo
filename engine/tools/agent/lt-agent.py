"""LogTriage 자원 사용률 에이전트(Python 3, 표준 라이브러리) — Linux/Windows 공용.
사용: python3 lt-agent.py http://<LogTriage서버>:8088 <토큰> [간격초=30] [디스크=all] [--once] [--no-procs]   (all: 모든 로컬 볼륨, 또는 특정 경로 / --once: 1회 전송 후 종료 / --no-procs: 계정별 프로세스 수집 안 함)
같은 폴더에 lt_procs.py 가 있으면 계정별 프로세스 수(집계·상위 20개)를 함께 보낸다.
LogTriage [모니터링]에 이 서버의 IP 를 '자원 사용률 수집: 에이전트'로 등록해 두어야 저장된다."""
import json, os, shutil, socket, sys, time, urllib.error, urllib.request

def _procs_sampler():
    """계정별 프로세스 수집기 — 같은 폴더의 lt_procs.py(표준 라이브러리, root 불필요). 없거나 LT_PROCS=0 이면 None."""
    if os.environ.get("LT_PROCS", "1") == "0" or "--no-procs" in sys.argv:
        return None
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import lt_procs
        return lt_procs.ProcSampler()
    except Exception as e:
        print(f"프로세스 수집 비활성(lt_procs.py 없음/오류: {e})", flush=True); return None

def cpu_times():
    if os.name == "nt":
        import ctypes
        idle, kern, user = ctypes.c_ulonglong(), ctypes.c_ulonglong(), ctypes.c_ulonglong()
        ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kern), ctypes.byref(user))
        total = kern.value + user.value
        return total - idle.value, total
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]][:8]  # guest·guest_nice 제외(user·nice 에 포함)
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v) - idle, sum(v)

def mem_pct():
    if os.name == "nt":
        import ctypes
        class MS(ctypes.Structure):
            _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in
                        ("ullTotalPhys", "ullAvailPhys", "ullTotalPageFile", "ullAvailPageFile", "ullTotalVirtual", "ullAvailVirtual", "ullAvailExtendedVirtual")]
        m = MS(); m.dwLength = ctypes.sizeof(MS); ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
        return round(100.0 * (m.ullTotalPhys - m.ullAvailPhys) / max(1, m.ullTotalPhys), 1)
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            k, _, v = line.partition(":"); info[k] = int(v.split()[0])
    avail = info.get("MemAvailable", info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0))
    return round(100.0 * (info["MemTotal"] - avail) / max(1, info["MemTotal"]), 1)

SKIP_FS = {"tmpfs", "devtmpfs", "squashfs", "overlay", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "efivarfs", "autofs", "mqueue", "debugfs",
           "tracefs", "securityfs", "pstore", "bpf", "configfs", "fusectl", "hugetlbfs", "binfmt_misc", "ramfs", "rpc_pipefs", "nsfs", "selinuxfs", "iso9660"}

def _unescape_mount(s):
    import re
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

def _usage(path):
    """서버와 같은 산식 — Linux: statvfs used/(used+avail)(df 와 동일), Windows: disk_usage"""
    if os.name == "nt":
        du = shutil.disk_usage(path)
        return (round(100.0 * du.used / du.total, 1), round(du.used / 2**30, 1), round(du.total / 2**30, 1)) if du.total else None
    st = os.statvfs(path)
    used = (st.f_blocks - st.f_bfree) * st.f_frsize; avail = st.f_bavail * st.f_frsize; total = st.f_blocks * st.f_frsize
    return (round(100.0 * used / (used + avail), 1), round(used / 2**30, 1), round(total / 2**30, 1)) if used + avail > 0 and total > 0 else None

def disks(which="all"):
    """[{path,pct,used_gb,total_gb}] — all: 모든 로컬 볼륨(Linux /proc/mounts 의 /dev 장치·실제 파일시스템, 같은 장치는 첫 마운트만 / Windows 고정 드라이브), 아니면 지정 경로 하나"""
    out = []
    def add(path, label=None):
        try:
            u = _usage(path)
        except OSError:
            return
        if u:
            out.append({"path": label or path, "pct": u[0], "used_gb": u[1], "total_gb": u[2]})
    if which != "all":
        add(which); return out
    if os.name == "nt":
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            root = f"{chr(65 + i)}:\\"
            if mask & (1 << i) and ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                add(root, root[:2])
        return out
    seen = set()
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dev, mp, fst = _unescape_mount(parts[0]), _unescape_mount(parts[1]), parts[2]
                if not dev.startswith("/dev/") or fst in SKIP_FS or fst.startswith("fuse.") or mp.startswith(("/snap/", "/var/lib/docker/", "/run/", "/sys/", "/proc/", "/dev/")) or dev in seen:
                    continue
                seen.add(dev); add(mp)
                if len(out) >= 32:
                    break
    except OSError:
        add("/")
    return out

def net_bytes():
    if os.name == "nt":
        return None
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f.readlines()[2:]:
            name, _, rest = line.partition(":")
            if name.strip() == "lo": continue
            v = rest.split(); rx += int(v[0]); tx += int(v[8])
    return rx, tx

def main():
    if len(sys.argv) < 3:
        print(__doc__); return 1
    once = "--once" in sys.argv          # 1회 전송 후 종료(설치형 ctl 의 test 용) — 성공(ok)이면 0, 아니면 1
    argv = [a for a in sys.argv if a not in ("--once", "--no-procs")]
    sampler = _procs_sampler()
    url, token = argv[1].rstrip("/"), argv[2]
    if token == "-":   # 설치형 ctl: 토큰은 환경변수로(명령행에 노출하지 않음)
        token = os.environ.get("LT_AGENT_TOKEN", "")
        if not token:
            print("토큰이 없습니다: 인자 또는 LT_AGENT_TOKEN 환경변수"); return 2
    if token == "-":   # 설치형 ctl: 토큰은 환경변수로(명령행에 노출하지 않음)
        token = os.environ.get("LT_AGENT_TOKEN", "")
        if not token:
            print("토큰이 없습니다: 인자 또는 LT_AGENT_TOKEN 환경변수"); return 2
    interval = max(1, int(argv[3])) if len(argv) > 3 else 30
    disk = argv[4] if len(argv) > 4 else "all"
    prev = cpu_times(); pnet = net_bytes(); pt = time.time()
    if sampler:
        try:
            sampler.collect()   # CPU% 기준값
        except Exception:
            sampler = None
    while True:
        time.sleep(interval)
        cur = cpu_times(); cpu = round(100.0 * (cur[0] - prev[0]) / max(1, cur[1] - prev[1]), 1); prev = cur
        rx = tx = None
        cn = net_bytes(); nt = time.time()
        if cn and pnet:
            rx = round(max(0, cn[0] - pnet[0]) / max(1e-3, nt - pt), 1); tx = round(max(0, cn[1] - pnet[1]) / max(1e-3, nt - pt), 1)
        pnet, pt = cn, nt
        ds = disks(disk)
        body = {"hostname": socket.gethostname(), "cpu": cpu, "mem": mem_pct(), "disk": max([d["pct"] for d in ds], default=None), "disks": ds,
                "load1": round(os.getloadavg()[0], 2) if hasattr(os, "getloadavg") else None, "rx": rx, "tx": tx, "os": os.name, "disk_path": disk}
        if sampler:
            try:
                body["procs"] = sampler.collect()   # {'total','known','ncpu','users':[...],'top':[...]} — 이름만, 명령행 인자 없음
            except Exception as e:
                body["procs"] = None; print(f"프로세스 수집 실패: {e}", flush=True)
        try:
            req = urllib.request.Request(url + "/api/nms/metrics", data=json.dumps(body).encode(), method="POST",
                                         headers={"Content-Type": "application/json", "X-Agent-Token": token})
            r = urllib.request.urlopen(req, timeout=5).read().decode()
        except urllib.error.HTTPError as e:   # 서버가 준 이유(401 토큰 불일치 / 404 미등록 IP)를 그대로 보여준다
            try:
                detail = e.read().decode("utf-8", "replace")[:200]
            except Exception:
                detail = ""
            r = f"전송 실패: HTTP {e.code} {detail}"
        except Exception as e:
            r = f"전송 실패: {e}"
        try:   # 14차: 서버 화면에서 정한 수집 주기(5~3600초)를 따른다 — 응답에 없으면 지금 주기 그대로
            want = json.loads(r).get("interval") if r.startswith("{") else None
            if type(want) is int and 5 <= want <= 3600 and want != interval:
                print(f"서버가 정한 수집 주기로 바꿉니다: {interval}초 → {want}초", flush=True); interval = want
        except ValueError:
            pass
        pc = body.get("procs"); ptxt = f" procs={pc['total']}/{len(pc['users'])}계정" if isinstance(pc, dict) else ""
        print(time.strftime("%Y-%m-%d %H:%M:%S"), body["cpu"], body["mem"], body["disk"], ptxt, "->", r[:120], flush=True)
        if once:
            return 0 if '"ok": true' in r or '"ok":true' in r else 1

if __name__ == "__main__":
    sys.exit(main() or 0)
