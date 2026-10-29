"""병렬 해석(12차 성능 · 2026-10-20 마스터: "PC 는 중요하지 않고 로그 분석기가 낼 수 있는 최대 성능으로").

로그 해석(파일 읽기·줄 나눔·시각 해석·룰 사전 거름)은 CPU 를 한 코어만 쓴다. 여기서는 작업자 프로세스 여러 개로 나눠 돌린다.
  · 여러 파일 — 파일마다 작업 하나.
  · 큰 단일 파일 — 쪼갤 수 있는 파서만 조각으로 나눈다:
      한 줄 = 한 이벤트인 파서(nginx·apache·accesslog·linux_syslog·webtob)는 아무 줄 경계,
      여러 줄을 한 이벤트로 합치는 tomcat 은 '이벤트 시작 줄'(시각으로 시작하는 줄) 경계에서만.
    조각은 원래와 **같은 줄 나눔 규칙**(텍스트 모드 newline='' — LF·CRLF·CR 단독)으로 읽고, 줄 번호(원문 위치)는 조각 앞까지의 줄 수를
    같은 규칙으로 세어 이어 붙인다. 조각 결과를 순서대로 이으면 순차 해석과 같다(시험: 순차 대조).
  · 32MB 미만이거나 작업자 1개면 순차(프로세스를 띄우는 비용이 더 크다). 병렬이 어떤 이유로든 실패하면 순차로 되돌아간다.
  · 작업자 수: 환경 변수 LOGTRIAGE_WORKERS(0·1 = 끔), 없으면 CPU 수(최대 16). 남은 물리 메모리의 60% / 64MB 를 넘지 않는다(100MB 실측: 작업자 8개 12.9초 ≈ 12개 13.1초).
"""
from __future__ import annotations

import io
import logging
import os
from pathlib import Path

PAR_MIN_TOTAL = 32 * 1024 * 1024     # 이보다 작으면 순차
CHUNK = 4 * 1024 * 1024              # 단일 파일 조각 목표 크기(작업자 수의 2배까지 — 4MB 가 실측 최적)
SNAP_LINES = 20000                   # 경계를 이벤트 시작 줄에 맞출 때 앞으로 볼 최대 줄 수

_ANY_LINE = (".nginx", ".apache", ".accesslog", ".linux_syslog", ".webtob")


WORKER_MB = 64                       # 작업자 하나에 잡는 메모리(포장본 실측 약 45MB 에 1.4배 여유)
MEM_SHARE = 0.6                      # 남은 물리 메모리 중 작업자에게 줄 몫


def avail_mb() -> int | None:
    """지금 쓸 수 있는 물리 메모리(MB) — 모르면 None."""
    try:
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong), ("ullTotalPhys", ctypes.c_ulonglong),
                            ("ullAvailPhys", ctypes.c_ulonglong), ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong), ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            st = MS()
            st.dwLength = ctypes.sizeof(MS)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullAvailPhys // (1024 * 1024))
            return None
        return linux_avail_mb()
    except (OSError, ValueError, AttributeError):
        return None


def _read_int(p: Path) -> int | None:
    try:
        v = p.read_text(encoding="ascii").strip()
    except OSError:
        return None
    return int(v) if v.isdigit() else None          # cgroup v2 의 'max'(제한 없음)는 None


def linux_avail_mb(proc: Path = Path("/proc"), cg: Path = Path("/sys/fs/cgroup")) -> int | None:
    """리눅스(12차 리눅스 동일 판 점검): 쓸 수 있는 메모리 = min(MemAvailable, 이 프로세스 cgroup 한도 − 지금 사용량).
    · SC_AVPHYS_PAGES 는 페이지 캐시를 빼 버려 서버에서 크게 작게 나온다 → MemAvailable(/proc/meminfo).
    · systemd 서비스는 MemoryMax=2G(logtriage-server.service) — 호스트가 넉넉해도 그 한도를 넘으면 작업자가 OOM 으로 죽는다 →
      cgroup v2(memory.max·memory.current) 또는 v1(memory.limit_in_bytes·memory.usage_in_bytes)."""
    best = None
    try:
        for ln in (proc / "meminfo").read_text(encoding="ascii").splitlines():
            if ln.startswith("MemAvailable:"):
                best = int(ln.split()[1]) // 1024            # kB → MB
                break
    except (OSError, ValueError, IndexError):
        pass
    if best is None:
        try:
            best = int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") // (1024 * 1024))
        except (OSError, ValueError, AttributeError):
            best = None
    rel = ""
    try:                                                     # 이 프로세스의 cgroup 경로 — v2 는 '0::/system.slice/x.service'
        for ln in (proc / "self" / "cgroup").read_text(encoding="ascii").splitlines():
            parts = ln.split(":", 2)
            if len(parts) == 3 and (parts[0] == "0" or "memory" in parts[1].split(",")):
                rel = parts[2].lstrip("/")
                if parts[0] == "0":
                    break
    except OSError:
        pass
    # GPT 93차 P1: 이 cgroup 이 'max'(제한 없음)여도 부모 slice 에 한도가 있을 수 있다 — 잎에서 뿌리까지 올라가며 가장 작은 여유를 쓴다
    parts = [x for x in rel.split("/") if x]
    chains = []
    for top in (cg, cg / "memory"):                          # v2(통합) · v1(memory 컨트롤러)
        chains.append([top.joinpath(*parts[:k]) for k in range(len(parts), -1, -1)])
    for chain in chains:
        seen = False
        for base in chain:
            lim = _read_int(base / "memory.max")
            use = _read_int(base / "memory.current")
            if lim is None and (base / "memory.max").is_file():
                seen = True                                  # v2 'max' — 이 단계는 제한 없음, 위로 계속
                continue
            if lim is None:
                lim = _read_int(base / "memory.limit_in_bytes")
                use = _read_int(base / "memory.usage_in_bytes")
                if lim is not None and lim >= (1 << 60):     # v1 의 '제한 없음'은 아주 큰 수
                    seen = True
                    continue
            if lim is not None:
                seen = True
                room = max(0, lim - (use or 0)) // (1024 * 1024)
                best = room if best is None else min(best, room)
        if seen:
            break
    return best


def workers() -> int:
    """작업자 수 — LOGTRIAGE_WORKERS 또는 CPU 수(최대 16). GPT 90차 P1: 지금 남은 물리 메모리의 60% 안에서만(작업자당 WORKER_MB),
    모자라면 줄이고(최소 1 = 순차) 그 사실을 기록한다 — 메모리 부족으로 분석이 죽는 대신 느려진다."""
    v = os.environ.get("LOGTRIAGE_WORKERS", "").strip()
    n = max(1, int(v)) if v.isdigit() else max(1, min(os.cpu_count() or 1, 16))
    mb = avail_mb()
    if mb is not None:
        cap = max(1, int(mb * MEM_SHARE // WORKER_MB))
        if cap < n:
            logging.getLogger(__name__).warning("parallel: workers %d -> %d (available memory %dMB)", n, cap, mb)
            n = cap
    return n


def chunk_rule(parser):
    """None = 쪼개지 않음 · () = 아무 줄 경계 · (정규식…) = 그 정규식에 맞는 줄(이벤트 시작) 경계."""
    mod = getattr(parser, "__module__", "") or ""
    if mod.endswith(_ANY_LINE):
        return ()
    if mod.endswith(".tomcat"):
        from .parsers import tomcat
        return tuple(p for p, _ in tomcat._PATTERNS)
    return None


_BLK = 8 * 1024 * 1024   # 줄 세기 읽기 단위(시험에서 작게 바꿔 블록 경계의 CR|LF 를 만든다)


def _count_lines_at(path: Path, offsets: list[int]) -> list[int]:
    """오름차순 오프셋들 각각까지의 줄 수를 **한 번 읽기로** — 텍스트 모드 newline='' 규칙(LF·CRLF·CR 단독 모두 줄 끝).
    (첫 구현은 조각마다 파일 처음부터 다시 세어 550MB·24조각에서 약 6.6GB 를 읽어 병렬이 순차보다 느렸다 — 실측으로 발견)"""
    out, n, prev_cr, pos = [], 0, False, 0
    with open(path, "rb") as f:
        for target in offsets:
            while pos < target:
                b = f.read(min(target - pos, _BLK))
                if not b:
                    break
                pos += len(b)
                n += b.count(b"\n") + b.count(b"\r") - b.count(b"\r\n")
                if prev_cr and b[:1] == b"\n":
                    n -= 1                  # 앞 블록 끝 CR + 이 블록 처음 LF = CRLF 한 줄
                prev_cr = b[-1:] == b"\r"
            out.append(n)
    return out


def _count_lines(path: Path, upto: int) -> int:
    return _count_lines_at(path, [upto])[0]


def _cuts(path: Path, size: int, k: int, start_res: tuple, enc: str) -> list[int]:
    from .parsers import mask_pii
    dec = "utf-8" if enc == "utf-8-sig" else enc
    cuts = [0]
    with open(path, "rb") as f:
        for j in range(1, k):
            f.seek(size * j // k)
            f.readline()                    # 다음 줄 처음으로(LF 뒤 = 어떤 규칙으로도 줄 처음)
            found = None
            for _ in range(SNAP_LINES):
                at = f.tell()
                raw = f.readline()
                if not raw:
                    break
                if not start_res:
                    found = at
                    break
                first = raw.decode(dec, "replace").replace("\r\n", "\n").replace("\r", "\n").split("\n", 1)[0]
                if any(p.match(mask_pii(first)) for p in start_res):
                    found = at
                    break
            if found and cuts[-1] < found < size:
                cuts.append(found)
    cuts.append(size)
    return cuts


def plan(inputs: list[dict], nw: int) -> list[dict]:
    """작업 목록 — 파일 하나 통째, 또는 쪼갤 수 있으면 조각들. 순서는 입력·조각 순서."""
    from .parsers import detect_encoding, get_parser
    tasks = []
    for idx, item in enumerate(inputs):
        path = Path(item["path"])
        _, parser = get_parser(item["product"])
        size = path.stat().st_size
        rule = chunk_rule(parser)
        enc = detect_encoding(path) if rule is not None else ""
        k = min(nw * 2, max(1, size // CHUNK)) if rule is not None else 1
        if rule is None or k < 2 or path.suffix.lower() == ".gz" or enc.startswith("utf-16"):
            tasks.append({"idx": idx, "path": str(path), "product": item["product"], "host": item.get("host") or "unknown",
                          "range": None})
            continue
        cuts = _cuts(path, size, k, rule, enc)
        firsts = dict(zip(cuts[1:-1], (c + 1 for c in _count_lines_at(path, cuts[1:-1]))))
        for a, b in zip(cuts, cuts[1:]):
            line0 = 1 if a == 0 else firsts[a]
            tasks.append({"idx": idx, "path": str(path), "product": item["product"], "host": item.get("host") or "unknown",
                          "range": (a, b, line0, "utf-8" if (enc == "utf-8-sig" and a > 0) else enc)})
    return tasks


def _work(task: dict, rules_dir: str | None, local_dir: str | None, year: int):
    """작업자 프로세스 — 같은 룰로 같은 사전 거름을 걸고, 맡은 파일(또는 조각)을 해석해 돌려준다."""
    from . import parsers
    from .parsers import linux_syslog, get_parser, set_event_filter
    from .rules import load_rules
    from .service import make_keep
    linux_syslog.DEFAULT_YEAR = year
    rules_pre = load_rules(Path(rules_dir), Path(local_dir) if local_dir else None) if rules_dir else []
    set_event_filter(make_keep(rules_pre))
    parsers.set_range(task["range"])
    try:
        _, parser = get_parser(task["product"])
        got = parser(Path(task["path"]), task["host"])
        return task["idx"], list(got), dict(getattr(got, "dropped", {}) or {}), getattr(got, "total", len(got))
    finally:
        parsers.set_range(None)
        set_event_filter(None)


import threading as _th

_BUSY = [0]                          # 이 프로세스에서 지금 돌고 있는 작업자 수(동시 분석 합계)
_BUSY_LOCK = _th.Lock()


def _reserve(want: int) -> int:
    """GPT 94차 P1: 서버형은 분석이 동시에 여러 건(MAX_ACTIVE) 돈다 — 건마다 따로 한도를 재면 합계가 CPU·메모리 한도를 넘는다.
    프로세스 전체 예산(workers())에서 남은 만큼만 빌려 준다. 2개 미만이면 0(순차)."""
    with _BUSY_LOCK:
        free = workers() - _BUSY[0]
        n = min(want, free)
        if n < 2:
            return 0
        _BUSY[0] += n
        return n


def _release(n: int) -> None:
    with _BUSY_LOCK:
        _BUSY[0] = max(0, _BUSY[0] - n)


def parse_all(inputs: list[dict], rules_dir, local_dir, year: int, progress=None):
    """병렬로 해석해 입력 순서대로 [(events, dropped, total)] — 병렬을 쓰지 않을 때는 None(호출자가 순차)."""
    if workers() < 2:
        return None
    try:
        total = sum(Path(i["path"]).stat().st_size for i in inputs)
    except OSError:
        return None
    if total < PAR_MIN_TOTAL:
        return None
    nw = _reserve(workers())
    if not nw:
        logging.getLogger(__name__).info("parallel parse: no free workers (other analyses running) — sequential")
        return None
    try:
        return _parse_all(inputs, rules_dir, local_dir, year, progress, nw)
    finally:
        _release(nw)


def _parse_all(inputs, rules_dir, local_dir, year, progress, nw):
    try:
        tasks = plan(inputs, nw)
        if len(tasks) < 2:
            return None
        import concurrent.futures as cf
        import multiprocessing as mp
        out = [{"events": [], "dropped": {}, "total": 0, "parts": 0} for _ in inputs]
        done = 0
        with cf.ProcessPoolExecutor(max_workers=min(nw, len(tasks)), mp_context=mp.get_context("spawn")) as ex:
            futs = [ex.submit(_work, t, str(rules_dir) if rules_dir else None, str(local_dir) if local_dir else None, year) for t in tasks]
            results = []
            for fu in futs:                 # 제출 순서대로 받는다 — 조각 순서 = 이어 붙일 순서
                results.append(fu.result())
                done += 1
                if progress:
                    try:
                        progress({"stage": "parallel", "done": done, "tasks": len(tasks)})
                    except Exception:   # noqa: BLE001
                        pass
        for idx, evs, dropped, tot in results:
            o = out[idx]
            o["events"].extend(evs)
            for mk, c in dropped.items():
                o["dropped"][mk] = o["dropped"].get(mk, 0) + c
            o["total"] += tot
            o["parts"] += 1
        logging.getLogger(__name__).info("parallel parse: files=%d tasks=%d workers=%d", len(inputs), len(tasks), min(nw, len(tasks)))
        return out
    except Exception as e:   # noqa: BLE001 — 병렬이 안 되면 순차로(결과는 같다)
        logging.getLogger(__name__).warning("parallel parse failed, falling back to sequential: %s: %s", type(e).__name__, e)
        return None
