"""리눅스 서버 묶음 자체 시험(12차) — 반출/logtriage-server-<판>.zip 을 풀어 **그 안의 엔진 코드로** 돌려 본다.

리눅스 실기가 이 PC 에 없다(WSL 배포판·Docker 없음). 대신 묶음에 든 파이썬 코드가 같은 판·같은 기능인지는 여기서 직접 본다:
  A. /healthz: 실제 HTTP 서버(묶음 엔진)를 띄워 build_id = 묶음 도장 id, code_id = 도장 code, code_modified 없음
  B. 30초 체험(서버형): sample_logs 4종 · 견본 분석 → DEMO- · 판정 > 0
  C. OS×제품 해법: code_solution(5 OS) 단계 1·2·3 · Windows 칩 PowerShell
  D. 병렬 = 순차: 합성 tomcat 40MB 를 묶음 엔진으로 순차(작업자 1)·병렬로 분석 — 발견·판정 같음
  E. 묶음 안 시험: 묶음의 전체 시험(tests/)을 **묶음 폴더에서** 실행 — 인증·보고서·룰팩·되돌리기 등 서버형 기능까지
  F. 예전 분석 가져오기: incidents.json.migrated 를 둔 자료 폴더에서 restore_legacy_history → 가져옴·백업·두 번째 0
못 보는 것(정직하게): 묶음의 리눅스용 python 3.11 실행 파일·systemd·SELinux·실제 RHEL 3.9 인터프리터(정적 검사 py39_compat 로 대신).
사용: python tools/build/linux_pkg_selftest.py [zip]
"""
from __future__ import annotations

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage import BUILD  # noqa: E402

P: list = []


def chk(name, ok, info=""):
    print(("통과 " if ok else "실패 ") + name, str(info)[:300], flush=True)
    if not ok:
        P.append(name)


PROBE = r'''
import json, os, sys, threading, time, urllib.request, shutil
from pathlib import Path
# spawn 작업자는 이 파일을 __mp_main__ 으로 다시 읽는다 — 가드가 없으면 작업자마다 이 시험 전체(서버 기동·분석·가져오기)를 되풀이한다
# (첫 실행에서 병렬이 순차보다 6배 느리고, 작업자가 먼저 가져와 본 실행이 '0건 가져옴'이 됐다 — 제품 결함 아님)
if __name__ == "__main__":
    eng = Path(sys.argv[1]); base = Path(sys.argv[2]); big = sys.argv[3]
    sys.path.insert(0, str(eng))
    from logtriage.server import make_server
    httpd, h = make_server("127.0.0.1", 0, base, None, allow_dirs=[str(Path(big).parent)])
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    hz = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=10).read().decode())
    api = h.api
    out = {"healthz": hz, "engine_file": __import__("logtriage").__file__}
    s = api.sample_logs()
    out["samples"] = sorted(x["name"] for x in s)
    cat = next((x for x in s if x["name"] == "catalina.out"), None)
    r = api.analyze({"inputs": [{"path": cat["path"], "product": "tomcat", "host": "demo"}]}) if cat else {"error": "견본 없음"}
    out["sample_run"] = {"id": r.get("id", ""), "f": r.get("findings_total", 0), "err": r.get("error", "")}
    sol = {}
    for o in ("linux", "aix", "hpux", "solaris", "windows"):
        q = api.code_solution("tomcat", "SEVERE", o) if False else api.code_solution("oracle", "ORA-00020", o)
        sol[o] = {"stages": [x["stage"] for x in q.get("stages", [])], "err": q.get("error", ""),
                  "ps": any("Get-" in (i.get("cmd") or "") for st in q.get("stages", []) for i in st.get("items", []))}
    out["solution"] = sol
    res = {}
    for w in ("1", "0"):
        if w == "0":
            os.environ.pop("LOGTRIAGE_WORKERS", None)
        else:
            os.environ["LOGTRIAGE_WORKERS"] = w
        t = time.time()
        rr = api.analyze({"inputs": [{"path": big, "product": "tomcat", "host": "big"}]})
        res[w] = {"sec": round(time.time() - t, 1), "f": rr.get("findings_total"), "e": rr.get("events_total"), "err": rr.get("error", ""),
                  "rules": sorted({c.get("rule_id") for c in rr.get("checklist") or []})}
    out["par"] = res
    mig = base / "incidents.json.migrated"
    if mig.is_file():
        a = api.restore_legacy_history(); b = api.restore_legacy_history()
        out["legacy"] = {"a": {k: a.get(k) for k in ("restored", "skipped", "backup", "error")}, "b": {k: b.get(k) for k in ("restored", "error")}}
    httpd.shutdown(); httpd.server_close()
    print("@@" + json.dumps(out, ensure_ascii=False))
'''


def main(argv=None) -> int:
    z = Path((argv or sys.argv[1:] or [str(ENGINE.parent / "반출" / f"logtriage-server-{BUILD}.zip")])[0])
    # 시스템 임시 폴더는 권한(ACL)에 다른 주체가 붙어 있어 묶음의 '믿지 않는 쓰기 권한' 시험(삭제 경계·보존)이 환경 탓으로 실패했다 —
    # 개발 트리와 같은 권한인 검증도구 폴더 아래에 푼다
    tmp = Path(tempfile.mkdtemp(prefix="lt-linuxpkg-", dir=str(ENGINE.parent / "검증도구")))
    try:
        with zipfile.ZipFile(z) as zf:
            zf.extractall(tmp / "x")
        root = next((tmp / "x").iterdir())
        eng = root / "engine"
        st = json.loads((eng / "logtriage" / "_build_id.json").read_text(encoding="utf-8"))
        base = tmp / "base"
        base.mkdir()
        for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
            shutil.copytree(eng / d, base / d)
        mig = ENGINE / "deploy" / "local" / "dist" / "incidents.json.migrated"   # 설치본 이관 파일 — 읽기만(복사본으로 시험)
        if mig.is_file():
            shutil.copy2(mig, base / "incidents.json.migrated")
        big = tmp / "big" / "catalina.out"
        big.parent.mkdir()
        rnd = random.Random(40)
        t0 = datetime(2026, 9, 2, 13, 0, 0)
        with open(big, "w", encoding="utf-8", newline="\n") as f:
            n = 0
            while f.tell() < 40 * 1024 * 1024:
                ts = (t0 + timedelta(seconds=n // 50)).strftime("%Y-%m-%d %H:%M:%S") + ",%03d" % (n % 1000)
                if n % 40000 == 7:
                    f.write(f"{ts} ERROR [exec-3] c.z.h.pool.HikariPool - HikariPool-1 - Connection is not available, request timed out after 30001ms.\n")
                elif n % 65000 == 11:
                    f.write(f"{ts} SEVERE [exec-1] java.lang.OutOfMemoryError: Java heap space\n")
                else:
                    f.write(f"{ts} INFO  [exec-{n % 40}] c.e.order.OrderController - order #{n} accepted {rnd.randint(1, 9)}\n")
                n += 1
        (tmp / "probe.py").write_text(PROBE, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        env["PYTHONIOENCODING"] = "utf-8"
        # -I 는 PYTHONIOENCODING 을 무시 — 출력 인코딩은 -X utf8(한글 경로가 깨져 '묶음 엔진' 대조가 틀렸다)
        r = subprocess.run([sys.executable, "-I", "-X", "utf8", str(tmp / "probe.py"), str(eng), str(base), str(big)], cwd=str(tmp), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", env=env, timeout=1800)
        line = next((l for l in r.stdout.splitlines() if l.startswith("@@")), "")
        if not line:
            chk("묶음 엔진 서버 기동", False, (r.stdout[-400:], r.stderr[-800:]))
            return 1
        o = json.loads(line[2:])
        chk("묶음 엔진으로 돌았음(개발 트리 아님)", Path(o["engine_file"]).resolve().is_relative_to(eng.resolve()), o["engine_file"])
        hz = o["healthz"]
        chk("A. /healthz 제품 판·배포 지문·코드 지문", hz.get("build") == BUILD and hz.get("build_id") == st["id"] and hz.get("code_id") == st["code"]
            and not hz.get("code_modified"), {k: hz.get(k) for k in ("build", "build_id", "code_id", "code_modified")})
        chk("B. 서버형 견본 4종", o["samples"] == sorted(["catalina.out", "alert_orcl.log", "SystemOut.log", "listener.log"]), o["samples"])
        sr = o["sample_run"]
        chk("B. 견본 분석 → DEMO- · 판정 > 0", sr["id"].startswith("DEMO-") and sr["f"] > 0 and not sr["err"], sr)
        sol = o["solution"]
        chk("C. OS×제품 해법 5 OS 단계 1·2·3", all(v["stages"] == [1, 2, 3] and not v["err"] for v in sol.values()), sol)
        chk("C. Windows 해법 PowerShell", sol["windows"]["ps"] and not sol["linux"]["ps"], {k: v["ps"] for k, v in sol.items()})
        pr = o["par"]
        chk(f"D. 병렬 = 순차(순차 {pr['1']['sec']}초 · 병렬 {pr['0']['sec']}초)", pr["1"]["f"] == pr["0"]["f"] and pr["1"]["e"] == pr["0"]["e"]
            and pr["1"]["rules"] == pr["0"]["rules"] and pr["1"]["f"] and not pr["0"]["err"], pr)
        if "legacy" in o:
            lg = o["legacy"]
            chk("F. 예전 분석 가져오기(백업·재실행 0)", (lg["a"].get("restored") or 0) > 0 and str(lg["a"].get("backup", "")).startswith("before-legacy-restore-")
                and lg["b"].get("restored") == 0, lg)
        # GPT 93차: 분석만이 아니라 인증·권한·보고서·시연 정리·가져오기·룰팩·되돌리기까지 — 묶음의 **전체 시험**을 묶음 폴더에서
        t = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
                           cwd=str(eng), capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=3600)
        tail = [l for l in (t.stdout + t.stderr).splitlines() if l.startswith(("Ran ", "OK", "FAILED", "FAIL:", "ERROR:"))]
        chk("E. 묶음 안 전체 시험(묶음 폴더에서 실행)", t.returncode == 0, tail[-6:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"[리눅스 묶음 자체 시험] {z.name} — 문제 {len(P)} {P}")
    return 1 if P else 0


if __name__ == "__main__":
    sys.exit(main())
