"""되돌리기 예행연습(9차 아이디어 ⑧) — '되돌리기 판(이전판)의 코드가 지금 판이 만든 **분석 DB(logtriage.db)** 를 열고 읽는가'와
'되돌리면 무엇을 잃거나 잘못 읽는가'를 판마다 확인한다. (rollback_compat 은 서식·룰만 본다 — DB 는 열지 않는다. 그 공백을 메운다.)

  1) 지금 코드로 시험 DB 를 만든다 — 모든 표에 줄이 있게(분석 건·판 지정(인스턴스 포함)·현장 보고·장애 묶음·피드백·사후 원인)
     (--db 를 주면 그 DB 의 **사본**을 쓴다 — 예: exe_guard --clone-data 로 떠 온 설치본 자료)
  2) 되돌리기 판의 자체 소스 스냅숏(backup/src/src-<해시>.zip)을 rollback_compat 과 같은 울타리(감사 훅) 안에서 돌려
     Storage 열기·history·get·count·host_versions·feedback_summary·postmortem_review 를 부른다
  3) 잃는 것·잘못 읽는 것 목록(지금 코드로 센다): 현장 보고·장애 묶음 줄 수(옛 판은 표를 모름 — 화면에 안 보임),
     인스턴스별 판 기록(옛 판은 (호스트, 제품)으로만 읽어 인스턴스가 다른 기록이 **섞여 마지막 것 하나로** 읽힘 — 잘못된 판 적용 위험)
결과: deploy/local/build/rollback_rehearsal.json — build_ledger 가 '되돌리기 자격'에 함께 적는다.
사용: python tools/build/rollback_rehearsal.py [--db <logtriage.db 사본으로 쓸 파일>]
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rollback_compat as rbc  # noqa: E402

RESULT = rbc.LOCAL / "build" / "rollback_rehearsal.json"

OLD_DB_SCRIPT = r'''
import json, sys, traceback
from pathlib import Path
db = Path(sys.argv[1]); steps = {}
def step(n, f):
    try:
        steps[n] = {"ok": True, "info": str(f())[:200]}
    except Exception as e:
        steps[n] = {"ok": False, "error": f"{type(e).__name__}: {str(e)[:160]}"}
from logtriage import storage
st = None
def _open():
    global st
    st = storage.Storage("sqlite:///" + db.as_posix()); return st.describe()
step("open", _open)
if st:
    step("history", lambda: len(st.history(50)))
    step("count", lambda: st.count())
    step("get", lambda: bool(st.get("RB-1")))
    if hasattr(st, "host_versions"):
        step("host_versions", lambda: sorted(map(str, st.host_versions(["db1"]).keys())))
    if hasattr(st, "feedback_summary"):
        step("feedback_summary", lambda: len(st.feedback_summary()))
    if hasattr(st, "postmortem_review"):
        step("postmortem_review", lambda: len(st.postmortem_review()))
    # GPT 70차 P0: 읽기만으로는 쓰기 안전이 아니다 — 격리 사본에 옛 코드로 써 본다(부모가 새 코드로 다시 읽어 확인)
    step("write_incident", lambda: st.save_incident({"id": "RB-OLD", "analyzed_at": "2026-10-19T12", "first": {}, "files": [{"name": "o", "product": "postgresql", "host": "db1"}],
                                                       "checklist": [{"rule_id": "R1", "product": "postgresql"}]}))
    if hasattr(st, "add_feedback"):
        step("write_feedback", lambda: st.add_feedback("R1", "b" * 16, "ok", "", {"login": "old"}, "RB-OLD"))
    if hasattr(st, "set_host_version"):
        step("write_host_version", lambda: st.set_host_version("db1", "postgresql", "15", "", {"login": "old"}))
print(json.dumps({"steps": steps}, ensure_ascii=False))
'''


def reread(path: Path, before: dict) -> dict:
    """옛 코드가 쓴 뒤 새 코드로 다시 읽기 — 무결성·새 표 그대로·옛 줄 읽힘·인스턴스 기록 그대로."""
    from logtriage import storage
    c = sqlite3.connect(str(path))
    ok_int = c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    c.close()
    st = storage.Storage("sqlite:///" + path.as_posix())
    hv = st.host_versions(["db1"])
    after = losses(path)
    res = {"integrity": ok_int, "old_incident": bool(st.get("RB-OLD")),
           "new_tables_kept": after["exec_reports"] >= before.get("exec_reports", 0) and after["incident_groups"] >= before.get("incident_groups", 0),
           "instance_rows_kept": sum(1 for k in hv if k[2]) >= before.get("instance_versions", 0),
           "old_row_hostwide": ("db1", "postgresql", "") in hv}
    res["ok"] = all(res.values())
    return res


def make_db(path: Path) -> None:
    from logtriage import storage
    st = storage.Storage("sqlite:///" + path.as_posix())
    for i in (1, 2):
        st.save_incident({"id": f"RB-{i}", "analyzed_at": f"2026-10-1{i}T10", "first": {"verdict": "데드락", "rule_id": "R1"},
                          "files": [{"name": "a", "product": "postgresql", "host": "db1", "instance": f"pg1{5 + i}"}],
                          "checklist": [{"rule_id": "R1", "product": "postgresql", "cmds": [{"cmd": "select 1;", "safe": True, "hash": "a" * 16}]}]})
    st.set_host_version("db1", "postgresql", "16", actor={"login": "op"}, instance="pg16")
    st.set_host_version("db1", "postgresql", "17", actor={"login": "op"}, instance="pg17")
    st.add_feedback("R1", "a" * 16, "version", "", {"login": "op"}, "RB-1")
    st.add_exec_report("R1", "a" * 16, "ok", "", ["TYPE", "ID1"], "postgresql", "16", {"login": "op"}, "RB-1")
    st.set_postmortem("RB-1", "실제는 스토리지", "confirmed", "no", "제조사 RCA 보고서로 확인", {"login": "op"})
    st.set_incident_group(["RB-1", "RB-2"], "G-1", "같은 장애 두 번 분석", {"login": "op"})


def losses(path: Path) -> dict:
    c = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        tabs = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        n = lambda q: int(c.execute(q).fetchone()[0]) if q.split(" FROM ")[1].split()[0] in tabs else 0  # noqa: E731
        hv_cols = {r[1] for r in c.execute("PRAGMA table_info(host_versions)")} if "host_versions" in tabs else set()
        mixed = 0
        if "instance" in hv_cols:
            mixed = int(c.execute("SELECT COUNT(*) FROM (SELECT host, product FROM host_versions WHERE COALESCE(instance,'')<>'' "
                                  "GROUP BY host, product HAVING COUNT(DISTINCT version) > 1)").fetchone()[0])
        return {"exec_reports": n("SELECT COUNT(*) FROM exec_reports"), "incident_groups": n("SELECT COUNT(*) FROM incident_groups"),
                "instance_versions": int(c.execute("SELECT COUNT(*) FROM host_versions WHERE COALESCE(instance,'')<>''").fetchone()[0]) if "instance" in hv_cols else 0,
                "instance_conflicts": mixed}
    finally:
        c.close()


def run(snap: Path, db_src: Path | None = None) -> dict:
    res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "snapshot": snap.name, "result": "fail", "steps": {}, "losses": {}}
    why = rbc.verify_snapshot(snap)
    if why:
        res["steps"] = {"integrity": {"ok": False, "error": why}}
        return res
    work = Path(tempfile.mkdtemp(prefix="lt_rbr_"))
    try:
        db = work / "logtriage.db"
        if db_src:
            a = sqlite3.connect(f"file:{Path(db_src).as_posix()}?mode=ro", uri=True)
            b = sqlite3.connect(str(db))
            a.backup(b)
            b.close()
            a.close()
        else:
            make_db(db)
        res["losses"] = losses(db)
        old = work / "old"
        with zipfile.ZipFile(snap) as z:
            for nm in z.namelist():
                if nm.startswith("/") or ".." in Path(nm).parts or not nm.startswith("logtriage/"):
                    raise ValueError(f"스냅숏 안에 허용되지 않는 경로: {nm[:60]}")
            z.extractall(old)
        script = work / "old_db.py"
        script.write_text(rbc.GUARD + OLD_DB_SCRIPT, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if k.upper() in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "COMSPEC", "PATHEXT")}
        env.update({"PYTHONIOENCODING": "utf-8", "PYTHONPATH": str(old), "PYTHONDONTWRITEBYTECODE": "1", "TEMP": str(work), "TMP": str(work)})
        # GUARD 는 argv[3] 을 작업 폴더로 본다 — 자리를 맞춘다(argv[1]=DB, argv[2]=빈칸, argv[3]=작업 폴더)
        r = subprocess.run([sys.executable, "-I", "-c", f"import sys;sys.path.insert(0,{str(old)!r});exec(open({str(script)!r},encoding='utf-8').read())",
                            str(db), "-", str(work)], capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=300, cwd=str(work))
        try:
            out = json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"steps": {"run": {"ok": False, "error": (r.stderr or r.stdout)[-300:]}}}
        res["steps"] = out["steps"]
        if "write_incident" in res["steps"]:
            rr = reread(db, res["losses"])
            res["steps"]["reread_by_new"] = {"ok": rr["ok"], "info": json.dumps(rr, ensure_ascii=False)} if rr["ok"] else \
                {"ok": False, "error": json.dumps(rr, ensure_ascii=False)}
        res["result"] = "pass" if res["steps"] and all(s.get("ok") for s in res["steps"].values()) else "fail"
    except Exception as e:   # noqa: BLE001
        res["steps"] = {"setup": {"ok": False, "error": f"{type(e).__name__}: {e}"}}
    finally:
        shutil.rmtree(work, ignore_errors=True)
    lo = res["losses"]
    res["note"] = (f"되돌리면 화면에서 사라지는 것: 현장 보고 {lo.get('exec_reports', 0)}줄 · 장애 묶음 {lo.get('incident_groups', 0)}줄 · "
                   f"인스턴스별 판 기록 {lo.get('instance_versions', 0)}줄(옛 판은 인스턴스를 모름 — 판이 다른 인스턴스 기록이 있는 호스트·제품 "
                   f"{lo.get('instance_conflicts', 0)}곳은 마지막 기록 하나로 섞여 읽힘: 되돌리기 전에 그 호스트의 판 지정을 다시 확인)")
    return res


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    exe = rbc.LOCAL / "dist" / "LogTriage.exe.이전판"
    snap = rbc.SRC / f"src-{rbc.sha16(exe)}.zip" if exe.is_file() else None
    db = Path(argv[argv.index("--db") + 1]) if "--db" in argv else None
    if not snap or not snap.is_file():
        res = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "result": "no_snapshot", "steps": {}, "losses": {}, "note": "되돌리기 판의 소스 스냅숏이 없습니다"}
    else:
        res = run(snap, db)
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"되돌리기 예행(DB): {res['result']} — " + " · ".join(f"{k} {'통과' if v.get('ok') else '실패: ' + v.get('error', '')}" for k, v in res["steps"].items()))
    print(res.get("note", ""))
    return 0 if res["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
