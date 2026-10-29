"""지식 명령 문법·실행 검사(2026-10-16 아이디어 4 · GPT 55차 조건) — '문법 통과 ≠ 실행 성공 ≠ 진단 정확성'.

  문법(syntax): 검사기가 이 PC 에 실제로 있을 때만 적는다. 없으면 '미실행'으로 남긴다(통과로 치지 않는다).
    · 셸 명령 → bash -n (자리표시 <…> 는 낱말로 바꿔 파싱만 — 실행하지 않음)
    · PowerShell → [Parser]::ParseInput (실행하지 않음)
    · SQL·WLST·도구 고유 명령 → 문법 검사기 없음 → 미실행
  실행(exec): PostgreSQL 제품의 SQL 만, 이 도구가 만들었다가 지우는 **시험용 클러스터**에서.
    · 다른 포트·127.0.0.1 만·로그인 역할은 슈퍼유저 아님 — pg_monitor(1차 대응 조회 계정의 표준 권한. pg_stat_scan_tables 를 포함하므로 '최소 권한'은 아님)
    · 허용 목록: 카탈로그·통계 뷰(pg_*·information_schema)만 FROM/JOIN, 부작용 함수·여러 문장·자리표시 있으면 실행 안 함
    · 읽기 전용 트랜잭션 + statement_timeout 3초 + 결과 100행까지만 읽고 되돌림 — READ ONLY 하나에 기대지 않는다
    · 운영 DB·OldCar DB 는 건드리지 않는다(새 클러스터를 임시 폴더에 만들고 끝나면 지운다)

결과는 errorcodes/_verification.yaml 의 syntax_pass/fail·exec_pass/fail 로(gpt 목록은 보존), 실패 목록은 보고서로.
판정 단위 = 제품:코드(에러코드) 또는 룰 ID — 그 판정의 1차 명령이 하나라도 실패하면 fail, 검사한 것이 모두 통과면 pass.

사용: python tools/build/knowledge_exec_check.py [--pg-bin C:/work/pg/pgsql/bin] [--report 경로] [--no-write]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage import knowledge_quality as KQ  # noqa: E402
from logtriage.codes import load_codes  # noqa: E402
from logtriage.yamlsafe import load as yload  # noqa: E402

PH = re.compile(r"<[^<>|;&\n]{1,40}>")
SQL = re.compile(r"(?is)^\s*(SELECT|SHOW|WITH)\b")
PS = re.compile(r"\b(Get|Select|Where|Sort|Format|Measure|Test|Resolve|Invoke|ForEach|Out|Export|Import|ConvertTo|ConvertFrom)-[A-Za-z]+\b|\$_\b")
# 셸이 아닌 것(문법 검사기 없음 → 미실행): WLST·wsadmin(jython) 호출, jboss-cli 경로, psql 메타, 셸 밖 SQL 조각, 파이프 조각, 로그 문구
OTHER = re.compile(r"^\s*(connect\(|cmo\.|ls\(|cd\(|serverRuntime|domainRuntime|print[ (]|\\[a-z]|\||/[\w.=*-]+(/[\w.=*-]+)*:[\w-]+\(|"
                   r"(DBCC|EXEC|EXECUTE|ALTER|UPDATE|DELETE|INSERT|WHERE|where|and|or|MAX_EXECUTION_TIME|KILL|DECLARE|USE|SET)\b)"
                   r"|^\s*[A-Za-z_][\w.]*\s*=?\s*[A-Za-z_][\w.]*\(.*\)\s*;?\s*$|Admin(Control|Config|App|Task)\.|Help\.|…")
WIN = ("windows", "iis")
PG_REL = re.compile(r"(?i)\b(FROM|JOIN)\s+([A-Za-z_][\w.]*)(\s*\()?")
PG_DENY = re.compile(r"(?i)\b(pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|set_config|pg_read_file|pg_read_binary_file|"
                     r"pg_ls_\w+|pg_stat_file|lo_\w+|dblink\w*|pg_sleep\w*|pg_switch_wal|pg_create_\w+|pg_drop_\w+|pg_promote|pg_stat_reset\w*|"
                     r"nextval|setval|pg_advisory\w*|pg_logical_\w+|pg_replication_\w+_advance|copy|insert|update|delete|alter|create|drop|grant|"
                     r"revoke|truncate|vacuum|analyze|cluster|reindex|lock|listen|notify|do|call|prepare|execute|set|reset|load)\b")
PORT = 55439
DBS = {"oracle", "tibero", "mssql", "mysql", "altibase", "cubrid", "goldilocks", "postgresql"}


def collect() -> dict[str, list[dict]]:
    """판정 키 → [{cmd, product}] — 화면이 보여 주는 1차 명령(즉시 조치 줄의 백틱 명령)과 같은 것."""
    out: dict[str, list[dict]] = {}
    for k, e in load_codes(ENGINE / "errorcodes").items():
        if ":" in k:
            for x in KQ.first_commands(e.immediate):
                out.setdefault(k.upper(), []).append({"cmd": x["cmd"], "product": e.product, "tail": x.get("tail", "")})
    for f in sorted((ENGINE / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                prods = r.get("product") or ["*"]
                prod = str((prods if isinstance(prods, list) else [prods])[0]).lower()
                for x in KQ.first_commands(r.get("immediate") or []):
                    out.setdefault(str(r["id"]).upper(), []).append({"cmd": x["cmd"], "product": prod, "tail": x.get("tail", "")})
    return out


def kind(cmd: str, product: str) -> str:
    if OTHER.search(cmd):
        return "other"
    if SQL.search(cmd):
        return "sql"
    if PS.search(cmd) or (product in WIN and not re.search(r"\b(grep|awk|tail|sed)\b", cmd)):
        return "ps" if PS.search(cmd) else "other"   # cmd.exe 명령(wevtutil·netsh 등)은 문법 검사기가 없다
    return "sh"


def check_shell(cmds: list[str], work: Path, jobs: int = 8) -> dict[str, str]:
    """bash -n — 실행하지 않고 파싱만. 반환: 명령 → '' (통과) 또는 오류 글. 폴더를 나눠 bash 여러 개로 동시에(Git bash 의 프로세스 생성이 느리다)."""
    bash = shutil.which("bash")
    if not bash:
        return {}
    idx = {}
    dirs = [work / f"sh{k}" for k in range(jobs)]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    for i, c in enumerate(cmds):
        p = dirs[i % jobs] / f"{i}.sh"
        p.write_text(PH.sub("PLACEHOLDER", c) + "\n", encoding="utf-8", newline="\n")
        idx[str(i)] = c
    script = 'cd "$1"; for f in *.sh; do e=$(bash -n "$f" 2>&1); if [ -n "$e" ]; then printf "%s\\t%s\\n" "${f%.sh}" "$(printf %s "$e" | head -1)"; fi; done'
    procs = [subprocess.Popen([bash, "-c", script, "_", d.as_posix()], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace") for d in dirs]
    out = "".join(pr.communicate(timeout=1800)[0] for pr in procs)
    bad = {}
    for line in out.splitlines():
        if "\t" in line:
            i, e = line.split("\t", 1)
            bad[idx.get(i, "")] = e[:200]
    return {c: bad.get(c, "") for c in cmds}


def check_ps(cmds: list[str], work: Path) -> dict[str, str]:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps or not cmds:
        return {}
    src = work / "ps_in.json"
    dst = work / "ps_out.json"
    src.write_text(json.dumps([PH.sub("PLACEHOLDER", c) for c in cmds], ensure_ascii=False), encoding="utf-8")
    code = ("$a = Get-Content -Raw -Encoding UTF8 '%s' | ConvertFrom-Json; $o = @(); foreach ($c in $a) { $t=$null; $e=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseInput($c,[ref]$t,[ref]$e); "
            "if ($e -and $e.Count) { $o += $e[0].Message } else { $o += '' } }; "
            "ConvertTo-Json -InputObject $o | Set-Content -Encoding UTF8 '%s'") % (src, dst)
    subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", code], capture_output=True, timeout=600)
    try:
        res = json.loads(dst.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {}
    if isinstance(res, str):
        res = [res]
    return {c: str(res[i] or "")[:200] for i, c in enumerate(cmds) if i < len(res)}


def pg_allowed(sql: str) -> str:
    """실행해도 되는 질의인지 — 안 되면 사유. 자리표시·여러 문장·카탈로그 밖 테이블·부작용 함수는 실행하지 않는다."""
    s = sql.strip().rstrip(";").strip()
    if PH.search(s) or "<" in s and ">" in s and re.search(r"<\w", s):
        return "자리표시 있음"
    if ";" in s:
        return "여러 문장"
    body = re.sub(r"'[^']*'", "''", s)
    if PG_DENY.search(re.sub(r"(?i)^\s*(SELECT|SHOW|WITH)\b", "", body)) and not re.match(r"(?i)^\s*SHOW\s+\w+\s*$", body):
        return "허용 목록 밖 낱말(부작용 가능)"
    for m in PG_REL.finditer(body):
        name = m.group(2).lower()
        if m.group(3):      # FROM 함수( … ) — 집합 반환 함수는 pg_ 통계 함수만
            if not name.startswith(("pg_stat", "pg_ls_waldir", "pg_show", "pg_get", "generate_series", "unnest")):
                return f"허용 목록 밖 함수 {name}"
            continue
        if not (name.startswith(("pg_", "pg_catalog.", "information_schema.")) or name in ("unnest",)):
            return f"허용 목록 밖 테이블 {name}"
    return ""


def pg_version(bindir: Path) -> str:
    r = subprocess.run([str(bindir / ("postgres" + (".exe" if os.name == "nt" else ""))), "--version"],
                       capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    m = re.search(r"(\d+)(?:\.\d+)?", r.stdout or "")
    return m.group(1) if m else ""


class ScratchPG:
    """버리는 시험용 PostgreSQL — 임시 폴더·다른 포트·127.0.0.1. 끝나면 멈추고 지운다."""

    def __init__(self, bindir: Path, work: Path):
        import secrets
        self.bin, self.dir = bindir, work / "pgdata"
        self.ok = False
        # GPT 56차: 127.0.0.1 이라도 trust 로 두지 않는다 — 실행마다 새로 만든 무작위 비밀번호(SCRAM), 클러스터와 함께 지운다
        self.pw_owner, self.pw_check = secrets.token_urlsafe(24), secrets.token_urlsafe(24)

    def __enter__(self):
        exe = lambda n: str(self.bin / (n + (".exe" if os.name == "nt" else "")))  # noqa: E731
        pwf = self.dir.parent / "pw.txt"
        pwf.write_text(self.pw_owner, encoding="utf-8")
        try:
            r = subprocess.run([exe("initdb"), "-D", str(self.dir), "-U", "ltowner", "--auth=scram-sha-256", f"--pwfile={pwf}",
                                "-E", "UTF8", "--no-locale"], capture_output=True, text=True, timeout=300)
        finally:
            pwf.unlink(missing_ok=True)
        if r.returncode:
            raise RuntimeError("initdb 실패: " + (r.stderr or r.stdout)[-300:])
        r = subprocess.run([exe("pg_ctl"), "-D", str(self.dir), "-w", "-t", "60", "-l", str(self.dir.parent / "pg.log"),
                            "-o", f"-p {PORT} -c listen_addresses=127.0.0.1", "start"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        # 출력을 잡지 않는다 — Windows 에서 서버가 파이프를 물려받아 pg_ctl 이 끝나도 run() 이 영영 기다린다(10-16 실측). 기록은 -l 파일로
        if r.returncode:
            raise RuntimeError("pg_ctl start 실패: " + (self.dir.parent / "pg.log").read_text(encoding="utf-8", errors="replace")[-300:])
        self.ok = True
        import psycopg2
        c = psycopg2.connect(host="127.0.0.1", port=PORT, user="ltowner", password=self.pw_owner, dbname="postgres")
        c.autocommit = True
        cur = c.cursor()
        # INHERIT 여야 아래 조회용 내장 역할이 실제로 적용된다(NOINHERIT 로 두면 '권한 거부'가 거짓으로 난다 — 10-16 실측)
        cur.execute("CREATE ROLE ltcheck LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION CONNECTION LIMIT 2 PASSWORD %s",
                    (self.pw_check,))
        cur.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
        cur.execute("ALTER ROLE ltcheck SET temp_file_limit = '16MB'")
        cur.execute("GRANT pg_monitor TO ltcheck")   # = pg_read_all_settings + pg_read_all_stats + pg_stat_scan_tables(1차 대응 조회 계정의 표준 권한)
        cur.execute("ALTER ROLE ltcheck SET default_transaction_read_only = on")
        cur.execute("ALTER ROLE ltcheck SET statement_timeout = '3s'")
        c.close()
        return self

    def run(self, sql: str) -> str:
        import psycopg2
        s = sql.strip().rstrip(";")
        try:
            c = psycopg2.connect(host="127.0.0.1", port=PORT, user="ltcheck", password=self.pw_check, dbname="postgres", connect_timeout=5)
        except Exception as e:  # noqa: BLE001
            return f"접속 실패 {e}"[:200]
        try:
            cur = c.cursor()
            cur.execute("BEGIN READ ONLY")
            cur.execute("SET LOCAL statement_timeout = '3s'")
            cur.execute("SET LOCAL work_mem = '4MB'")
            cur.execute(s)
            if cur.description:
                cur.fetchmany(100)
            return ""
        except Exception as e:  # noqa: BLE001
            return str(e).strip().splitlines()[0][:200]
        finally:
            try:
                c.rollback()
                c.close()
            except Exception:  # noqa: BLE001
                pass

    def __exit__(self, *a):
        if self.ok:
            exe = str(self.bin / ("pg_ctl" + (".exe" if os.name == "nt" else "")))
            subprocess.run([exe, "-D", str(self.dir), "-m", "immediate", "-w", "stop"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        for _ in range(5):
            try:
                shutil.rmtree(self.dir.parent, ignore_errors=False)
                break
            except OSError:
                time.sleep(1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pg-bin", default="C:/work/pg/pgsql/bin")
    ap.add_argument("--report", default=str(ENGINE / "deploy" / "local" / "지식검증" / "실행검증.md"))
    ap.add_argument("--no-write", action="store_true", help="_verification.yaml 을 고치지 않음(보고서만)")
    a = ap.parse_args(argv)
    entries = collect()
    allc = {(x["cmd"], x["product"]) for v in entries.values() for x in v}
    by_kind: dict[str, set] = {"sh": set(), "ps": set(), "sql": set(), "other": set()}
    for c, p in allc:
        by_kind[kind(c, p)].add(c)
    work = Path(tempfile.mkdtemp(prefix="lt-exec-"))
    try:
        syn = {}
        syn.update(check_shell(sorted(by_kind["sh"]), work))
        syn.update(check_ps(sorted(by_kind["ps"]), work))
        pg_sql = sorted({x["cmd"] for v in entries.values() for x in v if x["product"] == "postgresql" and kind(x["cmd"], "postgresql") == "sql"})
        exe: dict[str, str] = {}
        skipped: dict[str, str] = {}
        bindir = Path(a.pg_bin)
        if pg_sql and (bindir / ("initdb" + (".exe" if os.name == "nt" else ""))).exists():
            pgver = pg_version(bindir)
            # 명령 뒤 판 표기가 시험 클러스터 판과 어긋나면(예: '(16 이하)' 인데 시험 DB 가 17) 실행하지 않는다 — 실패로 세면 거짓 결함
            off = {x["cmd"] for v in entries.values() for x in v
                   if x["product"] == "postgresql" and KQ.version_fit(x.get("tail", ""), "postgresql", pgver) == "어긋남"}
            su = {x["cmd"] for v in entries.values() for x in v if x["product"] == "postgresql" and "superuser" in x.get("tail", "").lower()}
            runnable = []
            for q in pg_sql:
                why = (f"판 표기가 시험 DB({pgver})와 다름" if q in off
                       else "superuser 필요 표기 — 조회 전용(pg_monitor) 시험 계정으로는 실행하지 않음" if q in su else pg_allowed(q))
                (skipped.__setitem__(q, why) if why else runnable.append(q))
            if runnable:
                pgw = work / "pg"
                pgw.mkdir()
                with ScratchPG(bindir, pgw) as pg:
                    for q in runnable:
                        exe[q] = pg.run(q)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    res = {"syntax_pass": [], "syntax_fail": [], "exec_pass": [], "exec_fail": []}
    fails = []
    for key, cs in sorted(entries.items()):
        st = [syn[x["cmd"]] for x in cs if x["cmd"] in syn]
        if st:
            res["syntax_fail" if any(st) else "syntax_pass"].append(key)
        ex = [exe[x["cmd"]] for x in cs if x["cmd"] in exe]
        if ex:
            res["exec_fail" if any(ex) else "exec_pass"].append(key)
        for x in cs:
            if syn.get(x["cmd"]):
                fails.append(("문법", key, x["cmd"], syn[x["cmd"]]))
            if exe.get(x["cmd"]):
                fails.append(("실행", key, x["cmd"], exe[x["cmd"]]))
    n = {k: len(v) for k, v in by_kind.items()}
    summary = (f"명령 {len(allc)}개(판정 {len(entries)}개) — 셸 {n['sh']} · PowerShell {n['ps']} · SQL {n['sql']} · 기타(검사기 없음) {n['other']}\n"
               f"문법: 통과 판정 {len(res['syntax_pass'])} · 실패 판정 {len(res['syntax_fail'])}  |  "
               f"실행(PostgreSQL 시험 클러스터): 실행 {len(exe)} · 실패 {sum(1 for v in exe.values() if v)} · 허용 목록 밖이라 안 함 {len(skipped)}")
    print(summary)
    rp = Path(a.report)
    rp.parent.mkdir(parents=True, exist_ok=True)
    rp.write_text("# 지식 명령 문법·실행 검사\n\n" + summary.replace("\n", "  \n") +
                  "\n\n문법 통과 ≠ 실행 성공 ≠ 진단 정확성. SQL(PostgreSQL 외)·WLST·cmd.exe 명령은 검사기가 없어 '미실행'으로 남깁니다.\n\n"
                  "## 실패\n\n" + ("\n".join(f"- [{k}] `{key}` — `{c[:160]}` → {e}" for k, key, c, e in fails) or "없음") +
                  "\n\n## 실행하지 않은 PostgreSQL 질의(사유)\n\n" + ("\n".join(f"- `{q[:120]}` → {w}" for q, w in skipped.items()) or "없음") + "\n",
                  encoding="utf-8")
    if not a.no_write:
        import yaml
        vp = ENGINE / "errorcodes" / "_verification.yaml"
        txt = vp.read_text(encoding="utf-8")
        head = "".join(l + "\n" for l in txt.splitlines() if l.startswith("#"))
        doc = yaml.safe_load(txt) or {}
        doc.update(res)
        # 7차 아이디어 4: SQL·도구 명령이 있는데 시험 환경이 없는 제품 — 배지가 '미실행' 대신 '시험 환경 없음'
        na = {}
        for v in entries.values():
            for x in v:
                pr = str(x["product"]).lower()
                if pr in ("postgresql", "*", ""):
                    continue
                kd = kind(x["cmd"], pr)
                if kd not in ("sql", "other"):
                    continue
                if pr in DBS:
                    na[pr] = "시험 DB 없음 — 이 PC 에 Docker·WSL 이 없고 이 제품의 시험 인스턴스(상용 라이선스)가 없음"
                else:
                    na.setdefault(pr, "시험 서버 없음 — 제품 관리 도구(WLST·jeusadmin·wsadmin·appcmd 등)나 연동 DB 를 돌릴 시험 설치본이 없음")
        doc["exec_unavailable"] = dict(sorted(na.items()))
        # 12차(PC·리눅스 같은 판): 결과가 같으면 파일을 다시 쓰지 않는다 — 검사 시각 한 줄만 바뀌어도 지식 지문이 달라져,
        # 지식 출시 때마다 설치본과 이미 빌드한 PC exe 내장 지식·리눅스 묶음이 '다른 판'이 됐다(판 대조가 잡음)
        old = yaml.safe_load(txt) or {}
        old_check = dict(old.get("exec_check") or {})
        new_check = {"at": time.strftime("%Y-%m-%d %H:%M"), "summary": summary.replace("\n", " / ")}
        same = {k: v for k, v in old.items() if k != "exec_check"} == {k: v for k, v in doc.items() if k != "exec_check"} \
            and old_check.get("summary") == new_check["summary"]
        doc["exec_check"] = old_check if same else new_check
        if not same:
            vp.write_text(head + yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")
        else:
            print("결과가 지난번과 같아 _verification.yaml 을 고치지 않음(지식 지문 유지)")
    print("보고서:", rp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
