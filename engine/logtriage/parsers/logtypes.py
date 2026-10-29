"""로그 종류 카탈로그 기반 추가 파서 — 제품 공통 코드 사전을 쓰도록 product 는 기존 제품명 유지.

  oracle-listener : listener.log (접속 establish 라인의 return code, TNS- 메시지)
  mysql-slow      : slow query log (# Time / # User@Host / # Query_time … SQL)
  postgresql-csv  : csvlog (log_time,user,db,pid,…,error_severity,sql_state_code,message,…)
  iis-httperr     : HTTP.sys 오류 로그 (#Fields: date time c-ip … sc-status s-siteid s-reason s-queuename)
  aix-errpt       : errpt 요약(IDENTIFIER TIMESTAMP T C RESOURCE DESCRIPTION) 및 errpt -a 상세
"""
from __future__ import annotations

import csv
import re
from datetime import datetime
from pathlib import Path

from ..schema import Event
from . import EventSink, iter_lines, register, fast_strptime

# ── Oracle listener.log ───────────────────────────────────────
# 09-SEP-2026 14:02:11 * (CONNECT_DATA=(SERVICE_NAME=orcl)...) * (ADDRESS=(PROTOCOL=tcp)(HOST=10.0.0.5)(PORT=51234)) * establish * orcl * 12514
# 09-SEP-2026 14:02:11 * service_update * orcl * 0
# TNS-12541: TNS:no listener   (독립 라인)
_LSNR_LINE = re.compile(r"^(\d{2}-[A-Z]{3}-\d{4} \d{2}:\d{2}:\d{2})\s*\*\s*(.*)$")
_LSNR_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
_TNS = re.compile(r"\b(TNS-\d{5})\b")
_HOST = re.compile(r"\(HOST=([^)]+)\)")
_SVC = re.compile(r"SERVICE_NAME=([^)]+)")


def _lsnr_ts(s: str) -> datetime | None:
    for fmt in ("%d-%b-%Y %H:%M:%S",):
        try:
            return fast_strptime(s.title(), fmt)
        except ValueError:
            pass
    return None


@register("oracle-listener", "db")
def parse_oracle_listener(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur_ts: datetime | None = None
    for i, line in iter_lines(path):
        s = line.strip()
        if not s:
            continue
        m = _LSNR_LINE.match(s)
        if m:
            cur_ts = _lsnr_ts(m.group(1)) or cur_ts
            parts = [p.strip() for p in m.group(2).split("*")]
            rc = parts[-1] if parts else ""
            action = next((p for p in parts if p in ("establish", "service_update", "ping",
                                                     "status", "stop", "reload", "version")), "")
            if not rc.isdigit():
                continue
            code = f"TNS-{int(rc):05d}" if rc != "0" else None
            client = _HOST.search(m.group(2))
            svc = _SVC.search(m.group(2))
            if code:
                msg = (f"{action or 'request'} 실패 rc={rc} ({code}) service={svc.group(1) if svc else '?'} "
                       f"client={client.group(1) if client else '?'}")
                sev = "error"
            elif action in ("stop",):
                msg, sev = f"listener {action}", "warn"
            else:
                msg, sev = f"{action or 'request'} ok service={svc.group(1) if svc else '?'}", "info"
            events.append(Event(ts=cur_ts or datetime.now(), host=host, layer="db", product="oracle",
                                severity=sev, code=code, message=msg, raw_ref=f"{path}:{i}-{i}"))
            continue
        m = _LSNR_ISO.match(s)
        if m:
            cur_ts = fast_strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
        t = _TNS.search(s)
        if t and cur_ts:
            events.append(Event(ts=cur_ts, host=host, layer="db", product="oracle",
                                severity="error", code=t.group(1), message=s[:300],
                                raw_ref=f"{path}:{i}-{i}"))
    return events


# ── MySQL slow query log ──────────────────────────────────────
# # Time: 2026-09-09T14:02:11.123456Z
# # User@Host: app[app] @ was1 [10.0.0.5]  Id: 123
# # Query_time: 12.345678  Lock_time: 0.000123 Rows_sent: 1  Rows_examined: 1234567
# SET timestamp=1757394131;
# SELECT ...;
_SLOW_TIME = re.compile(r"^# Time: (\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})")
_SLOW_OLD = re.compile(r"^# Time: (\d{6}) +(\d{1,2}:\d{2}:\d{2})")
_SLOW_Q = re.compile(r"^# Query_time: ([\d.]+) +Lock_time: ([\d.]+) +Rows_sent: (\d+) +Rows_examined: (\d+)")
_SLOW_USER = re.compile(r"^# User@Host: (\S+).*?@ *(\S*) *\[([^\]]*)\]")
_SLOW_TS_SET = re.compile(r"^SET timestamp=(\d+);")


@register("mysql-slow", "db")
def parse_mysql_slow(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur_ts: datetime | None = None
    q = None
    user = ""
    start = 0
    sql: list[str] = []

    def flush(end: int):
        nonlocal q, sql
        if q is None:
            return
        qt, lt, rs, re_ = q
        sev = "critical" if qt >= 60 else "error" if qt >= 10 else "warn"
        text = " ".join(x.strip() for x in sql if x.strip() and not x.startswith("SET timestamp") and not x.startswith("use "))
        events.append(Event(ts=cur_ts or datetime.now(), host=host, layer="db", product="mysql",
                            severity=sev, code="MY-SLOW-QUERY",
                            message=f"slow query {qt:.1f}s (lock {lt:.3f}s, examined {re_}, sent {rs}) {user} :: {text[:200]}",
                            raw_ref=f"{path}:{start}-{end}"))
        q, sql = None, []

    for i, line in iter_lines(path):
        m = _SLOW_TIME.match(line)
        if m:
            flush(i - 1)
            cur_ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            continue
        m = _SLOW_OLD.match(line)
        if m:
            flush(i - 1)
            cur_ts = fast_strptime(f"{m.group(1)} {m.group(2)}", "%y%m%d %H:%M:%S")
            continue
        m = _SLOW_USER.match(line)
        if m:
            flush(i - 1)
            user = f"user={m.group(1)} from={m.group(2) or m.group(3)}"
            start = i
            continue
        m = _SLOW_Q.match(line)
        if m:
            q = (float(m.group(1)), float(m.group(2)), int(m.group(3)), int(m.group(4)))
            if not start:
                start = i
            continue
        m = _SLOW_TS_SET.match(line)
        if m:
            cur_ts = datetime.fromtimestamp(int(m.group(1)))
            continue
        if q is not None and not line.startswith("#"):
            sql.append(line)
            if line.rstrip().endswith(";"):
                flush(i)
                start = 0
    flush(0)
    return events


# ── PostgreSQL csvlog ─────────────────────────────────────────
_PG_COLS = ["log_time", "user_name", "database_name", "process_id", "connection_from",
            "session_id", "session_line_num", "command_tag", "session_start_time",
            "virtual_transaction_id", "transaction_id", "error_severity", "sql_state_code",
            "message", "detail", "hint", "internal_query", "internal_query_pos", "context",
            "query", "query_pos", "location", "application_name", "backend_type",
            "leader_pid", "query_id"]
_PG_SEV = {"PANIC": "critical", "FATAL": "critical", "ERROR": "error", "WARNING": "warn"}


@register("postgresql-csv", "db")
def parse_postgresql_csv(path: Path, host: str) -> list[Event]:
    events = EventSink()
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for i, row in enumerate(csv.reader(f), 1):
            if len(row) < 14:
                continue
            try:
                ts = fast_strptime(row[0][:19], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                continue
            sev_word = row[11].strip().upper()
            sev = _PG_SEV.get(sev_word, "info")
            state = row[12].strip()
            code = state if state and state != "00000" else None
            msg = f"{sev_word}: {row[13].strip()}"
            if row[14].strip():
                msg += f" | DETAIL: {row[14].strip()[:150]}"
            if row[1].strip() or row[2].strip():
                msg += f" (user={row[1].strip()} db={row[2].strip()})"
            events.append(Event(ts=ts, host=host, layer="db", product="postgresql",
                                severity=sev, code=code, message=msg[:600],
                                raw_ref=f"{path}:{i}-{i}"))
    return events


# ── IIS HTTPERR (HTTP.sys) ────────────────────────────────────
_HTTPERR_CRIT = {"QueueFull", "AppOffline", "AppPoolTimer", "AppShutdown",
                 "Connection_Abandoned_By_ReqQueue", "Connection_Abandoned_By_AppPool",
                 "ConnLimit", "Connection_Dropped_List_Full"}
_HTTPERR_WARN_PREFIX = ("Timer_", "Client_Reset")


@register("iis-httperr", "web")
def parse_iis_httperr(path: Path, host: str) -> list[Event]:
    events = EventSink()
    fields: list[str] = []
    for i, line in iter_lines(path):
        if line.startswith("#Fields:"):
            fields = line.split()[1:]
            continue
        if line.startswith("#") or not line.strip() or not fields:
            continue
        parts = line.split()
        if len(parts) < len(fields):
            parts += ["-"] * (len(fields) - len(parts))
        row = dict(zip(fields, parts))
        try:
            ts = fast_strptime(f"{row.get('date','')} {row.get('time','')}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        reason = row.get("s-reason", "-")
        if reason in _HTTPERR_CRIT:
            sev = "critical"
        elif reason.startswith(_HTTPERR_WARN_PREFIX):
            sev = "warn"
        else:
            sev = "error"
        status = row.get("sc-status", "-")
        events.append(Event(
            ts=ts, host=host, layer="web", product="iis", severity=sev,
            code=f"HTTP-{status}" if status.isdigit() and status.startswith("5") else None,
            message=f"HTTPERR {reason} status={status} {row.get('cs-method','-')} {row.get('cs-uri','-')} "
                    f"client={row.get('c-ip','-')} pool={row.get('s-queuename','-')}",
            raw_ref=f"{path}:{i}-{i}"))
    return events


# ── AIX errpt ─────────────────────────────────────────────────
# 요약: DCB47997   0909140226 T H hdisk3         DISK OPERATION ERROR
# 상세(errpt -a): LABEL: / IDENTIFIER: / Date/Time: Tue Sep  9 14:02:26 KST 2026 / Type: PERM / Class: H / Description
_ERRPT_SUM = re.compile(r"^([0-9A-F]{8})\s+(\d{10})\s+([TPIU])\s+([HSOU])\s+(\S+)\s+(.*)$")
_ERRPT_DT = re.compile(r"^Date/Time:\s+(.*)$")
_ERRPT_KV = re.compile(r"^(LABEL|IDENTIFIER|Type|Class|Resource Name|Description):\s*(.*)$")


def _errpt_sev(typ: str, cls: str) -> str:
    typ, cls = typ.upper()[:1], cls.upper()[:1]
    if typ == "P":
        return "critical" if cls in ("H", "S") else "error"
    if typ == "T":
        return "error" if cls == "H" else "warn"
    if typ == "U":
        return "error"
    return "info"


@register("aix-errpt", "os")
def parse_aix_errpt(path: Path, host: str) -> list[Event]:
    events = EventSink()
    cur: dict = {}
    start = 0

    def flush(end: int):
        nonlocal cur
        if cur.get("IDENTIFIER") and cur.get("ts"):
            events.append(Event(
                ts=cur["ts"], host=host, layer="os", product="aix",
                severity=_errpt_sev(cur.get("Type", "I"), cur.get("Class", "O")),
                code=cur["IDENTIFIER"],
                message=f"{cur.get('LABEL', '')} {cur.get('Description', '')} "
                        f"[{cur.get('Type', '?')}/{cur.get('Class', '?')} {cur.get('Resource Name', '')}]".strip(),
                raw_ref=f"{path}:{start}-{end}"))
        cur = {}

    for i, line in iter_lines(path):
        m = _ERRPT_SUM.match(line.strip())
        if m:
            ident, tsraw, typ, cls, res, desc = m.groups()
            try:
                ts = fast_strptime(tsraw, "%m%d%H%M%y")
            except ValueError:
                continue
            events.append(Event(ts=ts, host=host, layer="os", product="aix",
                                severity=_errpt_sev(typ, cls), code=ident,
                                message=f"{desc} [{typ}/{cls} {res}]", raw_ref=f"{path}:{i}-{i}"))
            continue
        if line.startswith("-----") or line.startswith("LABEL:"):
            flush(i - 1)
            start = i
        m = _ERRPT_KV.match(line.strip())
        if m:
            key, val = m.groups()
            if key == "Type":
                val = val.split()[0] if val else ""
            cur[key] = val.strip()
            continue
        m = _ERRPT_DT.match(line.strip())
        if m:
            raw = re.sub(r"\s+", " ", m.group(1)).strip()
            for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    cur["ts"] = fast_strptime(raw, fmt)
                    break
                except ValueError:
                    continue
            if "ts" not in cur:
                # 타임존 약어(KST 등)가 strptime 에서 실패하는 경우: 토큰 제거 후 재시도
                toks = raw.split()
                if len(toks) >= 6:
                    try:
                        cur["ts"] = fast_strptime(" ".join(toks[:4] + toks[5:6]), "%a %b %d %H:%M:%S %Y")
                    except ValueError:
                        pass
    flush(0)
    return events
