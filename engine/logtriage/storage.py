"""서버형 저장소(DBMS) — 분석 이력·이벤트 원본을 SQLite(기본, 표준 라이브러리) 또는 PostgreSQL(psycopg2) 에 보관.

데스크톱 exe 는 incidents.json + incidents/*.jsonl 파일을 쓰고, Linux 서버형은 다수 사용자·동시 분석을 위해 DB 를 쓴다.
같은 SQL 을 두 백엔드에 쓰도록 자리표시자(?)를 백엔드에 맞게 바꾸고, 연결은 호출마다 열고 닫는다(요청 빈도 낮음·단순).

  URL 형식 (환경변수 LOGTRIAGE_DB 또는 --db)
    sqlite:////opt/logtriage/data/logtriage.db      (기본: <base>/data/logtriage.db)
    postgresql://logtriage:비밀번호@127.0.0.1:5432/logtriage

  테이블
    incidents(id, analyzed_at, name, layer, verdict, critical, data)   data = 분석 결과 전체 JSON
    events(id, incident_id, ts, host, layer, product, severity, code, message, raw_ref)  로그 검색용(분석 건당 최대 20만 건)
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import urllib.parse
from contextlib import contextmanager
from pathlib import Path

# 보관 상한 없음 — 분석 이력과 그 근거(로그 원본)를 지우지 않는다.
# 2026-09-29 사용자 지시: 전사에서 생긴 이슈·조치·조치 방법을 모아 우리 자산으로 삼는다.
# 지우면 자산이 되지 않으므로 '오래됐다' 는 이유로는 아무것도 지우지 않는다.
# (지우는 길은 딱 둘 — 사람이 그 건을 지울 때(delete_incident), 시연 자료를 되돌릴 때)
HISTORY_KEEP = None     # None = 무제한(예전 값 500)
EVENTS_KEEP = None      # None = 무제한(예전 값 50)
HISTORY_VIEW = 50       # 화면이 한 번에 보여 주는 기본 개수(보관과 무관)

_SCHEMA_SQLITE = [
    """CREATE TABLE IF NOT EXISTS incidents(
        id TEXT PRIMARY KEY, analyzed_at TEXT NOT NULL, name TEXT, layer TEXT, verdict TEXT,
        critical INTEGER DEFAULT 0, data TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, ts TEXT, host TEXT, layer TEXT,
        product TEXT, severity TEXT, code TEXT, message TEXT, raw_ref TEXT)""",
    """CREATE TABLE IF NOT EXISTS actions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, at REAL NOT NULL,
        actor TEXT, actor_name TEXT, kind TEXT, what TEXT NOT NULL, result TEXT,
        minutes INTEGER, note TEXT, signature TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_events_inc ON events(incident_id)",
    "CREATE INDEX IF NOT EXISTS ix_incidents_at ON incidents(analyzed_at)",
    "CREATE INDEX IF NOT EXISTS ix_actions_inc ON actions(incident_id)",
    "CREATE INDEX IF NOT EXISTS ix_actions_sig ON actions(signature)",
    # 2026-10-16 아이디어 5: 1차 명령 현장 피드백(명령 해시·판정·결과·판만 — 명령 출력·호스트는 받지 않는다)
    """CREATE TABLE IF NOT EXISTS cmd_feedback(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, incident_id TEXT, rule_id TEXT NOT NULL, cmd_hash TEXT NOT NULL,
        result TEXT NOT NULL, version TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_fb_rule ON cmd_feedback(rule_id)",
    # 아이디어 12: 사후 원인 기록 — 실제 원인과 확실성(확정·추정·미확정), 1차 판정이 맞았는지
    """CREATE TABLE IF NOT EXISTS postmortems(
        id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, at REAL NOT NULL, actor TEXT, cause TEXT NOT NULL, certainty TEXT NOT NULL,
        verdict_ok TEXT NOT NULL, first_verdict TEXT, first_rule TEXT, note TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_pm_inc ON postmortems(incident_id)",
    # 7차 아이디어 9: 호스트별 제품 판 — 담당자 지정(manual)과 출력 확인(evidence)을 나눠 남긴다. 유효기간이 지나면 다시 '추정'
    """CREATE TABLE IF NOT EXISTS host_versions(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, host TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
        source TEXT NOT NULL, evidence_sha TEXT, expires REAL NOT NULL, instance TEXT)""",
    # 재평가 이력 — 원래 분석 결과는 고치지 않고, 어떤 판 기준으로 다시 봤는지를 따로 남긴다
    """CREATE TABLE IF NOT EXISTS version_reevals(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, incident_id TEXT NOT NULL, basis TEXT NOT NULL)""",
    # 8차 아이디어 6: 현장 읽기 전용 실행 결과 — 성공/오류·오류 코드·머리글 칼럼 이름만(값·호스트·출력은 받지 않는다)
    """CREATE TABLE IF NOT EXISTS exec_reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, incident_id TEXT, vkey TEXT NOT NULL, cmd_hash TEXT NOT NULL,
        status TEXT NOT NULL, error_code TEXT, headers TEXT, product TEXT, version TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_xr_key ON exec_reports(vkey)",
    # 8차 아이디어 10: 사후 원인 장애 묶음 — 자동 식별(시각·호스트)이 틀렸을 때 관리자가 합치거나 나눈다(이력, 마지막 줄이 현재)
    """CREATE TABLE IF NOT EXISTS incident_groups(
        id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, actor TEXT, incident_id TEXT NOT NULL, group_key TEXT, reason TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_ig_inc ON incident_groups(incident_id)",
]
_SCHEMA_PG = [
    """CREATE TABLE IF NOT EXISTS incidents(
        id TEXT PRIMARY KEY, analyzed_at TEXT NOT NULL, name TEXT, layer TEXT, verdict TEXT,
        critical INTEGER DEFAULT 0, data TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS events(
        id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL, ts TEXT, host TEXT, layer TEXT,
        product TEXT, severity TEXT, code TEXT, message TEXT, raw_ref TEXT)""",
    """CREATE TABLE IF NOT EXISTS actions(
        id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL, at DOUBLE PRECISION NOT NULL,
        actor TEXT, actor_name TEXT, kind TEXT, what TEXT NOT NULL, result TEXT,
        minutes INTEGER, note TEXT, signature TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_events_inc ON events(incident_id)",
    "CREATE INDEX IF NOT EXISTS ix_incidents_at ON incidents(analyzed_at)",
    "CREATE INDEX IF NOT EXISTS ix_actions_inc ON actions(incident_id)",
    "CREATE INDEX IF NOT EXISTS ix_actions_sig ON actions(signature)",
    # 2026-10-16 아이디어 5: 1차 명령 현장 피드백(명령 해시·판정·결과·판만 — 명령 출력·호스트는 받지 않는다)
    """CREATE TABLE IF NOT EXISTS cmd_feedback(
        id BIGSERIAL PRIMARY KEY, at DOUBLE PRECISION NOT NULL, actor TEXT, incident_id TEXT, rule_id TEXT NOT NULL, cmd_hash TEXT NOT NULL,
        result TEXT NOT NULL, version TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_fb_rule ON cmd_feedback(rule_id)",
    # 아이디어 12: 사후 원인 기록 — 실제 원인과 확실성(확정·추정·미확정), 1차 판정이 맞았는지
    """CREATE TABLE IF NOT EXISTS postmortems(
        id BIGSERIAL PRIMARY KEY, incident_id TEXT NOT NULL, at DOUBLE PRECISION NOT NULL, actor TEXT, cause TEXT NOT NULL, certainty TEXT NOT NULL,
        verdict_ok TEXT NOT NULL, first_verdict TEXT, first_rule TEXT, note TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_pm_inc ON postmortems(incident_id)",
    # 7차 아이디어 9: 호스트별 제품 판 — 담당자 지정(manual)과 출력 확인(evidence)을 나눠 남긴다. 유효기간이 지나면 다시 '추정'
    """CREATE TABLE IF NOT EXISTS host_versions(
        id BIGSERIAL PRIMARY KEY, at DOUBLE PRECISION NOT NULL, actor TEXT, host TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL,
        source TEXT NOT NULL, evidence_sha TEXT, expires DOUBLE PRECISION NOT NULL, instance TEXT)""",
    # 재평가 이력 — 원래 분석 결과는 고치지 않고, 어떤 판 기준으로 다시 봤는지를 따로 남긴다
    """CREATE TABLE IF NOT EXISTS version_reevals(
        id BIGSERIAL PRIMARY KEY, at DOUBLE PRECISION NOT NULL, actor TEXT, incident_id TEXT NOT NULL, basis TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS exec_reports(
        id BIGSERIAL PRIMARY KEY, at DOUBLE PRECISION NOT NULL, actor TEXT, incident_id TEXT, vkey TEXT NOT NULL, cmd_hash TEXT NOT NULL,
        status TEXT NOT NULL, error_code TEXT, headers TEXT, product TEXT, version TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_xr_key ON exec_reports(vkey)",
    """CREATE TABLE IF NOT EXISTS incident_groups(
        id BIGSERIAL PRIMARY KEY, at DOUBLE PRECISION NOT NULL, actor TEXT, incident_id TEXT NOT NULL, group_key TEXT, reason TEXT)""",
    "CREATE INDEX IF NOT EXISTS ix_ig_inc ON incident_groups(incident_id)",
]

# 분석 건이 지금 어떤 상태인가 — 자산으로 쌓일 때 '해결된 건' 과 '아직 붙잡고 있는 건' 을 가른다
STATUS = {"open": "대응 필요", "acting": "조치 중", "resolved": "해결", "known": "기지 사항"}
# 조치 종류 — 나중에 '무엇이 자주 통했는가' 를 셀 수 있게 갈래를 정해 둔다
ACTION_KIND = {
    "restart": "재기동", "config": "설정 변경", "resource": "자원 증설·정리",
    "patch": "패치·버전", "rollback": "되돌리기", "workaround": "우회 조치",
    "vendor": "제조사 문의", "watch": "관찰만", "etc": "기타",
}
FEEDBACK_RESULT = {"ok": "동작함", "fail": "안 됨", "version": "판 다름"}
CERTAINTY = {"confirmed": "확정", "probable": "추정", "unknown": "미확정"}
VERDICT_OK = {"yes": "맞음", "partial": "일부 맞음", "no": "빗나감"}
ACTION_RESULT = {"resolved": "해결됨", "partial": "부분 해결", "failed": "효과 없음",
                 "pending": "지켜보는 중"}


def signature_of(result: dict) -> str:
    """'같은 증상' 을 가리키는 표. 룰 ID 가 가장 정확하고, 없으면 계층·판정으로 묶는다."""
    f = (result or {}).get("first") or {}
    rid = (f.get("rule_id") or "").strip()
    if rid:
        return "rule:" + rid
    layer, verdict = (f.get("layer_ko") or "").strip(), (f.get("verdict") or "").strip()
    return ("vd:" + layer + "|" + verdict) if (layer or verdict) else ""


def _iso_to_epoch(iso: str) -> float:
    """'2026-09-01 00:00:00' → epoch. 못 읽으면 0(= 처음부터)."""
    import datetime as _dt
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return _dt.datetime.strptime((iso or "")[:19], fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def sqlite_url(path: Path) -> str:
    """절대 경로 → sqlite URL (Linux /opt/x.db → sqlite:////opt/x.db, Windows C:/x.db → sqlite:///C:/x.db)."""
    p = Path(path).resolve().as_posix()
    return "sqlite:///" + (p if p[1:2] == ":" else "/" + p.lstrip("/"))


class Storage:
    """sqlite / postgresql 공용 저장소."""

    def __init__(self, url: str):
        self.url = url
        u = urllib.parse.urlsplit(url)
        self.kind = "postgresql" if u.scheme.startswith("postgres") else "sqlite"
        self._lock = threading.Lock()  # sqlite 쓰기 직렬화
        if self.kind == "sqlite":
            # sqlite:////abs/path.db  또는 sqlite:///rel/path.db
            path = urllib.parse.unquote(u.path)
            if path.startswith("//"):          # sqlite:////abs → /abs
                path = path[1:]
            elif len(path) > 2 and path[0] == "/" and path[2] == ":":  # Windows sqlite:///C:/x → C:/x
                path = path[1:]
            self.path = Path(path if path != "/" else "logtriage.db")
            self.path.parent.mkdir(parents=True, exist_ok=True)
        else:
            try:
                import psycopg2  # noqa: F401
            except ImportError as e:
                raise RuntimeError("PostgreSQL 저장소에는 psycopg2 가 필요합니다 (pip install psycopg2-binary, 오프라인 번들 wheels/ 포함)") from e
        self._init()

    # ── 연결 ──
    @contextmanager
    def _conn(self):
        if self.kind == "sqlite":
            c = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
            try:
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA synchronous=NORMAL")
                yield c
                c.commit()
            except Exception:
                c.rollback()
                raise
            finally:
                c.close()
        else:
            import psycopg2
            c = psycopg2.connect(self.url)
            try:
                yield c
                c.commit()
            except Exception:
                c.rollback()
                raise
            finally:
                c.close()

    @staticmethod
    def _rows(cur) -> list[dict]:
        """커서 결과를 사전 목록으로 — sqlite 는 튜플을 돌려주므로 칼럼 이름을 붙여 준다."""
        cols = [d[0] for d in (cur.description or [])]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def _q(self, sql: str) -> str:
        return sql if self.kind == "sqlite" else sql.replace("?", "%s")

    _ADD_COLS = (("actor", "TEXT"), ("actor_name", "TEXT"), ("site", "TEXT"),
                 ("status", "TEXT"), ("signature", "TEXT"))

    def _init(self):
        with self._conn() as c:
            cur = c.cursor()
            for s in (_SCHEMA_SQLITE if self.kind == "sqlite" else _SCHEMA_PG):
                cur.execute(s)
            # 옛 DB 에는 없는 칼럼을 더한다 — 자료를 옮기지 않고 자리만 넓힌다
            have = set()
            try:
                if self.kind == "sqlite":
                    have = {r[1] for r in cur.execute("PRAGMA table_info(incidents)")}
                else:
                    cur.execute("SELECT column_name FROM information_schema.columns"
                                " WHERE table_name='incidents'")
                    have = {r[0] for r in cur.fetchall()}
            except Exception:
                pass
            for col, typ in self._ADD_COLS:
                if have and col not in have:
                    try:
                        cur.execute(f"ALTER TABLE incidents ADD COLUMN {col} {typ}")
                    except Exception:
                        pass
            cur.execute(self._q("CREATE INDEX IF NOT EXISTS ix_incidents_sig ON incidents(signature)"))
            # 8차 아이디어 8: 판 지정의 인스턴스 칸 — 7차 DB 에는 없다(빈 값 = 호스트 전체)
            try:
                if self.kind == "sqlite":
                    hv = {r[1] for r in cur.execute("PRAGMA table_info(host_versions)")}
                else:
                    cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='host_versions'")
                    hv = {r[0] for r in cur.fetchall()}
                if hv and "instance" not in hv:
                    cur.execute("ALTER TABLE host_versions ADD COLUMN instance TEXT")
            except Exception:   # noqa: BLE001 — 칸을 못 더하면 인스턴스 지정만 못 쓴다(저장 때 오류로 알린다)
                pass

    def describe(self) -> str:
        if self.kind == "sqlite":
            return f"sqlite {self.path}"
        u = urllib.parse.urlsplit(self.url)
        return f"postgresql {u.hostname}:{u.port or 5432}/{u.path.lstrip('/')}"

    # ── 분석 이력 ──
    def save_incident(self, result: dict, actor: dict | None = None, site: str = ""):
        """분석 한 건을 남긴다.

        actor 는 {'login','name'} — 사람이 돌렸으면 그 사람, 무인 1차 대응이면 그 계정.
        누가 한 일인지가 없으면 나중에 '이건 누가 왜 이렇게 판단했나' 를 되짚을 수 없다.
        """
        f = result.get("first") or {}
        crit = 1 if (result.get("sev_totals") or {}).get("critical") else 0
        a = actor or {}
        row = (result.get("id"), result.get("analyzed_at", ""), result.get("name", ""),
               f.get("layer_ko", "CLEAR"), f.get("verdict", ""), crit,
               json.dumps(result, ensure_ascii=False, default=str),
               (a.get("login") or "") or None, (a.get("name") or "") or None,
               (site or "") or None, "open", signature_of(result) or None)
        with self._lock, self._conn() as c:
            cur = c.cursor()
            # 다시 분석해 덮어써도 사람이 정한 상태와 이미 적어 둔 조치는 지키지 않는다면 자산이 아니다
            old = None
            try:
                cur.execute(self._q("SELECT status FROM incidents WHERE id=?"), (row[0],))
                r0 = cur.fetchone()
                old = (r0[0] if not isinstance(r0, dict) else r0.get("status")) if r0 else None
            except Exception:
                old = None
            if old:
                row = row[:10] + (old,) + row[11:]
            cur.execute(self._q("DELETE FROM incidents WHERE id=?"), (row[0],))
            cur.execute(self._q(
                "INSERT INTO incidents(id,analyzed_at,name,layer,verdict,critical,data,"
                "actor,actor_name,site,status,signature) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)"), row)
            # 보관 상한이 정해져 있을 때만 오래된 것을 정리한다(기본은 무제한 — 지우지 않는다)
            if HISTORY_KEEP is not None or EVENTS_KEEP is not None:
                cur.execute(self._q("SELECT id FROM incidents ORDER BY analyzed_at DESC, id DESC"))
                ids = [r[0] for r in cur.fetchall()]
                if HISTORY_KEEP is not None:
                    for old in ids[HISTORY_KEEP:]:
                        cur.execute(self._q("DELETE FROM incidents WHERE id=?"), (old,))
                if EVENTS_KEEP is not None:
                    for old in ids[EVENTS_KEEP:]:
                        cur.execute(self._q("DELETE FROM events WHERE incident_id=?"), (old,))

    def set_status(self, incident_id: str, status: str) -> bool:
        """이 건이 지금 어떤 상태인지 — 대응 필요 / 조치 중 / 해결 / 기지 사항."""
        if status not in STATUS:
            raise ValueError("상태는 " + ", ".join(STATUS) + " 중 하나여야 합니다")
        with self._lock, self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("UPDATE incidents SET status=? WHERE id=?"), (status, incident_id))
            return bool(cur.rowcount)

    def add_action(self, incident_id: str, what: str, *, actor: dict | None = None,
                   kind: str = "etc", result: str = "pending", minutes=None, note: str = "") -> int:
        """실제로 한 조치 한 건을 남긴다. '무엇을 했는가' 는 비울 수 없다."""
        what = (what or "").strip()
        if not what:
            raise ValueError("무엇을 했는지는 비워 둘 수 없습니다")
        if len(what) > 4000:
            raise ValueError("조치 내용이 너무 깁니다(4000자)")
        if kind not in ACTION_KIND:
            raise ValueError("조치 종류는 " + ", ".join(ACTION_KIND) + " 중 하나여야 합니다")
        if result not in ACTION_RESULT:
            raise ValueError("결과는 " + ", ".join(ACTION_RESULT) + " 중 하나여야 합니다")
        if minutes is not None:
            try:
                minutes = int(minutes)
            except (TypeError, ValueError):
                raise ValueError("걸린 시간은 분 단위 숫자여야 합니다")
            if not 0 <= minutes <= 60 * 24 * 30:
                raise ValueError("걸린 시간이 범위를 벗어났습니다")
        a = actor or {}
        with self._lock, self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT signature FROM incidents WHERE id=?"), (incident_id,))
            r0 = cur.fetchone()
            if not r0:
                raise ValueError("그런 분석 건이 없습니다")
            sig = (r0[0] if not isinstance(r0, dict) else r0.get("signature")) or ""
            cur.execute(self._q(
                "INSERT INTO actions(incident_id,at,actor,actor_name,kind,what,result,minutes,note,signature)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)"),
                (incident_id, time.time(), (a.get("login") or "") or None,
                 (a.get("name") or "") or None, kind, what, result, minutes,
                 (note or "").strip()[:2000] or None, sig or None))
            # 조치가 적히면 상태도 따라간다 — 사람이 따로 손대지 않아도 이력이 맞게 남는다
            cur.execute(self._q("UPDATE incidents SET status=? WHERE id=?"),
                        ("resolved" if result == "resolved" else "acting", incident_id))
            return int(cur.lastrowid or 0)

    def actions(self, incident_id: str) -> list[dict]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT * FROM actions WHERE incident_id=? ORDER BY at, id"),
                        (incident_id,))
            return self._rows(cur)

    def past_actions(self, signature: str, exclude: str = "", limit: int = 5) -> list[dict]:
        """같은 증상에서 지난번 우리가 한 조치 — 규칙이 제안한 조치보다 이것을 먼저 보여 준다.

        효과가 있었던 것(해결됨 → 부분 해결)을 앞에 둔다. 효과 없던 것도 남긴다 —
        '저건 해 봤는데 안 됐다' 도 자산이다.
        """
        if not signature:
            return []
        limit = max(1, min(int(limit or 5), 50))
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q(
                "SELECT * FROM actions WHERE signature=? AND incident_id<>? "
                "ORDER BY CASE result WHEN 'resolved' THEN 0 WHEN 'partial' THEN 1"
                " WHEN 'pending' THEN 2 ELSE 3 END, at DESC"), (signature, exclude or ""))
            return self._rows(cur)[:limit]

    def delete_incident(self, incident_id: str) -> bool:
        """분석 이력 한 건과 그 이벤트를 지운다.

        시연 자료를 되돌리려고 만들었다 — 넣을 수는 있는데 지울 수 없으면 넣으면 안 된다.
        """
        with self._lock, self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("DELETE FROM events WHERE incident_id=?"), (incident_id,))
            cur.execute(self._q("DELETE FROM actions WHERE incident_id=?"), (incident_id,))
            cur.execute(self._q("DELETE FROM incidents WHERE id=?"), (incident_id,))
            return bool(cur.rowcount)

    def incident_count(self) -> int:
        """보관된 분석 건수(화면 표시 개수와 무관) — 이력 감소 감지·자기진단용(10차)."""
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT count(*) FROM incidents")
            return int(cur.fetchone()[0])

    def incident_ids(self) -> set:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT id FROM incidents")
            return {r[0] for r in cur.fetchall()}

    def history(self, limit: int = HISTORY_VIEW) -> list[dict]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q(
                "SELECT data,actor,actor_name,site,status,signature FROM incidents"
                " ORDER BY analyzed_at DESC, id DESC LIMIT ?"), (limit,))
            out = []
            for row in cur.fetchall():
                try:
                    rec = json.loads(row[0])
                except Exception:
                    continue
                # 분석 본문은 그대로 두고, 누가·어디서·지금 상태만 얹어 준다
                rec["actor"], rec["actor_name"] = row[1] or "", row[2] or ""
                rec["site"], rec["status"] = row[3] or "", row[4] or "open"
                rec["signature"] = row[5] or ""
                out.append(rec)
            return out

    def status_counts(self) -> dict:
        """상태별 건수 — '내가 아직 붙잡고 있는 것' 을 홈에서 먼저 보여 주려고."""
        out = {k: 0 for k in STATUS}
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT COALESCE(status,'open'), COUNT(*) FROM incidents GROUP BY 1")
            for k, n in cur.fetchall():
                out[k if k in out else "open"] = out.get(k if k in out else "open", 0) + int(n)
        return out

    def by_status(self, status: str, limit: int = 10) -> list[dict]:
        """그 상태의 분석 건 — 최근 것부터."""
        limit = max(1, min(int(limit or 10), 200))
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q(
                "SELECT id,analyzed_at,name,layer,verdict,critical,actor_name,site,"
                "COALESCE(status,'open') FROM incidents WHERE COALESCE(status,'open')=?"
                " ORDER BY analyzed_at DESC, id DESC LIMIT ?"), (status, limit))
            keys = ("id", "analyzed_at", "name", "layer", "verdict", "critical",
                    "actor_name", "site", "status")
            return [dict(zip(keys, r)) for r in cur.fetchall()]

    def by_actor(self, login: str, limit: int = 5) -> list[dict]:
        """내가(또는 그 계정이) 돌린 분석 — 홈의 '내 최근 분석'."""
        if not login:
            return []
        limit = max(1, min(int(limit or 5), 100))
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q(
                "SELECT id,analyzed_at,name,layer,verdict,critical,actor_name,site,"
                "COALESCE(status,'open') FROM incidents WHERE actor=?"
                " ORDER BY analyzed_at DESC, id DESC LIMIT ?"), (login, limit))
            keys = ("id", "analyzed_at", "name", "layer", "verdict", "critical",
                    "actor_name", "site", "status")
            return [dict(zip(keys, r)) for r in cur.fetchall()]

    def asset_counts(self, since_iso: str) -> dict:
        """그 시각 뒤로 쌓인 것 — 분석·조치·해결. 자산이 늘고 있다는 것을 숫자로 보여 준다."""
        out = {"incidents": 0, "actions": 0, "resolved": 0, "minutes": 0}
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT COUNT(*) FROM incidents WHERE analyzed_at>=?"), (since_iso,))
            out["incidents"] = int(cur.fetchone()[0] or 0)
            ts = _iso_to_epoch(since_iso)
            cur.execute(self._q("SELECT COUNT(*),SUM(CASE WHEN result='resolved' THEN 1 ELSE 0 END),"
                                "SUM(COALESCE(minutes,0)) FROM actions WHERE at>=?"), (ts,))
            r = cur.fetchone() or (0, 0, 0)
            out["actions"], out["resolved"], out["minutes"] = int(r[0] or 0), int(r[1] or 0), int(r[2] or 0)
        return out

    # ── 아이디어 5: 1차 명령 현장 피드백 ──
    # GPT 56차: 같은 사람이 같은 건·같은 명령을 여러 번 눌러 수를 부풀리지 못하게 — 기록은 모두 남기되(변경 이력),
    # 세는 것은 (사람·분석 건·판정·명령) 마다 마지막 한 표. 명령 지문(sha256 앞 16자)은 '같은 명령 문자열' 표시일 뿐 보증이 아니다.
    _FB_LATEST = "SELECT MAX(id) FROM cmd_feedback GROUP BY actor, incident_id, rule_id, cmd_hash"

    def add_feedback(self, rule_id: str, cmd_hash: str, result: str, version: str = "", actor: dict | None = None,
                     incident_id: str = "") -> None:
        import re as _re
        rule_id = str(rule_id or "")[:120]
        if not rule_id or not _re.fullmatch(r"[0-9a-f]{16}", str(cmd_hash or "")):
            raise ValueError("판정 ID·명령 지문이 올바르지 않습니다")
        if result not in FEEDBACK_RESULT:
            raise ValueError("결과는 " + ", ".join(FEEDBACK_RESULT) + " 중 하나여야 합니다")
        if incident_id and not self.get(incident_id):
            raise ValueError("그런 분석 건이 없습니다")
        with self._lock, self._conn() as c:
            c.cursor().execute(self._q("INSERT INTO cmd_feedback(at,actor,incident_id,rule_id,cmd_hash,result,version) VALUES(?,?,?,?,?,?,?)"),
                               (time.time(), ((actor or {}).get("login") or "") or None, str(incident_id or "")[:80] or None,
                                rule_id, cmd_hash, result, str(version or "")[:40] or None))

    def feedback_summary(self, rule_ids: list | None = None) -> dict:
        """{판정 ID: {명령 지문: {ok, fail, version}}} — (사람·건·판정·명령)마다 마지막 표만 센다. rule_ids 가 없으면 전체."""
        out: dict = {}
        with self._conn() as c:
            cur = c.cursor()
            sql = ("SELECT rule_id, cmd_hash, result, COUNT(*) AS n FROM cmd_feedback WHERE id IN (" + self._FB_LATEST + ")")
            args: list = []
            if rule_ids:
                ids = [str(x)[:120] for x in rule_ids][:500]
                sql += " AND rule_id IN (" + ",".join("?" * len(ids)) + ")"
                args = ids
            cur.execute(self._q(sql + " GROUP BY rule_id, cmd_hash, result"), args)
            for r in self._rows(cur):
                out.setdefault(r["rule_id"], {}).setdefault(r["cmd_hash"], {"ok": 0, "fail": 0, "version": 0})[r["result"]] = int(r["n"])
        return out

    # ── 아이디어 12: 사후 원인 기록 — 고쳐 쓰면 새 줄(이력), 보이는 것과 세는 것은 건마다 마지막 줄 ──
    # GPT 56차: '확정'은 근거 없이 받지 않는다(근거·메모 칸 필수). 확정과 추정·미확정은 따로 센다.
    def set_postmortem(self, incident_id: str, cause: str, certainty: str, verdict_ok: str, note: str = "",
                       actor: dict | None = None) -> dict:
        cause = (cause or "").strip()
        note = (note or "").strip()
        if not cause:
            raise ValueError("실제 원인은 비워 둘 수 없습니다")
        if len(cause) > 2000:
            raise ValueError("실제 원인이 너무 깁니다(2000자)")
        if certainty not in CERTAINTY:
            raise ValueError("확실성은 " + ", ".join(CERTAINTY) + " 중 하나여야 합니다")
        if verdict_ok not in VERDICT_OK:
            raise ValueError("1차 판정 적중은 " + ", ".join(VERDICT_OK) + " 중 하나여야 합니다")
        if certainty == "confirmed" and len(note) < 5:
            raise ValueError("'확정'은 근거가 있어야 합니다 — 근거·메모 칸에 확인 방법(제조사 RCA·교체 부품·재현 결과 등)을 적으십시오")
        rec = self.get(incident_id)
        if not rec:
            raise ValueError("그런 분석 건이 없습니다")
        first = rec.get("first") or {}
        with self._lock, self._conn() as c:
            c.cursor().execute(self._q("INSERT INTO postmortems(incident_id,at,actor,cause,certainty,verdict_ok,first_verdict,first_rule,note)"
                                       " VALUES(?,?,?,?,?,?,?,?,?)"),
                               (incident_id, time.time(), ((actor or {}).get("login") or "") or None, cause, certainty, verdict_ok,
                                str(first.get("verdict", ""))[:200], str(first.get("rule_id", ""))[:120], note[:1000] or None))
        return self.get_postmortem(incident_id) or {}

    def pilot_rows(self, since: str) -> tuple[list, list, list]:
        """22차 시범 운영 지표용 — 기간 안 분석(본문) · 모든 조치(서명 · 시각 · 결과 · 분) · 기간 안 분석의 마지막 사후 원인."""
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT id, analyzed_at, data FROM incidents WHERE analyzed_at >= ? ORDER BY analyzed_at"), (since,))
            inc = self._rows(cur)
            cur.execute("SELECT incident_id, at, result, minutes, signature FROM actions")
            acts = self._rows(cur)
            cur.execute(self._q("SELECT p.incident_id, p.certainty, p.verdict_ok FROM postmortems p JOIN incidents i ON i.id = p.incident_id "
                                "WHERE i.analyzed_at >= ? AND p.id IN (SELECT MAX(id) FROM postmortems GROUP BY incident_id)"), (since,))
            pms = self._rows(cur)
        return inc, acts, pms

    def get_postmortem(self, incident_id: str) -> dict | None:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT * FROM postmortems WHERE incident_id=? ORDER BY id DESC"), (incident_id,))
            rows = self._rows(cur)
        if not rows:
            return None
        last = dict(rows[0])
        last["revisions"] = len(rows)
        return last

    def postmortem_review(self) -> list[dict]:
        """1차 판정별 적중 현황(건마다 마지막 기록) — 확정 빗나감이 쌓인 판정을 위로. 추정·미확정은 따로 센다."""
        agg: dict = {}
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT first_rule, first_verdict, certainty, verdict_ok, COUNT(*) AS n FROM postmortems "
                        "WHERE id IN (SELECT MAX(id) FROM postmortems GROUP BY incident_id) "
                        "GROUP BY first_rule, first_verdict, certainty, verdict_ok")
            for r in self._rows(cur):
                a = agg.setdefault(r["first_rule"] or "(판정 없음)", {"rule_id": r["first_rule"] or "", "verdict": r["first_verdict"] or "",
                                                                    "total": 0, "hit_confirmed": 0, "hit": 0,
                                                                    "miss_confirmed": 0, "miss_probable": 0, "miss_unknown": 0})
                n = int(r["n"])
                a["total"] += n
                if r["verdict_ok"] == "yes":
                    a["hit"] += n
                    if r["certainty"] == "confirmed":
                        a["hit_confirmed"] += n
                else:
                    a["miss_" + r["certainty"]] += n
        return sorted(agg.values(), key=lambda a: (-a["miss_confirmed"], -(a["miss_probable"] + a["miss_unknown"]), -a["total"]))

    def incident_ident(self, incident_id: str, groups: dict | None = None) -> tuple:
        """같은 장애를 다시 분석·기록한 것은 한 건 — 최초 이상 시각(시 단위)·호스트·파일 묶음이 같으면 같은 장애로 본다.
        8차 ⑩: 관리자가 합치거나 나눈 묶음이 자동 식별보다 먼저. 개선 제안·판 다름 신호가 같이 쓴다(GPT 64차 P1-⑦)."""
        g = (groups if groups is not None else self.incident_groups()).get(incident_id)
        if g and g.get("group_key"):
            return ("group", g["group_key"])
        rec = self.get(incident_id) or {}
        f0 = rec.get("first") or {}
        t = str(rec.get("incident_time") or f0.get("ts") or rec.get("analyzed_at") or "")[:13]
        fl = sorted({f"{f.get('host', '')}|{f.get('name', '')}" for f in rec.get("files") or [] if isinstance(f, dict)})
        return (t, tuple(fl)) if (t or fl) else ("id", incident_id)

    def postmortem_proposals(self, min_cases: int = 2, include_near: bool = False) -> list[dict]:
        """7차 아이디어 10: '확정'된 빗나감이 서로 다른 장애(증상 지문 기준)로 min_cases 건 이상인 1차 판정의 개선 제안 초안 재료.
        같은 장애를 여러 번 기록한 것은 한 건으로 센다(GPT 60차). 룰을 고치거나 학습 후보로 올리지 않는다 — 사람이 읽고 판단."""
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT p.*, i.signature AS sig FROM postmortems p LEFT JOIN incidents i ON i.id = p.incident_id "
                        "WHERE p.id IN (SELECT MAX(id) FROM postmortems GROUP BY incident_id) AND p.certainty = 'confirmed' AND p.verdict_ok <> 'yes'")
            rows = self._rows(cur)
        by: dict = {}
        for r in rows:
            by.setdefault(r["first_rule"] or "", []).append(r)
        out = []
        groups = self.incident_groups()

        def _ident(r):
            return self.incident_ident(r["incident_id"], groups)
        for rule, rs in by.items():
            sigs = {_ident(r) for r in rs}
            near = include_near and len(sigs) < min_cases and len({r["incident_id"] for r in rs}) >= min_cases   # 8차 ⑩: 분석 건은 둘 이상인데 자동 식별이 한 장애로 묶은 것 — 나누기 후보(제안 아님)
            if not rule or (len(sigs) < min_cases and not near):
                continue
            acts = []
            for sg in sorted({r.get("sig") for r in rs if r.get("sig")}):
                try:
                    acts += [a for a in self.past_actions(sg, exclude="", limit=5) if a.get("result") == "resolved"]
                except Exception:   # noqa: BLE001 — 조치 기록을 못 읽어도 초안은 만든다
                    pass
            members = []
            for r in sorted(rs, key=lambda r: r["incident_id"]):
                ik = _ident(r)
                g = groups.get(r["incident_id"])
                members.append({"incident_id": r["incident_id"], "ident": ("묶음 " + ik[1]) if ik[0] == "group" else
                                ("시각 " + str(ik[0]) + " · " + ", ".join(ik[1])[:120]) if ik[0] != "id" else "식별 정보 없음(건 자체)",
                                "manual": bool(g and g.get("group_key"))})
            out.append({"rule_id": rule, "verdict": rs[0].get("first_verdict") or "", "cases": len(sigs), "records": len(rs), "near": near,
                        "members": members[:40],
                        # GPT 64차 P1-⑩: 관리자가 묶음을 바꿔 '2건 이상'을 채울 수 있다 — 바꾼 건수를 제안에 같이 보인다(근거 건은 members)
                        "manual_groups": sum(1 for m in members if m["manual"]),
                        "causes": sorted({r["cause"] for r in rs})[:10], "evidence": sorted({r["note"] for r in rs if r.get("note")})[:10],
                        "incidents": sorted({r["incident_id"] for r in rs})[:20], "resolved_actions": sorted({a.get("what", "") for a in acts})[:10]})
        return sorted(out, key=lambda x: (x["near"], -x["cases"]))

    # ── 7차 아이디어 9: 호스트별 제품 판 ──
    VERSION_DAYS = 90

    def set_host_version(self, host: str, product: str, version: str, evidence: str = "", actor: dict | None = None,
                         instance: str = "") -> dict:
        """판 지정. evidence(그 호스트에서 돌린 판 확인 명령의 출력)를 주면 출력에서 판을 읽어 입력과 같을 때만 '출력 확인'.
        출력이 없으면 '담당자 지정' — 화면은 둘을 다르게 보인다(GPT 60차: 수동 선택 ≠ 실제 판 확인).
        8차 아이디어 8: instance(인스턴스 이름·포트)를 주면 (호스트, 제품, 인스턴스) 마다 따로 — 비우면 호스트 전체."""
        import hashlib as _h
        import re as _re
        from . import knowledge_quality as KQ
        host, product, version = str(host or "").strip()[:120], str(product or "").strip().lower()[:40], str(version or "").strip()[:40]
        instance = str(instance or "").strip()[:60]
        if not host or not product or not _re.fullmatch(r"[0-9][0-9A-Za-z._-]{0,39}", version):
            raise ValueError("호스트·제품·판(숫자로 시작)을 바르게 넣으십시오")
        if instance and not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,59}", instance):
            raise ValueError("인스턴스는 영문·숫자·._:- 로(예: tomcat-a, 8080, ORCL1)")
        source, sha = "manual", None
        if evidence:
            if len(evidence) > 64 * 1024:
                raise ValueError("출력이 너무 깁니다(64KB 이하)")
            pats = KQ._VER.get(product.split("-")[0]) or []
            got = next((m.group(1) for pt in pats for m in [_re.search(pt, evidence)] if m), "")
            if not got:
                raise ValueError("출력에서 이 제품의 판 문자열을 찾지 못했습니다 — 판 확인 명령의 출력을 그대로 붙이십시오")
            if not (version.startswith(got) or got.startswith(version)):
                raise ValueError(f"출력의 판({got})과 넣은 판({version})이 다릅니다")
            source, sha = "evidence", _h.sha256(evidence.encode("utf-8")).hexdigest()[:16]
        now = time.time()
        with self._lock, self._conn() as c:
            c.cursor().execute(self._q("INSERT INTO host_versions(at,actor,host,product,version,source,evidence_sha,expires,instance) "
                                       "VALUES(?,?,?,?,?,?,?,?,?)"),
                               (now, ((actor or {}).get("login") or "") or None, host, product, version, source, sha,
                                now + self.VERSION_DAYS * 86400, instance))
        return {"host": host, "product": product, "version": version, "source": source, "evidence_sha": sha, "instance": instance}

    def host_versions(self, hosts: list) -> dict:
        """{(host, product, instance): 마지막 유효 기록} — 유효기간 지난 것은 돌려주지 않는다. instance '' = 호스트 전체."""
        out = {}
        hs = [str(h)[:120] for h in hosts if h][:200]
        if not hs:
            return out
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT * FROM host_versions WHERE host IN (" + ",".join("?" * len(hs)) + ") AND expires > ? ORDER BY id"),
                        hs + [time.time()])
            for r in self._rows(cur):
                out[(r["host"], r["product"], r.get("instance") or "")] = r
        return out

    def add_reeval(self, incident_id: str, basis: dict, actor: dict | None = None) -> None:
        with self._lock, self._conn() as c:
            c.cursor().execute(self._q("INSERT INTO version_reevals(at,actor,incident_id,basis) VALUES(?,?,?,?)"),
                               (time.time(), ((actor or {}).get("login") or "") or None, incident_id,
                                json.dumps(basis, ensure_ascii=False)[:4000]))

    # ── 8차 아이디어 6: 현장 읽기 전용 실행 결과(성공·오류·오류 코드·머리글 칼럼 이름만) ──
    _XR_LATEST = "SELECT MAX(id) FROM exec_reports GROUP BY actor, incident_id, vkey, cmd_hash"

    def add_exec_report(self, vkey: str, cmd_hash: str, status: str, error_code: str = "", headers: list | None = None,
                        product: str = "", version: str = "", actor: dict | None = None, incident_id: str = "") -> None:
        import re as _re
        vkey = str(vkey or "")[:160]
        if not vkey or not _re.fullmatch(r"[0-9a-f]{16}", str(cmd_hash or "")):
            raise ValueError("판정·명령 지문이 올바르지 않습니다")
        if status not in ("ok", "error"):
            raise ValueError("결과는 성공·오류 중 하나")
        if error_code and not _re.fullmatch(r"[A-Za-z]{0,8}-?[0-9A-Za-z]{1,8}", error_code):
            raise ValueError("오류 코드는 ORA-00942 · TBR-12033 · 42P01 · -2 같은 코드만(문장·값은 받지 않습니다)")
        hs = list(headers or [])
        # % 는 df·bdf 머리글(Use%·%Used·IUse%)에 실제로 있다 — 포장본 점검(10-19)이 '정상 df 머리글이 거절됨'을 잡아 받게 했다
        if len(hs) > 64 or any(not _re.fullmatch(r"[A-Za-z_%][A-Za-z0-9_$#%]{0,40}", str(h)) for h in hs):
            raise ValueError("머리글은 칼럼 이름만(영문·숫자·_$#%, 41자·64개까지)")
        # GPT 66차: '%%%%'·'_%' 같은 이름 아닌 낱말도 위 꼴을 통과한다 — 영문자가 하나 이상 있고 % 는 두 개까지인 이름만
        if any(not _re.search(r"[A-Za-z]", str(h)) or str(h).count("%") > 2 for h in hs):
            raise ValueError("머리글 낱말마다 영문자가 하나 이상 있어야 하고 % 는 두 개까지입니다(칼럼 이름만)")
        # GPT 64차 P0: 글자 제한은 유출 방지가 아니다 — 값처럼 보이는 이름(숫자 4개 이상 연속)은 받지 않는다. 머리글은 이 PC 에만 남고 허브로 가지 않는다
        if any(_re.search(r"[0-9]{4,}", str(h)) for h in hs):
            raise ValueError("머리글에 숫자가 4개 이상 이어진 이름이 있습니다 — 값일 수 있어 받지 않습니다(칼럼 이름만)")
        with self._lock, self._conn() as c:
            c.cursor().execute(self._q("INSERT INTO exec_reports(at,actor,incident_id,vkey,cmd_hash,status,error_code,headers,product,version) "
                                       "VALUES(?,?,?,?,?,?,?,?,?,?)"),
                               (time.time(), ((actor or {}).get("login") or "") or None, str(incident_id or "")[:80] or None, vkey, cmd_hash,
                                status, (error_code or "").upper() or None, " ".join(hs) or None, str(product or "")[:40] or None,
                                str(version or "")[:40] or None))

    def exec_report_summary(self, vkeys: list | None = None) -> dict:
        """{판정 키: {명령 지문: {ok, error, codes:{코드: n}, headers:{머리글: n}}}} — (사람·건·판정·명령)마다 마지막 한 줄."""
        out: dict = {}
        with self._conn() as c:
            cur = c.cursor()
            sql = "SELECT vkey, cmd_hash, status, error_code, headers FROM exec_reports WHERE id IN (" + self._XR_LATEST + ")"
            args: list = []
            if vkeys:
                ks = [str(x)[:160] for x in vkeys][:500]
                sql += " AND vkey IN (" + ",".join("?" * len(ks)) + ")"
                args = ks
            cur.execute(self._q(sql), args)
            for r in self._rows(cur):
                d = out.setdefault(r["vkey"], {}).setdefault(r["cmd_hash"], {"ok": 0, "error": 0, "codes": {}, "headers": {}})
                d[r["status"]] += 1
                if r.get("error_code"):
                    d["codes"][r["error_code"]] = d["codes"].get(r["error_code"], 0) + 1
                if r.get("headers"):
                    d["headers"][r["headers"]] = d["headers"].get(r["headers"], 0) + 1
        return out

    # ── 8차 아이디어 7: '판 다름' 신호가 같은 호스트·제품에서 되풀이되면 판 지정을 확인하라고 알린다 ──
    def version_signals(self, min_count: int = 2) -> list[dict]:
        """현장 피드백 '판 다름'(사람·건·판정·명령마다 마지막 표)을 그 분석 건의 (호스트, 제품)으로 모은다.
        서로 다른 장애 min_count 건 이상이면 제안(같은 장애를 다시 분석한 건은 한 번 — incident_ident) — 판은 자동으로 바꾸지 않고
        호스트별 판 지정이 이미 있으면 그 판·출처를 같이 보인다."""
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT incident_id, rule_id FROM cmd_feedback WHERE id IN (" + self._FB_LATEST + ") AND result='version' "
                        "AND incident_id IS NOT NULL")
            rows = self._rows(cur)
        by: dict = {}
        groups = self.incident_groups()
        for r in rows:
            rec = self.get(r["incident_id"]) or {}
            ident = self.incident_ident(r["incident_id"], groups)   # GPT 64차 P1: 같은 장애를 다시 분석한 건은 한 번
            prod = next((str(cc.get("product") or "").split("-")[0] for cc in rec.get("checklist") or [] if cc.get("rule_id") == r["rule_id"]), "")
            for f in rec.get("files") or []:
                if f.get("host") and prod and str(f.get("product", "")).split("-")[0] == prod:
                    k = (f["host"], prod, str(f.get("instance") or ""))
                    by.setdefault(k, {"incidents": set(), "rules": set()})
                    by[k]["incidents"].add(ident)
                    by[k]["rules"].add(r["rule_id"])
        hv = self.host_versions(sorted({k[0] for k in by}))
        out = []
        for (h, p, ins), v in by.items():
            if len(v["incidents"]) < min_count:
                continue
            cur_v = hv.get((h, p, ins)) or hv.get((h, p, ""))
            out.append({"host": h, "product": p, "instance": ins, "incidents": len(v["incidents"]), "rules": sorted(v["rules"])[:10],
                        "current": ({"version": cur_v["version"], "source": cur_v["source"]} if cur_v else None)})
        return sorted(out, key=lambda x: -x["incidents"])

    # ── 8차 아이디어 10: 사후 원인 장애 묶음 — 합치기·나누기(이력, 마지막 줄이 현재) ──
    def set_incident_group(self, incident_ids: list, group_key: str | None, reason: str, actor: dict | None = None) -> dict:
        import re as _re
        ids = [str(x)[:80] for x in incident_ids or [] if x][:200]
        reason = str(reason or "").strip()[:300]
        if not ids:
            raise ValueError("분석 건을 고르십시오")
        if len(reason) < 5:
            raise ValueError("사유를 적으십시오(5자 이상) — 왜 같은(다른) 장애인지")
        if group_key is not None and not _re.fullmatch(r"[A-Za-z0-9가-힣._:-]{1,60}", group_key):
            raise ValueError("묶음 이름은 60자 이하 영문·한글·숫자·._:-")
        for i in ids:
            if not self.get(i):
                raise ValueError(f"그런 분석 건이 없습니다: {i}")
        now = time.time()
        with self._lock, self._conn() as c:
            cur = c.cursor()
            for i in ids:
                cur.execute(self._q("INSERT INTO incident_groups(at,actor,incident_id,group_key,reason) VALUES(?,?,?,?,?)"),
                            (now, ((actor or {}).get("login") or "") or None, i, group_key, reason))
        return {"ok": True, "incidents": ids, "group": group_key}

    def incident_groups(self) -> dict:
        """{분석 건: 마지막 묶음 기록} — group_key None(NULL) = 자동 식별로 되돌림."""
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT * FROM incident_groups WHERE id IN (SELECT MAX(id) FROM incident_groups GROUP BY incident_id)")
            return {r["incident_id"]: r for r in self._rows(cur)}

    def incident_group_history(self, incident_id: str) -> list:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT * FROM incident_groups WHERE incident_id=? ORDER BY id"), (str(incident_id)[:80],))
            return self._rows(cur)

    def get(self, incident_id: str) -> dict | None:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("SELECT data FROM incidents WHERE id=?"), (incident_id,))
            r = cur.fetchone()
            return json.loads(r[0]) if r else None

    def count(self) -> int:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT COUNT(*) FROM incidents")
            return int(cur.fetchone()[0])

    # ── 이벤트 원본(로그 검색) ──
    def import_events(self, incident_id: str, jsonl: Path, max_rows: int = 200_000) -> int:
        """run_analysis 가 쓴 분석 건별 jsonl 을 events 테이블로 옮기고 파일은 삭제."""
        if not jsonl.exists():
            return 0
        rows, n = [], 0
        with self._lock, self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q("DELETE FROM events WHERE incident_id=?"), (incident_id,))
            ins = self._q("INSERT INTO events(incident_id,ts,host,layer,product,severity,code,message,raw_ref) VALUES(?,?,?,?,?,?,?,?,?)")
            with open(jsonl, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    rows.append((incident_id, e.get("ts"), e.get("host"), e.get("layer"), e.get("product"),
                                 e.get("severity"), e.get("code"), e.get("message"), e.get("raw_ref")))
                    n += 1
                    if len(rows) >= 2000:
                        cur.executemany(ins, rows)
                        rows = []
                    if n >= max_rows:
                        break
            if rows:
                cur.executemany(ins, rows)
        try:
            jsonl.unlink()
        except OSError:
            pass
        return n

    def incidents_with_events(self) -> set[str]:
        with self._conn() as c:
            cur = c.cursor()
            cur.execute("SELECT DISTINCT incident_id FROM events")
            return {r[0] for r in cur.fetchall()}

    def search_events(self, incident_id: str, query: str = "", severity: str = "",
                      layer: str = "", limit: int = 300, t_from: str = "", t_to: str = "") -> dict:
        """t_from/t_to: 'YYYY-MM-DD HH:MM:SS' — 이벤트 발생 추이 막대·타임라인 요점에서 넘어온 시간 구간."""
        where, args = ["incident_id=?"], [incident_id]
        if severity:
            where.append("severity=?"); args.append(severity)
        if layer:
            where.append("layer=?"); args.append(layer)
        if (t_from or "").strip():
            where.append("ts>=?"); args.append(t_from.strip()[:19])
        if (t_to or "").strip():
            where.append("ts<=?"); args.append(t_to.strip()[:19])
        for t in [t.lower() for t in (query or "").split() if t.strip()]:
            where.append("LOWER(COALESCE(message,'')||' '||COALESCE(code,'')||' '||COALESCE(host,'')||' '||COALESCE(product,'')) LIKE ?")
            args.append(f"%{t}%")
        w = " AND ".join(where)
        with self._conn() as c:
            cur = c.cursor()
            cur.execute(self._q(f"SELECT COUNT(*) FROM events WHERE {w}"), tuple(args))
            total = int(cur.fetchone()[0])
            if total == 0:
                cur.execute(self._q("SELECT COUNT(*) FROM events WHERE incident_id=?"), (incident_id,))
                if int(cur.fetchone()[0]) == 0:
                    return {"error": "이 분석 건의 이벤트 원본(로그)이 없습니다 —"
                            " 보관 상한이 있던 판(2026-09-28 이전)에서 지워진 건입니다."
                            " 지금 판부터는 지우지 않습니다."}
            cur.execute(self._q(f"SELECT ts,host,layer,product,severity,code,message,raw_ref FROM events WHERE {w} ORDER BY id LIMIT ?"),
                        tuple(args) + (limit,))
            cols = ("ts", "host", "layer", "product", "severity", "code", "message", "raw_ref")
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
            hours = [0] * 24
            cur.execute(self._q(f"SELECT SUBSTR(ts,12,2) AS h, COUNT(*) FROM events WHERE {w} GROUP BY h"), tuple(args))
            for hh, n in cur.fetchall():
                try:
                    hours[int(hh)] += int(n)
                except (TypeError, ValueError):
                    pass
            cur.execute(self._q(f"SELECT code, COUNT(*) AS n FROM events WHERE {w} AND code IS NOT NULL AND code<>'' GROUP BY code ORDER BY n DESC LIMIT 5"), tuple(args))
            codes = [{"code": c0, "n": int(n)} for c0, n in cur.fetchall()]
            cur.execute(self._q(f"SELECT severity, COUNT(*) FROM events WHERE {w} GROUP BY severity"), tuple(args))
            sev = {k: int(v) for k, v in cur.fetchall()}
        return {"total": total, "shown": len(rows), "rows": rows, "hours": hours, "codes": codes, "sev": sev}

    # ── 파일 이력(incidents.json) 이관 ──
    def migrate_from_files(self, base: Path) -> int:
        """데스크톱 형식(incidents.json + incidents/*.jsonl)이 있고 DB 가 비어 있으면 가져온다."""
        hist_file = base / "incidents.json"
        if not hist_file.exists() or self.count() > 0:
            return 0
        try:
            hist = json.loads(hist_file.read_text(encoding="utf-8"))
        except Exception:
            return 0
        n = 0
        for h in reversed(hist):  # 오래된 것부터 저장 → analyzed_at 정렬 유지
            if not h.get("id"):
                continue
            self.save_incident(h)
            self.import_events(h["id"], base / "incidents" / f"{h['id']}.jsonl")
            n += 1
        hist_file.rename(hist_file.with_suffix(".json.migrated"))
        return n
