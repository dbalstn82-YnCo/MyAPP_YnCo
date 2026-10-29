"""Persistent single-worker scheduling. All timestamps are Unix seconds; daily time is host local time."""
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

LOG = logging.getLogger(__name__)
KINDS = ('backup', 'log_watch', 'asset_sync', 'report', 'health_check')
OPERATIONS = ('save', 'run', 'pause', 'resume', 'delete', 'ack', 'set_outputs', 'purge_uploads')
JOB_ID_RE = re.compile(r'[A-Za-z0-9_-]{1,64}')


def as_int(value, low, high, label):
    """Strict integer parameter: JSON integers or digit strings only. bool/float/list are rejected (r2)."""
    if isinstance(value, str) and value.strip().lstrip('-').isdigit():
        value = int(value.strip())
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f'{label}: {low}~{high} 정수 필요')
    if not low <= value <= high:
        raise ValueError(f'{label}: {low}~{high} 정수 필요')
    return value


def as_text(value, limit, label, required=False):
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise ValueError(f'{label}: 문자열 필요')
    value = value.strip()
    if required and not value:
        raise ValueError(f'{label}: 값 필요')
    if len(value) > limit:
        raise ValueError(f'{label}: 최대 {limit}자')
    return value


class InstanceLock:
    def __init__(self, path):
        self.path, self.file = Path(path), None

    def acquire(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        f = self.path.open('a+b')
        try:
            if f.tell() == 0:
                f.write(b'0'); f.flush()
            f.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            # 운영자가 읽을 글이어야 한다. 전에는 이 한 줄과 역추적만 남아서, 왜 서버가
            # 안 뜨는지 알 수 없었다(현장 기동 기록, 2026-10-02). 어느 파일이 걸렸고
            # 무엇을 하면 되는지 적는다. 이 자물쇠는 OS 자물쇠라 **프로세스가 죽으면
            # 저절로 풀린다** — 파일을 지워서 푸는 것이 아니다.
            raise RuntimeError(
                '이 자료 폴더의 예약·자동화를 이미 다른 프로세스가 쓰고 있습니다 — '
                '다른 LogTriage 서버이거나 복원 작업입니다.' + chr(10)
                + f'  자물쇠: {self.path}' + chr(10)
                + "  확인:  ps -eo pid,user,args | grep '[l]ogtriage'" + chr(10)
                + '  떠 있는 서버를 멈추십시오(bash stop.sh). 복원 중이면 끝날 때까지 기다리십시오.' + chr(10)
                + '  (이 파일을 지워서 푸는 것이 아닙니다 — 쥔 프로세스가 끝나면 저절로 풀립니다.)'
            ) from None
        self.file = f

    def release(self):
        if self.file:
            self.file.close(); self.file = None


class SharedExclusiveLock:
    """Analyses (manual and automatic) hold this shared so they keep running concurrently up to MAX_ACTIVE;
    rulepack replacement and backup hold it exclusively so no analysis reads a half-swapped rules tree.
    Writer-preferring, not reentrant: never nest shared() inside exclusive() on the same thread."""

    def __init__(self):
        self._cv = threading.Condition()
        self._readers = 0; self._writer = False; self._waiting = 0

    @contextmanager
    def shared(self):
        with self._cv:
            while self._writer or self._waiting:
                self._cv.wait()
            self._readers += 1
        try:
            yield
        finally:
            with self._cv:
                self._readers -= 1; self._cv.notify_all()

    @contextmanager
    def exclusive(self):
        with self._cv:
            self._waiting += 1
            try:
                while self._writer or self._readers:
                    self._cv.wait()
            finally:
                self._waiting -= 1
            self._writer = True
        try:
            yield
        finally:
            with self._cv:
                self._writer = False; self._cv.notify_all()

    @contextmanager
    def try_exclusive(self):
        """기다리지 않는 배타 — 분석이 돌고 있으면 바로 거절한다(화면 요청이 분석 끝날 때까지 멈춰 있지 않게)."""
        with self._cv:
            if self._writer or self._readers or self._waiting:
                raise ValueError('분석·백업이 진행 중입니다 — 끝난 뒤 다시 시도하십시오')
            self._writer = True
        try:
            yield
        finally:
            with self._cv:
                self._writer = False; self._cv.notify_all()


def migrate_jobs(db):
    """16차(현장: '작업 등록일시를 보여 달라'): 등록 시각 칸. 이 판 이전에 등록된 작업은 알 수 없으므로 비워 둔다(지어내지 않음)."""
    if 'created' not in {r[1] for r in db.execute('PRAGMA table_info(jobs)')}:
        db.execute('ALTER TABLE jobs ADD COLUMN created REAL')


def next_due(spec, now):
    if spec['mode'] == 'interval':
        return now + spec['seconds']
    hour, minute = map(int, spec['time'].split(':'))
    due = datetime.fromtimestamp(now).replace(hour=hour, minute=minute, second=0, microsecond=0)
    if due.timestamp() <= now:
        due += timedelta(days=1)
    return due.timestamp()


def validate_job(value):
    if not isinstance(value, dict) or value.get('kind') not in KINDS:
        raise ValueError('작업 종류 오류')
    name = as_text(value.get('name'), 100, '작업명', required=True)
    if 'id' in value and value['id'] is not None:
        if not isinstance(value['id'], str) or not JOB_ID_RE.fullmatch(value['id']):
            raise ValueError('작업 ID 형식 오류')
    if 'enabled' in value and not isinstance(value['enabled'], bool):
        raise ValueError('예약 사용 여부는 true/false')
    spec = value.get('schedule')
    if not isinstance(spec, dict):
        raise ValueError('interval 또는 daily 예약 필요')
    if spec.get('mode') == 'interval':
        spec = {'mode': 'interval', 'seconds': as_int(spec.get('seconds', 0), 30, 31*86400, '반복 주기(초)')}
    elif spec.get('mode') == 'daily':
        if not isinstance(spec.get('time'), str):
            raise ValueError('실행 시각은 HH:MM')
        t = datetime.strptime(spec['time'].strip(), '%H:%M')
        spec = {'mode': 'daily', 'time': t.strftime('%H:%M')}
    else:
        raise ValueError('interval 또는 daily 예약 필요')
    params = value.get('params', {})
    if params is None:
        params = {}
    if not isinstance(params, dict) or len(json.dumps(params)) > 16000:
        raise ValueError('작업 설정 오류')
    return name, spec, params


class Automation:
    def __init__(self, api):
        self.api = api
        self.base = api._base
        self.path = self.base/'data/automation/jobs.sqlite3'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = InstanceLock(self.base/'.automation-worker.lock')
        self.guard = SharedExclusiveLock()
        self.stop_event = threading.Event()
        self.thread = self.alert_thread = None
        self.error = ''; self.heartbeat = 0; self.alert_heartbeat = 0
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, name TEXT, kind TEXT, schedule TEXT,
              params TEXT, enabled INTEGER, next_due REAL, state TEXT DEFAULT 'idle', attempts INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,job_id TEXT,name TEXT,started REAL,ended REAL,
              state TEXT,output TEXT,error TEXT);
            CREATE TABLE IF NOT EXISTS kv(key TEXT PRIMARY KEY,value TEXT);
            CREATE TABLE IF NOT EXISTS notices(id INTEGER PRIMARY KEY,at REAL,category TEXT,message TEXT,ack INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS alarms(key TEXT PRIMARY KEY,since REAL,active INTEGER,last_seen REAL);
            ''')
            migrate_jobs(db)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def get_value(self, key, default=None):
        with self.db() as db:
            r = db.execute('SELECT value FROM kv WHERE key=?', (key,)).fetchone()
            return json.loads(r[0]) if r else default

    def set_value(self, key, value):
        with self.db() as db:
            db.execute('INSERT OR REPLACE INTO kv VALUES(?,?)', (key, json.dumps(value, ensure_ascii=False)))

    def save(self, value):
        name, schedule, params = validate_job(value)
        from .automation_actions import validate_params
        validate_params(self.api, value['kind'], params)
        jid = value.get('id') or uuid.uuid4().hex
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
            if value.get('id') and not old:
                raise ValueError('작업 없음')
            if old and old['state'] == 'running':
                raise ValueError('실행 중인 작업은 완료 후 편집하십시오')
            # 편집해도 등록 시각은 처음 값 그대로(편집 = 등록이 아님)
            created = old['created'] if old else time.time()
            db.execute('INSERT OR REPLACE INTO jobs(id,name,kind,schedule,params,enabled,next_due,state,attempts,created) '
                       'VALUES(?,?,?,?,?,?,?,?,0,?)',
                       (jid, name, value['kind'], json.dumps(schedule), json.dumps(params),
                        int(bool(value.get('enabled', True))), next_due(schedule, time.time()), 'idle', created))
        return {'id': jid}

    def notices(self, limit=20):
        """상단 알림용 — 안 읽은 수와 최근 몇 건만(status 전체를 끌어오지 않는다)."""
        limit = max(1, min(int(limit or 20), 50))
        with self.db() as db:
            unack = db.execute('SELECT COUNT(*) FROM notices WHERE ack=0').fetchone()[0]
            rows = [dict(r) for r in db.execute(
                'SELECT id,at,category,message,ack FROM notices ORDER BY id DESC LIMIT ?', (limit,))]
        return {'unack': int(unack), 'notices': rows}

    def command(self, operation, value):
        if operation not in OPERATIONS:
            raise ValueError('지원하지 않는 작업')
        if not isinstance(value, dict):
            raise ValueError('JSON 객체 필요')
        if operation == 'save':
            return self.save(value)
        if operation == 'set_outputs':
            return self.set_outputs(value)
        if operation == 'purge_uploads':
            return self.purge_uploads(value)
        if operation == 'ack':
            nid = as_int(value.get('id'), 1, 2**53, '알림 ID')
            with self.db() as db:
                if db.execute('UPDATE notices SET ack=1 WHERE id=?', (nid,)).rowcount == 0:
                    raise ValueError('알림 없음')
            return {'ok': True}
        jid = value.get('id')
        if not isinstance(jid, str) or not JOB_ID_RE.fullmatch(jid):
            raise ValueError('작업 ID 형식 오류')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            job = db.execute('SELECT * FROM jobs WHERE id=?', (jid,)).fetchone()
            if not job:
                raise ValueError('작업 없음')
            if job['state'] == 'running':
                raise ValueError('실행 중인 작업은 완료 후 변경하십시오')
            if operation == 'run':
                # One immediate run; a paused job stays paused afterwards (r2: no silent re-enable).
                db.execute("UPDATE jobs SET next_due=0,attempts=0,state='idle' WHERE id=?", (job['id'],))
            elif operation == 'pause':
                db.execute('UPDATE jobs SET enabled=0 WHERE id=?', (job['id'],))
            elif operation == 'resume':
                due = next_due(json.loads(job['schedule']), time.time())
                db.execute("UPDATE jobs SET enabled=1,next_due=?,attempts=0,state='idle' WHERE id=?", (due, job['id']))
            elif operation == 'delete':
                db.execute('DELETE FROM jobs WHERE id=?', (job['id'],))
        return {'ok': True}

    # ── 산출물 저장 경로(r4): 기본 <설치경로>/reports, 추가 사본 경로(공유 폴더·NAS 등) 최대 5곳, 기본 형식, 보관 기간 ──
    OUT_DEFAULT = {'dir': '', 'copy_dirs': [], 'formats': ['html', 'pdf', 'hwpx'], 'keep_days': 180}

    def outputs(self):
        v = dict(self.OUT_DEFAULT); v.update(self.get_value('outputs', {}) or {})
        return v

    def output_dir(self):
        d = self.outputs().get('dir') or ''
        return Path(d) if d else self.base/'reports'

    @staticmethod
    def _writable(p, label):
        p = Path(p)
        if not p.is_absolute():
            raise ValueError(f'{label}: 절대 경로를 입력하십시오 (예: /data/logtriage/reports, D:\\LogTriage\\reports)')
        try:
            p.mkdir(parents=True, exist_ok=True)
            t = p/('.lt-write-test-'+uuid.uuid4().hex[:6]); t.write_text('ok', encoding='utf-8'); t.unlink()
        except OSError as e:
            raise ValueError(f'{label}: 쓸 수 없는 경로입니다 ({e.strerror or e})') from None
        return str(p)

    def set_outputs(self, value):
        from .ops_report import FORMATS
        cur = self.outputs()
        d = value.get('dir', cur['dir'])
        if not isinstance(d, str) or len(d) > 500:
            raise ValueError('저장 경로 형식 오류')
        d = self._writable(d.strip(), '산출물 저장 경로') if d.strip() else ''
        cds = value.get('copy_dirs', cur['copy_dirs'])
        if not isinstance(cds, list) or len(cds) > 5 or not all(isinstance(x, str) and len(x) <= 500 for x in cds):
            raise ValueError('추가 사본 경로는 5곳 이하 목록')
        cds = [self._writable(x.strip(), '추가 사본 경로') for x in cds if x.strip()]
        main = str(Path(d) if d else self.base/'reports')
        if any(str(Path(x)) == main for x in cds):
            raise ValueError('추가 사본 경로가 저장 경로와 같습니다')
        fm = value.get('formats', cur['formats'])
        if not isinstance(fm, list) or not fm or any(f not in FORMATS for f in fm):
            raise ValueError('기본 형식은 html · pdf · hwpx 중 하나 이상')
        kd = as_int(value.get('keep_days', cur['keep_days']), 7, 3650, '산출물 보관 기간(일)')
        v = {'dir': d, 'copy_dirs': cds, 'formats': [f for f in FORMATS if f in fm], 'keep_days': kd}
        self.set_value('outputs', v)
        return {'ok': True, 'outputs': v}

    def deliver(self, files):
        """자동 산출물을 추가 사본 경로로 복사(실패는 알림함에 남기고 계속). 본사 사본은 hub 전송기가 따로 보낸다."""
        import shutil
        copied, errors = 0, []
        for d in self.outputs().get('copy_dirs') or []:
            for f in files:
                try:
                    Path(d).mkdir(parents=True, exist_ok=True)
                    tmp = Path(d)/('.'+f.name+'.partial'); shutil.copyfile(f, tmp); tmp.replace(Path(d)/f.name); copied += 1
                except OSError as e:
                    errors.append(f'{d}: {e.strerror or e}')
        if errors:
            self.notice('failed', '추가 사본 경로 복사 실패 — ' + '; '.join(sorted(set(errors)))[:600])
        return copied

    def prune_outputs(self):
        keep = self.outputs().get('keep_days', 180)
        cut = time.time() - keep*86400
        n = 0
        for d in [self.output_dir()]:
            if d.is_dir():
                for f in d.iterdir():
                    if f.is_file() and f.name.startswith(('periodic-', 'check-')) and f.stat().st_mtime < cut:
                        f.unlink(missing_ok=True); n += 1
        return n

    @staticmethod
    def _dir_stat(p, limit=5000):
        p = Path(p)
        if not p.is_dir():
            return {'exists': False, 'count': 0, 'bytes': 0}
        n = b = 0
        try:
            for i, f in enumerate(p.iterdir()):
                if i >= limit:
                    return {'exists': True, 'count': n, 'bytes': b, 'more': True}
                if f.is_file():
                    n += 1; b += f.stat().st_size
        except OSError:
            pass
        return {'exists': True, 'count': n, 'bytes': b}

    def paths(self):
        api = self.api
        out = self.output_dir()
        try:
            rdir = Path(api.reports_dir())
        except Exception:
            rdir = self.base/'reports'
        hc = getattr(api, 'hub_conf', None)
        rows = [
            ('inbox', '로그 반입 폴더 (자동 분석 대상)', self.base/'uploads'/'inbox', '완성된 .log/.txt/.out 을 넣으면 30초 안정화 후 자동 분석'),
            ('uploads', '업로드 원본 로그', self.base/'uploads', '화면에서 올린 로그 원본'),
            ('incidents', '분석 결과 (이벤트 원본)', self.base/'incidents', '분석별 이벤트 원본(JSONL) — 로그 검색에 사용'),
            ('out', '자동 산출물 (점검 결과 · 운영 보고서)', out, '예약 작업이 만든 HTML · PDF · HWPX'),
        ]
        if rdir.resolve() != out.resolve():
            rows.append(('reports', '분석 보고서 (화면에서 생성)', rdir, '[분석 리포트]에서 만든 보고서·양식'))
        for i, d in enumerate(self.outputs().get('copy_dirs') or []):
            rows.append((f'copy{i}', f'추가 사본 경로 {i+1}', Path(d), '자동 산출물을 같은 이름으로 복사'))
        rows.append(('backups', '백업 (ZIP + SHA-256)', self.base/'backups', '예약 백업 결과 — 관리자만 내려받기'))
        res = []
        for key, label, p, desc in rows:
            res.append({'key': key, 'label': label, 'path': str(p), 'desc': desc, **self._dir_stat(p)})
        if hc:
            res.append({'key': 'hub', 'label': '본사 사본', 'path': (hc.get('hub_url') or '') if hc.get('role') == 'site' else str(self.base/'data'/'hub'/'files'),
                        'desc': '본사 서버로 1분마다 전송(요약·보고서)' if hc.get('role') == 'site' else '각 사이트가 보낸 보고서 사본', 'exists': True, 'count': None, 'bytes': None})
        log = self.base/'logtriage_server.log'
        res.append({'key': 'log', 'label': '서버 실행 로그', 'path': str(log) if log.exists() else 'systemd journal (journalctl -u logtriage-server)',
                    'desc': '접속·오류 기록', 'exists': log.exists(), 'count': None, 'bytes': log.stat().st_size if log.exists() else None})
        return res

    @staticmethod
    def _kind_of(name):
        if name.startswith('check-'):
            return 'check'
        if name.startswith('periodic-'):
            return 'report'
        if name.startswith('backup-'):
            return 'backup'
        return 'analysis'

    def files(self, limit=300):
        exts = ('.html', '.htm', '.pdf', '.hwpx', '.hwp', '.docx', '.json', '.txt', '.xlsx', '.zip')
        out = []
        areas = [('out', self.output_dir())]
        try:
            rdir = Path(self.api.reports_dir())
            if rdir.resolve() != self.output_dir().resolve():
                areas.append(('reports', rdir))
        except Exception:
            pass
        areas.append(('backups', self.base/'backups'))
        for area, d in areas:
            if not d.is_dir():
                continue
            for f in d.iterdir():
                if f.is_file() and f.suffix.lower() in exts and not f.name.startswith('.') and not f.name.endswith('.partial'):
                    st = f.stat()
                    out.append({'area': area, 'name': f.name, 'size': st.st_size, 'mtime': st.st_mtime,
                                'kind': 'backup' if area == 'backups' else self._kind_of(f.name), 'ext': f.suffix.lower().lstrip('.')})
        out.sort(key=lambda x: x['mtime'], reverse=True)
        return out[:limit]

    def file_path(self, area, name):
        name = Path(str(name)).name
        if not name or name.startswith('.') or area not in ('out', 'reports', 'backups'):
            return None
        d = {'out': self.output_dir(), 'backups': self.base/'backups'}.get(area)
        if area == 'reports':
            try:
                d = Path(self.api.reports_dir())
            except Exception:
                return None
        f = d/name
        return f if f.is_file() and f.resolve().parent == d.resolve() else None

    def purge_uploads(self, value):
        """16차(현장 '저장 경로에 삭제 메뉴'): 화면에서 올린 로그 원본(data/uploads 바로 아래 파일)만 정리한다 — 관리자 전용(서버 관문).
        지난 분석의 판정·원문 미리보기·로그 검색은 분석 결과(incidents)에 따로 저장돼 있어 그대로 남는다.
        반입 폴더(inbox)·하위 폴더·바로가기(symlink)는 건드리지 않는다. 분석이 도는 중이면 거절(읽는 파일을 지우지 않게)."""
        import stat as _st
        days = as_int(value.get('older_days', 7), 0, 3650, '보관 일수')
        up = self.base/'uploads'
        now = time.time()
        cut = now - days*86400
        removed = kept = size = 0
        # GPT 107 P0-02: uploads 폴더 자체가 바로가기·연결 지점(junction)으로 바뀌어 있으면 바깥 파일을 지우게 된다 → 거절
        if up.exists() and (up.is_symlink() or getattr(os.path, 'isjunction', lambda p: False)(up)
                            or up.resolve() != self.base.resolve()/'uploads'):
            raise ValueError('업로드 폴더가 바로가기(링크)로 바뀌어 있어 정리하지 않습니다 — 서버 관리자가 폴더를 확인하십시오')
        real = up.resolve() if up.is_dir() else None
        with self.guard.try_exclusive():
            for f in (up.iterdir() if real else ()):
                try:
                    st = os.lstat(f)
                    if not _st.S_ISREG(st.st_mode) or f.resolve().parent != real:
                        continue
                    # GPT 107 P1-01: 방금 올리는 중인 파일(1분 안에 바뀜)은 '전부'여도 남긴다 — 올리기와 지우기가 겹치지 않게
                    if st.st_mtime > cut or st.st_mtime > now - 60:
                        kept += 1; continue
                    st2 = os.lstat(f)          # 지우기 직전 같은 파일인지 다시 확인(그사이 바꿔치기 방지)
                    if (st2.st_ino, st2.st_dev, st2.st_size, st2.st_mtime) != (st.st_ino, st.st_dev, st.st_size, st.st_mtime) \
                            or not _st.S_ISREG(st2.st_mode):
                        kept += 1; continue
                    f.unlink(); removed += 1; size += st.st_size
                except OSError:
                    kept += 1
        actor = str(value.get('_actor') or '')[:120]
        self.notice('정리', f'업로드 원본 로그 {removed}개({size/1048576:.1f} MB) 삭제 — {days}일 지난 것'
                    + (f' · {actor}' if actor else '') + (f' · 남김 {kept}개' if kept else ''))
        return {'ok': True, 'removed': removed, 'bytes': size, 'kept': kept, 'older_days': days}

    def notice(self, category, message):
        with self.db() as db:
            db.execute('INSERT INTO notices(at,category,message) VALUES(?,?,?)', (time.time(), category, message[:4000]))

    def wake_assets(self, document_name):
        with self.db() as db:
            for row in db.execute("SELECT id,params FROM jobs WHERE kind='asset_sync' AND enabled=1 AND state!='running'").fetchall():
                if json.loads(row['params']).get('document_name') == document_name:
                    db.execute("UPDATE jobs SET next_due=0,state='idle',attempts=0 WHERE id=?",(row['id'],))

    def status(self):
        with self.db() as db:
            jobs = [dict(r) for r in db.execute('SELECT * FROM jobs ORDER BY name')]
            runs = [dict(r) for r in db.execute('SELECT * FROM runs ORDER BY started DESC LIMIT 100')]
            notices = [dict(r) for r in db.execute('SELECT * FROM notices ORDER BY id DESC LIMIT 200')]
        for j in jobs:
            j['schedule'] = json.loads(j['schedule']); j['params'] = json.loads(j['params'])
        reports = self.base/'reports'
        files = [p.name for p in sorted(reports.glob('periodic-*')) if p.is_file() and not p.name.endswith('.partial')] if reports.is_dir() else []
        try:
            outs, paths, allfiles = self.outputs(), self.paths(), self.files()
        except Exception as e:   # 경로 문제로 상태 화면 전체가 멈추지 않게
            outs, paths, allfiles = self.outputs(), [], []; self.error = self.error or f'경로 확인 오류: {e}'
        return {'jobs': jobs, 'runs': runs, 'notices': notices, 'heartbeat': self.heartbeat,
                'alert_heartbeat': self.alert_heartbeat, 'error': self.error,
                'running': bool(self.thread and self.thread.is_alive()),
                'timezone': str(datetime.now().astimezone().tzinfo),
                'files': files, 'patch': '2026.09.18-automation.2', 'outputs': outs, 'output_dir': str(self.output_dir()),
                'paths': paths, 'products': allfiles}

    def recover(self):
        with self.db() as db:
            db.execute("UPDATE runs SET state='interrupted',ended=?,error='프로세스 중단; 작업 재시도 예약' WHERE state='running'", (time.time(),))
            db.execute("UPDATE jobs SET state='idle',next_due=0 WHERE state='running'")

    def tick(self, runner=None, now=None):
        now = time.time() if now is None else now
        self.heartbeat = now
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            # next_due<=0 marks an explicit '즉시 실행'; it runs once even while the schedule is paused.
            row = db.execute("SELECT * FROM jobs WHERE state!='running' AND next_due<=? AND (enabled=1 OR next_due<=0) ORDER BY next_due LIMIT 1", (now,)).fetchone()
            if not row:
                return False
            job = dict(row); rid = uuid.uuid4().hex
            db.execute("UPDATE jobs SET state='running',attempts=attempts+1 WHERE id=?", (job['id'],))
            db.execute("INSERT INTO runs(id,job_id,name,started,state) VALUES(?,?,?,?,'running')", (rid,job['id'],job['name'],now))
        job['params'] = json.loads(job['params']); job['run_id'] = rid
        try:
            if runner is None:
                from .automation_actions import execute
                output = execute(self, job)
            else:
                output = runner(job)
            error = ''; state = 'success'; attempts = 0
            due = next_due(json.loads(job['schedule']), max(time.time(), now))
        except Exception as exc:
            if isinstance(exc, (ValueError, RuntimeError, OSError)):   # expected job failure: one line, no stack trace (r2)
                LOG.error('Automation job failed: %s (%s): %s', job['name'], job['id'], exc)
            else:
                LOG.exception('Automation job failed: %s (%s)', job['name'], job['id'])
            error = str(exc)[:4000]; output = {}; attempts = job['attempts']+1
            state = 'retry' if attempts < 3 else 'failed'
            due = now + 30 * (2 ** (attempts-1)) if attempts < 3 else next_due(json.loads(job['schedule']), max(time.time(), now))
            if attempts >= 3:
                self.notice('job_failed', job['name']+': '+error); attempts = 0
            elif not job['enabled']:
                # Paused job run once by hand: report the failure now instead of retrying silently.
                self.notice('job_failed', job['name']+': '+error); attempts = 0; state = 'failed'
                due = next_due(json.loads(job['schedule']), max(time.time(), now))
        with self.db() as db:
            db.execute('UPDATE jobs SET state=?,attempts=?,next_due=? WHERE id=?', (state,attempts,due,job['id']))
            db.execute('UPDATE runs SET ended=?,state=?,output=?,error=? WHERE id=?',
                       (time.time(),state,json.dumps(output,ensure_ascii=False,default=str),error,rid))
            db.execute('DELETE FROM runs WHERE id NOT IN (SELECT id FROM runs ORDER BY started DESC LIMIT 5000)')
        return True

    QZ_NOTICE_AGE = 86400      # 격리·표식 없는 임시 백업이 이만큼 남아 있으면 알린다(아이디어 10)
    QZ_CHECK_EVERY = 600

    RETENTION_KEY = 'tmp_backup_retention_days'

    def tmp_retention(self):
        """격리 폴더 보관 기간(일). 0 = 사용 안 함(기본 — 관리자가 지운다)."""
        try:
            v = int(self.get_value(self.RETENTION_KEY, 0) or 0)
        except (TypeError, ValueError):
            v = 0
        return v if 0 <= v <= 365 else 0

    def set_tmp_retention(self, days):
        d = int(days)
        if not 0 <= d <= 365:
            raise ValueError('보관 기간은 0(사용 안 함)~365일')
        self.set_value(self.RETENTION_KEY, d)
        return d

    def purge_quarantined(self, now=None):
        """3차 아이디어 11: 관리자가 정한 보관 기간이 지난 '격리한' 폴더만 지운다(표식 없는·진행 중 폴더는 손대지 않음).
        지우기는 관리자 화면과 같은 delete_backup — 링크·변경·묶음 쓰는 중 검사를 그대로 거친다."""
        from .safe_backup import list_backups, delete_backup
        days = self.tmp_retention()
        if not days:
            return 0
        now = time.time() if now is None else now
        n = 0
        for x in list_backups(self.base):
            if x['state'] == 'quarantined' and x.get('quarantined_at') and now - x['quarantined_at'] >= days * 86400:
                r = delete_backup(self.base, x['name'])
                if r.get('ok'):
                    n += 1
                elif r.get('partial'):   # GPT 41차: 일부만 지운 것은 지운 수에 넣지 않고 따로 알린다
                    self.notice('tmp_backup', str(r.get('error', ''))[:160])
        if n:
            self.notice('tmp_backup', f'보관 기간({days}일)이 지난 격리 폴더 {n}개를 지웠습니다')
        return n

    def check_tmp_backups(self, now=None):
        """하루 넘게 남은 격리 폴더·표식 없는 임시 백업을 상단 알림 종에 알린다 — 자동으로 지우지는 않는다(관리자 확인 원칙).
        같은 알림은 하루 한 번. 알림에는 개수만(경로·내용 없음)."""
        from .safe_backup import list_backups
        now = time.time() if now is None else now
        items = list_backups(self.base)
        old_qz = [x for x in items if x['state'] == 'quarantined' and x.get('quarantined_at') and now - x['quarantined_at'] >= self.QZ_NOTICE_AGE]
        old_un = [x for x in items if x['state'] == 'unowned' and x.get('modified') and now - x['modified'] >= self.QZ_NOTICE_AGE]
        if not (old_qz or old_un):
            return None
        with self.db() as db:
            if db.execute("SELECT 1 FROM notices WHERE category='tmp_backup' AND at>?", (now - 86400,)).fetchone():
                return None
        parts = ([f'격리한 폴더 {len(old_qz)}개'] if old_qz else []) + ([f'주인 표식 없는 폴더 {len(old_un)}개'] if old_un else [])
        msg = '임시 백업 ' + ' · '.join(parts) + '가 하루 넘게 남아 있습니다 — 관리자 > 임시 백업에서 확인 후 지우십시오(자료 사본이 들어 있습니다)'
        self.notice('tmp_backup', msg)
        return msg

    def _loop(self):
        last_qz = 0.0
        while not self.stop_event.is_set():
            try:
                self.tick(); self.error = ''
            except Exception as exc:
                self.error = str(exc); LOG.exception('Scheduler error')
            if time.time() - last_qz >= self.QZ_CHECK_EVERY:
                last_qz = time.time()
                try:
                    self.purge_quarantined()
                    self.check_tmp_backups()
                except Exception:   # 알림 점검이 예약 작업을 멈추지 않는다
                    LOG.exception('임시 백업 점검 실패')
            self.stop_event.wait(1)

    def _alarms(self):
        from .automation_actions import poll_alarms
        while not self.stop_event.is_set():
            try:
                poll_alarms(self); self.alert_heartbeat = time.time()
            except Exception:
                LOG.exception('Alarm polling failed')
            self.stop_event.wait(10)

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.lock.acquire()
        try:
            self.recover(); self.stop_event.clear()
            if not self.get_value('defaults_installed', False):
                inbox = self.base/'uploads/inbox'; inbox.mkdir(parents=True, exist_ok=True)
                defaults = [
                    {'name':'매일 백업','kind':'backup','schedule':{'mode':'daily','time':'02:00'},'params':{'keep':14}},
                    {'name':'매일 운영 보고서','kind':'report','schedule':{'mode':'daily','time':'17:00'},'params':{'days':1}},
                    {'name':'반입 로그 자동 분석','kind':'log_watch','schedule':{'mode':'interval','seconds':60},'params':{'directory':str(inbox),'stable_seconds':30}}
                ]
                for job in defaults:
                    with self.db() as db:
                        exists = db.execute('SELECT 1 FROM jobs WHERE name=? AND kind=?',(job['name'],job['kind'])).fetchone()
                    if not exists:
                        self.save(job)
                self.set_value('defaults_installed', True)
            if not self.get_value('defaults_r4', False):   # r4: 스케줄 기반 모니터링 — 기존 설치에도 한 번 추가
                for job in ({'name':'상시 상태 점검','kind':'health_check','schedule':{'mode':'interval','seconds':600},'params':{'save':False,'notify':True}},
                            {'name':'매일 상태 점검 보고','kind':'health_check','schedule':{'mode':'daily','time':'08:50'},'params':{'save':True,'notify':False}}):
                    with self.db() as db:
                        exists = db.execute('SELECT 1 FROM jobs WHERE name=? AND kind=?',(job['name'],job['kind'])).fetchone()
                    if not exists:
                        self.save(job)
                self.set_value('defaults_r4', True)
            self.thread = threading.Thread(target=self._loop, name='automation', daemon=False)
            self.alert_thread = threading.Thread(target=self._alarms, name='server-alarms', daemon=False)
            self.thread.start(); self.alert_thread.start()
        except Exception:
            self.lock.release(); raise

    def stop(self):
        self.stop_event.set()
        for thread in (self.thread, self.alert_thread):
            if thread:
                thread.join()  # Never release lock while a job is still writing.
        self.lock.release()
