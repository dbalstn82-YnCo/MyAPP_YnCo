"""Built-in automation jobs. No arbitrary shell command execution."""
import hashlib
import logging
import html
import json
import shutil
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from . import first_response

from .automation import as_int, as_text

LOG = logging.getLogger(__name__)

TARGET_KINDS = ('server', 'network', 'security', 'storage', 'other')


def asset_document(api, params):
    name = params.get('document_name')
    if not name:
        original = api.docs.get(as_int(params.get('document_id', 0), 1, 2**31, '자원 문서 ID'))
        name = original.get('name')
        if not name:
            return original
        params['document_name'] = name
    matches = [d for d in api.docs.list() if d['name'] == name]
    if not matches:
        raise ValueError('연동 자원 문서가 없습니다: '+name)
    latest = max(matches, key=lambda d: (d['at'], d['id']))
    return api.docs.get(latest['id'])


def _formats(p):
    """형식 목록(빈 값 = 저장 경로 설정의 기본 형식)."""
    from .ops_report import FORMATS
    f = p.get('formats')
    if f in (None, '', []):
        p.pop('formats', None)
        return
    if not isinstance(f, list) or any(x not in FORMATS for x in f):
        raise ValueError('보고서 형식은 html · pdf · hwpx 중에서 고르십시오')
    p['formats'] = [x for x in FORMATS if x in f]


def validate_params(api, kind, p):
    """Strict, normalising validation (r2): every numeric field is stored back as int; bool/float/list are rejected."""
    if kind == 'backup':
        p['keep'] = as_int(p.get('keep', 14), 1, 365, '백업 보관 개수')
    elif kind == 'log_watch':
        # 화면은 '빈 값 = uploads/inbox' 라고 안내한다 — 그 약속을 서버가 지킨다(없으면 만든다)
        directory = as_text(p.get('directory'), 1000, '로그 폴더')
        if not directory:
            inbox = Path(api._base) / 'uploads' / 'inbox'
            inbox.mkdir(parents=True, exist_ok=True)
            directory = str(inbox)
        root = Path(directory).resolve()
        if not root.is_dir() or not api._allowed(root):
            raise ValueError('로그 폴더는 uploads 또는 --allow-dir로 허용한 경로여야 합니다')
        p['directory'] = directory
        p['stable_seconds'] = as_int(p.get('stable_seconds', 30), 10, 86400, '파일 안정화 시간(초)')
        p['max_mb'] = as_int(p.get('max_mb', 100), 1, 600, '파일 제한(MB)')
        p['batch'] = as_int(p.get('batch', 5), 1, 50, '회당 처리 수')
        p['product'] = as_text(p.get('product', ''), 100, '제품 식별자')
        from .first_response import normalize as _fr_norm
        p['followup'] = _fr_norm(p.get('followup'))   # 무인 1차 대응: 분석 뒤에 무엇을 할지
    elif kind == 'asset_sync':
        if 'document_name' in p and p['document_name'] not in (None, ''):
            p['document_name'] = as_text(p['document_name'], 255, '자원 문서명', required=True)
        else:
            p.pop('document_name', None)
        doc = asset_document(api, p)
        p['sheet'] = as_text(p.get('sheet'), 80, '시트명', required=True)
        sheet = next((s for s in doc['sheets'] if s['name'] == p['sheet']), None)
        if sheet is None:
            raise ValueError('자원 문서의 시트명을 지정하십시오')
        for field, label in (('id_column', '고유 자산 ID 열'), ('name_column', '장비명 열'), ('ip_column', 'IP 주소 열')):
            p[field] = as_int(p.get(field, 0), 1, max(1, int(sheet['ncols'])), label+' (1부터 시작하는 엑셀 열 번호)')
        if p.get('header_rows') in (None, ''):
            p.pop('header_rows', None)
        else:
            p['header_rows'] = as_int(p['header_rows'], 0, 50, '제목 행 수')
        p['method'] = as_text(p.get('method', 'icmp') or 'icmp', 10, '감시 방식')
        p['kind'] = as_text(p.get('kind', 'server') or 'server', 20, '장비 유형')
        if p['method'] not in ('icmp', 'tcp') or p['kind'] not in TARGET_KINDS:
            raise ValueError('감시 방식/장비 유형 오류')
        p['port'] = as_int(p.get('port', 443), 1, 65535, 'TCP 포트')
    elif kind == 'report':
        p['days'] = as_int(p.get('days', 1), 1, 366, '보고 기간(일)')
        _formats(p)
    elif kind == 'health_check':
        for k, d in (('save', True), ('notify', True)):
            v = p.get(k, d)
            if not isinstance(v, bool):
                raise ValueError(f'{k}: true/false')
            p[k] = v
        _formats(p)
    else:
        raise ValueError('작업 종류 오류')


def execute(worker, job):
    p = job['params']; api = worker.api
    validate_params(api, job['kind'], p)
    if job['kind'] == 'backup':
        from .safe_backup import snapshot
        # RPK updates, running analyses and backup of the knowledge trees must not overlap.
        with api._rc_lock, worker.guard.exclusive():
            result = snapshot(worker.base, api.store)
        backups = sorted((worker.base/'backups').glob('backup-*.zip'), key=lambda f:f.stat().st_mtime, reverse=True)
        for old in backups[p['keep']:]:
            old.unlink(); old.with_suffix('.zip.sha256').unlink(missing_ok=True)
        for leftover in (worker.base/'backups').glob('*.partial'):   # crashed earlier run
            if time.time() - leftover.stat().st_mtime > 3600:
                leftover.unlink(missing_ok=True)
        return result
    if job['kind'] == 'log_watch':
        return watch_logs(worker, job)
    if job['kind'] == 'asset_sync':
        return sync_assets(worker, job)
    if job['kind'] == 'report':
        return report(worker, job)
    if job['kind'] == 'health_check':
        return health_check(worker, job)
    raise ValueError('지원하지 않는 작업')


def watch_logs(worker, job):
    from .safe_backup import sha
    from .detect import detect_product
    from .service import run_analysis
    from .server import _ACTIVE
    p = job['params']; api = worker.api; root = Path(p['directory']).resolve()
    key = 'watch:'+job['id']; state = worker.get_value(key, {})
    files = sorted(root.glob('*'))
    if len(files) > 10000:
        raise ValueError('폴더당 10,000개 이하로 로그를 분할하십시오')
    done = []; acted = []; errors = []; seen = set(); now = time.time()
    for src in files:
        if not src.is_file() or src.suffix.lower() not in ('.log','.txt','.out') or src.is_symlink():
            continue
        if not src.resolve().is_relative_to(root) or not api._allowed(src):
            continue
        identity = str(src); seen.add(identity); stat = src.stat()
        signature = [stat.st_size, stat.st_mtime_ns]
        previous = state.get(identity, {})
        if previous.get('stat') != signature:
            state[identity] = {'stat': signature, 'since': now, 'done': previous.get('done')}
            continue
        if now-previous['since'] < int(p.get('stable_seconds',30)) or len(done) >= int(p.get('batch',5)):
            continue
        if stat.st_size > int(p.get('max_mb',100))*1024**2:
            errors.append(src.name+': 크기 제한 초과'); continue
        digest = sha(src)
        if previous.get('done') == digest:
            continue
        incident_id = 'AUTO-'+hashlib.sha256((job['id']+'|'+identity+'|'+digest).encode()).hexdigest()[:32]
        if api.store.get(incident_id):
            previous['done'] = digest; continue
        cache = worker.base/'uploads/automation'; cache.mkdir(parents=True, exist_ok=True)
        copied = cache/(uuid.uuid4().hex+src.suffix)
        try:
            shutil.copyfile(src,copied)
            if sha(copied) != digest or [src.stat().st_size,src.stat().st_mtime_ns] != signature:
                continue  # Writer changed file while copying; wait for a new stable observation.
            product = p.get('product') or detect_product(copied)
            if not product:
                raise ValueError('제품 판별 실패: 작업의 제품 식별자를 설정하십시오')
            if not _ACTIVE.acquire(blocking=False):
                raise RuntimeError('분석 슬롯 사용 중; 재시도')
            try:
                with worker.guard.shared():   # concurrent with manual analyses, exclusive against RPK/backup
                    result = run_analysis([{'path':str(copied),'product':product,'host':src.stem}], None,30,10,
                                          worker.base/'rules',worker.base/'rules-local',worker.base/'errorcodes',
                                          events_export=worker.base/'incidents'/(incident_id+'.jsonl'))
                    result.update(id=incident_id,name='자동 분석: '+src.name)
                    try:   # 룰 학습 후보 기록(결과·이력에는 남기지 않는다)
                        from .learn import LearnStore
                        LearnStore(worker.base).record(result.pop('learn', []) or [], incident_id)
                    except Exception:
                        result.pop('learn', None)
                    api._save_history(result)
            finally:
                _ACTIVE.release()
            previous['done'] = digest; done.append(incident_id)
            worker.set_value(key, state)
            worker.notice('analysis',src.name+' 분석 완료: '+incident_id)
            # 감지·분석에서 끝내지 않고 1차 대응까지 — 실패해도 분석 결과는 그대로 둔다
            try:
                fr = first_response.run(worker, job, incident_id, result, source=src.name)
                if fr.get('done'):
                    acted.append({'id': incident_id, 'level': fr['level'], 'did': fr['done']})
            except Exception as exc:
                LOG.warning('무인 1차 대응 후속 조치 실패 %s: %s', incident_id, exc)
        except Exception as exc:
            errors.append(src.name+': '+str(exc))
        finally:
            copied.unlink(missing_ok=True)
    worker.set_value(key, {k:v for k,v in state.items() if k in seen})
    if errors:
        raise RuntimeError('; '.join(errors[:10]))
    return {'analyzed':done,'observed':len(seen),'first_response':acted}


def sync_assets(worker, job):
    from .nms import validate
    p = job['params']; doc = asset_document(worker.api, p)
    sheet = next(s for s in doc['sheets'] if s['name']==p['sheet'])
    header_rows = int(sheet['header_rows'])
    if p.get('header_rows') not in (None, ''):
        header_rows = int(p['header_rows'])   # job-level override survives re-uploads (r2)
    desired = {}; errors = []
    for rowno, cells in sheet['rows'][header_rows:]:
        def cell(field):
            i = int(p[field])-1
            return str(cells[i] if i<len(cells) and cells[i] is not None else '').strip()
        identity,name,address = cell('id_column'),cell('name_column'),cell('ip_column')
        if not identity and not name and not address:
            continue
        try:
            if not identity or identity in desired:
                raise ValueError('자산 ID 누락 또는 중복')
            data = validate({'name':name,'address':address,'kind':p.get('kind','server'),
                             'method':p.get('method','icmp'),'port':int(p.get('port',443))})
            desired[identity] = data
        except Exception as exc:
            errors.append(f'{rowno}행: {exc}')
    if errors:
        raise ValueError('동기화 전체 취소: '+'; '.join(errors[:10]))
    if not desired:
        raise ValueError(f'빈 자산 목록(제목 행 {header_rows}행 제외): 기존 감시 항목을 일괄 중지하지 않습니다')
    added = changed = paused = 0
    # Mapping and targets share one transaction: crashes cannot create orphan duplicates.
    with worker.api.nms.db() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS automation_assets(owner TEXT,asset TEXT,target TEXT,PRIMARY KEY(owner,asset))')
        mapping = {r['asset']:r['target'] for r in db.execute('SELECT * FROM automation_assets WHERE owner=?',(job['id'],))}
        for asset, data in desired.items():
            tid = mapping.get(asset)
            old = db.execute('SELECT * FROM targets WHERE id=?',(tid,)).fetchone() if tid else None
            if old is None:
                if db.execute('SELECT count(*) FROM targets').fetchone()[0]>=500:
                    raise ValueError('NMS 500개 제한: 전체 동기화 취소')
                # Do not silently take ownership of an existing manually configured IP.
                if db.execute('SELECT id FROM targets WHERE address=?',(data['address'],)).fetchone():
                    raise ValueError('기존 감시 IP 중복: '+data['address']+'; 수동 항목 유지, 전체 동기화 취소')
                tid = uuid.uuid4().hex
                db.execute(f"INSERT INTO targets(id,{','.join(data)},status) VALUES({','.join('?' for _ in range(len(data)+2))})",(tid,*data.values(),'unknown'))
                db.execute('INSERT OR REPLACE INTO automation_assets VALUES(?,?,?)',(job['id'],asset,tid)); added += 1
            else:
                updates = {k:data[k] for k in ('name','address','kind','method','port','enabled') if old[k]!=data[k]}
                if updates:
                    db.execute(f"UPDATE targets SET {','.join(k+'=?' for k in updates)},revision=revision+1,status='unknown',failures=0,successes=0,next_due=0,last_check=NULL WHERE id=?",(*updates.values(),tid))
                    db.execute("UPDATE alerts SET closed=?,close_reason='asset sync' WHERE target_id=? AND closed IS NULL",(time.time(),tid)); changed += 1
        for asset,tid in mapping.items():
            if asset not in desired:
                paused += db.execute("UPDATE targets SET enabled=0,status='paused',revision=revision+1 WHERE id=? AND enabled=1",(tid,)).rowcount
                db.execute("UPDATE alerts SET closed=?,close_reason='asset missing' WHERE target_id=? AND closed IS NULL",(time.time(),tid))
    return {'added':added,'updated':changed,'paused':paused,'assets':len(desired),'header_rows':header_rows,
            'document_id':doc.get('id'),'document_revision':doc.get('rev')}


def poll_alarms(worker, now=None):
    now = time.time() if now is None else now
    snap = worker.api.nms.snapshot(); current = {}; known = set(); labels = {}
    for target in snap['targets']:
        tid = target['id']; usage = target.get('usage') or {}
        for metric in ('cpu','mem','disk'):
            key = tid+':'+metric; labels[key] = target['name']+' '+metric
            if not target['enabled'] or target.get('metrics')=='none':
                current[key] = (False,False); known.add(key)
            elif usage and not usage.get('stale') and usage.get(metric) is not None:
                value = usage[metric]; threshold = snap['settings']['th_'+metric]
                current[key] = (value>=threshold,value>=threshold-5); known.add(key)
        key = tid+':availability'; labels[key] = target['name']+' 가용성'
        if target['status'] in ('down','recovering','up','paused'):
            down = target['status'] in ('down','recovering')
            current[key] = (down,down); known.add(key)
    with worker.db() as db:
        db.execute('BEGIN IMMEDIATE')
        existing = {r['key']:dict(r) for r in db.execute('SELECT * FROM alarms')}
        for key in known:
            high,hold = current[key]; old = existing.get(key); active = bool(old and old['active'])
            since = old['since'] if old and (active or now-old['last_seen']<=30) else now
            if not old:
                since = now
            # Availability already passed NMS fail/recovery counters; metrics require 60 seconds.
            fire = high and (key.endswith(':availability') or now-since>=60)
            if not active and fire:
                db.execute("INSERT INTO notices(at,category,message) VALUES(?,'alarm',?)",(now,labels[key]+' 장애/임계치 초과'))
                active = True
            elif active and not hold:
                db.execute("INSERT INTO notices(at,category,message) VALUES(?,'recovery',?)",(now,labels[key]+' 정상 복구/감시 중지'))
                active = False
            if high or active:
                db.execute('INSERT OR REPLACE INTO alarms VALUES(?,?,?,?)',(key,since,int(active),now))
            else:
                db.execute('DELETE FROM alarms WHERE key=?',(key,))
        # Missing/stale metrics do not prove recovery. Keep active alarms until fresh evidence.
        db.execute('DELETE FROM notices WHERE id NOT IN (SELECT id FROM notices ORDER BY id DESC LIMIT 10000)')


def _site_name(worker):
    hc = getattr(worker.api, 'hub_conf', None)
    if hc:
        return hc.get('site_name') or hc.get('site_id')
    import platform
    return platform.node() or 'LogTriage'


def _hm(ts):
    return datetime.fromtimestamp(ts).strftime('%m-%d %H:%M') if ts else '-'


def _emit(worker, job, doc, stem):
    """형식별 산출물 쓰기 → 추가 사본 복사 → 오래된 산출물 정리. 결과 요약(dict) 반환."""
    from .ops_report import write_outputs
    fm = job['params'].get('formats') or worker.outputs().get('formats') or ['html']
    tpl = worker.base/'report-template'/'form_status.hwpx'
    made, errors = write_outputs(doc, worker.output_dir(), stem, fm, tpl)
    copied = worker.deliver(made) if made else 0
    worker.prune_outputs()
    if errors:
        worker.notice('failed', f"{job.get('name') or '예약 작업'}: 일부 형식 생성 실패 — " + '; '.join(errors)[:600])
    return {'files': [f.name for f in made], 'dir': str(worker.output_dir()), 'copies': copied, 'errors': errors}


def _usage(t):
    u = t.get('usage') or {}
    return u.get('cpu'), u.get('mem'), u.get('disk')


def _pct(v):
    return '-' if v is None else f'{v:.0f}%'


def health_check(worker, job):
    """정기 상태 점검: 감시 장비 가용성·자원 사용률·수집 지연·미확인 알림을 한 번에 점검하고(스냅숏),
    이상이 새로 생기거나 바뀌면 알림함에 남긴다. save=True 이면 점검 결과를 HTML/PDF/HWPX 로 저장한다."""
    p = job['params']; api = worker.api
    now = time.time()
    snap = api.nms.snapshot(); st = snap.get('settings') or {}
    targets = [t for t in snap['targets'] if t.get('enabled')]
    down = [t for t in targets if t.get('status') in ('down', 'suspect')]
    stale = [t for t in targets if t.get('stale') and t not in down]
    hot = []
    for t in targets:
        c, m, d = _usage(t)
        u = t.get('usage') or {}
        if u and not u.get('stale') and any(v is not None and v >= st.get('th_'+k, 90) for k, v in (('cpu', c), ('mem', m), ('disk', d))):
            hot.append(t)
    with worker.db() as db:
        unack = db.execute('SELECT count(*) FROM notices WHERE ack=0').fetchone()[0]
        fails = [dict(r) for r in db.execute("SELECT name,started,error FROM runs WHERE state='failed' AND started>=? ORDER BY started DESC LIMIT 50", (now-86400,))]
    ok_n = sum(1 for t in targets if t.get('status') == 'up')
    issues = sorted({t['name'] for t in down} | {t['name'] for t in hot})
    key = 'hc:last:'+job['id']
    last = worker.get_value(key, [])
    if p.get('notify', True) and issues != last:
        if issues:
            worker.notice('alarm', f"정기 상태 점검: 장애·의심 {len(down)}대 · 임계 초과 {len(hot)}대 — " + ', '.join(issues[:12]) + (' 외' if len(issues) > 12 else ''))
        elif last:
            worker.notice('recovery', '정기 상태 점검: 이상 장비 없음(이전 점검 대비 정상화)')
    worker.set_value(key, issues)
    result = {'targets': len(targets), 'up': ok_n, 'down': len(down), 'hot': len(hot), 'stale': len(stale), 'unacked_notices': unack,
              'summary': f"점검 {len(targets)}대 · 정상 {ok_n} · 장애/의심 {len(down)} · 임계 {len(hot)} · 수집 지연 {len(stale)}"}
    if not p.get('save', True):
        return result
    TS = {'up': '정상', 'down': '장애', 'suspect': '의심', 'unknown': '확인 전', 'paused': '중지', 'recovering': '복구 중'}
    nowdt = datetime.now().astimezone()
    doc = {'title': '정기 상태 점검 결과', 'site': _site_name(worker),
           'subtitle': f"{nowdt:%Y-%m-%d %H:%M} 기준 · 감시 장비 {len(targets)}대",
           'meta': [('작업', job.get('name') or '예약 작업'), ('생성', f"{nowdt:%Y-%m-%d %H:%M:%S}"), ('임계치', f"CPU {st.get('th_cpu',90)}% · 메모리 {st.get('th_mem',90)}% · 디스크 {st.get('th_disk',90)}%")],
           'kpis': [('감시 장비', f'{len(targets)}대', 'mute'), ('정상', f'{ok_n}대', 'ok'), ('장애 · 의심', f'{len(down)}대', 'crit' if down else 'ok'),
                    ('임계 초과', f'{len(hot)}대', 'warn' if hot else 'ok'), ('미확인 알림', f'{unack}건', 'warn' if unack else 'ok')],
           'sections': [
               {'title': '장애 · 의심 장비', 'note': '가용성 점검(ICMP/TCP)에서 연속 실패한 장비입니다.',
                'cols': [('장비', 3, 'L'), ('주소', 2.2, 'L'), ('유형', 1.6, 'C'), ('상태', 1.1, 'C'), ('마지막 확인', 2, 'C'), ('내용', 4, 'L')],
                'rows': [[t['name'], t.get('address'), t.get('kind'), TS.get(t.get('status'), t.get('status')), _hm(t.get('last_check')), t.get('detail') or ''] for t in down],
                'tones': ['crit' if t.get('status') == 'down' else 'warn' for t in down], 'empty': '장애·의심 장비가 없습니다.'},
               {'title': '자원 사용률 임계 초과', 'note': '에이전트·SNMP·로컬 수집 최신값 기준(3분 이내 값만).',
                'cols': [('장비', 3, 'L'), ('주소', 2, 'L'), ('CPU', 1, 'R'), ('메모리', 1, 'R'), ('디스크', 1, 'R')],
                'rows': [[t['name'], t.get('address'), *[_pct(v) for v in _usage(t)]] for t in hot], 'tones': ['warn']*len(hot), 'empty': '임계 초과 장비가 없습니다.'},
               {'title': '수집 지연 장비', 'note': '점검 주기의 3배 이상 결과가 들어오지 않은 장비입니다(수집기·네트워크 확인).',
                'cols': [('장비', 3, 'L'), ('주소', 2, 'L'), ('마지막 확인', 2, 'C')],
                'rows': [[t['name'], t.get('address'), _hm(t.get('last_check'))] for t in stale], 'tones': ['warn']*len(stale), 'empty': '수집 지연 장비가 없습니다.'},
               {'title': '전체 장비 상태', 'cols': [('장비', 3, 'L'), ('주소', 2, 'L'), ('상태', 1, 'C'), ('응답', 1, 'R'), ('CPU', 1, 'R'), ('메모리', 1, 'R'), ('디스크', 1, 'R')],
                'rows': [[t['name'], t.get('address'), TS.get(t.get('status'), t.get('status')), ('-' if t.get('latency') is None else f"{t['latency']:.0f}ms"), *[_pct(v) for v in _usage(t)]] for t in targets],
                'tones': ['crit' if t.get('status') == 'down' else ('warn' if t in hot or t.get('status') == 'suspect' else '') for t in targets], 'empty': '등록된 감시 장비가 없습니다.'},
               {'title': '최근 24시간 실패한 예약 작업', 'cols': [('작업', 3, 'L'), ('시각', 2, 'C'), ('오류', 5, 'L')],
                'rows': [[f['name'], _hm(f['started']), (f['error'] or '')[:200]] for f in fails], 'tones': ['crit']*len(fails), 'empty': '실패한 예약 작업이 없습니다.'}],
           'footer': '이 결과는 점검 시점의 스냅숏입니다. 가동률·SLA 통계가 아닙니다. 생성: LogTriage 예약 작업(정기 상태 점검).'}
    result.update(_emit(worker, job, doc, 'check-'+nowdt.strftime('%Y%m%d-%H%M%S')))
    return result


def report(worker, job):
    now = datetime.now().astimezone(); start = now-timedelta(days=int(job['params'].get('days',1)))
    history = worker.api.store.history(limit=5000); incidents = []
    for item in history:
        try:
            at = datetime.fromisoformat(item['analyzed_at']).astimezone()
        except (ValueError,KeyError,TypeError):
            continue
        if start <= at <= now:
            incidents.append(item)
    with worker.db() as db:
        notices = [dict(r) for r in db.execute('SELECT * FROM notices WHERE at>=? AND at<=? ORDER BY at DESC',(start.timestamp(),now.timestamp()))]
        runs = [dict(r) for r in db.execute('SELECT name,started,state,error FROM runs WHERE started>=? AND id!=? ORDER BY started DESC LIMIT 200',(start.timestamp(),job.get('run_id','')))]
    snap = worker.api.nms.snapshot()
    targets = [t for t in snap['targets'] if t.get('enabled')]
    down = [t for t in targets if t.get('status') in ('down','suspect')]
    alerts = [a for a in snap.get('alerts', []) if (a.get('opened') or 0) >= start.timestamp()]
    crit = sum(1 for i in incidents if (i.get('sev_totals') or {}).get('critical'))
    CAT = {'alarm': '장애·임계', 'recovery': '복구', 'failed': '실패', 'down': '장애', 'recovered': '복구'}
    ST = {'success': '성공', 'failed': '실패', 'retry': '재시도', 'interrupted': '중단', 'running': '실행 중'}
    TS = {'up': '정상', 'down': '장애', 'suspect': '의심', 'unknown': '확인 전', 'paused': '중지'}
    doc = {'title': '정기 운영 보고서', 'site': _site_name(worker),
           'subtitle': f"{start:%Y-%m-%d %H:%M} ~ {now:%Y-%m-%d %H:%M} ({job['params'].get('days',1)}일)",
           'meta': [('작업', job.get('name') or '예약 작업'), ('생성', f"{now:%Y-%m-%d %H:%M:%S}")],
           'kpis': [('로그 분석', f'{len(incidents)}건', 'mute'), ('치명 판정', f'{crit}건', 'crit' if crit else 'ok'),
                    ('장비 장애 발생', f'{len(alerts)}건', 'crit' if alerts else 'ok'), ('현재 장애 · 의심', f'{len(down)}대', 'crit' if down else 'ok'),
                    ('알림', f'{len(notices)}건', 'warn' if notices else 'ok')],
           'sections': [
               {'title': '로그 분석 결과', 'cols': [('분석 시각', 2, 'C'), ('대상', 3, 'L'), ('판정 계층', 1, 'C'), ('원인 추정', 4, 'L'), ('치명/오류', 1, 'C')],
                'rows': [[i.get('analyzed_at'), i.get('name') or ', '.join(Path(str(f.get('name') if isinstance(f, dict) else f)).name for f in (i.get('files') or [])[:2]),
                          (i.get('first') or {}).get('layer_ko', 'CLEAR'), (i.get('first') or {}).get('verdict', '') or '특이 사항 없음',
                          f"{(i.get('sev_totals') or {}).get('critical',0)}/{(i.get('sev_totals') or {}).get('error',0)}"] for i in incidents[:300]],
                'tones': ['crit' if (i.get('sev_totals') or {}).get('critical') else '' for i in incidents[:300]], 'empty': '기간 내 분석 이력이 없습니다.'},
               {'title': '장비 장애 이력', 'cols': [('장비', 3, 'L'), ('주소', 2, 'L'), ('발생', 2, 'C'), ('복구', 2, 'C'), ('확인', 1, 'C')],
                'rows': [[a.get('name'), a.get('address'), _hm(a.get('opened')), _hm(a.get('closed')) if a.get('closed') else '진행 중', '확인' if a.get('acknowledged') else '-'] for a in alerts],
                'tones': ['' if a.get('closed') else 'crit' for a in alerts], 'empty': '기간 내 장비 장애가 없습니다.'},
               {'title': '현재 장비 상태 (장애 · 의심)', 'cols': [('장비', 3, 'L'), ('주소', 2, 'L'), ('상태', 1, 'C'), ('마지막 확인', 2, 'C')],
                'rows': [[t['name'], t.get('address'), TS.get(t.get('status'), t.get('status')), _hm(t.get('last_check'))] for t in down],
                'tones': ['crit']*len(down), 'empty': f'감시 장비 {len(targets)}대 모두 정상입니다.'},
               {'title': '알림함 기록', 'cols': [('시각', 2, 'C'), ('구분', 1, 'C'), ('내용', 7, 'L')],
                'rows': [[_hm(n['at']), CAT.get(n['category'], n['category']), n['message']] for n in notices[:300]],
                'tones': ['crit' if n['category'] in ('alarm','failed','down') else ('ok' if n['category'] in ('recovery','recovered') else '') for n in notices[:300]], 'empty': '기간 내 알림이 없습니다.'},
               {'title': '예약 작업 실행 결과', 'cols': [('작업', 3, 'L'), ('시작', 2, 'C'), ('결과', 1, 'C'), ('오류', 4, 'L')],
                'rows': [[r['name'], _hm(r['started']), ST.get(r['state'], r['state']), (r['error'] or '')[:200]] for r in runs],
                'tones': ['crit' if r['state'] == 'failed' else '' for r in runs], 'empty': '기간 내 실행된 예약 작업이 없습니다.'}],
           'footer': '범위: 분석 이력 보관분(최대 500건)·알림 보관분(최대 10,000건). 장비 상태는 보고서 생성 시점 기준이며 가동률·SLA 통계가 아닙니다.'}
    stem = 'periodic-'+now.strftime('%Y%m%d-%H%M%S')+'-'+job['run_id'][:8]
    raw = {'from': start.isoformat(), 'to': now.isoformat(), 'incidents': [{k: i.get(k) for k in ('id','name','analyzed_at','sev_totals','first')} for i in incidents],
           'notices': notices, 'targets': [{k: t.get(k) for k in ('id','name','address','kind','status','last_check')} for t in snap['targets']]}
    res = _emit(worker, job, doc, stem)
    dest = worker.output_dir(); dest.mkdir(parents=True, exist_ok=True)   # 기계 판독용 JSON(다른 시스템 연계)
    tmp = dest/('.'+stem+'.json.partial'); tmp.write_text(json.dumps(raw, ensure_ascii=False, indent=2, default=str), encoding='utf-8'); tmp.replace(dest/(stem+'.json'))
    res['files'].append(stem+'.json')
    if stem+'.html' in res['files']:
        res['html'] = stem+'.html'
    res['json'] = stem+'.json'
    res.update(incidents=len(incidents), notices=len(notices), summary=f"분석 {len(incidents)}건 · 장애 {len(alerts)}건 · 알림 {len(notices)}건 → {', '.join(res['files'])}")
    return res
