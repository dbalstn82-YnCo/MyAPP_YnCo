import http.client
import json
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from logtriage import rulepack, safe_backup
from logtriage.automation import Automation, InstanceLock, next_due
from logtriage.automation_actions import poll_alarms, report, sync_assets, watch_logs
from logtriage.server import ServerApi, make_server

ENGINE = Path(__file__).resolve().parents[1]
RULE = 'rules:\n- id: TEST-1\n  layer: was\n  product: [tomcat]\n  match: {regex: "OutOfMemoryError"}\n  verdict: Memory failure\n'


class AutomationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.api = ServerApi(self.base, [])
        self.worker = self.api.automation

    def tearDown(self):
        self.worker.stop()
        self.tmp.cleanup()

    def job(self, kind='report', params=None):
        return self.worker.save({'name':kind,'kind':kind,'schedule':{'mode':'interval','seconds':60},'params':params or {}})['id']

    def test_lock_rejects_duplicate_worker(self):
        one=InstanceLock(self.base/'lock'); two=InstanceLock(self.base/'lock')
        one.acquire()
        try:
            with self.assertRaises(RuntimeError):two.acquire()
        finally:one.release()
        two.acquire(); two.release()

    def test_retry_crash_recovery_and_persistence(self):
        jid=self.job(); self.worker.command('run',{'id':jid})
        def fail(j):raise RuntimeError('fixture failure')
        with self.assertLogs('logtriage.automation',level='ERROR'):
            self.worker.tick(fail,now=100)
        self.assertEqual(self.worker.status()['runs'][0]['state'],'retry')
        self.assertFalse(self.worker.tick(lambda j:{},now=129))
        self.assertTrue(self.worker.tick(lambda j:{'ok':True},now=130))
        with self.worker.db() as db:
            db.execute("UPDATE jobs SET state='running'")
            db.execute("INSERT INTO runs(id,job_id,started,state) VALUES('crash',?,0,'running')",(jid,))
        fresh=Automation(self.api);fresh.recover()
        self.assertEqual(fresh.status()['jobs'][0]['next_due'],0)
        self.assertIn('interrupted',[r['state'] for r in fresh.status()['runs']])

    def test_three_failures_record_alarm(self):
        jid=self.job();self.worker.command('run',{'id':jid})
        def fail(j):raise ValueError('bad data')
        with self.assertLogs('logtriage.automation',level='ERROR'):
            for now in (100,130,190):self.worker.tick(fail,now)
        self.assertEqual(self.worker.status()['jobs'][0]['state'],'failed')
        self.assertEqual(len(self.worker.status()['notices']),1)

    def test_atomic_claim_two_callers(self):
        jid=self.job();self.worker.command('run',{'id':jid}); started=threading.Event();release=threading.Event()
        def runner(j):started.set();release.wait(3);return {}
        t=threading.Thread(target=lambda:self.worker.tick(runner));t.start();self.assertTrue(started.wait(3))
        try:
            self.assertFalse(self.worker.tick(lambda j:self.fail('duplicate')))
            with self.assertRaises(ValueError):self.worker.command('delete',{'id':jid})
        finally:release.set();t.join()

    def test_path_boundary(self):
        self.assertFalse(self.api._allowed(self.base/'uploads-outside/private.log'))
        self.assertTrue(self.api._allowed(self.base/'uploads/test.log'))
        with self.assertRaises(ValueError):self.job('log_watch',{'directory':str(self.base)})

    def test_backup_sqlite_restore_and_corruption(self):
        self.api.store.save_incident({'id':'one','analyzed_at':'2026-09-18T01:00:00'})
        (self.base/'rules').mkdir();(self.base/'rules/a.yaml').write_text(RULE)
        result=safe_backup.snapshot(self.base,self.api.store)
        safe_backup.verify(result['file'])
        self.api.store.save_incident({'id':'two'})
        safe_backup.restore(self.base,result['file'],offline=True)
        self.assertEqual(self.api.store.count(),1)
        self.assertEqual((self.base/'rules/a.yaml').read_text(),RULE)
        corrupted=self.base/'bad.zip'
        with zipfile.ZipFile(result['file']) as source,zipfile.ZipFile(corrupted,'w') as dest:
            for n in source.namelist():dest.writestr(n,b'bad' if n=='rules/a.yaml' else source.read(n))
        with self.assertRaises(ValueError):safe_backup.restore(self.base,corrupted,offline=True)
        self.assertEqual(self.api.store.count(),1)

    def test_restore_refuses_live_worker(self):
        r=safe_backup.snapshot(self.base,self.api.store)
        self.worker.lock.acquire()
        try:
            with self.assertRaises(RuntimeError):safe_backup.restore(self.base,r['file'],offline=True)
        finally:self.worker.lock.release()

    def test_external_database_roundtrip_and_transaction_failure(self):
        from logtriage.storage import Storage,sqlite_url
        with tempfile.TemporaryDirectory() as external:
            db=Storage(sqlite_url(Path(external)/'external.db'))
            db.save_incident({'id':'original','analyzed_at':'2026-09-18'})
            r=safe_backup.snapshot(self.base,db)
            db.save_incident({'id':'later','analyzed_at':'2026-09-18'})
            with self.assertRaises(ValueError):safe_backup.restore(self.base,r['file'],offline=True)
            safe_backup.restore(self.base,r['file'],offline=True,storage=db)
            self.assertEqual(db.count(),1)
            bad=Path(external)/'bad.jsonl'
            bad.write_text('{"schema":1,"kind":"sqlite"}\n{"table":"unexpected","values":[]}\n')
            with self.assertRaises(ValueError):safe_backup.import_database(db,bad)
            self.assertEqual(db.count(),1)

    def test_restore_swap_failure_rolls_back(self):
        (self.base/'rules').mkdir();(self.base/'rules/x').write_text('before')
        r=safe_backup.snapshot(self.base,self.api.store)
        (self.base/'rules/x').write_text('current')
        original=Path.rename
        def fail(path,target):
            if path.name=='rules' and path.parent.name=='stage':raise OSError('simulated disk error')
            return original(path,target)
        with patch.object(Path,'rename',fail),self.assertRaises(OSError):safe_backup.restore(self.base,r['file'],offline=True)
        self.assertEqual((self.base/'rules/x').read_text(),'current')

    def test_alarm_duration_hysteresis_stale_and_ack(self):
        target={'id':'a','name':'app','enabled':1,'metrics':'agent','status':'up','usage':{'cpu':95,'stale':False}}
        snap={'targets':[target],'settings':{'th_cpu':90,'th_mem':90,'th_disk':90}}
        with patch.object(self.api.nms,'snapshot',return_value=snap):
            for now in range(100,161,10):poll_alarms(self.worker,now)
            self.assertEqual(len(self.worker.status()['notices']),1)
            poll_alarms(self.worker,170);self.assertEqual(len(self.worker.status()['notices']),1)
            notice=self.worker.status()['notices'][0];self.worker.command('ack',{'id':notice['id']})
            target['usage']['stale']=True;poll_alarms(self.worker,180)
            self.assertEqual(len(self.worker.status()['notices']),1)
            target['usage'].update(stale=False,cpu=87);poll_alarms(self.worker,190)
            self.assertEqual(len(self.worker.status()['notices']),1)
            target['usage']['cpu']=80;poll_alarms(self.worker,200)
            self.assertEqual(len(self.worker.status()['notices']),2)

    def test_asset_sync_transaction_idempotency_and_missing_pause(self):
        doc={'rev':1,'sheets':[{'name':'servers','header_rows':1,'ncols':3,'rows':[[1,['ID','name','ip']],[2,['a','app','127.0.0.1']],[3,['b','db','127.0.0.2']]]}]}
        j={'id':'sync','params':{'document_id':1,'sheet':'servers','id_column':1,'name_column':2,'ip_column':3}}
        with patch.object(self.api.docs,'get',return_value=doc):
            self.assertEqual(sync_assets(self.worker,j)['added'],2)
            self.assertEqual(sync_assets(self.worker,j)['updated'],0)
            doc['sheets'][0]['rows'][1][1][1]='changed'
            doc['sheets'][0]['rows'][2][1][2]='invalid'
            with self.assertRaises(ValueError):sync_assets(self.worker,j)
            self.assertIn('app',[t['name'] for t in self.api.nms.snapshot()['targets']])
            doc['sheets'][0]['rows'].pop()
            self.assertEqual(sync_assets(self.worker,j)['paused'],1)
            self.assertEqual(len(self.api.nms.snapshot()['targets']),2)

    def test_reuploaded_asset_file_selects_latest_and_wakes_job(self):
        from test_inventory_docs import build
        from logtriage.automation_actions import asset_document
        raw=build([['ID','name','ip'],['a','first','127.0.0.1']],title='servers')
        first=self.api.docs.add(raw,'servers.xlsx')
        params={'document_id':first['id'],'sheet':'servers','id_column':1,'name_column':2,'ip_column':3}
        jid=self.job('asset_sync',params)
        saved=self.worker.status()['jobs'][0]['params']
        self.assertEqual(saved['document_name'],'servers.xlsx')
        latest=self.api.docs.add(build([['ID','name','ip'],['a','latest','127.0.0.1']],title='servers'),'servers.xlsx')
        self.worker.wake_assets('servers.xlsx')
        self.assertEqual(self.worker.status()['jobs'][0]['next_due'],0)
        self.assertEqual(asset_document(self.api,saved)['id'],latest['id'])

    def test_log_stability_actual_analysis_and_dedup(self):
        shutil.copytree(ENGINE/'rules',self.base/'rules');shutil.copytree(ENGINE/'errorcodes',self.base/'errorcodes')
        log=self.base/'uploads/server.log';log.write_text('2026-09-18 10:00:00 ERROR java.lang.OutOfMemoryError: Java heap space\n',encoding='utf-8')
        job={'id':'watch','params':{'directory':str(log.parent),'product':'tomcat','stable_seconds':10}}
        with patch('logtriage.automation_actions.time.time',return_value=100):self.assertEqual(watch_logs(self.worker,job)['analyzed'],[])
        with patch('logtriage.automation_actions.time.time',return_value=120):result=watch_logs(self.worker,job)
        self.assertEqual(len(result['analyzed']),1)
        self.assertEqual(self.api.store.count(),1)
        with patch('logtriage.automation_actions.time.time',return_value=140):self.assertEqual(watch_logs(self.worker,job)['analyzed'],[])
        # Simulate crash after incident commit but before watcher watermark.
        state=self.worker.get_value('watch:watch');state[str(log)]['done']=None;self.worker.set_value('watch:watch',state)
        with patch('logtriage.automation_actions.time.time',return_value=160):watch_logs(self.worker,job)
        self.assertEqual(self.api.store.count(),1)

    def test_report_generated_escaped_and_scoped(self):
        self.api.store.save_incident({'id':'new','name':'<script>alert(1)</script>','analyzed_at':__import__('datetime').datetime.now().isoformat()})
        self.api.store.save_incident({'id':'old','analyzed_at':'2020-01-01T00:00:00'})
        r=report(self.worker,{'params':{'days':1},'run_id':'test'})
        self.assertEqual(r['incidents'],1)
        output=(self.base/'reports'/r['html']).read_text(encoding='utf-8')
        self.assertIn('&lt;script&gt;',output);self.assertNotIn('<script>',output)


class RulepackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name)
        for n in ('rules','errorcodes','manuals'):
            (self.base/n).mkdir();(self.base/n/'old.txt').write_text('keep-'+n)
        self.source=self.base/'source';self.source.mkdir();(self.source/'new.yaml').write_text(RULE)
        self.codes=self.base/'codes';self.codes.mkdir();(self.codes/'new.yaml').write_text('product: test\ncodes: []\n')
        self.sig=rulepack.load_signing_key(self.base/'sign.pem',create=True);self.pub=rulepack.public_bytes(self.sig);self.fp=rulepack.fingerprint(self.pub)
        self.rpk=self.base/'new.rpk';rulepack.build(self.source,self.rpk,None,codes_dir=self.codes,signer=self.sig)

    def tearDown(self):self.tmp.cleanup()

    def test_valid_apply_and_wrong_key(self):
        with self.assertRaises(ValueError):rulepack.apply(self.rpk,self.base/'rules',rulepack.public_bytes(rulepack.load_signing_key(self.base/'other.pem',create=True)),self.base/'errorcodes',confirm_fp=self.fp)
        self.assertTrue((self.base/'rules/old.txt').exists())
        rulepack.apply(self.rpk,self.base/'rules',self.pub,self.base/'errorcodes',confirm_fp=self.fp)
        self.assertTrue((self.base/'rules/new.yaml').exists())
        self.assertTrue((self.base/'manuals/old.txt').exists())

    def test_second_tree_failure_rolls_all_back(self):
        original=Path.rename
        def fail(path,target):
            if path.name=='rules' and path.parent.name.startswith('.rpk-stage-'):raise OSError('disk fault')
            return original(path,target)
        with patch.object(Path,'rename',fail),self.assertRaises(OSError):rulepack.apply(self.rpk,self.base/'rules',self.pub,self.base/'errorcodes',confirm_fp=self.fp)
        for n in ('rules','errorcodes'):self.assertEqual((self.base/n/'old.txt').read_text(),'keep-'+n)

    def test_recovery_after_interrupted_apply(self):
        tx=self.base/'.rpk-transactions/fixture';tx.mkdir(parents=True)
        shutil.copytree(self.base/'rules',tx/'previous/rules')
        (self.base/'rules/old.txt').write_text('half-update')
        rulepack._journal(tx/'transaction.json',{'state':'applying','previous':{'rules':True}})
        rulepack.recover(self.base)
        self.assertEqual((self.base/'rules/old.txt').read_text(),'keep-rules')

    def test_duplicate_rules_invalid_regex_and_traversal(self):
        (self.source/'duplicate.yaml').write_text(RULE)
        rulepack.build(self.source,self.rpk,None,signer=self.sig)
        with self.assertRaises(ValueError):rulepack.apply(self.rpk,self.base/'rules',self.pub,confirm_fp=self.fp)
        (self.source/'duplicate.yaml').unlink();(self.source/'new.yaml').write_text(RULE.replace('OutOfMemoryError','['))
        rulepack.build(self.source,self.rpk,None,signer=self.sig)
        with self.assertRaises(Exception):rulepack.apply(self.rpk,self.base/'rules',self.pub,confirm_fp=self.fp)
        with zipfile.ZipFile(self.rpk,'a') as z:z.writestr('../escape','x')
        with self.assertRaises(ValueError):rulepack.verify(self.rpk,self.pub)
        self.assertTrue((self.base/'rules/old.txt').exists())


class AutomationHttpTests(unittest.TestCase):
    def test_client_disconnect_during_response(self):
        import socket,struct,os
        with tempfile.TemporaryDirectory() as td:
            server,handler=make_server('127.0.0.1',0,Path(td),None)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            entered=threading.Event();release=threading.Event();finished=threading.Event()
            def slow_meta():entered.set();release.wait(3);return {'fixture':'x'*100000}
            original=handler.handle
            def observed(request):
                try:return original(request)
                finally:finished.set()
            try:
                with patch.object(handler.api,'meta',slow_meta),patch.object(handler,'handle',observed),patch.object(server,'handle_error') as errors:
                    c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                    c.request('POST','/api/meta','[]',{'Content-Type':'application/json','X-NMS-Request':'1'})
                    self.assertTrue(entered.wait(3))
                    c.sock.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('hh' if os.name=='nt' else 'ii',1,0))
                    c.close();release.set();self.assertTrue(finished.wait(5));errors.assert_not_called()
                c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                c.request('GET','/healthz');r=c.getresponse();self.assertEqual(r.status,200);r.read();c.close()
            finally:release.set();server.shutdown();server.server_close();thread.join()

    def test_authenticated_routes_and_csrf(self):
        with tempfile.TemporaryDirectory() as td:
            server,handler=make_server('127.0.0.1',0,Path(td),'secret')
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            handler._sessions.add('a'*32)
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10)
            try:
                c.request('GET','/api/automation/status');r=c.getresponse();self.assertEqual(r.status,401);r.read()
                headers={'Cookie':'lt_session='+'a'*32,'Content-Type':'application/json','X-NMS-Request':'1'}
                body=json.dumps({'name':'report','kind':'report','params':{'days':1},'schedule':{'mode':'daily','time':'17:00'}})
                c.request('POST','/api/automation/save',body,headers|{'Origin':'http://other.example'});r=c.getresponse();self.assertEqual(r.status,403);r.read()
                c.request('POST','/api/automation/save',body,headers);r=c.getresponse();self.assertEqual(r.status,200);jid=json.loads(r.read())['id']
                c.request('POST','/api/automation/run',json.dumps({'id':jid}),headers);r=c.getresponse();self.assertEqual(r.status,200);r.read()
                self.assertTrue(handler.api.automation.tick())
                c.request('GET','/api/automation/status',headers=headers);r=c.getresponse();s=json.loads(r.read());self.assertEqual(s['runs'][0]['state'],'success')
                c.request('GET','/automation',headers=headers);r=c.getresponse();self.assertEqual(r.status,200);self.assertIn('예약'.encode(),r.read())
            finally:c.close();server.shutdown();server.server_close();thread.join()


class R2RegressionTests(unittest.TestCase):
    """Regressions for defects fixed in 2026.09.18-automation.2 (수정내역.md)."""
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=Path(self.tmp.name)
        self.api=ServerApi(self.base,[]);self.worker=self.api.automation

    def tearDown(self):
        self.worker.stop();self.tmp.cleanup()

    def job(self,kind='report',params=None,**extra):
        return self.worker.save({'name':kind,'kind':kind,'schedule':{'mode':'interval','seconds':60},'params':params or {},**extra})['id']

    def test_non_string_ids_are_rejected_not_crashed(self):
        # Before: sqlite3.ProgrammingError escaped the handler -> traceback and dropped connection.
        for value in ({'id':['x']},{'id':{'a':1}},{},{'id':'x'*65},{'id':'../x'}):
            with self.assertRaises(ValueError):self.worker.command('run',value)
        for value in ({'id':'abc'},{'id':10**30},{'id':True},{},{'id':1.5}):
            with self.assertRaises(ValueError):self.worker.command('ack',value)
        with self.assertRaises(ValueError):self.worker.command('frobnicate',{'id':'x'})
        with self.assertRaises(ValueError):self.worker.command('run',['x'])
        with self.assertRaises(ValueError):self.worker.save({'name':'x','kind':'report','schedule':{'mode':'interval','seconds':60},'id':['a']})

    def test_strict_parameter_types(self):
        base={'name':'x','kind':'report','schedule':{'mode':'interval','seconds':60}}
        for params in ({'days':True},{'days':1.5},{'days':'abc'},{'days':None},{'days':[1]}):
            with self.assertRaises(ValueError,msg=str(params)):self.worker.save(base|{'params':params})
        with self.assertRaises(ValueError):self.worker.save(base|{'enabled':'yes'})
        with self.assertRaises(ValueError):self.worker.save(base|{'schedule':{'mode':'interval','seconds':True}})
        with self.assertRaises(ValueError):self.worker.save(base|{'schedule':{'mode':'interval','seconds':60.5}})
        with self.assertRaises(ValueError):self.worker.save(base|{'schedule':'daily'})
        with self.assertRaises(ValueError):self.worker.save(base|{'kind':'backup','params':{'keep':0}})
        with self.assertRaises(ValueError):self.worker.save(base|{'kind':'backup','params':{'keep':None}})
        with self.assertRaises(ValueError):self.worker.save(base|{'kind':'log_watch','params':{'directory':str(self.base/'uploads'),'product':['x']}})
        with self.assertRaises(ValueError):self.worker.save(base|{'kind':'log_watch','params':{'directory':['x']}})
        # digit strings are normalised to int; the stored job carries ints only
        jid=self.worker.save(base|{'schedule':{'mode':'interval','seconds':'90'},'params':{'days':'2'}})['id']
        job=next(j for j in self.worker.status()['jobs'] if j['id']==jid)
        self.assertEqual((job['schedule']['seconds'],job['params']['days']),(90,2))
        self.assertEqual(len(self.worker.status()['jobs']),1)

    def test_run_now_on_paused_job_runs_once_without_enabling(self):
        jid=self.job();self.worker.command('pause',{'id':jid})
        self.assertFalse(self.worker.tick(lambda j:self.fail('paused job must not run'),now=100))
        self.worker.command('run',{'id':jid})
        self.assertTrue(self.worker.tick(lambda j:{'ok':True},now=101))
        job=self.worker.status()['jobs'][0]
        self.assertEqual(job['enabled'],0);self.assertEqual(job['state'],'success')
        self.assertFalse(self.worker.tick(lambda j:self.fail('still paused'),now=10**9))
        self.worker.command('resume',{'id':jid})
        job=self.worker.status()['jobs'][0]
        self.assertEqual(job['enabled'],1);self.assertGreater(job['next_due'],time.time()-1)
        with self.assertRaises(ValueError):self.worker.command('resume',{'id':'missing'})

    def test_paused_job_manual_failure_is_reported_not_retried(self):
        jid=self.job();self.worker.command('pause',{'id':jid});self.worker.command('run',{'id':jid})
        def fail(j):raise RuntimeError('boom')
        with self.assertLogs('logtriage.automation',level='ERROR'):self.worker.tick(fail,now=100)
        st=self.worker.status()
        self.assertEqual(st['jobs'][0]['state'],'failed');self.assertEqual(st['jobs'][0]['enabled'],0)
        self.assertEqual([n['category'] for n in st['notices']],['job_failed'])
        self.assertFalse(self.worker.tick(fail,now=200))   # no silent retry of a paused job

    def test_asset_sync_header_rows_override(self):
        doc={'id':7,'rev':0,'sheets':[{'name':'servers','header_rows':2,'ncols':3,'rows':[[1,['ID','name','ip']],[2,['a','app','127.0.0.1']],[3,['b','db','127.0.0.2']]]}]}
        with patch.object(self.api.docs,'get',return_value=doc),patch.object(self.api.docs,'list',return_value=[{'id':7,'name':'servers.xlsx','at':1}]):
            j={'id':'sync','params':{'document_id':7,'sheet':'servers','id_column':1,'name_column':2,'ip_column':3}}
            r=sync_assets(self.worker,j);self.assertEqual((r['added'],r['header_rows']),(1,2))   # document heuristic
            j['params']['header_rows']=1
            r=sync_assets(self.worker,j);self.assertEqual((r['added'],r['header_rows']),(1,1))   # override adds the skipped row
            self.assertEqual(sorted(t['name'] for t in self.api.nms.snapshot()['targets']),['app','db'])
            from logtriage.automation_actions import validate_params
            for bad in ({'header_rows':-1},{'header_rows':True},{'header_rows':'x'}):
                with self.assertRaises(ValueError):validate_params(self.api,'asset_sync',j['params']|bad)
            p=j['params']|{'header_rows':''};validate_params(self.api,'asset_sync',p);self.assertNotIn('header_rows',p)

    def test_snapshot_skips_transient_files_and_survives_vanishing(self):
        (self.base/'reports').mkdir(exist_ok=True);(self.base/'reports/periodic-x.html.partial').write_text('half')
        (self.base/'reports/periodic-x.html').write_text('done')
        (self.base/'uploads/automation').mkdir(parents=True);(self.base/'uploads/automation/tmp.log').write_text('copy')
        (self.base/'uploads/keep.log').write_text('keep');(self.base/'uploads/vanish.log').write_text('gone')
        original=shutil.copy2
        def flaky(src,dst,*a,**k):
            if Path(src).name=='vanish.log':Path(src).unlink();raise FileNotFoundError(src)
            return original(src,dst,*a,**k)
        with patch('logtriage.safe_backup.shutil.copy2',flaky):r=safe_backup.snapshot(self.base,self.api.store)
        with zipfile.ZipFile(r['file']) as z:names=set(z.namelist())
        self.assertIn('uploads/keep.log',names);self.assertIn('reports/periodic-x.html',names)
        for n in ('reports/periodic-x.html.partial','uploads/automation/tmp.log','uploads/vanish.log'):self.assertNotIn(n,names)
        safe_backup.verify(r['file'])
        self.assertNotIn('periodic-x.html.partial',self.worker.status()['files'])

    def test_rulepack_transactions_are_pruned(self):
        for n in ('rules','errorcodes','manuals'):(self.base/n).mkdir(exist_ok=True)
        src=self.base/'src';src.mkdir();(src/'r.yaml').write_text(RULE)
        sig=rulepack.load_signing_key(self.base/'sign.pem',create=True);pub=rulepack.public_bytes(sig);fp=rulepack.fingerprint(pub)
        for i in range(5):
            rpk=self.base/f'v{i}.rpk';rulepack.build(src,rpk,None,version=f'1.0.{i}',signer=sig)
            rulepack.apply(rpk,self.base/'rules',pub,self.base/'errorcodes',self.base/'manuals',confirm_fp=fp)
        tx=list((self.base/'.rpk-transactions').glob('*/transaction.json'))
        self.assertEqual(len(tx),3)
        self.assertTrue(all(json.loads(t.read_text(encoding='utf-8'))['state']=='committed' for t in tx))
        self.assertTrue((self.base/'rules/r.yaml').exists())

    def test_shared_exclusive_lock_semantics(self):
        from logtriage.automation import SharedExclusiveLock
        lock=SharedExclusiveLock();inside=threading.Event();go=threading.Event();both=[]
        def reader(n):
            with lock.shared():
                both.append(n);inside.set();go.wait(3)
        t1=threading.Thread(target=reader,args=(1,));t2=threading.Thread(target=reader,args=(2,));t1.start();t2.start()
        self.assertTrue(inside.wait(3));time.sleep(0.2)
        self.assertEqual(sorted(both),[1,2])   # two analyses run concurrently
        acquired=threading.Event()
        def writer():
            with lock.exclusive():acquired.set()
        w=threading.Thread(target=writer);w.start();time.sleep(0.2)
        self.assertFalse(acquired.is_set())     # rulepack/backup waits for running analyses
        go.set();t1.join();t2.join();self.assertTrue(acquired.wait(3));w.join()
        # analysis waits while an exclusive holder is active
        held=threading.Event();release=threading.Event();entered=threading.Event()
        def holder():
            with lock.exclusive():held.set();release.wait(3)
        def late_reader():
            with lock.shared():entered.set()
        h=threading.Thread(target=holder);h.start();self.assertTrue(held.wait(3))
        r=threading.Thread(target=late_reader);r.start();time.sleep(0.2);self.assertFalse(entered.is_set())
        release.set();h.join();self.assertTrue(entered.wait(3));r.join()

    def test_http_bad_ids_return_400_json_and_nav_injection(self):
        with tempfile.TemporaryDirectory() as td:
            server,handler=make_server('127.0.0.1',0,Path(td),None,desktop=True,native=False)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            c=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=10);h={'Content-Type':'application/json','X-NMS-Request':'1'}
            try:
                with patch.object(server,'handle_error') as errors:
                    for body in ('{"id":["x"]}','{"id":{"a":1}}','{"id":99999999999999999999999}'):
                        c.request('POST','/api/automation/run',body,h);r=c.getresponse();data=json.loads(r.read())
                        self.assertEqual(r.status,400,body);self.assertIn('error',data)
                    c.request('POST','/api/automation/ack','{"id":1e400}',h);r=c.getresponse();self.assertEqual(r.status,400);r.read()
                    c.request('POST','/api/automation/resume','{"id":"nope"}',h);r=c.getresponse();self.assertEqual(r.status,400);r.read()
                    errors.assert_not_called()
                c.request('GET','/');r=c.getresponse();page=r.read().decode('utf-8')
                self.assertIn('window.LT_NATIVE=false',page)            # companion launcher: browser, no pywebview dialogs
                self.assertIn('data-href="/automation"',page); self.assertIn("/api/me",page)   # r4: static menu entry + user chip script
                # no floating button over nms.html #alarms — 15차 업로드 진행 카드는 올리는 동안만 upPanel() 이 만들므로 그 함수 밖에서 찾는다
                lazy=page[page.index('function upPanel()'):page.index('function put(')] if 'function upPanel()' in page else ''
                self.assertNotIn('right:18px;bottom:18px',page.replace(lazy,''))
                self.assertIn("document.getElementById('lt-up')",lazy or "document.getElementById('lt-up')")
                for path in ('/nms','/resources'):
                    c.request('GET',path);r=c.getresponse();body=r.read().decode('utf-8');self.assertEqual(r.status,200)
                    self.assertIn('data-href="/automation"',body,path);self.assertEqual(body.count("fetch('/api/me'"),1,path);self.assertNotIn('사건',body)
                    self.assertNotIn('right:18px;bottom:18px',body)
                c.request('GET','/automation');r=c.getresponse();body=r.read().decode('utf-8')
                self.assertEqual(body.count("fetch('/api/me'"),1);self.assertNotIn('사건',body)
                c.request('GET','/api/automation/status');r=c.getresponse();self.assertEqual(json.loads(r.read())['patch'],'2026.09.18-automation.2')
            finally:c.close();server.shutdown();server.server_close();thread.join()
            server2,_=make_server('127.0.0.1',0,Path(td),None,desktop=True)
            try:self.assertTrue(server2.RequestHandlerClass.native)   # default keeps the EXE window behaviour
            finally:server2.server_close()


if __name__=='__main__':unittest.main()
