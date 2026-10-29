import sys
sys.dont_write_bytecode=True
import json, socket, socket, tempfile, threading, time, unittest, urllib.request, urllib.error, http.cookiejar
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from logtriage.nms import Store, Collector, validate, probe
from logtriage.server import make_server


def config(**kw):
    return {'name':'Test server','address':'127.0.0.1','kind':'server','method':'tcp',
            'port':443,'interval':10,'timeout':1,'fail_limit':3,'recover_limit':2,**kw}


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name)/'nms.sqlite3')
        self.id=self.store.save(config())['id']
        self.target=self.store.due()[0]

    def tearDown(self):
        self.tmp.cleanup()

    def test_hysteresis_one_alert_recovery(self):
        for i in range(2): self.store.record(self.target,'down',None,'timeout')
        self.assertEqual(self.store.snapshot()['active_alerts'],0)
        self.store.record(self.target,'down',None,'timeout')
        self.store.record(self.target,'down',None,'timeout')
        self.assertEqual(self.store.snapshot()['active_alerts'],1)
        self.store.record(self.target,'up',4,'ok')
        self.assertEqual(self.store.snapshot()['targets'][0]['status'],'recovering')
        self.store.record(self.target,'up',5,'ok')
        state=self.store.snapshot()
        self.assertEqual(state['active_alerts'],0)
        self.assertEqual(state['alerts'][0]['close_reason'],'recovered')
        self.assertEqual(len(self.store.history(self.id)),6)

    def test_collector_error_not_device_failure(self):
        for _ in range(4): self.store.record(self.target,'error',None,'ping missing')
        self.assertEqual(self.store.snapshot()['active_alerts'],0)
        self.assertEqual(self.store.snapshot()['targets'][0]['status'],'unknown')
        for _ in range(3): self.store.record(self.target,'down',None,'timeout')
        self.store.record(self.target,'error',None,'permission')
        self.assertEqual(self.store.snapshot()['active_alerts'],1)

    def test_pause_and_inflight_revision(self):
        self.store.save(config(id=self.id,enabled=False))
        self.store.record(self.target,'up',1,'stale result')
        self.assertEqual(self.store.snapshot()['targets'][0]['status'],'paused')
        self.assertEqual(self.store.history(self.id),[])
        self.store.save(config(id=self.id,port=8443))
        self.store.record(self.target,'down',None,'old port')
        self.assertEqual(self.store.history(self.id),[])

    def test_delete_cascade(self):
        for _ in range(3): self.store.record(self.target,'down',None,'timeout')
        self.store.delete(self.id)
        self.assertEqual(self.store.snapshot()['alerts'],[])
        self.assertEqual(self.store.history(self.id),[])
        self.store.record(self.target,'up',1,'deleted')

    def test_ack_does_not_resolve(self):
        for _ in range(3): self.store.record(self.target,'down',None,'timeout')
        alert=self.store.snapshot()['alerts'][0]
        self.store.ack(alert['id'])
        self.assertEqual(self.store.snapshot()['active_alerts'],1)
        self.assertEqual(self.store.snapshot()['alerts'][0]['acknowledged'],1)

    def test_retention_and_persistence(self):
        self.store.record(self.target,'up',2,'old',now=time.time()-9*86400)
        self.store.prune()
        self.assertEqual(self.store.history(self.id),[])
        second=Store(self.store.path)
        self.assertEqual(second.snapshot()['targets'][0]['id'],self.id)

    def test_validation_all_categories(self):
        for kind in ('server','network','security','storage','other'):
            self.assertEqual(validate(config(kind=kind))['kind'],kind)
        for bad in ({'address':'-c 100 target'},{'address':'example.com'},{'address':'224.0.0.1'},
                    {'interval':0},{'timeout':99},{'port':True},{'enabled':'false'},{'kind':'unknown'}):
            with self.assertRaises(ValueError): validate(config(**bad))

    def test_real_tcp_probe(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1',0));listener.listen()
            port=listener.getsockname()[1]
            self.assertEqual(probe(config(port=port))[0],'up')
        self.assertEqual(probe(config(port=port))[0],'down')

    def test_ping_failure_classification(self):
        with patch('logtriage.nms.shutil.which',return_value=None):
            self.assertEqual(probe(config(method='icmp'))[0],'error')
        with patch('logtriage.nms.os.name','posix'),patch('logtriage.nms.shutil.which',return_value='/bin/ping'),patch('logtriage.nms.subprocess.run') as run:
            run.return_value.returncode=0;run.return_value.stdout=b'time=0.42 ms';run.return_value.stderr=b''
            self.assertEqual(probe(config(method='icmp'))[:2],('up',.42))
            run.return_value.returncode=2
            self.assertEqual(probe(config(method='icmp'))[0],'error')
            run.return_value.returncode=1
            self.assertEqual(probe(config(method='icmp'))[0],'down')

    def test_local_disks_and_metrics_disks(self):
        from logtriage.nms import local_disks, local_metrics, validate_metrics
        ds = local_disks()
        self.assertTrue(ds and all(0 <= d["pct"] <= 100 and d["path"] for d in ds))
        local_metrics(); m = local_metrics()
        self.assertIsNotNone(m["disk"]); self.assertEqual(m["disk"], max(json.loads(m["disks"]) and [d["pct"] for d in json.loads(m["disks"])]))
        v = validate_metrics({"cpu": 1, "mem": 2, "disks": [{"path": "/", "pct": 45.5, "used_gb": 10, "total_gb": 22}, {"path": "/data", "pct": 91}]})
        self.assertEqual(v["disk"], 91.0); self.assertIn('"/data"', v["disks"])
        with self.assertRaises(ValueError):
            validate_metrics({"cpu": 1, "disks": [{"path": "/", "pct": 120}]})
        s = Store(Path(self.tmp.name) / "d.sqlite3"); tid = s.save(config(name="d", metrics="agent"))["id"]
        s.record_metrics(tid, v)
        u = s.snapshot()["targets"][0]["usage"]; self.assertEqual(u["disks"][1]["path"], "/data"); self.assertEqual(u["disk"], 91.0)

    def test_settings_and_usage_alarms(self):
        s = Store(Path(self.tmp.name) / "s.sqlite3")
        self.assertEqual(s.get_settings()["th_cpu"], 90)
        with self.assertRaises(ValueError):
            s.set_settings({"th_cpu": 30})
        s.set_settings({"th_cpu": 80, "th_disk": 95, "repeat_min": 5, "alarm_down": False})
        self.assertEqual(s.get_settings(), {"th_cpu": 80, "th_mem": 90, "th_disk": 95, "alarm_down": False, "repeat_min": 5})
        tid = s.save(config(name="a", metrics="agent"))["id"]
        s.record_metrics(tid, {"cpu": 85.0, "mem": 50.0, "disk": 96.0, "disks": json.dumps([{"path": "C:", "pct": 40}, {"path": "D:", "pct": 96}]), "extra": "{}"})
        snap = s.snapshot(); al = {a["metric"]: a for a in snap["usage_alarms"]}
        self.assertEqual(set(al), {"cpu", "disk"}); self.assertEqual(al["disk"]["detail"], "D:"); self.assertEqual(al["cpu"]["threshold"], 80)
        self.assertTrue(al["cpu"]["over"]); self.assertEqual(snap["settings"]["th_cpu"], 80)
        s.record_metrics(tid, {"cpu": 77.0, "mem": 50.0, "disk": 10.0, "extra": "{}"}, now=time.time() + 1)
        al = {a["metric"]: a for a in s.snapshot()["usage_alarms"]}
        self.assertEqual(set(al), {"cpu"}); self.assertFalse(al["cpu"]["over"])   # 임계치-5 이내: 유지(hysteresis), 새 팝업 아님

    def test_snmp_roundtrip(self):
        from logtriage import snmp
        from logtriage.nms import snmp_metrics, validate
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); srv.bind(("127.0.0.1", 0)); port = srv.getsockname()[1]; srv.settimeout(5)
        TABLE = {"1.3.6.1.2.1.1.3.0": (snmp.TIMETICKS, 8640000), "1.3.6.1.2.1.1.1.0": (snmp.OCTET_STRING, "SECUI MF2"), "1.3.6.1.2.1.1.5.0": (snmp.OCTET_STRING, "fw01"),
                 "1.3.6.1.4.1.2021.11.11.0": (snmp.INTEGER, 63), "1.3.6.1.4.1.2021.4.5.0": (snmp.INTEGER, 1000), "1.3.6.1.4.1.2021.4.6.0": (snmp.INTEGER, 250),
                 "1.3.6.1.2.1.2.2.1.2.1": (snmp.OCTET_STRING, "eth0"), "1.3.6.1.2.1.2.2.1.2.3": (snmp.OCTET_STRING, "eth2"),
                 "1.3.6.1.2.1.31.1.1.1.6.3": (snmp.COUNTER64, 2**40), "1.3.6.1.2.1.31.1.1.1.10.3": (snmp.COUNTER64, 2**33)}
        def key(o): return [int(x) for x in o.split(".")]
        def serve():
            while True:
                try:
                    data, addr = srv.recvfrom(65535)
                except OSError:
                    return
                ver, comm, kind, rid, es, ei, vbs = snmp.parse_message(data)
                if comm != "s3cret":
                    continue   # community 불일치 → 무응답(실장비와 동일)
                if kind == snmp.GET_REQUEST:
                    out = [(o, TABLE.get(o, (snmp.NO_SUCH_INSTANCE, None))) for o, _, _ in vbs]
                else:
                    o = vbs[0][0]; nxt = next((k for k in sorted(TABLE, key=key) if key(k) > key(o)), None)
                    out = [(nxt, TABLE[nxt])] if nxt else [(o, (snmp.END_OF_MIB, None))]
                srv.sendto(snmp.build_response(comm, rid, out), addr)
        th = threading.Thread(target=serve, daemon=True); th.start()
        try:
            v = snmp.get("127.0.0.1", ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.2021.11.11.0", "1.3.6.1.2.1.31.1.1.1.6.3", "1.3.6.1.2.1.9.9.0"], "s3cret", port)
            self.assertEqual(v["1.3.6.1.2.1.1.1.0"], "SECUI MF2"); self.assertEqual(v["1.3.6.1.2.1.31.1.1.1.6.3"], 2**40); self.assertIsNone(v["1.3.6.1.2.1.9.9.0"])
            self.assertEqual(snmp.walk("127.0.0.1", "1.3.6.1.2.1.2.2.1.2", "s3cret", port), [("1.3.6.1.2.1.2.2.1.2.1", "eth0"), ("1.3.6.1.2.1.2.2.1.2.3", "eth2")])
            with self.assertRaises(snmp.SnmpError):
                snmp.get("127.0.0.1", ["1.3.6.1.2.1.1.1.0"], "wrong", port, timeout=0.3, retries=0)
            raw = {"name": "fw", "address": "127.0.0.1", "kind": "security", "method": "icmp", "metrics": "snmp", "snmp_community": "s3cret", "snmp_port": port,
                   "snmp_oid_cpu": "1.3.6.1.4.1.2021.11.11.0", "snmp_cpu_mode": "idle", "snmp_oid_mem": "1.3.6.1.4.1.2021.4.6.0", "snmp_mem_mode": "avail",
                   "snmp_oid_mem2": "1.3.6.1.4.1.2021.4.5.0", "snmp_ifindex": 3}
            tg = validate(raw)
            prev = {}; m1 = snmp_metrics(tg, prev)
            self.assertEqual(m1["cpu"], 37.0); self.assertEqual(m1["mem"], 75.0); self.assertIsNone(m1["rx"]); self.assertEqual(json.loads(m1["extra"])["uptime"], 86400)
            TABLE["1.3.6.1.2.1.31.1.1.1.6.3"] = (snmp.COUNTER64, 2**40 + 5000); time.sleep(0.3); m2 = snmp_metrics(tg, prev)
            self.assertGreater(m2["rx"], 0); self.assertEqual(m2["tx"], 0.0)
            TABLE["1.3.6.1.2.1.31.1.1.1.6.3"] = (snmp.COUNTER64, 10); m3 = snmp_metrics(tg, prev)   # 카운터 감소(재시작) → 건너뜀
            self.assertIsNone(m3["rx"])
            with self.assertRaises(ValueError):
                validate({**config(), "metrics": "snmp", "snmp_community": "x", "snmp_oid_cpu": "abc"})
            with self.assertRaises(ValueError):
                validate({**config(), "metrics": "snmp", "snmp_community": "x", "snmp_oid_mem": "1.2.3", "snmp_mem_mode": "used"})
            # 저장 → 상태 API 는 community 를 숨기고, 편집 시 빈 community 는 기존 값 유지
            s = Store(Path(self.tmp.name) / "n.sqlite3"); tid = s.save(raw)["id"]
            snap = s.snapshot()["targets"][0]; self.assertEqual(snap["snmp_community"], ""); self.assertTrue(snap["snmp_has_community"])
            s.save({**raw, "id": tid, "snmp_community": ""})
            stored = s.snmp_targets()[0]["snmp_community"]
            self.assertTrue(stored.startswith("enc1:"))            # DB 에는 암호문으로(2026-09-22)
            self.assertEqual(s._sc_dec(stored, tid), "s3cret")     # 쓸 때만, 그 대상 것으로만 풀린다
            self.assertNotIn(b"s3cret", (Path(self.tmp.name) / "n.sqlite3").read_bytes())
            c = Collector(s); c._poll_snmp(s.snmp_targets()[0])
            self.assertEqual(s.snapshot()["targets"][0]["usage"]["cpu"], 37.0)
        finally:
            srv.close(); th.join(timeout=2)

    def test_scheduler_executes_and_stops(self):
        self.store.save(config(id=self.id,fail_limit=1))
        collector=Collector(self.store,workers=2)
        with patch('logtriage.nms.probe',return_value=('up',1,'test')):
            collector.start()
            try:
                deadline=time.monotonic()+4
                while not self.store.history(self.id) and time.monotonic()<deadline: time.sleep(.05)
                self.assertTrue(self.store.history(self.id))
            finally: collector.stop()
        self.assertFalse(collector.thread.is_alive())


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.httpd,cls.handler=make_server('127.0.0.1',0,Path(cls.tmp.name),'testing-password')
        cls.thread=threading.Thread(target=cls.httpd.serve_forever,daemon=True);cls.thread.start()
        cls.url='http://127.0.0.1:'+str(cls.httpd.server_port)
        cls.client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        cls.client.open(cls.url+'/login',data=b'password=testing-password').read()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown();cls.thread.join();cls.httpd.server_close();cls.tmp.cleanup()

    def test_auth_and_csrf(self):
        with self.assertRaises(urllib.error.HTTPError) as cm: urllib.request.urlopen(self.url+'/api/nms/status')
        self.assertEqual(cm.exception.code,401)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.client.open(self.url+'/api/nms/save',data=json.dumps(config()).encode())
        self.assertEqual(cm.exception.code,403)

    def test_crud_http_and_existing_routes(self):
        req=urllib.request.Request(self.url+'/api/nms/save',data=json.dumps(config(name='<img src=x onerror=alert(1)>')).encode(),headers={'Content-Type':'application/json','X-NMS-Request':'1'})
        saved=json.load(self.client.open(req))
        state=json.load(self.client.open(self.url+'/api/nms/status'))
        self.assertIn(saved['id'],[t['id'] for t in state['targets']])
        self.assertIn('모니터링',self.client.open(self.url+'/nms').read().decode())
        self.assertIn('data-href="/nms"',self.client.open(self.url+'/').read().decode())
        self.assertTrue(json.load(self.client.open(self.url+'/healthz'))['ok'])
        req=urllib.request.Request(self.url+'/api/history',data=b'[]',headers={'Content-Type':'application/json','X-NMS-Request':'1'})
        self.assertIsInstance(json.load(self.client.open(req)),list)

    def test_agent_zip_and_links(self):
        import io, zipfile
        page = self.client.open(self.url + '/nms').read().decode()
        self.assertIn('모니터링 대상', page); self.assertNotIn('감시 대상', page)
        # 에이전트 내려받기 링크는 data-href 로만(주소만으로 받을 수 없게). 메뉴·상단 바 링크는 09-23 결정대로 진짜 href 를 쓴다
        # (2026-10-15: 이 줄의 \b 가 백스페이스 문자로 깨져 있어 아무것도 검사하지 못하던 것을 고치며 의도대로 좁힘)
        self.assertNotRegex(page, r'<a\b[^>]*\shref="[^"]*(lt-agent|/api/nms/agent)')
        self.assertRegex(page, r'<a\b[^>]*\shref="/"')   # 검사 식이 실제로 동작하는지 — 상단 바 홈 링크는 잡혀야 한다
        # 내려받기 주소는 대본이 '대상별 토큰' 질의를 붙여 만든다(정적 마크업에는 자리만 있다)
        for el in ('id="agzip"', 'id="agdlsh"', 'id="agdlinst"'):
            self.assertIn(el, page)
        self.assertIn("'/static/lt-agent.zip'", page)
        # 내려받기는 POST 로 발급받은 1회용 표로만 — 주소에 target 을 붙이지 않는다(2026-09-22)
        self.assertIn("agent_token", page)
        self.assertIn("?ticket=", page)
        self.assertNotIn("?target=", page)
        r = self.client.open(self.url + '/static/lt-agent.zip')
        self.assertEqual(r.headers.get('Content-Type'), 'application/zip')
        z = zipfile.ZipFile(io.BytesIO(r.read())); names = z.namelist()
        for n in ('lt-agent/lt-agent-ctl.sh', 'lt-agent/lt-agent.py', 'lt-agent/lt-agent-posix.sh', 'lt-agent/lt-agent.cmd', 'lt-agent/README.txt', 'lt-agent/agent.conf'):
            self.assertIn(n, names)
        conf = z.read('lt-agent/agent.conf').decode()
        self.assertIn('URL=' + self.url, conf); self.assertIn('TOKEN=', conf)
        self.assertNotIn(b'\r', z.read('lt-agent/lt-agent-ctl.sh'))
        self.assertEqual(z.getinfo('lt-agent/lt-agent-ctl.sh').external_attr >> 16 & 0o777, 0o755)
        info = json.load(self.client.open(self.url + '/api/nms/agent'))
        self.assertEqual(info['zip'], '/static/lt-agent.zip'); self.assertTrue(info['url'].startswith('http://'))
        self.assertEqual(self.client.open(self.url + '/static/lt-agent-posix.sh').status, 200)

    def test_desktop_bootstrap_auth(self):
        """데스크톱(exe) 모드 + 비밀번호: 루프백이라도 로그인 필요, 창은 부트스트랩 토큰으로 세션. Host 가 도메인이면 403(DNS 리바인딩 방어)"""
        from logtriage.server import make_server
        import threading
        httpd, handler = make_server('127.0.0.1', 0, Path(self.tmp.name), 'pw', [], None, desktop=True)
        th = threading.Thread(target=httpd.serve_forever, daemon=True); th.start()
        try:
            u = f'http://127.0.0.1:{httpd.server_address[1]}'
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(u + '/api/nms/status')
            self.assertEqual(cm.exception.code, 401)   # 쿠키 없는 루프백 → 401
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(u + '/auth/bootstrap?t=wrong')
            self.assertEqual(cm.exception.code, 403)
            cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
            self.assertEqual(op.open(u + '/auth/bootstrap?t=' + handler.boot_token).status, 200)   # 302 → / (로그인 없이)
            self.assertEqual(op.open(u + '/api/nms/status').status, 200)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                op.open(urllib.request.Request(u + '/api/nms/status', headers={'Host': 'evil.example.com'}))
            self.assertEqual(cm.exception.code, 403)
            self.assertEqual(json.load(urllib.request.urlopen(u + '/healthz'))['app'], 'LogTriage')
        finally:
            httpd.shutdown(); httpd.server_close()

    def test_settings_and_snmp_http(self):
        h = {'Content-Type': 'application/json', 'X-NMS-Request': '1'}
        r = json.load(self.client.open(urllib.request.Request(self.url + '/api/nms/settings', data=json.dumps({'th_cpu': 85}).encode(), headers=h)))
        self.assertEqual(r['th_cpu'], 85); self.assertEqual(json.load(self.client.open(self.url + '/api/nms/settings'))['th_cpu'], 85)
        self.assertIn('usage_alarms', json.load(self.client.open(self.url + '/api/nms/status')))
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.client.open(urllib.request.Request(self.url + '/api/nms/snmp_test', data=json.dumps({'address': '127.0.0.1', 'community': 'x', 'port': 1, 'oids': ['1.2.3']}).encode(), headers=h))
        self.assertIn(cm.exception.code, (502, 400))   # 응답 없음 → 502
        page = self.client.open(self.url + '/nms').read().decode()
        self.assertIn('id="alarms"', page); self.assertIn('>상세<', page)   # 시안 09: [실시간] → [상세](응답 시간·자원·장애 이력 탭); self.assertIn('snmpbox', page)


if __name__=='__main__': unittest.main(verbosity=2)
