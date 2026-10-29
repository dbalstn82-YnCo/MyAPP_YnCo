import sys
sys.dont_write_bytecode = True
import json, os, tempfile, threading, time, unittest, urllib.request, urllib.error, http.cookiejar
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logtriage import procs
from logtriage.nms import Store, validate_metrics, clean_procs, validate
from logtriage.server import make_server


def config(**kw):
    return {'name': 'p', 'address': '127.0.0.1', 'kind': 'server', 'method': 'tcp', 'port': 1, 'interval': 10, 'timeout': 1, 'fail_limit': 3, 'recover_limit': 2, **kw}


def fake_proc(root: Path, pid: int, name: str, uid: int, rss_kb: int, utime: int, stime: int):
    d = root / str(pid); d.mkdir(parents=True, exist_ok=True)
    (d / 'status').write_text(f'Name:\t{name}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t0\t0\t0\t0\nVmRSS:\t{rss_kb} kB\n')
    (d / 'stat').write_text(f'{pid} ({name}) S 1 {pid} {pid} 0 -1 4194560 100 0 0 0 {utime} {stime} 0 0 20 0 1 0 100 1000000 {rss_kb // 4} 18446744073709551615\n')


class LinuxParse(unittest.TestCase):
    def test_proc_fixture_and_cpu_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_proc(root, 1, 'systemd', 0, 11000, 10, 5); fake_proc(root, 2201, 'java', 1000, 250000, 1000, 200); fake_proc(root, 2202, 'bash', 1000, 12000, 1, 0)
            (root / 'self').mkdir(); (root / 'meminfo').write_text('MemTotal: 1 kB\n')
            s = procs.ProcSampler(); s._clk = 100
            names = {0: 'root', 1000: 'yms'}
            with patch.object(procs, 'os') as fos:
                fos.listdir = lambda p: os.listdir(root); fos.name = 'posix'; fos.cpu_count = os.cpu_count; fos.sysconf = lambda n: 100
                real_open = open
                with patch('builtins.open', lambda p, *a, **k: real_open(str(p).replace('/proc', str(root), 1), *a, **k)):
                    # 12차: 실제 시계를 쓰면 부하가 큰 PC 에서 두 수집 사이가 1.047초로 늘어 71.6% 로 실패했다(전체 회귀 중) — 가짜 시계로 정확히 1초
                    clock = [1000.0]
                    from types import SimpleNamespace
                    with patch.object(s, '_uname', lambda uid: names.get(uid, str(uid))), \
                            patch.object(procs, 'time', SimpleNamespace(monotonic=lambda: clock[0])):
                        s._ncpu = 2
                        r1 = s.collect()
                        fake_proc(root, 2201, 'java', 1000, 250000, 1100, 250)   # 1.5초 CPU 증가
                        clock[0] += 1.0   # 정확히 1초 경과
                        r2 = s.collect()
        self.assertEqual(r1['total'], 3); self.assertEqual({u['user']: u['count'] for u in r1['users']}, {'root': 1, 'yms': 2})
        java = next(x for x in r2['top'] if x['name'] == 'java')
        self.assertAlmostEqual(java['cpu'], 75.0, delta=3.0)   # 1.5s / ~1s / 2cpu ≈ 75%
        self.assertEqual(java['user'], 'yms'); self.assertAlmostEqual(java['mem_mb'], 244.1, delta=0.2)
        self.assertEqual(r2['top'][0]['name'], 'java')
        # PID 재사용: 같은 pid·이름이지만 starttime 이 다르면 차분하지 않는다(CPU 0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); s = procs.ProcSampler(); s._clk = 100; s._ncpu = 1
            real_open = open
            with patch.object(procs, 'os') as fos, patch('builtins.open', lambda p, *a, **k: real_open(str(p).replace('/proc', str(root), 1), *a, **k)), patch.object(s, '_uname', lambda uid: 'u'):
                fos.listdir = lambda p: os.listdir(root); fos.name = 'posix'; fos.readlink = os.readlink; fos.path = os.path
                fake_proc(root, 77, 'x', 1, 100, 100, 0); s.collect(); s._t -= 1.0
                (root / '77' / 'stat').write_text('77 (x) S 1 77 77 0 -1 4194560 100 0 0 0 5000 0 0 0 20 0 1 0 999 1000000 25 0\n')   # 새 프로세스(starttime 999), CPU 50s
                r = s.collect()
        self.assertEqual(r['top'][0]['cpu'], 0.0); self.assertEqual(r['failed'], 0)

    def test_summarize_caps(self):
        rows = [(i, f'u{i % 50}', f'p{i}', float(i % 7), 1.0) for i in range(500)]
        d = procs.summarize(rows, 20, 40, 4)
        self.assertEqual(d['total'], 500); self.assertEqual(len(d['users']), 41); self.assertTrue(d['users'][-1]['user'].startswith('(기타'))
        self.assertEqual(sum(u['count'] for u in d['users']), 500); self.assertEqual(len(d['top']), 20); self.assertEqual(d['top'][0]['cpu'], 6.0)

    @unittest.skipUnless(os.name == 'nt', 'Windows 전용')
    def test_windows_real_collect(self):
        s = procs.ProcSampler(); s.collect(); time.sleep(0.5); d = s.collect()
        self.assertGreater(d['total'], 10); self.assertTrue(any(u['user'] not in ('N/A', '?') for u in d['users']))
        self.assertTrue(all(isinstance(x['pid'], int) and x['name'] for x in d['top']))

    def test_agent_copy_identical(self):
        a = (Path(__file__).resolve().parents[1] / 'logtriage/procs.py').read_bytes(); b = (Path(__file__).resolve().parents[1] / 'tools/agent/lt_procs.py').read_bytes()
        self.assertEqual(a, b, 'tools/agent/lt_procs.py 는 logtriage/procs.py 와 같아야 합니다(복사 필요)')


class StoreProcs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = Store(Path(self.tmp.name) / 'nms.sqlite3')

    def tearDown(self):
        self.tmp.cleanup()

    def sample(self, n=3):
        return {'total': n, 'known': n, 'ncpu': 4, 'users': [{'user': 'root', 'count': 1, 'cpu': 0.5, 'mem_mb': 10}, {'user': 'yms', 'count': n - 1, 'cpu': 12.5, 'mem_mb': 300}],
                'top': [{'pid': 2201, 'user': 'yms', 'name': 'java', 'cpu': 12.5, 'mem_mb': 244}]}

    def test_clean_and_validate(self):
        v = validate_metrics({'cpu': 1, 'mem': 2, 'procs': self.sample()})
        self.assertEqual(v['pcount'], 3); self.assertEqual(v['procs']['users'][1]['user'], 'yms')
        self.assertIsNone(validate_metrics({'cpu': 1, 'procs': 'bad'})['procs'])
        bad = clean_procs({'total': 5, 'users': [{'user': 'a\u202eb\x01c', 'count': -3}, {'user': 'ok', 'count': 2.0}, {'user': 'nan', 'count': float('nan')}, {'user': 'f', 'count': 1.5}, {'user': 'b', 'count': True}], 'top': [{'pid': -1, 'name': 'x'}, {'pid': 3.0, 'name': 'y\u2066z'}]})
        self.assertEqual([u['user'] for u in bad['users']], ['ok']); self.assertEqual(bad['users'][0]['count'], 2)
        self.assertEqual(bad['top'], [{'pid': 3, 'user': '?', 'name': 'y z', 'cpu': 0.0, 'mem_mb': 0.0}]); self.assertEqual(bad['failed'], 0)
        self.assertIsNone(clean_procs({'total': 1.5})); self.assertIsNone(clean_procs({'total': True}))
        big = {'total': 99, 'users': [{'user': 'u' * 200, 'count': 5, 'cpu': -5, 'mem_mb': 1}] * 60, 'top': [{'pid': 1, 'name': 'x' * 100, 'cpu': 1e9}] * 50}
        c = clean_procs(big); self.assertEqual(len(c['users']), 41); self.assertEqual(len(c['users'][0]['user']), 64); self.assertEqual(c['users'][0]['count'], 5)
        self.assertEqual(clean_procs({'total': 1, 'users': [{'user': 'a', 'count': 10 ** 9}]})['users'], [])   # 범위 초과 항목은 버림
        self.assertEqual(c['users'][0]['cpu'], 0.0); self.assertEqual(len(c['top']), 20); self.assertEqual(len(c['top'][0]['name']), 48); self.assertEqual(c['top'][0]['cpu'], 0.0)
        with self.assertRaises(ValueError):
            validate(config(procs='all'))
        self.assertEqual(validate(config())['procs'], 'top')

    def test_store_levels_and_snapshot(self):
        tid = self.store.save(config(metrics='agent'))['id']
        self.store.record_metrics(tid, validate_metrics({'cpu': 1, 'mem': 2, 'procs': self.sample(5)}))
        d = self.store.procs_detail(tid); self.assertEqual(d['total'], 5); self.assertEqual(len(d['top']), 1)
        u = self.store.snapshot()['targets'][0]['usage']; self.assertEqual(u['pcount'], 5); self.assertEqual(u['pusers'], 2); self.assertEqual(u['pknown'], 5)
        self.assertEqual(self.store.metrics(tid)[-1]['pcount'], 5)
        self.store.save(config(id=tid, metrics='agent', procs='users'))
        self.store.record_metrics(tid, validate_metrics({'cpu': 1, 'procs': self.sample(6)}), now=time.time() + 1)
        d = self.store.procs_detail(tid); self.assertEqual(d['total'], 6); self.assertEqual(d['top'], [])   # users 수준: 상위 목록 제외
        self.store.save(config(id=tid, metrics='agent', procs='none'))
        self.store.record_metrics(tid, validate_metrics({'cpu': 1, 'procs': self.sample(7)}), now=time.time() + 2)
        self.assertEqual(self.store.procs_detail(tid)['total'], 6)   # none: 갱신 안 함
        self.assertIsNone(self.store.metrics(tid)[-1]['pcount'])
        self.store.delete(tid); self.assertIsNone(self.store.procs_detail(tid))   # cascade


class HttpProcs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.httpd, self.handler = make_server('127.0.0.1', 0, Path(self.tmp.name), None, [], None)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f'http://127.0.0.1:{self.httpd.server_address[1]}'; self.api = self.handler.api

    def tearDown(self):
        self.httpd.shutdown(); self.httpd.server_close(); self.tmp.cleanup()

    def post(self, path, body, headers):
        return json.load(urllib.request.urlopen(urllib.request.Request(self.url + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json', **headers})))

    def test_push_and_detail(self):
        tid = self.post('/api/nms/save', config(metrics='agent'), {'X-NMS-Request': '1'})['id']
        tok = self.api.nms.agent_token
        body = {'hostname': 'h', 'cpu': 5, 'mem': 6, 'disk': 7, 'procs': {'total': 300, 'known': 200, 'ncpu': 8,
                'users': [{'user': f'user{i}', 'count': 3, 'cpu': 0.1, 'mem_mb': 5.5} for i in range(40)], 'top': [{'pid': i, 'user': 'u', 'name': 'n' * 40, 'cpu': 1.0, 'mem_mb': 1.0} for i in range(20)]}}
        body['pad'] = 'x' * 6000   # 8KB 한도였다면 거부됐을 크기(무시되는 필드)
        self.assertGreater(len(json.dumps(body)), 8192)
        r = self.post('/api/nms/metrics', body, {'X-Agent-Token': tok}); self.assertTrue(r['ok'])
        d = json.load(urllib.request.urlopen(self.url + '/api/nms/procs?id=' + tid))
        self.assertEqual(d['total'], 300); self.assertEqual(len(d['users']), 40); self.assertEqual(len(d['top']), 20)
        st = json.load(urllib.request.urlopen(self.url + '/api/nms/status'))['targets'][0]['usage']
        self.assertEqual(st['pcount'], 300); self.assertEqual(st['pusers'], 40)
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self.url + '/api/nms/procs?id=nope')
        self.assertEqual(cm.exception.code, 404)
        page = urllib.request.urlopen(self.url + '/nms').read().decode()
        self.assertIn('id="procsSel"', page); self.assertIn('procsCards', page)
        z = urllib.request.urlopen(self.url + '/static/lt-agent.zip').read()
        import io, zipfile
        self.assertIn('lt-agent/lt_procs.py', zipfile.ZipFile(io.BytesIO(z)).namelist())


if __name__ == '__main__':
    unittest.main()
