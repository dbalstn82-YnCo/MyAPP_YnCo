"""12차 성능(2026-10-20 마스터: "PC 는 중요하지 않고 로그 분석기가 낼 수 있는 최대 성능으로") — 빨라져도 판정은 같아야 한다.

① fast_strptime: 고정 폭 형식은 자리로 잘라 읽되 결과·오류가 datetime.strptime 과 같다(무작위·경계·잘못된 입력 대조)
② 룰 사전 거름 관문: 관문을 거쳐도 거름 결과가 관문 없을 때와 같다(실제 룰 전부 × 견본·합성 줄)
③ 견본 전체 판정 동일성: 성능 변경 전 기준 결과(판정 집합)와 같다
"""
import random
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.parsers import fast_strptime  # noqa: E402

FMTS = ["%Y-%m-%d %H:%M:%S", "%y%m%d %H:%M:%S", "%m/%d/%y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m%d%H%M%y",
        "%d %b %Y %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%Y %b %d %H:%M:%S", "%b %d %H:%M:%S",
        "%a %b %d %H:%M:%S %Y", "%Y%m%d%H%M%S", "%d/%b/%Y:%H:%M:%S"]


def _same(s, fmt):
    try:
        a = ("ok", datetime.strptime(s, fmt))
    except Exception as e:   # noqa: BLE001
        a = ("err", type(e))
    try:
        b = ("ok", fast_strptime(s, fmt))
    except Exception as e:   # noqa: BLE001
        b = ("err", type(e))
    return a == b, a, b


class FastStrptime(unittest.TestCase):
    def test_random_valid(self):
        rnd = random.Random(12)
        base = datetime(1970, 1, 1)
        for _ in range(4000):
            d = base + timedelta(seconds=rnd.randrange(0, 3_000_000_000))
            for fmt in FMTS:
                s = d.strftime(fmt)
                ok, a, b = _same(s, fmt)
                self.assertTrue(ok, (s, fmt, a, b))

    def test_edges_and_garbage(self):
        cases = ["2026-02-29 10:00:00", "2024-02-29 10:00:00", "2026-13-01 10:00:00", "2026-1-2 3:04:05", "2026-01-02  03:04:05",
                 "2026-01-02\t03:04:05", "2026-01-02 24:00:00", "2026-01-02 23:59:60", "２０２６-01-02 03:04:05", "2026-01-02 03:04:05 ",
                 "", "abcd-ef-gh ij:kl:mn", "0000-01-01 00:00:00", "9999-12-31 23:59:59"]
        for s in cases:
            ok, a, b = _same(s, "%Y-%m-%d %H:%M:%S")
            self.assertTrue(ok, (s, a, b))
        for s in ["02-Sep-2026 14:02:48", "02-sep-2026 14:02:48", "02-SEP-2026 14:02:48", "02-Sept-2026 14:02:48", "2-Sep-2026 14:02:48",
                  "31-Feb-2026 00:00:00", "02-Xyz-2026 14:02:48"]:
            ok, a, b = _same(s, "%d-%b-%Y %H:%M:%S")
            self.assertTrue(ok, (s, a, b))
        for s in ["690101 00:00:00", "680101 00:00:00", "991231 23:59:59", "000101 00:00:00"]:
            ok, a, b = _same(s, "%y%m%d %H:%M:%S")
            self.assertTrue(ok, (s, a, b))
        for s in ["Sep  2 14:02:48", "Sep 02 14:02:48", "Feb 29 00:00:00"]:
            ok, a, b = _same(s, "%b %d %H:%M:%S")
            self.assertTrue(ok, (s, a, b))


class GateEquivalence(unittest.TestCase):
    def test_prefilter_same_with_and_without_gate(self):
        """실제 룰 전부의 (계층, 제품) 후보마다 — 관문이 있는 거름과 관문 없는 기준 거름의 결과가 줄마다 같다."""
        from logtriage import rules as R
        rules = R.load_rules(ENGINE / "rules", ENGINE / "rules-local")
        lines = []
        for f in sorted((ENGINE / "samples").glob("*")):
            if f.suffix in (".json",):
                continue
            lines += f.read_text(encoding="utf-8", errors="replace").splitlines()
        rnd = random.Random(7)
        lits = sorted({x for r in rules if r.anchors for br in r.anchors for x in br})
        for _ in range(3000):   # 리터럴을 섞어 만든 경계 줄(일부만 갖춘 줄 포함)
            k = rnd.randint(1, 4)
            lines.append(" ".join(rnd.choice(lits) for _ in range(k)) + " 2026 error x")
        keys = {(r.layer, p) for r in rules for p in (r.products or ["*"])}
        checked = 0
        for layer, prod in sorted(keys):
            cand = R.candidates(rules, layer, prod)
            if not cand:
                continue
            fast = R.build_prefilter(cand)
            anchored = [r.anchors for r in cand if r.anchors]
            loose = [r for r in cand if not r.anchors]
            import re
            master = re.compile("|".join(f"(?:{r.pattern.pattern})" for r in loose), re.IGNORECASE) if loose else None

            def slow(text, tl):
                return any(R.anchor_hit(a, tl) for a in anchored) or (master is not None and bool(master.search(text)))
            for ln in lines:
                tl = ln.lower()
                self.assertEqual(fast(ln, tl), slow(ln, tl), (layer, prod, ln[:120]))
                checked += 1
        self.assertGreater(checked, 10000)


class TrieRegex(unittest.TestCase):
    def test_same_as_plain_alternation(self):
        import re
        from logtriage.rules import trie_regex
        rnd = random.Random(3)
        alpha = "abc.-_()[]*+?xyz 가나"
        for _ in range(300):
            words = {"".join(rnd.choice(alpha) for _ in range(rnd.randint(1, 8))) for _ in range(rnd.randint(1, 25))}
            plain = re.compile("|".join(re.escape(w) for w in sorted(words, key=len, reverse=True)))
            trie = re.compile(trie_regex(words))
            for _ in range(60):
                s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 30)))
                if rnd.random() < 0.3:
                    s += rnd.choice(sorted(words))
                self.assertEqual(bool(plain.search(s)), bool(trie.search(s)), (words, s))


def _strip(r):
    import json
    r = dict(r)
    for k in ("elapsed_sec", "analyzed_at"):
        r.pop(k, None)
    return json.loads(json.dumps(r, ensure_ascii=False, default=str, sort_keys=True))


class ParallelEqualsSequential(unittest.TestCase):
    """12차 병렬 해석 — 작업자 여러 개·조각 64KB 로 경계를 많이 만들어도 분석 결과 전체가 순차(작업자 1개)와 같다."""

    @classmethod
    def setUpClass(cls):
        import os
        import shutil
        import tempfile
        cls.td = Path(tempfile.mkdtemp())
        rnd = random.Random(42)
        t0 = datetime(2026, 9, 2, 13, 0, 0)
        # tomcat: 여러 줄 스택트레이스 · CRLF · CR 단독 · BOM · 개인정보 형태 숫자
        lines = []
        for n in range(30000):
            ts = (t0 + timedelta(seconds=n // 7)).strftime("%Y-%m-%d %H:%M:%S") + ",%03d" % (n % 1000)
            if n % 997 == 0:
                lines.append(f"{ts} ERROR [exec-{n % 9}] c.z.h.pool.HikariPool - HikariPool-1 - Connection is not available, request timed out after 30001ms.")
                lines.append("java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30001ms.")
                lines += [f"\tat com.zaxxer.hikari.pool.HikariPool.getConnection(HikariPool.java:{k})" for k in range(rnd.randint(1, 30))]
            elif n % 1499 == 0:
                lines.append(f"{ts} SEVERE [exec-1] java.lang.OutOfMemoryError: Java heap space 주민 900101-1234567")
            else:
                lines.append(f"{ts} INFO  [exec-{n % 40}] c.e.order.OrderController - order #{n} accepted")
        body = ""
        for k, ln in enumerate(lines):
            body += ln + ("\r\n" if k % 5 == 0 else "\r" if k % 13 == 0 else "\n")
        (cls.td / "catalina.out").write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
        # nginx 오류 로그(한 줄 = 한 이벤트) · CP949
        ng = []
        for n in range(40000):
            ts = (t0 + timedelta(seconds=n // 5)).strftime("%Y/%m/%d %H:%M:%S")
            lvl = "error" if n % 211 == 0 else "warn" if n % 97 == 0 else "notice"
            msg = "upstream timed out (110: Connection timed out) while reading response header" if lvl == "error" else "한글 요청 처리"
            ng.append(f"{ts} [{lvl}] 1234#0: *{n} {msg}, client: 10.0.0.{n % 250}, server: _")
        (cls.td / "error.log").write_bytes("\n".join(ng).encode("cp949") + b"\n")
        cls.old = (os.environ.get("LOGTRIAGE_WORKERS"),)
        cls.shutil = shutil

    @classmethod
    def tearDownClass(cls):
        cls.shutil.rmtree(cls.td, True)

    def _run(self, inputs, workers, chunk=None, minimum=None):
        import os
        from logtriage import parallel as P
        from logtriage.service import run_analysis
        old = (P.CHUNK, P.PAR_MIN_TOTAL, os.environ.get("LOGTRIAGE_WORKERS"))
        try:
            os.environ["LOGTRIAGE_WORKERS"] = str(workers)
            if chunk:
                P.CHUNK = chunk
            if minimum is not None:
                P.PAR_MIN_TOTAL = minimum
            return run_analysis([dict(i) for i in inputs], None, 30, 10, ENGINE / "rules", ENGINE / "rules-local", ENGINE / "errorcodes")
        finally:
            P.CHUNK, P.PAR_MIN_TOTAL = old[0], old[1]
            if old[2] is None:
                os.environ.pop("LOGTRIAGE_WORKERS", None)
            else:
                os.environ["LOGTRIAGE_WORKERS"] = old[2]

    def _same(self, inputs):
        seq = self._run(inputs, 1)
        par = self._run(inputs, 6, chunk=64 * 1024, minimum=0)
        self.assertGreater(seq["findings_total"], 0)
        self.assertEqual(_strip(par), _strip(seq))

    def _tasks(self, name, product):
        from logtriage import parallel as P
        old = P.CHUNK
        P.CHUNK = 64 * 1024
        try:
            return P.plan([{"path": str(self.td / name), "product": product, "host": "h"}], 6)
        finally:
            P.CHUNK = old

    def test_tomcat_chunked(self):
        tasks = self._tasks("catalina.out", "tomcat")
        self.assertGreater(len(tasks), 2)                                      # 실제로 쪼개졌다
        from logtriage.parsers import tomcat
        raw = (self.td / "catalina.out").read_bytes()
        for t in tasks[1:]:                                                    # 경계는 모두 이벤트 시작 줄(시각으로 시작)
            line = raw[t["range"][0]:].split(b"\n", 1)[0].decode("utf-8").split("\r")[0]
            self.assertTrue(any(p.match(line) for p, _ in tomcat._PATTERNS), line[:60])
        self._same([{"path": str(self.td / "catalina.out"), "product": "tomcat", "host": "h"}])

    def test_nginx_chunked_cp949(self):
        self.assertGreater(len(self._tasks("error.log", "nginx")), 2)
        self._same([{"path": str(self.td / "error.log"), "product": "nginx", "host": "w"}])

    def test_unchunkable_parser_whole_file(self):
        from logtriage import parallel as P
        old = P.CHUNK
        P.CHUNK = 1024
        try:
            t = P.plan([{"path": str(ENGINE / "samples" / "alert_orcl.log"), "product": "oracle", "host": "d"}], 6)
        finally:
            P.CHUNK = old
        self.assertEqual([x["range"] for x in t], [None])                      # 쪼갤 수 없는 파서는 파일 통째

    def test_multi_file(self):
        self._same([{"path": str(self.td / "catalina.out"), "product": "tomcat", "host": "h"},
                    {"path": str(self.td / "error.log"), "product": "nginx", "host": "w"},
                    {"path": str(ENGINE / "samples" / "alert_orcl.log"), "product": "oracle", "host": "d"}])

    def test_line_count_rules(self):
        from logtriage.parallel import _count_lines
        p = self.td / "nl.txt"
        p.write_bytes(b"a\r\nb\rc\nd\r\r\ne")
        with open(p, encoding="utf-8", newline="") as f:
            want = [len(f.read(i).splitlines()) for i in range(0)]
        for upto in range(0, 13):
            with open(p, "rb") as f:
                pref = f.read(upto)
            text_lines = pref.decode().replace("\r\n", "\n").replace("\r", "\n").count("\n")
            self.assertEqual(_count_lines(p, upto), text_lines, upto)

    def test_line_count_block_boundaries(self):
        """읽기 단위(_BLK) 경계에 CR|LF 가 걸쳐도 줄 수가 같다 — 단위를 1~7 바이트로 줄여 모든 자리에 경계를 만든다(12차 변이에서 놓친 자리)."""
        from logtriage import parallel as P
        p = self.td / "nl2.txt"
        data = b"a\r\nb\rc\nd\r\r\ne\r\n\r\nf\rg\r\n"
        p.write_bytes(data)
        old = P._BLK
        try:
            for blk in range(1, 8):
                P._BLK = blk
                offs = list(range(0, len(data) + 1))
                for upto, n in zip(offs, P._count_lines_at(p, offs)):
                    want = data[:upto].replace(b"\r\n", b"\n").replace(b"\r", b"\n").count(b"\n")
                    self.assertEqual(n, want, (blk, upto))
        finally:
            P._BLK = old

    def test_cuts_snap_to_event_start(self):
        """연속 줄(스택)이 대부분인 로그 — 자르는 자리가 매번 이벤트 시작 줄로 옮겨지고, 결과도 순차와 같다(12차 변이에서 놓친 자리)."""
        t0 = datetime(2026, 9, 2, 13, 0, 0)
        out = []
        for n in range(3000):
            ts = (t0 + timedelta(seconds=n)).strftime("%Y-%m-%d %H:%M:%S") + ",000"
            if n % 50 == 0:
                out.append(f"{ts} ERROR [exec-3] c.z.h.pool.HikariPool - HikariPool-1 - Connection is not available, request timed out after 30001ms.")
                out.append("java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available")
            else:
                out.append(f"{ts} ERROR [exec-1] c.e.Svc - call failed #{n}")
                out.append("java.lang.IllegalStateException: boom")
            out += [f"\tat c.e.Svc.m{k}(Svc.java:{k})" for k in range(40)]
        (self.td / "dense.out").write_text("\n".join(out) + "\n", encoding="utf-8")
        tasks = self._tasks("dense.out", "tomcat")
        self.assertGreater(len(tasks), 4)
        from logtriage.parsers import tomcat
        raw = (self.td / "dense.out").read_bytes()
        for t in tasks[1:]:
            line = raw[t["range"][0]:].split(b"\n", 1)[0].decode("utf-8")
            self.assertTrue(any(p.match(line) for p, _ in tomcat._PATTERNS), line[:60])
        self._same([{"path": str(self.td / "dense.out"), "product": "tomcat", "host": "h"}])

    def test_utf16_not_chunked(self):
        """UTF-16 은 바이트 자리로 자르면 글자가 깨진다 — 파일 통째."""
        lines = [f"2026/09/02 13:00:{n % 60:02d} [error] 1#0: *{n} upstream timed out, client: 10.0.0.1" for n in range(20000)]
        (self.td / "u16.log").write_bytes("\n".join(lines).encode("utf-16"))
        self.assertEqual([t["range"] for t in self._tasks("u16.log", "nginx")], [None])


class WorkersMemoryCap(unittest.TestCase):
    """GPT 90차 P1: 남은 물리 메모리의 MEM_SHARE / 작업자당 WORKER_MB 를 넘는 작업자를 띄우지 않는다(LOGTRIAGE_WORKERS 를 줘도)."""

    def test_cap(self):
        import os
        from unittest.mock import patch
        from logtriage import parallel as P
        with patch.dict(os.environ, {"LOGTRIAGE_WORKERS": "12"}):
            with patch.object(P, "avail_mb", lambda: 400):      # 400MB 남음 → 240MB / 64 = 3
                self.assertEqual(P.workers(), 3)
            with patch.object(P, "avail_mb", lambda: 50):       # 거의 없음 → 순차(1)
                self.assertEqual(P.workers(), 1)
            with patch.object(P, "avail_mb", lambda: 64000):
                self.assertEqual(P.workers(), 12)
            with patch.object(P, "avail_mb", lambda: None):     # 모르면 그대로
                self.assertEqual(P.workers(), 12)
        real = P.avail_mb()
        self.assertTrue(real is None or real > 0, real)


class KnowledgeLoadSame(unittest.TestCase):
    """12차 성능 ④: 절차·매뉴얼·OS 해법 지식을 C 안전 파서(yamlsafe)로 읽어도 파이썬 파서와 결과가 같다 — 실제 지식 파일 전부."""

    def test_c_loader_same_as_python(self):
        import yaml
        from logtriage import yamlsafe
        n = 0
        for d in ("manuals", "errorcodes", "rules"):
            for p in sorted((ENGINE / d).rglob("*.yaml")):
                t = p.read_text(encoding="utf-8")
                self.assertEqual(yamlsafe.load(t), yaml.safe_load(t), p.name)
                n += 1
        self.assertGreater(n, 150)

    def test_loaders_use_c_parser(self):
        import inspect
        from logtriage import kb, os_solution, procedures
        for m in (procedures, kb, os_solution):
            src = inspect.getsource(m)
            self.assertNotIn("yaml.safe_load(", src, m.__name__)
            self.assertIn("yamlsafe.load(", src, m.__name__)


class FastPathTaken(unittest.TestCase):
    def test_fixed_width_formats_skip_strptime(self):
        """고정 폭 형식은 실제로 빠른 길을 탄다 — strptime 이 불리면 실패(빠른 길이 조용히 원래 함수로 새는 회귀 · 12차 변이에서 놓친 자리)."""
        import logtriage.parsers as PZ

        class NoStrp(datetime):
            @classmethod
            def strptime(cls, *a):
                raise AssertionError("strptime 호출됨")
        old = PZ.datetime
        PZ.datetime = NoStrp
        PZ._FMT_CACHE.clear()
        try:
            d = datetime(2026, 9, 2, 13, 4, 5)
            for fmt in ["%Y-%m-%d %H:%M:%S", "%y%m%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%Y%m%d%H%M%S",
                        "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%y %H:%M:%S"]:
                self.assertEqual(PZ.fast_strptime(d.strftime(fmt), fmt), d, fmt)
        finally:
            PZ.datetime = old
            PZ._FMT_CACHE.clear()


class SampleVerdictsUnchanged(unittest.TestCase):
    BASE = {   # 성능 변경 전(11차 엔진)으로 잰 견본별 (판정 룰 집합, 발견 수)
    }

    def test_samples(self):
        from logtriage.service import run_analysis
        from logtriage.detect import detect_product
        import json
        # 12차: tests/data 는 리눅스 반출 검사가 '운영 자료 폴더'로 막는다 — tests/fixtures 로 옮김
        ref = json.loads((ENGINE / "tests" / "fixtures" / "perf_baseline.json").read_text(encoding="utf-8"))
        for name, want in ref.items():
            p = ENGINE / "samples" / name
            r = run_analysis([{"path": str(p), "product": want["product"], "host": "h"}], None, 30, 10,
                             ENGINE / "rules", ENGINE / "rules-local", ENGINE / "errorcodes")
            got = sorted({c.get("rule_id") for c in r.get("checklist") or []})
            self.assertEqual(got, want["rules"], name)
            self.assertEqual(r["findings_total"], want["findings"], name)
            self.assertEqual(r.get("events_total"), want["events"], name)


if __name__ == "__main__":
    unittest.main()
