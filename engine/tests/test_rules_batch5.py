"""룰 학습 5차(국산, 2026-10-15) — 마스터 지시 "남은 일 순차 적용". GPT 14차 웹 대조 + 벤더 원문 재확인.

파서 결함(원문 대조로 발견):
- CUBRID 이벤트 로그(.event, 'MM/DD/YY hh:mm:ss.mmm - SLOW_QUERY …')를 읽지 못했다
- CUBRID NOTIFICATION 은 'CODE = -1125'(ERROR 없이) — 'ERROR CODE' 만 받아 알림 코드가 사전에 닿지 못했다
- Goldilocks system.trc 는 머리줄 다음 줄에 본문 — 본문의 문구·ERR 코드를 버렸다
- Altibase 시각 없는 다음 줄을 버렸다
사전 키 결함: Goldilocks 11141·14168 은 숫자만 적혀 파서 코드(ERR-…)와 맞지 않았다
"""
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.codes import load_codes  # noqa: E402
from logtriage.rules import load_rules  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

KW = dict(rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")


def tl(product, text, name="x.log"):
    f = Path(tempfile.mkdtemp()) / name
    f.write_text(text, encoding="utf-8")
    r = run_analysis([{"path": str(f), "product": product, "host": "h1"}], None, **KW)
    return [(t["rule_id"], t["source"]) for t in r["timeline"]]


class Batch5(unittest.TestCase):
    def test_previous_rules_are_kept(self):
        ids = {r.id for r in load_rules(ENGINE / "rules", ENGINE / "rules-local")}
        self.assertGreaterEqual(len(ids), 427)
        for keep in ("DB-ALT-001", "DB-ALT-005", "OS-WIN-005", "WEB-NGX-011", "DB-MSS-001", "WAS-TC-015"):
            self.assertIn(keep, ids)

    def test_cubrid_event_log(self):
        ev = ("06/12/13 16:41:05.558 - SLOW_QUERY   client: PUBLIC@testhost|csql(13173)  sql: update [y] [y] set [y].[a]= ?:1\n"
              "  where [y].[a]= ?:0  using index [y].[pk_y_a](+)  bind: 5  bind: 200  time: 1015\n"
              "06/12/13 17:07:29.457 - MANY_IOREADS   client: PUBLIC@testhost|csql(12852)  sql: update [x] [x] set [x].[a]= ?:1\n"
              "  where ([x].[a]> ?:0 ) using index [x].[idx](+)  bind: 8  bind: 100  time: 528  ioreads: 15648\n")
        self.assertEqual(tl("cubrid", ev, "demodb_20131206_1641.event"), [("DB-CUB-001", "시그니처 룰"), ("DB-CUB-002", "시그니처 룰")])

    def test_cubrid_notification_code(self):
        err = ("Time: 06/14/13 19:23:40.485 - NOTIFICATION *** file ../../src/storage/btree.c, line 10617 CODE = -1125 Tran = 1, CLIENT = testhost:csql(24670), EID = 6\n"
               "Created the overflow key file.\n")
        self.assertEqual(tl("cubrid", err, "demodb.err"), [("-1125", "벤더 에러코드")])

    def test_goldilocks_multiline(self):
        trc = ("[2014-09-12 10:49:21.842179 THREAD(3972,139706316711680)] [WARNING]\n"
               "[CLEANUP] long statement timeout - pid(8029), thread(140053960505088), program(gsql), statement start time(2014-09-12 10:48:49.963471)\n"
               "[2014-09-12 10:50:01.000001 THREAD(3972,139706316711680)] [ERROR]\n"
               "ERR-08S01(11141): communication link failure\n")
        self.assertEqual(tl("goldilocks", trc, "system.trc"), [("DB-GD-001", "시그니처 룰"), ("ERR-11141", "벤더 에러코드")])

    def test_altibase_multiline_and_single(self):
        log = ("[2026/10/12 09:00:01] [Thread-7f4b] [Level-1] [Notify : Query Timeout] Query Canceled by Server : Session ID = 102373\n"
               "[2026/10/12 09:00:02] [Thread-7f4c] [Level-1]\n"
               "[Notify : Query Timeout] Query Canceled by Server : Session ID = 102374\n")
        self.assertEqual(tl("altibase", log, "altibase_boot.log"), [("DB-ALT-006", "시그니처 룰"), ("DB-ALT-006", "시그니처 룰")])

    def test_multiline_boundaries(self):
        """GPT 15차 필수 1: 다음 머리줄에서 직전 기록 확정 · 파일 끝·잘린 파일에서 마지막 기록 유실 없음 · 길이 상한에서 다음 기록과 섞이지 않음."""
        from logtriage import parsers
        import logtriage.parsers.db_logs  # noqa: F401
        def parse(product, text):
            f = Path(tempfile.mkdtemp()) / "x.log"
            f.write_text(text, encoding="utf-8")
            return list(parsers._REGISTRY[product][1](f, "h"))
        gd = parse("goldilocks", "[2014-09-12 10:49:21.1 THREAD(1,2)] [WARNING]\n[CLEANUP] long statement timeout - pid(1)\n"
                                 "[2014-09-12 10:49:22.1 THREAD(1,2)] [ERROR]\nERR-08S01(11141): communication link failure\n"
                                 "[2014-09-12 10:49:23.1 THREAD(1,2)] [WARNING]\n")          # 잘린 파일 — 머리줄만 남은 마지막 기록
        self.assertEqual(len(gd), 3)
        self.assertIn("[CLEANUP]", gd[0].message); self.assertNotIn("ERR-08S01", gd[0].message)
        self.assertEqual(gd[1].code, "ERR-11141"); self.assertNotIn("CLEANUP", gd[1].message)
        self.assertEqual(gd[2].message, "THREAD(1,2)] [WARNING]")
        long = "[2026/10/12 09:00:01] [Thread-1] [Level-1] ERROR start\n" + "".join(f"body line {k} " + "x" * 80 + "\n" for k in range(20)) \
               + "[2026/10/12 09:00:02] [Thread-2] [Level-1] [Notify : Query Timeout] Query Canceled by Server : Session ID = 7\n"
        al = parse("altibase", long)
        self.assertEqual(len(al), 2)
        self.assertLessEqual(len(al[0].message), 700)                         # 상한에서 멈춤
        self.assertNotIn("Query Timeout", al[0].message)                      # 다음 기록과 섞이지 않음
        self.assertTrue(al[1].message.startswith("[Thread-2]"))
        cu = parse("cubrid", "Time: 06/14/13 19:23:40.485 - NOTIFICATION *** file a.c, line 1 CODE = -1125 Tran = 1, EID = 6\nCreated the overflow key file.\n"
                             "06/14/13 19:23:41.000 - DEADLOCK   client: u@h|csql(1)  sql: update [t] set [t].[a]=1\n")
        self.assertEqual([(e.code, e.severity) for e in cu], [("-1125", "info"), (None, "error")])
        self.assertIn("overflow key", cu[0].message); self.assertNotIn("DEADLOCK", cu[0].message)

    def test_learn_template_masks_sql_body(self):
        """GPT 15차 필수 2: CUBRID 이벤트 본문의 SQL·바인드 값·사용자는 학습 후보 틀에 남지 않는다(반출 경로 보호)."""
        from logtriage import learn
        t = learn.template("LOCK_TIMEOUT client: dba@dbhost01|csql(13173) sql: update [acct] set [acct].[pw]= ?:1 | bind: 'Hong Gildong' bind: '010-1234-5678'")
        for leak in ("acct", "pw", "Hong", "1234", "dba", "dbhost01"):
            self.assertNotIn(leak, t)
        self.assertTrue(t.startswith("LOCK_TIMEOUT client:"))

    def test_dictionary_keys_match_parser_shape(self):
        """Goldilocks 파서는 늘 'ERR-<내부번호>' — 숫자만 적힌 사전 키는 닿지 못한다."""
        c = load_codes(ENGINE / "errorcodes")
        gd = [k.split(":", 1)[1] for k in c if k.startswith("goldilocks:")]
        self.assertTrue(gd and all(k.startswith("ERR-") for k in gd), [k for k in gd if not k.startswith("ERR-")])
        for k in ("cubrid:-1125", "cubrid:-1126", "goldilocks:ERR-16004", "goldilocks:ERR-16312"):
            self.assertIn(k, c)


if __name__ == "__main__":
    unittest.main()
