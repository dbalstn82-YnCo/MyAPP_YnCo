"""룰 학습 2차(DB, 2026-10-15) — 마스터 지시 "그동안 학습했던 룰팩은 유지 및 추가 학습 반드시 실시".

- MS-SQL ERRORLOG 본문만 남는 문구(833·17883·17884·5144·5145·825·17890)는 예전엔 파서가 버려 판정 0 → 파서·별칭·룰로 판정
- MySQL·PostgreSQL 빈칸(performance·lock·storage·capacity) 새 룰 6개(GPT 11차 벤더 문서 대조 반영)
- 지금까지의 룰(402)은 그대로 유지
"""
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.rules import load_rules  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

KW = dict(rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")


def analyze(product, lines):
    f = Path(tempfile.mkdtemp()) / "x.log"
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = run_analysis([{"path": str(f), "product": product, "host": "h1"}], None, **KW)
    return [t["rule_id"] for t in r["timeline"]]


class Batch2(unittest.TestCase):
    def test_previous_rules_are_kept(self):
        ids = {r.id for r in load_rules(ENGINE / "rules", ENGINE / "rules-local")}
        self.assertGreaterEqual(len(ids), 409)
        for keep in ("DB-MYS-001", "DB-MYS-002", "DB-PG-001", "DB-ORA-001", "WAS-TC-015", "WAS-WLS-011", "WAS-JB-010"):   # 기존·1차 학습 룰 유지
            self.assertIn(keep, ids)
        self.assertNotIn("DB-MYS-006", ids)                                 # GPT 11차: 고정 문구 미확인 — 넣지 않음

    def test_mssql_body_only_messages(self):
        got = analyze("mssql", [
            "2026-10-12 09:00:01.12 Server      Process 0:0:0 (0x1c10) Worker 0x00000002E8C2C160 appears to be non-yielding on Scheduler 1.",
            "2026-10-12 09:00:02.12 Server      New queries assigned to process on Node 0 haven't been picked up by a worker thread in the last 60 seconds.",
            "2026-10-12 09:00:03.12 spid12s     SQL Server has encountered 3 occurrence(s) of I/O requests taking longer than 15 seconds to complete on file [D:\\a.mdf] in database id 5.",
            "2026-10-12 09:00:04.12 spid55      Autogrow of file 'app_log' in database 'app' was cancelled by user or timed out after 30000 milliseconds.",
            "2026-10-12 09:00:05.12 spid55      Autogrow of file 'app_data' in database 'app' took 12345 milliseconds.",
            "2026-10-12 09:00:06.12 spid61      A read of the file 'D:\\a.mdf' at offset 0x000000a1234000 succeeded after failing 1 time(s) with error: incorrect checksum.",
            "2026-10-12 09:00:07.12 spid4s      A significant part of sql server process memory has been paged out. This may result in a performance degradation.",
            "2026-10-12 09:00:08.12 spid8s      Starting up database 'tempdb'.",
        ])
        self.assertEqual(got, ["MSSQL-17883", "MSSQL-17884", "MSSQL-833", "MSSQL-5144", "MSSQL-5145", "MSSQL-825", "DB-MSS-001"])

    def test_mysql_and_postgresql_new_rules(self):
        self.assertEqual(analyze("mysql", [
            "2026-10-12T09:00:01.123456Z 0 [Note] InnoDB: page_cleaner: 1000ms intended loop took 4013ms. The settings might not be optimal.",
            "2026-10-12T09:00:02.123456Z 0 [ERROR] [MY-012872] [InnoDB] Semaphore wait has lasted > 600 seconds. We intentionally crash the server because it appears to be hung.",
            "2026-10-12T09:00:03.123456Z 0 [ERROR] [MY-011906] [InnoDB] Database page corruption on disk or a failed file read of page [page id: space=12, page number=3].",
            "2026-10-12T09:00:04.123456Z 0 [Warning] InnoDB: A long semaphore wait:",            # 006 은 넣지 않았다 — 걸리지 않아야
        ]), ["DB-MYS-005", "DB-MYS-007", "DB-MYS-008"])
        self.assertEqual(analyze("postgresql", [
            "2026-10-12 09:00:01.123 KST [1234] LOG:  could not fork new process for connection: Resource temporarily unavailable",
            "2026-10-12 09:00:02.123 KST [1234] LOG:  could not fork autovacuum worker process: Cannot allocate memory",
            '2026-10-12 09:00:03.123 KST [1234] ERROR:  could not read block 0 in file "base/16384/16385": read only 0 of 8192 bytes',
            "2026-10-12 09:00:04.123 KST [1234] LOG:  database system is ready to accept connections",
        ]), ["DB-PG-005", "DB-PG-007", "DB-PG-006"])


if __name__ == "__main__":
    unittest.main()
