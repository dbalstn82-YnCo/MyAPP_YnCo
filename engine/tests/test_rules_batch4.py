"""룰 학습 4차(OS, 2026-10-15) — 마스터 지시 "남은 일 순차 적용". GPT 13차 벤더 문서 대조 반영.

- Windows 파서: 본문은 서버 언어(한글판이면 한글)를 따른다 → 문구 맨 앞에 '[이벤트ID] 제공자: 본문'. 룰은 ID·제공자로 걸어 언어 무관
  · 맨 앞인 까닭: 현장에서 학습한 룰은 '제공자: 본문' 을 이어 붙인 정규식 — 가운데에 끼우면 깨진다(아래 시험으로 고정)
  · '^제공자:' 로 고정된 기존 룰(OS-WIN-SEC-001)은 옛 형식·새 형식 모두
- 새 룰: Windows 37(펌웨어 CPU 제한)·ESENT 507/508/509/510/532/533(DB 디스크 지연)·Ntfs 140, HP-UX kthread 고갈, Solaris Cluster 스레드 2
- AIX DELAYED_INTS(A2205861)는 errpt IDENTIFIER 가 코드라 사전 항목
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
HEAD = '"TimeCreated","LevelDisplayName","ProviderName","Id","Message"\n'


def _csv(rows):
    q = lambda v: '"' + v.replace('"', '""') + '"'
    return HEAD + "".join(",".join([q("2026-10-12 09:00:%02d" % i), q(lv), q(pr), q(eid), q(msg)]) + "\n" for i, (eid, pr, lv, msg) in enumerate(rows, 1))


def analyze(product, text, name="x.log"):
    f = Path(tempfile.mkdtemp()) / name
    f.write_text(text, encoding="utf-8")
    r = run_analysis([{"path": str(f), "product": product, "host": "h1"}], None, **KW)
    return r


class Batch4(unittest.TestCase):
    def test_previous_rules_are_kept(self):
        ids = {r.id for r in load_rules(ENGINE / "rules", ENGINE / "rules-local")}
        self.assertGreaterEqual(len(ids), 423)
        for keep in ("OS-WIN-001", "OS-WIN-SEC-001", "OS-WIN-SEC-002", "OS-UNX-001", "OS-AIX-ERRPT-001", "WEB-NGX-011", "DB-MSS-001"):
            self.assertIn(keep, ids)
        self.assertNotIn("OS-HPUX-002", ids)                               # HPVM 명령 출력 — 넣지 않음

    def test_windows_rules_by_id_any_language(self):
        rows = [("37", "Microsoft-Windows-Kernel-Processor-Power", "경고", "그룹 0에 있는 프로세서 4의 속도가 시스템 펌웨어에 의해 제한되고 있습니다."),
                ("37", "Microsoft-Windows-Kernel-Processor-Power", "Warning", "The speed of processor 4 in group 0 is being limited by system firmware."),
                ("37", "Microsoft-Windows-Time-Service", "정보", "시간 공급자 NtpClient가 유효한 시간 데이터를 받고 있습니다."),       # 같은 번호 다른 제공자 — 안 걸림
                ("508", "ESENT", "경고", "svchost (2244,D,12) SUSDB: 파일 쓰기 요청이 성공했지만 OS 처리에 비정상적으로 오래(24초) 걸렸습니다."),
                ("102", "ESENT", "정보", "데이터베이스 엔진이 새 인스턴스를 시작했습니다."),                                                       # 같은 제공자 다른 번호 — 안 걸림
                ("140", "Microsoft-Windows-Ntfs", "경고", "시스템이 트랜잭션 로그에 데이터를 플러시하지 못했습니다. VolumeId: E:에서 손상이 발생할 수 있습니다.")]
        r = analyze("windows", _csv(rows), "sys.csv")
        got = [t["rule_id"] for t in r["timeline"]]
        self.assertEqual(got.count("OS-WIN-005"), 2)
        self.assertEqual(got.count("OS-WIN-006"), 1)
        self.assertEqual(got.count("OS-WIN-007"), 1)
        msgs = [t["message"] for t in r["timeline"]]
        self.assertTrue(all(m.startswith("[") for m in msgs))               # '[ID] 제공자: 본문'

    def test_security_rule_accepts_both_formats(self):
        rows = [("4625", "Microsoft-Windows-Security-Auditing", "정보", "계정이 로그온하지 못했습니다.")]
        got = [t["rule_id"] for t in analyze("windows", _csv(rows), "sec.csv")["timeline"]]
        self.assertEqual(got, ["OS-WIN-SEC-001"])
        rx = next(r for r in load_rules(ENGINE / "rules", ENGINE / "rules-local") if r.id == "OS-WIN-SEC-001").pattern
        self.assertTrue(rx.search("Microsoft-Windows-Security-Auditing: 계정이 로그온하지 못했습니다."))   # 옛 판 형식도(되돌려도 같은 판정)

    def test_field_learned_rule_still_matches_new_format(self):
        """현장에서 옛 형식('제공자: 본문')으로 학습한 룰이 새 형식('[ID] 제공자: 본문')에서도 걸려야 한다 — 학습 지식 유지."""
        from logtriage import learn
        old = "Service Control Manager: OrderSync 서비스가 예기치 않게 종료되었습니다. 이 동작이 1번 발생했습니다."
        import re
        rx = re.compile(learn.regex_of(learn.template(old)), re.I)
        self.assertTrue(rx.search(old))
        self.assertTrue(rx.search("[7031] " + old))

    def test_unix_rules_and_aix_dictionary(self):
        hp = analyze("hpux", "Oct 12 09:00:01 hpux1 vmunix: kthread: table is full\nOct 12 09:00:02 hpux1 vmunix: file: table is full\n")
        self.assertIn("OS-HPUX-001", [t["rule_id"] for t in hp["timeline"]])
        so = analyze("solaris", "Oct 12 09:00:01 node1 Cluster.Event: [ID 594396 daemon.error] Thread creation failed for node 2.\n"
                                "Oct 12 09:00:02 node1 Cluster.Framework: [ID 414431 kern.warning] Unable to create server thread for immediate failfast of zone appzone with zone ID 3\n")
        self.assertEqual([t["rule_id"] for t in so["timeline"]], ["OS-SOL-001", "OS-SOL-002"])
        errpt = ("---------------------------------------------------------------------------\n"
                 "LABEL:          DELAYED_INTS\nIDENTIFIER:     A2205861\n\n"
                 "Date/Time:       Mon Oct 12 09:00:01 2026\nSequence Number: 101\nClass:           S\nType:            PERF\n"
                 "Resource Name:   SYSPROC\n\nDescription\nEXCESSIVE INTERRUPT DISABLEMENT TIME\n"
                 "---------------------------------------------------------------------------\n")
        ax = analyze("aix-errpt", errpt, "errpt.txt")
        self.assertEqual([(t["rule_id"], t["source"]) for t in ax["timeline"]], [("A2205861", "벤더 에러코드")])


if __name__ == "__main__":
    unittest.main()
