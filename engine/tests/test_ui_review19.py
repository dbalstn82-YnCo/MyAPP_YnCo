"""GPT UI 19차 필수 수정(2026-10-15) — Ctrl+K·근거 ID·손상 기록.

① 서버 화면의 Ctrl+K 가 이력 전체를 내려받지 않는다 — quickfind: 최대 20건, 필요한 칸만, 보는 사람 기준으로 가린 뒤 거른다
② 근거 ID: SHA-256 12자리 + 한 분석 안 중복 막기(같은 입력이면 늘 같은 ID)
③ 근거 링크는 분석 ID 와 함께(?inc=&ev=) — 못 찾으면 알리고 다른 분석으로 넘어가지 않는다
④ 손상 기록: 예외 글 대신 정해진 사유 유형 코드
"""
import json
import re
import sys
import unittest
from datetime import datetime
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import kbaudit, privacy, server  # noqa: E402
from logtriage.gui.app import quickfind_rows  # noqa: E402
from logtriage.service import _evidence_id  # noqa: E402

GUI = ENGINE / "logtriage" / "gui"


def inc(i, owner, host, eids=()):
    return {"id": f"INC-{i:04d}", "name": f"{host} 장애", "owner": owner, "analyzed_at": "2026-10-15 09:00:00",
            "first": {"verdict": "Memory failure", "layer_ko": "WAS", "rule_id": "WAS-TC-001", "severity": "critical", "host": host},
            "files": [{"name": "a.log", "host": host}],
            "timeline": [{"eid": e, "verdict": "OOM", "ts": "09:00:01", "host": host, "message": f"{host} down"} for e in eids]}


class QuickFind(unittest.TestCase):
    def test_limit_and_minimal_fields(self):
        hist = [inc(i, "kim", "was-a") for i in range(60)]
        rows = quickfind_rows(hist, "장애")
        self.assertEqual(len(rows), 20)
        self.assertEqual(set(rows[0]), {"id", "name", "verdict", "severity", "at"})     # timeline·files 같은 본문은 안 나간다
        self.assertEqual(quickfind_rows(hist, "a"), [])                                 # 한 글자는 찾지 않는다

    def test_exact_id_first_and_evidence_carries_incident(self):
        hist = [inc(1, "kim", "was-a", ["E-AAAAAAAAAAAA"]), inc(2, "kim", "was-b", ["E-AAAAAAAAAAAA"]), inc(12, "kim", "was-c")]
        self.assertEqual(quickfind_rows(hist, "INC-0012")[0]["id"], "INC-0012")
        ev = quickfind_rows(hist, "E-AAAAAA")
        self.assertEqual([(r["id"], r["eid"]) for r in ev], [("INC-0001", "E-AAAAAAAAAAAA"), ("INC-0002", "E-AAAAAAAAAAAA")])   # 같은 ID 라도 분석으로 구분

    def test_mask_before_filter(self):
        """남의 분석은 가린 뒤에 거른다 — 가려진 호스트명으로 찾으면 걸리지 않아야(존재가 새지 않게)."""
        hist = [inc(1, "kim", "secret-db01"), inc(2, "lee", "secret-db02")]
        masked = privacy.mask_for_viewer(hist, "kim")
        self.assertEqual([r["id"] for r in quickfind_rows(masked, "secret-db0")], ["INC-0001"])
        self.assertEqual(quickfind_rows(masked, "secret-db02"), [])

    def test_server_wiring(self):
        self.assertIn("quickfind", server.API_NAMES)
        self.assertIn("quickfind", server.READ_APIS)
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn('quickfind_rows(privacy.mask_for_viewer(self.api.history()', src)
        pal = (GUI / "_palette.js").read_text(encoding="utf-8")
        self.assertIn("/api/quickfind", pal)
        self.assertNotIn("/api/history", pal)                       # 서버 화면에서 이력 전체를 받지 않는다
        self.assertIn("if(my!==rseq)return", pal)                   # 늦게 온 옛 응답은 버린다
        self.assertIn("r.status===429", pal)                         # 빈도 상한은 '찾는 것이 없음' 과 다른 말로(GPT 20차)
        self.assertIn("요청이 많습니다", pal)


class EvidenceId(unittest.TestCase):
    def test_sha256_12_and_duplicate_guard(self):
        f = {"raw_ref": "a.log:10", "id": "R1", "_ts": datetime(2026, 10, 15, 9, 0, 1)}
        e = _evidence_id(f)
        self.assertRegex(e, r"^E-[0-9A-F]{12}$")
        used = set()
        a, b, c = _evidence_id(f, used), _evidence_id(f, used), _evidence_id(f, used)   # 일부러 같은 근거 셋
        self.assertEqual(a, e)
        self.assertEqual(len({a, b, c}), 3)
        used2 = set()
        self.assertEqual([a, b, c], [_evidence_id(f, used2) for _ in range(3)])          # 같은 순서면 늘 같은 ID

    def test_ids_do_not_depend_on_input_order(self):
        """GPT 19차 후속 필수 02: 같은 로그를 순서만 바꿔 넣어도(같은 파일을 두 번 넣어 일부러 겹치게 해도) 같은 근거엔 같은 ID."""
        from logtriage.service import run_analysis
        S = ENGINE / "samples"
        kw = dict(rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        a = {"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"}
        b = {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}
        def mapping(inputs):
            r = run_analysis(inputs, None, **kw)
            ids = [t["eid"] for t in r["timeline"]]
            self.assertEqual(len(ids), len(set(ids)))                   # 한 분석 안에서는 겹치지 않는다
            return sorted((t["raw_ref"], t["rule_id"], t["ts"], t["eid"]) for t in r["timeline"])
        self.assertEqual(mapping([a, b]), mapping([b, a]))
        dup1, dup2 = mapping([a, b, a]), mapping([a, a, b])           # 같은 파일 두 번 = 같은 열쇠의 근거가 둘씩 → '|2' 경로
        self.assertEqual(dup1, dup2)
        self.assertGreater(len(dup1), len(mapping([a, b])))

    def test_forced_hash_collision(self):
        """GPT 19차 후속: 충돌을 기다리지 말고 해시를 바꿔 끼워 강제로 — 첫 해시가 전부 같아도 근거마다 다른 ID, 순서를 바꿔도 대응 유지."""
        import hashlib
        from unittest import mock
        from logtriage.service import run_analysis
        real = hashlib.sha256
        class Same:
            def hexdigest(self):
                return "0" * 64
        fake = lambda b=b"": Same() if b.decode("utf-8").count("|") == 2 else real(b)   # '|2' 를 붙이기 전 첫 해시만 모두 같게
        S = ENGINE / "samples"
        kw = dict(rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        a = {"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"}
        b = {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}
        def mapping(inputs):
            r = run_analysis(inputs, None, **kw)
            return sorted((t["raw_ref"], t["rule_id"], t["ts"], t["message"], t["eid"]) for t in r["timeline"])
        with mock.patch.object(hashlib, "sha256", fake):
            m1, m2 = mapping([a, b]), mapping([b, a])
        ids = [x[-1] for x in m1]
        self.assertGreater(len(ids), 3)
        self.assertEqual(len(ids), len(set(ids)))                       # 다른 근거 = 다른 최종 ID
        self.assertEqual(sum(1 for x in ids if x == "E-000000000000"), 1)   # 첫 해시는 한 근거만 갖는다
        self.assertEqual(m1, m2)                                        # 순서를 바꿔도 근거↔ID 대응 그대로

    def test_deep_link_needs_incident_and_no_fallback(self):
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        pal = (GUI / "_palette.js").read_text(encoding="utf-8")
        self.assertIn("function openEvidence(eid,inc)", ui)
        self.assertIn("다른 분석으로 넘어가지 않았습니다", ui)
        self.assertIn("/^E-[0-9A-F]{12}$/i", ui)
        self.assertNotIn("history.find(x=>(x.timeline||[]).some(t=>t.eid===eid))", ui)   # 근거 ID 만으로 아무 분석이나 열던 길
        self.assertIn("'/?inc='+encodeURIComponent(it.inc||'')+'&ev='", pal)


class DamageReason(unittest.TestCase):
    def test_reason_codes(self):
        rc = kbaudit.reason_code
        self.assertEqual(rc("YamlRejected: 파일이 너무 큽니다(1자 > 2)"), "YAML_SIZE")
        self.assertEqual(rc("YamlRejected: 중첩이 64단을 넘습니다"), "YAML_DEPTH")
        self.assertEqual(rc("YamlRejected: 별칭(*)이 100개를 넘습니다"), "YAML_ALIAS")
        self.assertEqual(rc(r"ScannerError: while scanning C:\secret\path"), "YAML_SYNTAX")
        self.assertEqual(rc("PatternError: missing ), unterminated subpattern"), "REGEX")
        self.assertEqual(rc("error: bad escape"), "REGEX")
        self.assertEqual(rc("UnicodeDecodeError: 'utf-8' codec"), "ENCODING")
        self.assertEqual(rc(r"PermissionError: [Errno 13] C:\x"), "FILE_READ")
        self.assertEqual(rc("ValueError: rule id missing"), "SCHEMA")
        self.assertEqual(rc("Weird: x"), "OTHER")
        self.assertTrue(all(k in kbaudit.REASON_KO for k in ("YAML_SIZE", "YAML_DEPTH", "YAML_ALIAS", "YAML_SYNTAX", "REGEX", "SCHEMA", "ENCODING", "FILE_READ", "OTHER")))

    def test_log_has_no_exception_text(self):
        import shutil, tempfile
        td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        new = kbaudit.sync(td, [{"file": "rules/x.yaml", "why": r"ScannerError: C:\Users\secret\x.yaml line 3"}])
        self.assertEqual(new[0]["code"], "YAML_SYNTAX")
        txt = (td / "data" / "kb_damage.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("secret", txt); self.assertNotIn("ScannerError", txt)
        self.assertEqual(kbaudit.recent(td, 5)[0]["why"], "YAML 문법 오류")
        ui = (GUI / "ui.html").read_text(encoding="utf-8")
        self.assertIn("최근 1,000건 상태 변경 기록", ui)


if __name__ == "__main__":
    unittest.main()
