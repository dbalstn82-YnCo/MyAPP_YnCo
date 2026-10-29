"""룰 학습(2026-10-13, 마스터 결정 '로컬 학습 + 화면 검토').

모으기(룰·코드에 안 걸린 오류만, 값·개인정보 제거) → 후보 초안 → 기계 검증 → 승인한 것만 학습 룰(rules-learned/)
→ 다음 분석에서 판정 → 서명 룰팩(rules/learned/)으로 묶어 폐쇄망에서 적용까지 이어지는지 본다.
"""
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import learn, rulepack  # noqa: E402
from logtriage.rules import load_rules  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

UNKNOWN = "Batch settlement aborted: ledger snapshot {n} rejected by reconciler for account group {g}"
LOG = """12-Oct-2026 09:00:01.100 INFO [main] org.apache.catalina.startup.Catalina.start Server startup in [5432] milliseconds
12-Oct-2026 09:01:02.200 SEVERE [exec-1] com.acme.Batch.run {u1}
12-Oct-2026 09:01:03.300 SEVERE [exec-2] com.acme.Batch.run {u2}
12-Oct-2026 09:01:04.400 SEVERE [exec-3] com.acme.Batch.run {u3}
12-Oct-2026 09:02:00.000 SEVERE [main] org.apache.catalina.core.StandardContext.startInternal Context [/app] startup failed due to previous errors
"""



def _hmac_pack(src: Path, out: Path) -> Path:
    """옛 방식(HMAC) 룰팩 모양을 흉내 낸다 — 같은 내용에 서명 파일만 signature.sig(HMAC)."""
    import hashlib, hmac as _hmac
    with zipfile.ZipFile(src) as zi, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for n in zi.namelist():
            if n != "signature.ed25519":
                zo.writestr(n, zi.read(n))
    with zipfile.ZipFile(out, "a") as zo:
        zo.writestr("signature.sig", _hmac.new(b"k" * 32, rulepack._digest(zo).encode(), hashlib.sha256).hexdigest())
    return out

class Learn(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        for d in ("rules", "errorcodes", "manuals"):
            shutil.copytree(ENGINE / d, self.base / d)
        (self.base / "rules-local").mkdir()
        self.log = self.base / "catalina.out"
        self.log.write_text(LOG.format(u1=UNKNOWN.format(n=111, g=7), u2=UNKNOWN.format(n=2222, g=8),
                                       u3=UNKNOWN.format(n=33, g=900101)) + "12-Oct-2026 09:03:00.000 SEVERE [exec-4] com.acme.Owner owner check failed for 900101-1234567\n",
                            encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def _run(self):
        return run_analysis([{"path": str(self.log), "product": "tomcat", "host": "h1"}], None,
                            rules_dir=self.base / "rules", local_dir=self.base / "rules-local", codes_dir=self.base / "errorcodes")

    def test_template_masks_values_and_pii(self):
        t1 = learn.template("conn to 10.1.2.3:1521 failed after 30s at /opt/app/x.log user 'kim' id 0x1F2E")
        self.assertNotIn("10.1.2.3", t1)
        self.assertNotIn("kim", t1)
        self.assertNotIn("/opt/app", t1)
        self.assertIn("<IP>", t1)
        self.assertEqual(learn.template(UNKNOWN.format(n=1, g=2)), learn.template(UNKNOWN.format(n=999, g=12345)))
        self.assertNotIn("1234567", learn.template("owner 900101-1234567 rejected"))      # 주민번호 형태는 남지 않는다
        # 오류 코드는 그대로(코드가 다르면 다른 오류), 계정·호스트·테이블 이름은 값으로 지운다(승인하면 룰팩으로 반출되므로)
        self.assertTrue(learn.template("ORA-00060: deadlock detected").startswith("ORA-00060"))
        self.assertNotEqual(learn.template("ORA-00060: x failed"), learn.template("ORA-04031: x failed"))
        self.assertIn("WFLYCTL0013", learn.template("WFLYCTL0013: Operation failed"))
        for raw, gone in (("Login failed for user dbals. Reason: bad", "dbals"), ("user=kim01 denied", "kim01"),
                          ("connect to host web-prd-02 port 8080 failed", "web-prd"), ("connect to host dbserver failed", "dbserver"),
                          ("table EMP_SALARY lock wait timeout", "EMP_SALARY")):
            self.assertNotIn(gone, learn.template(raw), raw)
        self.assertIn("Login failed", learn.template("Login failed for user dbals"))     # 낱말은 이름으로 오인하지 않는다
        # 실증 ②(누출 퍼징)에서 찾은 것: 비밀값·접속 문자열이 틀에 남았다
        for raw, gone in (("ERROR cannot open password=c#c3aZ#X22 for writing", "c#c3aZ"),
                          ("ERROR login denied jdbc:oracle:thin:@db4:1521/ORCL", "db4"),
                          ("ERROR login denied jdbc:oracle:thin:@db4:1521/ORCL", "ORCL"),
                          ("WARN auth Bearer 8E3fbc09c19F3Acfb8de33178C9fEd0B rejected", "8E3fbc09"),
                          ("ERROR call https://intra.corp.local/v1/x?id=7 failed", "intra")):
            self.assertNotIn(gone, learn.template(raw), raw)
        self.assertTrue(learn.export_check({"regex": r"open\s+password=c\#c3aZ\#X22", "verdict": "x"}))   # 이스케이프된 비밀값도 반출 검사에 걸린다
        for raw in ("ERROR auth password\\x3dMockPass123 failed", "ERROR auth password\\u003dMockPass123 failed", "ERROR call token%3DMockToken123 rejected"):
            self.assertNotIn("Mock", learn.template(raw), raw)               # GPT 8차 필수 5: 인코딩된 '=' 뒤 비밀값
        st = learn.LearnStore(self.base)
        st.dir.mkdir(parents=True, exist_ok=True)
        st.path.write_text("{망가진", encoding="utf-8")
        self.assertEqual(st.items(), [])
        self.assertTrue(list(st.dir.glob("candidates.json.broken-*")))     # 망가진 파일은 보관

    def test_collects_only_unjudged_errors(self):
        r = self._run()
        tpls = [x["template"] for x in r["learn"]]
        hit = [x for x in r["learn"] if "ledger snapshot" in x["template"]]
        self.assertEqual(len(hit), 1, tpls)                       # 같은 종류 3건 → 틀 하나
        self.assertEqual(hit[0]["count"], 3)
        self.assertFalse([t for t in tpls if "startup failed" in t])   # 이미 코드·룰로 판정되는 문구는 후보가 아니다
        self.assertFalse([t for t in tpls if "1234567" in t or "900101" in t])

    def test_candidate_to_judgment_to_rulepack(self):
        r = self._run()
        st = learn.LearnStore(self.base)
        st.record(r["learn"], "INC-1")
        st.record(r["learn"], "INC-2")
        item = next(x for x in st.items() if "ledger snapshot" in x["template"])
        self.assertEqual((item["count"], item["hits"]), (6, 2))
        spec = learn.suggest(item)
        chk = learn.check(spec, self.base)
        self.assertTrue(chk["ok"], chk)
        spec["verdict"] = "정산 배치 중단 — 원장 스냅숏 대사 거부"
        out = learn.approve(spec, self.base, who="test")
        self.assertEqual(out.get("id"), spec["id"], out)
        rules = load_rules(self.base / "rules", self.base / "rules-local")
        mine = [x for x in rules if x.id == spec["id"]]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0].source, "learned")
        r2 = self._run()                                          # 다음 분석부터 판정에 쓰인다
        self.assertIn(spec["id"], [t.get("rule_id") for t in r2["timeline"]] + [c.get("rule_id") for c in r2["checklist"]])
        self.assertFalse([x for x in r2["learn"] if "ledger snapshot" in x["template"]])   # 더는 후보로 모이지 않는다
        self.assertEqual(st.get(item["key"])["status"], "approved")
        # 룰팩: rules/learned/ 로 들어가고, 폐쇄망(새 폴더)에 적용하면 같은 룰이 읽힌다
        signer = rulepack.load_signing_key(self.base / "conf" / "rulepack_signing.pem", create=True)
        pk = learn.build_pack(self.base, signer, self.base / "reports")
        self.assertEqual(pk["learned"], 1)
        pub = (self.base / "reports" / pk["pub_file"]).read_bytes()
        self.assertIn(b"BEGIN PUBLIC KEY", pub)
        self.assertNotIn(b"PRIVATE", pub)
        with zipfile.ZipFile(pk["file"]) as z:
            self.assertIn("rules/learned/learned.yaml", z.namelist())
            self.assertIn("signature.ed25519", z.namelist())
            self.assertNotIn("signature.sig", z.namelist())
        closed = Path(self.td.name) / "closed"
        (closed / "rules").mkdir(parents=True)
        (closed / "rules" / "x.yaml").write_text("rules: []\n", encoding="utf-8")
        # 처음 보는 서명 키: 인터넷망 화면의 지문을 입력하지 않으면(또는 틀리면) 아무것도 바꾸지 않는다
        for fp in (None, "0000-0000-0000-0000"):
            with self.assertRaises(rulepack.TrustNeeded):
                rulepack.apply(Path(pk["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals", confirm_fp=fp)
            self.assertFalse((closed / "conf" / "rulepack_trust.pub").exists())
            self.assertEqual([p.name for p in (closed / "rules").iterdir()], ["x.yaml"])
        m = rulepack.apply(Path(pk["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals",
                           confirm_fp=pk["signer_fp"].lower().replace("-", " "))      # 대소문자·구분자는 무관
        self.assertTrue(m["_trust_new"])
        self.assertEqual(m["_signer_fp"], pk["signer_fp"])
        self.assertTrue((closed / "conf" / "rulepack_trust.pub").exists())     # 처음 적용 때 공개키 등록
        learned = [x for x in load_rules(closed / "rules") if x.id == spec["id"]]
        self.assertEqual([x.source for x in learned], ["learned"])            # 폐쇄망에서도 학습 룰(공식 룰 아래 순위)
        with self.assertRaises(Exception):
            rulepack.verify(Path(pk["file"]), b"x" * 32)                       # 옛 HMAC 키로는 검증 안 됨
        # 다른 서명 키로 만든 룰팩은 공개키를 같이 가져와도 거부(키 고정)
        other = rulepack.load_signing_key(Path(self.td.name) / "evil.pem", create=True)
        evil = learn.build_pack(self.base, other, Path(self.td.name) / "evil")
        with self.assertRaises(ValueError) as cm:
            rulepack.apply(Path(evil["file"]), closed / "rules", rulepack.public_bytes(other), closed / "errorcodes", closed / "manuals")
        self.assertIn("등록된 서명 키와 다릅니다", str(cm.exception))
        # 옛 HMAC 룰팩은 언제나 거부(2026-10-15 틈 닫기) — 등록 뒤에도, 등록 파일·전환 기록을 지워도
        old = _hmac_pack(Path(pk["file"]), Path(self.td.name) / "old.rpk")
        for _ in range(3):
            with self.assertRaises(ValueError) as cm:
                rulepack.apply(old, closed / "rules", b"k" * 32, closed / "errorcodes", closed / "manuals")
            self.assertIn("옛 방식(HMAC) 룰팩은 받지 않습니다", str(cm.exception))
            for f in (closed / "conf" / "rulepack_trust.pub", closed / "conf" / "rulepack_policy.json"):
                if f.exists():
                    f.unlink(); break
        self.assertEqual(len(pk["signer_fp"].replace("-", "")), 32)          # 지문 128비트
        # 실증 ⑤에서 찾은 것: 정상 서명이라도 옛 판으로 되돌리기는 거부(같은 판 재적용은 허용)
        rulepack.apply(Path(pk["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals",
                       confirm_fp=pk["signer_fp"])                                # 위에서 등록 파일을 지웠으니 지문으로 다시 등록
        older = learn.build_pack(self.base, signer, Path(self.td.name) / "older", version="2026.01.01.0000")
        with self.assertRaises(ValueError) as cm:
            rulepack.apply(Path(older["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals")
        self.assertIn("옛 판", str(cm.exception))
        # GPT 8차 필수 3: 같은 판 번호인데 내용이 다른 룰팩(다른 결과물) — 되돌리기 수단이 되지 않게 거부
        twin = learn.build_pack(self.base, signer, Path(self.td.name) / "twin", version=pk["version"])   # 같은 판, 다른 결과물(만든 시각이 다름)
        with zipfile.ZipFile(twin["file"]) as za, zipfile.ZipFile(pk["file"]) as zb:
            self.assertNotEqual(rulepack._digest(za), rulepack._digest(zb))
        with self.assertRaises(ValueError) as cm:
            rulepack.apply(Path(twin["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals")
        self.assertIn("같은 판", str(cm.exception))
        rulepack.apply(Path(pk["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals")   # 같은 판·같은 내용은 허용
        # 삭제하면 후보로 되돌아간다
        learn.remove_learned(self.base, spec["id"])
        self.assertNotIn(spec["id"], {x.id for x in load_rules(self.base / "rules", self.base / "rules-local")})
        self.assertEqual(st.get(item["key"])["status"], "new")

    def test_check_refuses_bad_rules(self):
        base = {"id": "LRN-T-1", "layer": "was", "product": "tomcat", "severity": "error", "verdict": "x", "category": "internal"}
        self.assertFalse(learn.check(dict(base, regex="(unclosed"), self.base)["ok"])
        self.assertFalse(learn.check(dict(base, regex=".*"), self.base)["ok"])              # 아무 문장에나 걸림
        self.assertFalse(learn.check(dict(base, regex="(a+)+$x"), self.base)["ok"])         # 반복 안의 반복(끝나지 않을 수 있음)
        self.assertFalse(learn.check(dict(base, regex=r"ledger (\w*\s?)*x"), self.base)["ok"])
        self.assertTrue(learn.nested_repeat("(?:a|b+)+"))
        self.assertFalse(learn.nested_repeat(learn.regex_of(learn.template(UNKNOWN.format(n=1, g=2)))))   # 자동 초안은 해당 없음
        self.assertFalse(learn.check(dict(base, regex="ledger snapshot", verdict=""), self.base)["ok"])
        self.assertFalse(learn.check(dict(base, regex="ledger snapshot", id="WAS-TC-015"), self.base)["ok"])   # ID 충돌

    def test_server_permissions(self):
        from logtriage import server
        for n in ("learn_list", "learn_suggest", "learn_check", "learn_rules",
                  "learn_approve", "learn_dismiss", "learn_restore", "learn_remove_rule", "learn_build_pack"):
            self.assertIn(n, server.ADMIN_APIS)                 # 후보 틀·임의 정규식 검증까지 관리자만(GPT P1-03)
            self.assertIn(n, server.API_NAMES)
            self.assertNotIn(n, server.READ_APIS)

    def test_unsafe_and_leaking_rules_refused(self):
        base = {"id": "LRN-T-2", "layer": "was", "product": "tomcat", "severity": "error", "verdict": "x", "category": "internal"}
        for rx in (r"(a|aa)+x", r"(?=ledger)ledger snapshot", r"(ledger)\s+\1", r"ledger(?:\s+\w+)*x",
                   r"Critical failure|a+a+a+a+a+Z", r"ledger .*snapshot .*rejected", r"ledger\w+_x",   # GPT 2차 반례(인접 반복)
                   r"^" + "a?" * 24 + r"a{24}$", r"^" + "(a|aa)" * 28 + r"$", r"\S+\s+\S+",          # GPT 3차 반례(선택 연속·대안 연속·시작 고정 글자 없음)
                   r"ERROR (a?){24}a{24}Z", r"ERROR (a|aa){24}Z", r"ERROR (ab){24}Z",                   # GPT 4차 반례(고정 횟수 반복)
                   "ERROR \\w+Ж\\w+Ж\\w+Ж\\w+ЖZ", "ERROR \\w+ΩZ", "ERROR \\d+٣Z",            # 유니코드 글자 겹침(키릴·그리스·아랍 숫자)
                   "ERROR \\w+[\u0A81-\u0ABC]\\w+[\u0A81-\u0ABC]Z", "ERROR [a-z]+\u212aZ",   # GPT 5차: 범위 안쪽 겹침(구자라트), 켈빈 기호(대소문자 무시)
                   "ERROR (?i:[i]+\u0130[i]+\u0130Z)", "ERROR [s]+\u017fZ",                   # GPT 6차: sre 대소문자 특례(İ↔i, ſ↔s)
                   "ERROR \\w+[^\U00040000-\U00071000]\\w+[^\U00040000-\U00071000]Z"):     # GPT 6차: 큰 범위의 부정(여집합이 빈 집합으로 줄면 안 됨)
            self.assertFalse(learn.check(dict(base, regex=rx), self.base)["ok"], rx)
        out = learn.approve(dict(base, regex=r"ledger snapshot rejected from 10\.0\.0\.5"), self.base)
        self.assertIn("반출하면 안 되는 값", out.get("error", ""))
        out = learn.approve(dict(base, regex=r"ledger snapshot rejected", verdict="kim@corp.com 확인"), self.base)
        self.assertIn("이메일", out.get("error", ""))
        # 계층·분류는 정해진 값만(2026-10-15 XSS 전수 점검 — 코드 조회 화면 제목으로 그려진다)
        out = learn.approve(dict(base, regex=r"ledger snapshot rejected", layer='<img src=x onerror="1">'), self.base)
        self.assertIn("계층", out.get("error", ""))
        out = learn.approve(dict(base, regex=r"ledger snapshot rejected", category="constructor"), self.base)
        self.assertIn("분류", out.get("error", ""))
        # 손으로 고친 learned.yaml 의 위험한 정규식은 읽지 않는다(분석기 멈춤 방지)
        bad = self.base / "rules-learned" / "learned.yaml"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("rules:\n- id: LRN-BAD-1\n  layer: was\n  product: [tomcat]\n  match: {regex: '(a+)+$'}\n  verdict: x\n"
                       "- id: LRN-BAD-2\n  layer: was\n  product: [tomcat]\n  match: {regex: 'Critical failure|a+a+a+a+a+Z'}\n  verdict: x\n"
                       "- id: WAS-TC-015\n  layer: was\n  product: [tomcat]\n  match: {regex: 'ledger snapshot'}\n  verdict: x\n",
                       encoding="utf-8")
        loaded = {x.id: x for x in load_rules(self.base / "rules", self.base / "rules-local")}
        self.assertNotIn("LRN-BAD-1", loaded)
        self.assertNotIn("LRN-BAD-2", loaded)
        self.assertNotEqual(loaded["WAS-TC-015"].source, "learned")       # 같은 ID 의 공식 룰을 학습 룰이 덮지 않는다

    def test_gpt8_attack_inputs(self):
        """GPT 8차가 만든 공격 입력(합성) — R: 느린 정규식은 모두 거부, M: 같은/다른 틀 기대대로, T: 사람·장비·비밀값 조각이 틀에 남지 않음."""
        lines = (ENGINE / "tests" / "learn_attacks_gpt8.txt").read_text(encoding="utf-8").splitlines()
        must_go = ["Han Sol", "Finance", "svc-payroll", "nas-prod", "sql-ledger", "FinCore", "svc_job", "MockOnly", "ora-ledger",
                   "COREPAY", "FakeSigned", "eyJhbG", "SESSIONMock", "MockSession", "ops_admin", "fileserver", "sample.operator",
                   "svc_report", "MockPass9", "db-prod", "sql-prod", "hr_employee", "svc_reader", "DummyTemporary", "svc_backup",
                   "DB-PROD", "svc_etl", "FakePass", "svc_prod", "ledger-qa", "MockPW", "finance-api", "client-north", "user01",
                   "payroll.service", "LAB.INTERNAL", "Synthetic777", "svc-proxy"]
        r = m = t = 0
        for ln in lines:
            if ln.startswith("R;;"):
                r += 1
                self.assertTrue(learn.unsafe_regex(ln[3:]), ln)
            elif ln.startswith("M;;"):
                m += 1
                a, b, want = ln[3:].split(";;")
                self.assertEqual(learn.template(a) == learn.template(b), want.strip() == "same", ln)
            elif ln.startswith("T;;"):
                t += 1
                tpl = learn.template(ln[3:])
                for frag in must_go:
                    self.assertNotIn(frag, tpl, (ln, tpl))
                self.assertEqual(learn.unsafe_regex(learn.regex_of(tpl)), "", tpl)
                self.assertEqual(learn.export_check({"regex": learn.regex_of(tpl), "verdict": "x"}), [], tpl)
        self.assertEqual((r, m, t), (16, 20, 20))

    def test_checker_itself_is_fast_and_cap(self):
        """검사기 자신이 느려지면 안 된다(실증 ⑪: a?×24 에서 2^24 번 돌아 첫 로드 130초) + 학습 룰 개수 상한."""
        import time as _t
        for rx in ("^" + "a?" * 200 + "a{200}$", "ERROR " + "(?:ab|a)?" * 200 + "Z", "ERROR " + "x?" * 300 + "Z"):
            t0 = _t.perf_counter()
            self.assertTrue(learn.unsafe_regex(rx))
            self.assertLess(_t.perf_counter() - t0, 1.0, rx[:30])
        saved = learn.MAX_LEARNED
        learn.MAX_LEARNED = 1
        try:
            base = {"layer": "was", "product": "tomcat", "severity": "error", "category": "internal", "verdict": "상한"}
            self.assertEqual(learn.approve(dict(base, id="LRN-CAP-1", regex=r"ledger\s+cap\s+one"), self.base).get("id"), "LRN-CAP-1")
            self.assertIn("상한", learn.approve(dict(base, id="LRN-CAP-2", regex=r"ledger\s+cap\s+two"), self.base).get("error", ""))
        finally:
            learn.MAX_LEARNED = saved

    def test_self_test_and_fail_closed(self):
        """안전 검사 자기 점검: 지금 파이썬에서는 통과, 틀어지면 학습 룰을 아예 읽지 않는다(닫힌 쪽)."""
        self.assertEqual(learn.self_test(), "")
        spec = {"id": "LRN-SELF-1", "layer": "was", "product": "tomcat", "severity": "error", "category": "internal",
                "verdict": "자기 점검", "regex": r"ledger\s+snapshot\s+rejected"}
        self.assertEqual(learn.approve(spec, self.base).get("id"), spec["id"])
        ids = lambda: {x.id for x in load_rules(self.base / "rules", self.base / "rules-local")}
        self.assertIn("LRN-SELF-1", ids())
        saved = learn._IV_CACHE.get("self")
        learn._IV_CACHE["self"] = "모의 실패"
        try:
            self.assertNotIn("LRN-SELF-1", ids())
        finally:
            learn._IV_CACHE["self"] = saved

    def test_gpt9_findings(self):
        """GPT 9차 가설을 실행해 확인된 결함: (?s) 깃발로 '. 은 줄바꿈 안 먹음' 전제 깨짐(다항 폭발), 극단 반복·깊은 괄호,
        정규식 표기로 반출 검사 비켜 가기, 로더 쪽 상한 없음, 정책 기록 두 곳의 해시 불일치."""
        import json as _json
        import time as _t
        for rx in (r"(?s)ERROR .*\n.*\n.*\n.*\nZ", r"ERROR (?s:.*\n.*\n)Z", r"(?x)ERROR a b c", r"(?m)ERROR $x", r"(?a)ERROR \w+ Z",
                   r"ERROR a{2147483647}Z", r"ERROR x{1001}", "ERROR " + "(" * 290 + "a" + ")" * 290):
            t0 = _t.perf_counter()
            self.assertTrue(learn.unsafe_regex(rx), rx[:40])
            self.assertLess(_t.perf_counter() - t0, 1.0, rx[:40])
        for rx in (r"ERROR (?i:abc)d", r"ERROR (?-i:a)b", r"ERROR x{1000}"):
            self.assertEqual(learn.unsafe_regex(rx), "", rx)
        for rx in (r"ERROR authentication failed user=han[s]ol", r"ERROR p[a]ssword=MockPass987 rejected",
                   r"ERROR pass(?:w)ord=MockPass987 rejected", r"ERROR p(a)ssword=MockPass987 rejected",
                   r"ERROR pas{2}word=MockPass987 rejected", r"ERROR password=MockPass987 rejected",
                   r"ERROR pass(?:X)?word=MockPass987 rejected", r"ERROR 10\.10\.2\x2e3 refused",
                   r"ERROR mail han[.]sol@exam[p]le\.com bounced", "ERROR " + "(?:ab|cd)" * 13 + " x"):   # 갈래 8192 → 검사 못 끝냄 = 거부
            self.assertTrue(learn.export_check({"regex": rx, "verdict": "x"}), rx)
        self.assertEqual(learn.export_check({"regex": r"[Ll]edger\s+snapshot\s+\d+\s+rejected", "verdict": "x"}), [])
        # 로더 쪽 상한 — 손으로 고친 YAML 로 넘쳐도 상한까지만 읽는다
        p = self.base / "rules-learned" / "learned.yaml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("rules:\n" + "".join(f"- id: LRN-CAPL-{i}\n  layer: was\n  product: [tomcat]\n  match: {{regex: 'ledger cap {i}'}}\n  verdict: x\n"
                                          for i in range(3)), encoding="utf-8")
        saved = learn.MAX_LEARNED
        learn.MAX_LEARNED = 2
        try:
            got = [x.id for x in load_rules(self.base / "rules", self.base / "rules-local") if x.id.startswith("LRN-CAPL-")]
        finally:
            learn.MAX_LEARNED = saved
        self.assertEqual(got, ["LRN-CAPL-0", "LRN-CAPL-1"])
        p.unlink()
        # 정책 기록 두 곳의 같은 판 해시가 다르면 어느 하나를 고르지 않고 멈춘다
        spec = {"id": "LRN-POL-1", "layer": "was", "product": "tomcat", "severity": "error", "category": "internal",
                "verdict": "정책", "regex": r"ledger\s+policy\s+check"}
        self.assertEqual(learn.approve(spec, self.base).get("id"), spec["id"])
        signer = rulepack.load_signing_key(self.base / "conf" / "rulepack_signing.pem", create=True)
        pk = learn.build_pack(self.base, signer, self.base / "reports")
        pub = (self.base / "reports" / pk["pub_file"]).read_bytes()
        closed = Path(self.td.name) / "closed9"
        (closed / "rules").mkdir(parents=True)
        args = (Path(pk["file"]), closed / "rules", pub, closed / "errorcodes", closed / "manuals")
        rulepack.apply(*args, confirm_fp=pk["signer_fp"])
        pol2 = closed / ".rpk-transactions" / "policy.json"
        rec = _json.loads(pol2.read_text(encoding="utf-8"))
        pol2.write_text(_json.dumps(dict(rec, last_digest="0" * 64)), encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            rulepack.apply(*args)
        self.assertIn("서로 다릅니다", str(cm.exception))
        pol2.write_text(_json.dumps(rec), encoding="utf-8")
        rulepack.apply(*args)                                   # 기록이 맞으면 같은 판·같은 내용 재적용 허용

    def test_learned_rules_cost_bounded(self):
        """학습 룰 실행 비용 상한(GPT 3차): 시작 고정 글자 + 결정성 + 앞 1,000자 — 악성 줄 2,000개에도 1초 안쪽."""
        import time as _t
        from logtriage.rules import LEARNED_SCAN, match_events
        from logtriage.schema import Event
        from datetime import datetime as _dt
        spec = {"id": "LRN-COST-1", "layer": "was", "product": "tomcat", "severity": "error", "category": "internal",
                "verdict": "비용 시험", "regex": r"ledger\s+snapshot\s+[^\s]+\s+rejected\s+[^\s,]+,\s+code\s+-?\d[\d.,]*"}
        self.assertEqual(learn.approve(spec, self.base).get("id"), spec["id"])
        rules = [r for r in load_rules(self.base / "rules", self.base / "rules-local") if r.id == spec["id"]]
        self.assertEqual(rules[0].scan, LEARNED_SCAN)
        evil = [("ledger " * 600)[:3000], ("ledger snapshot " * 300)[:3000], ("ledger snapshot x rejected " + "a" * 2970)[:3000]]
        evs = [Event(ts=_dt(2026, 10, 12, 9, 0, 0), host="h", layer="was", product="tomcat", severity="error", message=evil[i % 3])
               for i in range(2000)]
        t0 = _t.perf_counter()
        match_events(rules, evs)
        self.assertLess(_t.perf_counter() - t0, 1.0)

    def test_auto_drafts_are_safe_on_sample_lines(self):
        import re as _re
        n = 0
        for f in (ENGINE / "samples").iterdir():
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines()[:200]:
                t = learn.template(line)
                if len(_re.sub(r"<[A-Z]+>|[^A-Za-z가-힣]", "", t)) < 6:
                    continue
                rx = learn.regex_of(t)
                n += 1
                self.assertEqual(learn.unsafe_regex(rx), "", (t, rx))
                self.assertEqual(learn.export_check({"regex": rx, "verdict": "x"}), [], (t, rx))   # 반출 검사 거짓 양성 없음
                self.assertTrue(_re.search(rx, learn.example_of(t), _re.I), (t, rx))
        self.assertGreater(n, 50)

    def test_learned_rule_does_not_override_vendor_code(self):
        # 'startup failed due to previous errors' 는 별칭 → 코드(TOMCAT-CONTEXT-START-FAILED)로 판정되는 문구
        spec = {"id": "LRN-TOMCAT-OVERRIDE", "layer": "was", "product": "tomcat", "severity": "critical", "category": "internal",
                "verdict": "학습 룰이 덮으면 안 됨", "regex": r"startup\s+failed\s+due\s+to\s+previous\s+errors"}
        self.assertEqual(learn.approve(spec, self.base).get("id"), spec["id"])
        r = self._run()
        ids = [t.get("rule_id") for t in r["timeline"]] + [c.get("rule_id") for c in r["checklist"]]
        self.assertNotIn(spec["id"], ids)
        self.assertIn("TOMCAT-CONTEXT-START-FAILED", ids)


if __name__ == "__main__":
    unittest.main()
