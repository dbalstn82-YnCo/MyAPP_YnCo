"""룰팩 공개키 서명 전용(2026-10-15 마스터 결정 "틈 닫고 새로운 도장 받기").

- 새 설치(공개키 등록 전)도 옛 HMAC 룰팩을 받지 않는다 — 예전엔 등록 전까지 받던 틈
- 옛 방식 룰팩은 만들지도 않는다(build 에 서명 개인키 필수)
- 명령줄 도구도 Ed25519 만: build 는 개인키·공개키·지문, apply 는 처음 한 번 지문 입력, --key-file 은 거절
- 마스터 지시 "그동안 학습했던 룰팩은 유지": 막히는 것은 옛 룰팩 '반입'뿐 — 이미 있는 룰·학습 룰·사이트 룰은 그대로
"""
import hashlib
import hmac
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import rulepack  # noqa: E402
from logtriage.rules import load_rules  # noqa: E402

RULE = 'rules:\n- id: TEST-ED-1\n  layer: was\n  product: [tomcat]\n  match: {regex: "OutOfMemoryError"}\n  verdict: Memory failure\n'


class Ed25519Only(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))
        self.src = self.td / "src"; self.src.mkdir(); (self.src / "r.yaml").write_text(RULE, encoding="utf-8")
        self.sig = rulepack.load_signing_key(self.td / "sign.pem", create=True)
        self.pub = rulepack.public_bytes(self.sig)
        self.fp = rulepack.fingerprint(self.pub)
        self.closed = self.td / "closed"
        (self.closed / "rules" / "learned").mkdir(parents=True)
        (self.closed / "rules" / "base.yaml").write_text(RULE.replace("TEST-ED-1", "KEEP-BASE"), encoding="utf-8")
        (self.closed / "rules" / "learned" / "learned.yaml").write_text(RULE.replace("TEST-ED-1", "KEEP-LEARNED"), encoding="utf-8")
        (self.closed / "rules-local").mkdir()
        (self.closed / "rules-local" / "site.yaml").write_text(RULE.replace("TEST-ED-1", "KEEP-SITE"), encoding="utf-8")

    def _hmac_pack(self) -> Path:
        good = self.td / "good.rpk"; rulepack.build(self.src, good, None, signer=self.sig)
        old = self.td / "old.rpk"
        with zipfile.ZipFile(good) as zi, zipfile.ZipFile(old, "w") as zo:
            for n in zi.namelist():
                if n != rulepack.SIG_ED:
                    zo.writestr(n, zi.read(n))
        with zipfile.ZipFile(old, "a") as zo:
            zo.writestr(rulepack.SIG_FILE, hmac.new(b"k" * 32, rulepack._digest(zo).encode(), hashlib.sha256).hexdigest())
        return old

    def _ids(self):
        return sorted(r.id for r in load_rules(self.closed / "rules", self.closed / "rules-local"))

    def test_fresh_install_refuses_hmac_pack(self):
        """예전 틈: 공개키 등록 전(새 설치)에는 옛 HMAC 룰팩을 받았다 → 이제는 처음부터 거부, 기존 지식은 그대로."""
        before = self._ids()
        self.assertFalse((self.closed / "conf").exists())                     # 등록 전 상태
        with self.assertRaises(ValueError) as cm:
            rulepack.apply(self._hmac_pack(), self.closed / "rules", b"k" * 32)
        self.assertIn("옛 방식(HMAC) 룰팩은 받지 않습니다", str(cm.exception))
        self.assertEqual(self._ids(), before)                                 # 룰·학습 룰·사이트 룰 그대로
        self.assertEqual(before, ["KEEP-BASE", "KEEP-LEARNED", "KEEP-SITE"])
        with self.assertRaises(ValueError):
            rulepack.verify(self._hmac_pack(), b"k" * 32)
        with self.assertRaises(ValueError):                                   # 공개키 대신 옛 배포 키를 줘도
            rulepack.verify(self.td / "good.rpk", b"k" * 32)

    def test_unsigned_or_tampered_pack_is_refused(self):
        """GPT 11차 A-01: 서명 파일을 빼거나 바꾼 Ed25519 룰팩도 거부 — '서명 없음 = 로컬 룰팩' 같은 우회가 없다."""
        good = self.td / "good.rpk"; rulepack.build(self.src, good, None, signer=self.sig)
        def variant(name, edit):
            out = self.td / name
            with zipfile.ZipFile(good) as zi, zipfile.ZipFile(out, "w") as zo:
                for n in zi.namelist():
                    data = edit(n, zi.read(n))
                    if data is not None:
                        zo.writestr(n, data)
            return out
        nosig = variant("nosig.rpk", lambda n, d: None if n == rulepack.SIG_ED else d)
        badsig = variant("badsig.rpk", lambda n, d: (b"00" * 64) if n == rulepack.SIG_ED else d)
        changed = variant("changed.rpk", lambda n, d: d.replace(b"OutOfMemoryError", b"OutOfMemoryErrorX") if n.startswith("rules/") else d)
        before = self._ids()
        for p in (nosig, badsig, changed):
            with self.assertRaises(ValueError):
                rulepack.apply(p, self.closed / "rules", self.pub, confirm_fp=self.fp)
        self.assertEqual(self._ids(), before)

    def test_existing_rules_same_verdict_after_restart_and_refusal(self):
        """GPT 11차 A-02: 기존 적용 룰 → (재시작 = 새로 읽기) → 같은 판정 → 옛 HMAC 반입 거부 → 다시 같은 판정."""
        from logtriage.service import run_analysis
        for d in ("rules", "rules-local", "errorcodes"):
            shutil.rmtree(self.closed / d, ignore_errors=True)
            shutil.copytree(ENGINE / d, self.closed / d)
        S = ENGINE / "samples"
        args = ([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"}], None)
        kw = dict(rules_dir=self.closed / "rules", local_dir=self.closed / "rules-local", codes_dir=self.closed / "errorcodes")
        v1 = run_analysis(*args, **kw)
        with self.assertRaises(ValueError):
            rulepack.apply(self._hmac_pack(), self.closed / "rules", b"k" * 32)
        v2 = run_analysis(*args, **kw)
        pick = lambda r: (r["first"]["rule_id"], r["first"]["verdict"], [t["rule_id"] for t in r["timeline"]])
        self.assertEqual(pick(v1), pick(v2))
        self.assertGreaterEqual(len(load_rules(self.closed / "rules", self.closed / "rules-local")), 400)

    def test_cannot_build_hmac_pack(self):
        with self.assertRaises(ValueError) as cm:
            rulepack.build(self.src, self.td / "x.rpk", b"k" * 32)
        self.assertIn("서명 개인키(Ed25519)가 필요합니다", str(cm.exception))
        self.assertNotIn("import hmac", (ENGINE / "logtriage" / "rulepack.py").read_text(encoding="utf-8"))

    def test_ed25519_pack_still_applies_with_fingerprint(self):
        good = self.td / "good.rpk"; rulepack.build(self.src, good, None, signer=self.sig)
        with self.assertRaises(rulepack.TrustNeeded):
            rulepack.apply(good, self.closed / "rules", self.pub)            # 처음엔 지문 필요
        m = rulepack.apply(good, self.closed / "rules", self.pub, confirm_fp=self.fp)
        self.assertEqual(m["_signature"], "ed25519")
        self.assertIn("KEEP-SITE", self._ids())                               # 사이트 룰(rules-local)은 룰팩과 무관하게 유지

    def test_cli_is_ed25519_only(self):
        cli = [sys.executable, str(ENGINE / "tools" / "rulepack_cli.py")]
        run = lambda *a: subprocess.run(cli + list(a), capture_output=True, text=True, encoding="utf-8", errors="replace")
        r = run("build", "--key-file", str(self.td / "dist.key"), "--out", str(self.td / "c.rpk"), "--rules", str(self.src))
        self.assertEqual(r.returncode, 2, r.stderr); self.assertIn("--key-file", r.stderr)
        r = run("build", "--sign-key", str(self.td / "cli.pem"), "--out", str(self.td / "c.rpk"), "--rules", str(self.src),
                "--codes", str(self.td / "none"), "--manuals", str(self.td / "none"), "--version", "2026.10.15")
        self.assertEqual(r.returncode, 0, r.stderr)
        pub = self.td / "rulepack-signing.pub"; self.assertTrue(pub.exists())
        fp = rulepack.fingerprint(pub.read_bytes()); self.assertIn(fp, r.stdout)
        with zipfile.ZipFile(self.td / "c.rpk") as z:
            self.assertIn(rulepack.SIG_ED, z.namelist()); self.assertNotIn(rulepack.SIG_FILE, z.namelist())
        args = ["--pub", str(pub), "--rules", str(self.closed / "rules"), "--codes", str(self.closed / "errorcodes"),
                "--manuals", str(self.closed / "manuals")]
        self.assertEqual(run("verify", str(self.td / "c.rpk"), *args).returncode, 0)
        self.assertEqual(run("apply", str(self.td / "c.rpk"), *args).returncode, 3)              # 지문 없으면 멈춤
        r = run("apply", str(self.td / "c.rpk"), *args, "--confirm-fp", fp)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("TEST-ED-1", self._ids())


if __name__ == "__main__":
    unittest.main()
