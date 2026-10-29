"""빌드 지문 장부(아이디어 11)·렌더링 관문 결과 읽기 — 배포 폴더 대신 임시 폴더로."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE / "tools" / "build"))
import build_ledger as bl  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent)); import _privtmp  # noqa: E402,E702


class Ledger(unittest.TestCase):
    def setUp(self):
        self.td = Path(_privtmp.mkdtemp())   # 등록 파일 권한 검사(GPT 38차) — 개인 폴더
        self.addCleanup(__import__("shutil").rmtree, self.td, True)
        dist = self.td / "dist"
        dist.mkdir()
        (dist / "LogTriage.exe").write_bytes(b"gui")
        (dist / "logtriage-cli.exe").write_bytes(b"cli")
        (dist / "LogTriage.exe.이전판").write_bytes(b"old")
        (self.td / "build").mkdir()
        self.p = [mock.patch.object(bl, "DIST", dist), mock.patch.object(bl, "LOCAL", self.td),
                  mock.patch.object(bl, "MD", self.td / "장부.md"), mock.patch.object(bl, "JL", self.td / "build" / "ledger.jsonl")]
        import rollback_compat as rbc
        self.p.append(mock.patch.object(rbc, "SRC", self.td / "src"))   # 시험이 실제 스냅숏 폴더에 쓰지 않게
        # 가짜 exe 는 PE 가 아니라 서명 읽기가 UnknownError — 평소 시험은 '서명 없음'으로 둔다(서명 관문 시험은 따로)
        self.p.append(mock.patch.object(bl, "signature", return_value={"status": "NotSigned", "thumbprint": ""}))
        for x in self.p:
            x.start()
            self.addCleanup(x.stop)

    def test_record_then_check(self):
        (self.td / "build" / "render_gate.json").write_text(json.dumps({"result": "skip", "at": "t"}), encoding="utf-8")
        self.assertEqual(bl.main(["record", "--rollback", "통과", "--note", "a|b"]), 0)
        self.assertTrue(list((self.td / "src").glob("src-*.zip")))          # 이 판의 소스 스냅숏(아이디어 12)
        self.assertEqual(bl.main(["record"]), 0)                             # 이전판 스냅숏이 없으면 '미확인(스냅숏 없음)'
        self.assertIn("스냅숏 없음", (self.td / "장부.md").read_text(encoding="utf-8"))
        md = (self.td / "장부.md").read_text(encoding="utf-8")
        self.assertIn("V3 승인", md)
        self.assertIn("(수동)", md)                       # V3 칸은 손으로 — 도구가 채우지 않는다
        self.assertIn("건너뜀", md)
        self.assertIn("서명이 아님", md)
        self.assertIn("a/b", md)                          # 표를 깨는 | 는 바꾼다
        row = json.loads((self.td / "build" / "ledger.jsonl").read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(row["v3"], "")
        self.assertEqual(len(row["gui"]), 64)
        self.assertEqual(bl.main(["check"]), 0)
        (bl.DIST / "LogTriage.exe").write_bytes(b"gui2")   # 장부에 없는 판
        self.assertEqual(bl.main(["check"]), 1)

    def test_broken_signature_fails_build(self):
        """3차 아이디어 10: 서명이 깨졌거나 신뢰 안 되면 장부엔 남기되 실패(1). 서명 없음은 지금처럼 통과."""
        with mock.patch.object(bl, "signature", return_value={"status": "HashMismatch", "thumbprint": ""}):
            self.assertEqual(bl.main(["record", "--rollback", "통과"]), 1)
        self.assertIn("서명 깨짐", (self.td / "장부.md").read_text(encoding="utf-8"))
        with mock.patch.object(bl, "signature", return_value={"status": "NotSigned", "thumbprint": ""}):
            self.assertEqual(bl.main(["record", "--rollback", "통과"]), 0)
        # GPT 37차: '유효'라도 등록하지 않은 발행자면 실패, 등록한 지문이면 통과
        valid = {"status": "Valid", "thumbprint": "AB" * 20}
        with mock.patch.object(bl, "signature", return_value=valid):
            self.assertEqual(bl.main(["record", "--rollback", "통과"]), 1)
            (self.td / "code_signing.json").write_text(json.dumps({"expected_thumbprints": ["AB" * 20]}), encoding="utf-8")
            with mock.patch.object(bl, "SIGNERS", self.td / "code_signing.json"):
                self.assertEqual(bl.main(["record", "--rollback", "통과"]), 0)
                # GPT 38차: 등록 파일을 넓은 집단이 고칠 수 있으면 등록을 믿지 않는다
                from logtriage import safe_backup
                with mock.patch.object(safe_backup, "_shared_writable", return_value=True):
                    self.assertEqual(bl.expected_signers(), [])
                    self.assertEqual(bl.main(["record", "--rollback", "통과"]), 1)

    def test_v3_request_switches_to_publisher(self):
        import make_v3_request as m
        valid = {"status": "Valid", "thumbprint": "AB" * 20, "subject": "CN=사내"}
        with mock.patch.object(m, "signer", return_value=valid):
            self.assertIn("코드 서명: 없음", m.build_md(bl.DIST))              # 등록 안 된 발행자면 해시 기준 그대로
            (self.td / "code_signing.json").write_text(json.dumps({"expected_thumbprints": ["AB" * 20]}), encoding="utf-8")
            with mock.patch.object(bl, "SIGNERS", self.td / "code_signing.json"):
                md = m.build_md(bl.DIST)
        self.assertIn("발행자(인증서) 기준 예외", md)
        with mock.patch.object(m, "signer", return_value={"status": "NotSigned"}):
            self.assertIn("코드 서명: 없음", m.build_md(bl.DIST))

    def test_no_render_result(self):
        self.assertTrue(bl.render_result().startswith("미실행"))


if __name__ == "__main__":
    unittest.main()
