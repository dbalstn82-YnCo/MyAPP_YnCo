"""되돌리기 호환 시험 도구(아이디어 12) — 지금 소스를 스냅숏으로 떠서 돌리면 통과, 바깥 경로가 든 스냅숏은 거부,
옛 코드가 아닌 코드를 읽으면 실패로 잡는다."""
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE / "tools" / "build"))
import rollback_compat as rbc  # noqa: E402


class RollbackCompat(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)

    def test_current_source_passes(self):
        exe = self.td / "fake.exe"
        exe.write_bytes(b"x")
        with mock.patch.object(rbc, "SRC", self.td / "src"):
            snap = rbc.snapshot(exe)
            self.assertTrue(snap.name.startswith("src-") and snap.is_file())
            self.assertEqual(rbc.snapshot(exe), snap)                     # 이미 있으면 그대로
        res = rbc.run(snap)
        self.assertEqual(res["result"], "pass", res)
        self.assertTrue(res["steps"]["code"]["ok"])                       # 스냅숏의 코드를 실제로 읽었다
        self.assertEqual(set(res["steps"]), {"fence", "code", "report", "rules", "quarantine", "fence_check"})
        self.assertTrue(res["steps"]["fence"]["ok"])                      # 밖 읽기·쓰기·지우기·프로세스·네트워크가 실제로 막혔다(GPT 34차)
        self.assertTrue(res["steps"]["fence_check"]["ok"])                # 부모가 바깥 파일을 다시 봐도 그대로

    def test_hostile_snapshot_refused(self):
        z = self.td / "bad.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("../evil.py", "print(1)")
        res = rbc.run(z)                                                   # 지문 파일이 없으면 풀지도 않는다
        self.assertFalse(res["steps"]["integrity"]["ok"])
        z.with_suffix(".zip.sha256").write_text(rbc._sha(z), encoding="utf-8")
        res = rbc.run(z)
        self.assertEqual(res["result"], "fail")
        self.assertIn("허용되지 않는 경로", res["steps"]["setup"]["error"])
        self.assertFalse((self.td.parent / "evil.py").exists())

    def test_malicious_old_code_cannot_touch_outside(self):
        """스냅숏의 코드가 (지문까지 맞춰) 바깥 파일을 쓰려 해도 울타리가 막는다 — 시험은 실패로 끝나고 바깥 파일은 생기지 않는다."""
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, outside, True)
        target = outside / "pwned.txt"
        exe = self.td / "fake2.exe"
        exe.write_bytes(b"z")
        with mock.patch.object(rbc, "SRC", self.td / "src2"):
            snap = rbc.snapshot(exe)
        evil = self.td / "evil.zip"
        with zipfile.ZipFile(snap) as zi, zipfile.ZipFile(evil, "w") as zo:
            for n in zi.namelist():
                b = zi.read(n)
                if n == "logtriage/__init__.py":
                    b += f"\ntry:\n    open({str(target)!r}, 'w').write('x')\nexcept PermissionError:\n    pass\n".encode()
                zo.writestr(n, b)
        evil.with_suffix(".zip.sha256").write_text(rbc._sha(evil), encoding="utf-8")
        res = rbc.run(evil)
        self.assertFalse(target.exists(), "울타리 밖에 파일이 생겼습니다")
        self.assertTrue(res["steps"]["fence_check"]["ok"])

    def test_tampered_snapshot_is_not_run(self):
        exe = self.td / "fake.exe"
        exe.write_bytes(b"y")
        with mock.patch.object(rbc, "SRC", self.td / "src"):
            snap = rbc.snapshot(exe)
        with zipfile.ZipFile(snap, "a") as zf:                             # 만든 뒤 누가 코드를 끼워 넣음
            zf.writestr("logtriage/zz_added.py", "x = 1")
        res = rbc.run(snap)
        self.assertEqual(res["result"], "fail")
        self.assertIn("지문 불일치", res["steps"]["integrity"]["error"])


if __name__ == "__main__":
    unittest.main()
