"""배포 폴더 지식 정합성 검사(GPT UI 20차 권고, 2026-10-15) — 10-14 설치에서 1차 학습 룰 26개가 배포 폴더에 빠졌던 일의 재발 방지.

복사 전: 배포 폴더에만 있는 룰·별칭·파일이 있으면 멈춘다(덮으면 사라짐), 일부러 뺀 것은 은퇴 목록으로만 통과.
복사 후: 파일 SHA-256 이 모두 같아야 통과, 매니페스트를 남긴다. build_exe.bat 가 앞뒤로 부른다.
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE / "tools" / "build"))
import check_dist_knowledge as ck  # noqa: E402


class DistKnowledge(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp()); self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))
        for d in ("rules", "errorcodes", "manuals"):   # 10-16 아이디어 10: 매뉴얼도 해시로 묶는다
            shutil.copytree(ENGINE / d, self.td / d, ignore=shutil.ignore_patterns("__pycache__"))

    def test_same_passes_and_writes_manifest(self):
        self.assertEqual(ck.check(ENGINE, self.td, "before"), [])
        self.assertEqual(ck.main(["--after", "--dist", str(self.td)]), 0)
        self.assertTrue((self.td / ck.MANIFEST).exists())

    def test_dist_only_rule_stops(self):
        (self.td / "rules" / "zz.yaml").write_text('rules:\n- id: DIST-ONLY-1\n  layer: was\n  product: [tomcat]\n  match: {regex: "zzqq"}\n  verdict: x\n', encoding="utf-8")
        self.assertEqual(ck.main(["--before", "--dist", str(self.td)]), 1)

    def test_missing_engine_rule_in_dist_stops_after_copy(self):
        (self.td / "rules" / "db" / "mssql.yaml").unlink()                   # 10-14 같은 누락(복사 빠뜨림)
        self.assertEqual(ck.check(ENGINE, self.td, "before"), [])          # 복사 전에는 엔진이 더 많아도 정상
        self.assertTrue(ck.check(ENGINE, self.td, "after"))                # 복사 뒤에 남아 있으면 멈춤

    def test_retired_alias_is_the_only_exception(self):
        self.assertIn("alias|tomcat|TOMCAT-STUCK-THREAD|StuckThreadDetectionValve|has been active for", ck.retired())
        if not (ENGINE / "deploy" / "local" / "build_exe.bat").is_file():
            return                                                           # 리눅스 묶음 — PC 빌드 파일은 없다(위 은퇴 목록 확인까지만)
        bat = (ENGINE / "deploy" / "local" / "build_exe.bat").read_text(encoding="ascii")   # cmd.exe 가 OEM 코드 페이지로 읽는다 — ASCII 만
        # 12차: 빌드는 build_pc.py(빌드 폴더에만), 배포 폴더 지식 동기화는 knowledge_release.py — 둘 다 검사 앞뒤를 지킨다
        self.assertIn("build_pc.py", bat)
        bp = (ENGINE / "tools" / "build" / "build_pc.py").read_text(encoding="utf-8")
        self.assertIn('"check_dist_knowledge.py"), "--after"', bp)
        self.assertLess(bp.index("--clone-data"), bp.index("shutil.copytree(ENGINE / d, rd / d"))      # 복제 뒤에 엔진 지식을 다시 넣는다
        kr = (ENGINE / "tools" / "build" / "knowledge_release.py").read_text(encoding="utf-8")
        self.assertLess(kr.index('step_dist(dist, "before")'), kr.index("copy_knowledge(dist)"))
        self.assertIn('"after"', kr[kr.index("copy_knowledge(dist)"):])


if __name__ == "__main__":
    unittest.main()
