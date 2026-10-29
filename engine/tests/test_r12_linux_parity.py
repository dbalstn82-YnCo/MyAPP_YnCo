"""12차 리눅스 동일 판(2026-10-20 마스터: "12차 기능을 리눅스 서버용 ZIP 에도 동일하게 · PC 와 리눅스가 같은 판으로 빌드되어 관리").

① 3.9 호환: RHEL 9 의 install.sh 는 시스템 python3(3.9) — 엔진·도구·시험 모두 3.9 문법·라이브러리(py39_compat 0건)
② 리눅스 메모리: MemAvailable·cgroup(MemoryMax) 한도를 읽어 작업자 수를 줄인다(가짜 /proc·/sys/fs/cgroup)
③ PC exe 판 도장: 얼어붙은 exe 는 원본을 다시 셀 수 없어 빌드 도장의 code 를 쓴다 — 리눅스 묶음 code 와 같은 값
④ 서버형(리눅스·Windows 서버 모드) 30초 체험: 엔진에 함께 온 합성 견본만 허용 경로 — 다른 경로는 여전히 거절
⑤ 리눅스 묶음 구성: samples·사용법·소개서가 실리고, install.sh·패치가 samples 를 복사한다
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(ENGINE / "tools" / "build"))


class Py39(unittest.TestCase):
    def test_engine_tools_tests_are_39(self):
        import py39_compat
        for d in ("logtriage", "tools", "tests"):
            self.assertEqual(py39_compat.check(ENGINE / d), [], d)

    def test_checker_catches(self):
        import py39_compat
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        cases = {"a.py": "from dataclasses import dataclass\n@dataclass(slots=True)\nclass A:\n    x: int = 0\n",
                 "b.py": "def f(x: int | None) -> None:\n    pass\n",
                 "c.py": "match 1:\n    case 1:\n        pass\n",
                 "d.py": "x = isinstance(1, int | str)\n",
                 "e.py": "import tomllib\n",
                 "g.py": "from pathlib import Path\nfor x in Path('.').walk():\n    pass\n",
                 "h.py": "x = int.from_bytes(b'ab')\n",
                 "i.py": "import bisect\nbisect.bisect([1], 1, key=abs)\n",
                 "j.py": "import glob\nglob.glob('*', root_dir='.')\n",
                 "f.py": "a = {'k': 1}\ns = f\"{a['k']}\"\nt = f'{a[\"k\"]}'\nu = f\"{a[\"k\"]}\"\n"}
        for n, src in cases.items():
            (td / n).write_text(src, encoding="utf-8")
        got = py39_compat.check(td)
        for n in cases:
            self.assertTrue(any(f"/{n}:" in g for g in got), (n, got))
        self.assertEqual(len([g for g in got if "/f.py:" in g]), 1, got)      # 같은 따옴표 중첩 한 줄만(3.12 전용)

    def test_schema_imports_without_slots_on_39(self):
        import importlib
        import logtriage.schema as S
        with mock.patch.object(sys, "version_info", (3, 9, 18, "final", 0)):
            m = importlib.reload(S)
            self.assertFalse(hasattr(m.Event, "__slots__") and "ts" in getattr(m.Event, "__slots__", ()))
        importlib.reload(S)


class LinuxMemory(unittest.TestCase):
    def _tree(self, meminfo_kb: int, cgroup_line: str, files: dict):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        proc, cg = td / "proc", td / "cg"
        (proc / "self").mkdir(parents=True)
        (proc / "meminfo").write_text(f"MemTotal: 16000000 kB\nMemFree: 100000 kB\nMemAvailable: {meminfo_kb} kB\n", encoding="ascii")
        (proc / "self" / "cgroup").write_text(cgroup_line + "\n", encoding="ascii")
        for rel, v in files.items():
            p = cg / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(v, encoding="ascii")
        return proc, cg

    def test_memavailable_not_free(self):
        from logtriage.parallel import linux_avail_mb
        proc, cg = self._tree(8 * 1024 * 1024, "0::/user.slice", {})
        self.assertEqual(linux_avail_mb(proc, cg), 8192)                  # MemFree(약 100MB)가 아니라 MemAvailable

    def test_cgroup_v2_memorymax(self):
        from logtriage.parallel import linux_avail_mb
        svc = "system.slice/logtriage-server.service"
        proc, cg = self._tree(8 * 1024 * 1024, f"0::/{svc}", {f"{svc}/memory.max": str(2 << 30), f"{svc}/memory.current": str(1536 << 20)})
        self.assertEqual(linux_avail_mb(proc, cg), 512)                   # 2G − 1.5G = 512MB 가 호스트 8GB 보다 작다
        proc, cg = self._tree(8 * 1024 * 1024, f"0::/{svc}", {f"{svc}/memory.max": "max", f"{svc}/memory.current": "1"})
        self.assertEqual(linux_avail_mb(proc, cg), 8192)                  # 'max' = 제한 없음

    def test_cgroup_parent_slice_limit(self):
        """GPT 93차 P1: 서비스 cgroup 은 'max' 인데 부모 slice 에 1GB 한도 — 부모 여유가 쓰인다."""
        from logtriage.parallel import linux_avail_mb
        svc = "system.slice/logtriage-server.service"
        proc, cg = self._tree(8 * 1024 * 1024, f"0::/{svc}", {f"{svc}/memory.max": "max", f"{svc}/memory.current": str(100 << 20),
                                                              "system.slice/memory.max": str(1 << 30), "system.slice/memory.current": str(700 << 20)})
        self.assertEqual(linux_avail_mb(proc, cg), 324)                   # 1024 − 700
        # 잎과 부모 모두 한도 — 더 작은 여유
        proc, cg = self._tree(8 * 1024 * 1024, f"0::/{svc}", {f"{svc}/memory.max": str(2 << 30), f"{svc}/memory.current": str(100 << 20),
                                                              "system.slice/memory.max": str(4 << 30), "system.slice/memory.current": str(1 << 30)})
        self.assertEqual(linux_avail_mb(proc, cg), 1948)                  # 2048 − 100 (부모 여유 3072 보다 작음)

    def test_cgroup_v1(self):
        from logtriage.parallel import linux_avail_mb
        proc, cg = self._tree(4 * 1024 * 1024, "4:memory:/system.slice/x.service",
                              {"memory/system.slice/x.service/memory.limit_in_bytes": str(1 << 30),
                               "memory/system.slice/x.service/memory.usage_in_bytes": str(256 << 20)})
        self.assertEqual(linux_avail_mb(proc, cg), 768)
        proc, cg = self._tree(4 * 1024 * 1024, "4:memory:/", {"memory/memory.limit_in_bytes": str(9223372036854771712)})
        self.assertEqual(linux_avail_mb(proc, cg), 4096)                  # v1 제한 없음(아주 큰 수)

    def test_concurrent_analyses_share_budget(self):
        """GPT 94차 P1: 동시 분석은 프로세스 전체 작업자 예산을 나눠 쓴다 — 합계가 한도를 넘지 않고, 남은 게 2 미만이면 순차."""
        from logtriage import parallel as P
        with mock.patch.object(P, "workers", lambda: 8):
            a = P._reserve(8)
            b = P._reserve(8)
            c = P._reserve(8)
            try:
                self.assertEqual((a, b, c), (8, 0, 0))
                P._release(a)
                a = 0
                b = P._reserve(5)
                c = P._reserve(8)
                self.assertEqual((b, c), (5, 3))
                self.assertEqual(P._reserve(8), 0)                        # 0 남음 → 순차
            finally:
                for n in (a, b, c):
                    P._release(n)
            self.assertEqual(P._BUSY[0], 0)

    def test_workers_follow_cgroup(self):
        from logtriage import parallel as P
        with mock.patch.dict(os.environ, {"LOGTRIAGE_WORKERS": "16"}), mock.patch.object(P, "avail_mb", lambda: 512):
            self.assertEqual(P.workers(), int(512 * P.MEM_SHARE // P.WORKER_MB))


class PcStamp(unittest.TestCase):
    def test_frozen_uses_stamp(self):
        from logtriage import buildid as B
        old = list(B._CODE)
        B._CODE.clear()
        try:
            with mock.patch.object(sys, "frozen", True, create=True), \
                    mock.patch.object(B, "stamped", lambda pkg_dir=None: {"id": "abc", "code": "0123456789ab", "scope": "pc"}):
                self.assertEqual(B.code(), "0123456789ab")
                self.assertFalse(B.modified())
        finally:
            B._CODE.clear()
            B._CODE.extend(old)

    def test_specs_carry_stamp(self):
        if not (ENGINE / "deploy" / "local" / "logtriage.spec").is_file():
            self.skipTest("PC 빌드 spec 이 없는 곳(리눅스 묶음) — PC 빌드 전용 확인")
        for spec in ("logtriage.spec", "logtriage-cli.spec"):
            self.assertIn("('build/pc_stamp/_build_id.json', 'logtriage')", (ENGINE / "deploy" / "local" / spec).read_text(encoding="utf-8"), spec)
        bat = (ENGINE / "deploy" / "local" / "build_exe.bat").read_text(encoding="utf-8")
        self.assertIn("build_pc.py", bat)
        self.assertNotIn("--distpath deploy\\local\\dist", bat)            # 배포 폴더에 바로 굽지 않는다(V3·이동 설치)

    def test_source_code_id_equals_linux_rule(self):
        """PC 도장은 엔진 원본에서, 리눅스 묶음은 복사본에서 센다 — 복사 규칙(__pycache__·custom 제외)이 같으면 같은 값."""
        from logtriage import buildid as B
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        shutil.copytree(ENGINE / "logtriage", td / "logtriage", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "custom", "report_profile.json"))
        (td / "logtriage" / B.STAMP).write_text("{}", encoding="utf-8")   # 리눅스 묶음에는 도장 파일이 들어간다 — 지문에서 빠져야
        self.assertEqual(B.compute(td / "logtriage"), B.compute(ENGINE / "logtriage"))


class ServerSamples(unittest.TestCase):
    def test_server_mode_quicktry_only_packaged_samples(self):
        from logtriage.server import ServerApi, make_server
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
            shutil.copytree(ENGINE / d, td / d)
        httpd, h = make_server("127.0.0.1", 0, td, None)
        self.addCleanup(httpd.server_close)
        api = h.api
        self.assertIsInstance(api, ServerApi)
        s = api.sample_logs()
        self.assertEqual(sorted(x["name"] for x in s), sorted(ServerApi.SAMPLE_PICK), s)
        root = api._samples_root()
        self.assertTrue(api._allowed(root / "catalina.out"))
        self.assertFalse(api._allowed(root / "SystemOut.log.bak"))       # 정해진 이름만
        self.assertFalse(api._allowed(root / "nginx_error.log"))          # 견본 폴더에 있어도 고른 4종이 아니면 거절
        self.assertFalse(api._allowed(ENGINE / "logtriage" / "server.py"))
        self.assertFalse(api._allowed(Path(tempfile.gettempdir()) / "x.log"))


class ServerSampleTamper(unittest.TestCase):
    def test_tampered_sample_path_rejected_not_reopened(self):
        """GPT 93차 P0(조건부): 견본 규칙으로만 허용된 경로가 지문이 안 맞으면(바꿔치기·다른 파일) 분석하지 않는다."""
        from logtriage.server import ServerApi, make_server
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
            shutil.copytree(ENGINE / d, td / d)
        sd = td / "samples"
        shutil.copytree(ENGINE / "samples", sd)
        httpd, h = make_server("127.0.0.1", 0, td, None)
        self.addCleanup(httpd.server_close)
        with mock.patch.object(ServerApi, "_samples_root", staticmethod(lambda: sd)):
            ok = h.api.analyze({"inputs": [{"path": str(sd / "catalina.out"), "product": "tomcat", "host": "d"}]})
            self.assertTrue(str(ok.get("id", "")).startswith("DEMO-"), ok.get("error"))
            (sd / "catalina.out").write_text("2026-09-02 13:00:00,000 SEVERE [x] 바꿔치기\n", encoding="utf-8")
            bad = h.api.analyze({"inputs": [{"path": str(sd / "catalina.out"), "product": "tomcat", "host": "d"}]})
            self.assertIn("지문", bad.get("error", ""))
            self.assertNotIn("id", bad)


class ImportPathHijack(unittest.TestCase):
    """GPT 95차 P0: 서비스가 새 파일을 만들 수 있는 설치 폴더가 작업 폴더(import 경로 첫 자리)면 가짜 모듈(yaml.py)이 진짜보다 먼저 잡힌다.
    재현(옛 배치) → 막힘(새 배치: root 소유 import 전용 폴더에 logtriage 하나만 두고 그 폴더에서 실행)."""

    def _run(self, cwd: Path) -> str:
        import subprocess
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        r = subprocess.run([sys.executable, "-c", "import yaml, logtriage; print(getattr(yaml, 'PLANTED', 0), logtriage.__name__)"],
                           cwd=str(cwd), capture_output=True, text=True, env=env, timeout=120)
        return r.stdout.strip() + r.stderr.strip()[-200:]

    def test_planted_module_reproduced_then_blocked(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        base = td / "opt-logtriage"                       # 서비스가 쓸 수 있는 설치 폴더
        base.mkdir()
        shutil.copytree(ENGINE / "logtriage", base / "logtriage", ignore=shutil.ignore_patterns("__pycache__"))
        (base / "yaml.py").write_text("PLANTED = 1\n", encoding="utf-8")       # 무해한 시험용 가짜 모듈
        self.assertTrue(self._run(base).startswith("1 logtriage"), self._run(base))   # 옛 배치: 가짜가 잡힘(재현)
        lti = base / "venv" / "lt-import"                 # 새 배치: import 전용 폴더(리눅스에서는 logtriage 링크 하나)
        lti.mkdir(parents=True)
        shutil.copytree(base / "logtriage", lti / "logtriage")
        self.assertTrue(self._run(lti).startswith("0 logtriage"), self._run(lti))     # 진짜 PyYAML

    def test_installers_use_import_dir(self):
        inst = (ENGINE / "deploy" / "server" / "install.sh").read_text(encoding="utf-8")
        unit = (ENGINE / "deploy" / "server" / "logtriage-server.service").read_text(encoding="utf-8")
        b = (ENGINE / "tools" / "build" / "build_linux_pkgs.py").read_text(encoding="utf-8")
        self.assertIn("WorkingDirectory=/opt/logtriage/venv/lt-import", unit)
        self.assertNotIn("WorkingDirectory=/opt/logtriage\n", unit)
        self.assertIn('ln -sfn "$INSTALL_DIR/logtriage" "$INSTALL_DIR/venv/lt-import/logtriage"', inst)
        self.assertGreater(inst.index('chown -R root:root "$INSTALL_DIR/venv"'), inst.index('chown -R "$SVC_USER":"$SVC_USER" "$INSTALL_DIR"'))
        self.assertNotIn('cd "$INSTALL_DIR" && exec', inst)                 # 감싸개도 import 전용 폴더에서
        self.assertEqual(inst.count('cd "$INSTALL_DIR/venv/lt-import" && exec'), 2)
        self.assertIn('WorkingDirectory=$INST/venv/lt-import', b)            # 패치가 옛 설치의 유닛·감싸개·venv 도 옮긴다
        self.assertIn('$SUDO chown -R root:root "$INST/venv"', b)
        # GPT 96차: PYTHON* 환경 변수 무시(-E -s)·UnsetEnvironment·서비스 계정으로 import 경로 점검(설치·패치 둘 다, 실패하면 멈춤)
        self.assertIn("ExecStart=/opt/logtriage/venv/bin/python -E -s -m logtriage.server", unit)
        self.assertIn("UnsetEnvironment=PYTHONPATH PYTHONHOME", unit)
        self.assertEqual(inst.count('/venv/bin/python" -E -s -m logtriage'), 2)
        for src in (inst, b):
            self.assertIn('runuser -u "$SVC_USER" -- ', src)
            self.assertIn("IMPORT_CHECK='import sys, os", src)
        self.assertIn("/venv/bin/python -E -s -m logtriage.server#", b)

    def test_import_check_code_catches_writable(self):
        """설치 때 서비스 계정으로 돌리는 점검 코드 자체 — 쓸 수 있는 import 경로가 있으면 1 로 끝난다(이 PC 에서는 시험 폴더가 쓰기 가능하므로 걸려야 정상)."""
        import re as _re
        import subprocess
        inst = (ENGINE / "deploy" / "server" / "install.sh").read_text(encoding="utf-8")
        code = _re.search(r"IMPORT_CHECK='(.*?)'\n", inst, _re.S).group(1)
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        shutil.copytree(ENGINE / "logtriage", td / "logtriage", ignore=shutil.ignore_patterns("__pycache__"))
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}
        env["PYTHONIOENCODING"] = "utf-8"
        # -E 는 PYTHONIOENCODING 도 무시 — 출력 인코딩은 -X utf8
        r = subprocess.run([sys.executable, "-E", "-s", "-X", "utf8", "-c", code], cwd=str(td), capture_output=True, text=True, encoding="utf-8",
                           env=env, timeout=120)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("서비스가 쓸 수 있는 곳", r.stdout)
        listed = [ln.strip() for ln in r.stdout.splitlines()[1:]]
        self.assertEqual(listed[0], str(td), r.stdout)                       # sys.path 점검이 먼저 — 작업 폴더('')도 실제 경로로 바꿔 본다(패키지 파일 점검과 따로)


class LinuxPackageLists(unittest.TestCase):
    def test_package_and_installers_copy_samples_docs(self):
        b = (ENGINE / "tools" / "build" / "build_linux_pkgs.py").read_text(encoding="utf-8")
        self.assertIn('"tests", "samples")', b)
        self.assertIn("for d in logtriage rules rules-local errorcodes manuals tools deploy tests samples; do", b)
        self.assertIn("사용법.txt", b)
        inst = (ENGINE / "deploy" / "server" / "install.sh").read_text(encoding="utf-8")
        self.assertIn("for d in logtriage rules errorcodes manuals tools report-template samples; do", inst)
        # GPT 94차 P0: 설치 폴더는 root:서비스그룹 + sticky — 서비스 계정 소유로 두는 줄 다음에 와야 한다(뒤에서 다시 덮지 않게)
        self.assertGreater(inst.index('chmod 1770 "$INSTALL_DIR"'), inst.index('chown -R "$SVC_USER":"$SVC_USER" "$INSTALL_DIR"'))
        self.assertIn('chown root:"$SVC_USER" "$INSTALL_DIR"', inst)
        self.assertNotIn('chmod 750 "$INSTALL_DIR"', inst)
        self.assertIn('$SUDO chown root:"$SVC_USER" "$INST"; $SUDO chmod 1770 "$INST"', b)
        self.assertTrue((ENGINE / "samples" / "SHA256SUMS.json").is_file())

    def test_linux_text_files_are_lf(self):
        """10-06 리눅스 묶음의 install.sh·backup.sh·uninstall.sh·에이전트 .sh 가 CRLF 였다 — `bash install.sh` 는 첫 줄부터 $'\\r' 오류.
        리눅스가 읽는 글 파일(셸·systemd·설정 예시·에이전트)은 원본부터 LF, shebang 으로 시작."""
        files = list(ENGINE.rglob("*.sh")) + [p for p in (ENGINE / "deploy" / "server").rglob("*") if p.suffix in (".service", ".timer", ".conf", ".example")] \
            + [p for p in (ENGINE / "tools" / "agent").rglob("*") if p.suffix in (".py", ".example", ".txt")]
        bad = [str(p.relative_to(ENGINE)) for p in files if p.is_file() and "__pycache__" not in p.parts and b"\r" in p.read_bytes()]
        self.assertEqual(bad, [])
        self.assertEqual([str(p) for p in ENGINE.rglob("*.sh") if not p.read_bytes().startswith(b"#!")], [])
        # GPT 94차 P1: .py 는 지문 때문에 바이트 그대로 두지만, 직접 실행(./x.py)하는 것(shebang 이 있는 것)은 첫 줄이 LF 여야 한다('python3\r')
        shebang_crlf = [str(p.relative_to(ENGINE)) for p in ENGINE.rglob("*.py")
                        if "__pycache__" not in p.parts and p.read_bytes().startswith(b"#!") and b"\r" in p.read_bytes().split(b"\n", 1)[0]]
        self.assertEqual(shebang_crlf, [])


if __name__ == "__main__":
    unittest.main()
