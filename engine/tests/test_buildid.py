# -*- coding: utf-8 -*-
"""판 지문(Build ID) — 제품 판을 고정한 대신 **코드가 바뀌었는지**를 가린다 (2026-10-01)

제품 판 표시를 1.0.0 하나로 고정했다(사용자 결정). 그러면 "패치했는데 화면이 그대로" 를
제품 판으로는 못 가려낸다 — 패치해도 1.0.0, 안 해도 1.0.0 이다. 전에는 날짜-r번호가 그 일을
했다. 그래서 코드 내용에서 뽑는 값을 따로 둔다(GPT 8차).
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import buildid                       # noqa: E402
from logtriage import runlock                       # noqa: E402
from logtriage.server import make_server            # noqa: E402

ENG = Path(__file__).resolve().parents[1]
PKG = ENG / "logtriage"


class ComputeTests(unittest.TestCase):

    def copy(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        d = Path(td.name) / "logtriage"
        shutil.copytree(PKG, d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        return d

    def test_the_same_source_gives_the_same_value(self):
        d = self.copy()
        self.assertEqual(buildid.compute(d), buildid.compute(d))

    def test_one_changed_line_changes_it(self):
        d = self.copy()
        before = buildid.compute(d)
        f = d / "hub.py"
        f.write_text(f.read_text(encoding="utf-8") + "# 한 줄" + chr(10), encoding="utf-8")
        self.assertNotEqual(buildid.compute(d), before, "코드를 고쳤는데 지문이 그대로입니다")

    def test_a_changed_screen_changes_it_too(self):
        """화면 파일도 돌아가는 것이다 — 고치면 지문이 달라져야 한다."""
        d = self.copy()
        before = buildid.compute(d)
        f = d / "gui" / "hub.html"
        f.write_text(f.read_text(encoding="utf-8") + "<!-- 한 줄 -->", encoding="utf-8")
        self.assertNotEqual(buildid.compute(d), before)

    def test_moving_a_file_changes_it(self):
        """경로도 함께 넣는다 — 내용이 같아도 자리가 바뀌면 다른 판이다."""
        d = self.copy()
        before = buildid.compute(d)
        (d / "hub.py").rename(d / "hub_moved.py")
        self.assertNotEqual(buildid.compute(d), before)

    def test_caches_do_not_change_it(self):
        """같은 소스에서도 달라지는 것(파이썬 캐시)은 넣지 않는다."""
        d = self.copy()
        before = buildid.compute(d)
        (d / "__pycache__").mkdir(exist_ok=True)
        (d / "__pycache__" / "x.pyc").write_bytes(bytes([0, 1]))
        self.assertEqual(buildid.compute(d), before)

    def test_it_is_a_short_hex_string(self):
        v = buildid.compute(PKG)
        self.assertRegex(v, "^[0-9a-f]{12}$")

    def test_it_is_quick_enough_for_startup(self):
        """기동할 때 한 번 구한다 — 여기서 몇 초를 쓰면 안 된다."""
        t = time.time()
        buildid.compute(PKG)
        self.assertLess(time.time() - t, 2.0)


class HealthzTests(unittest.TestCase):
    """**/healthz 는 디스크를 다시 읽지 않는다.**

    옛 프로세스가 그대로 떠 있는데 새 파일만 덮어쓴 상황에서 매번 읽으면, 돌고 있는 것은
    옛 코드인데 새 지문을 돌려주는 **거짓 성공**이 된다 — 그것이 바로 이 값으로 잡으려는
    상황이다(GPT 8차).
    """

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.httpd, h = make_server("127.0.0.1", 0, Path(self.td.name), None)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def health(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=5) as r:
            return json.load(r)

    def test_healthz_carries_both_values(self):
        d = self.health()
        self.assertEqual(d["version"], d["build"], "제품 판은 한 값이어야 합니다")
        self.assertRegex(d["build_id"], "^[0-9a-f]{12}$")

    def test_it_does_not_reread_the_disk(self):
        before = self.health()["build_id"]
        f = PKG / "hub.py"
        was = f.read_bytes()
        f.write_bytes(was + b"# changed" + bytes([10]))
        try:
            self.assertEqual(self.health()["build_id"], before,
                             "소스를 고치자 돌고 있는 서버의 지문이 바뀌었습니다 — 거짓 성공입니다")
        finally:
            f.write_bytes(was)


class RunLockTests(unittest.TestCase):
    """관리 명령은 **다른 프로세스**다 — 서버 안의 자물쇠가 닿지 않는다(GPT 8차)."""

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.b = Path(self.td.name)
        (self.b / "data").mkdir(parents=True)

    def test_nothing_running_means_zero(self):
        self.assertEqual(runlock.running(self.b), 0)

    def test_a_held_lock_is_seen_from_the_same_process(self):
        held = runlock.acquire(self.b)
        self.addCleanup(held.release)
        self.assertTrue(held)
        self.assertNotEqual(runlock.running(self.b), 0, "쥐고 있는데 안 돈다고 합니다")

    def test_releasing_frees_it(self):
        held = runlock.acquire(self.b)
        held.release()
        self.assertEqual(runlock.running(self.b), 0)

    def test_a_leftover_file_does_not_block_forever(self):
        """서버가 죽어 버려도 흔적 파일 때문에 영영 못 고치는 일은 없어야 한다."""
        (self.b / "data" / runlock.LOCK_FILE).write_bytes(b"x 99999")
        self.assertEqual(runlock.running(self.b), 0, "남은 파일만으로 돌고 있다고 봅니다")

    def test_the_server_takes_it_while_running(self):
        src = (ENG / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertIn("runlock.acquire(base)", src, "서버가 자물쇠를 쥐지 않습니다")


if __name__ == "__main__":
    unittest.main()
