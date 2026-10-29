# -*- coding: utf-8 -*-
"""한 자료 폴더에는 서버 하나 — **현장에서 터진 기동 실패**를 지킨다 (2026-10-02)

왜 이 파일이 생겼나. 현장에서 1.0.0 을 띄우다 이렇게 됐다.

    [4/4] 서버 기동 (포트 8098)
      ! 포트 8098 를 쥔 것은 새 프로세스가 아닙니다 — 옛 서버가 응답하고 있습니다
    $ sudo sh run.sh 8190            ← 포트만 바꿔 다시
    [4/4] 서버 기동 (포트 8190)
      ! 기동 확인 실패 — server.log 마지막 줄:
         ... [LogTriage server] http://0.0.0.0:8190 ...      ← 떴다고 찍고
         Traceback (most recent call last):
           File ".../automation.py", line 63, in acquire
         RuntimeError: 다른 실행기 또는 복원 작업이 사용 중입니다

같은 자료 폴더를 쓰는 서버가 이미 떠 있었다. 그것 자체는 막는 게 맞다(분석 이력·예약
작업·감사 기록을 함께 쓴다). 틀린 것은 **막는 방식**이었다.

  ① 서버는 '다른 서버가 쓰는 중인가' 를 보는 자물쇠(runlock)를 이미 가지고 있었는데
     serve() 가 그 **답을 버리고** 있었다 — `_held = runlock.acquire(base)` 뿐이었다.
  ② 그래서 포트를 먼저 잡고, 기동 안내까지 찍은 **뒤에** 자동화 자물쇠에서 죽었다.
     운영자에게는 '떴다가 역추적' 으로 보인다.
  ③ 메시지에 어느 폴더·어느 프로세스인지도, 무엇을 하면 되는지도 없었다.

[무엇을 보는가]
  ① 같은 base 의 두 번째 서버는 **포트를 잡기 전에** 거절된다
  ② --check-start 가 그것을 **미리** 알려 준다(기동 스크립트가 아무것도 띄우기 전에)
  ③ 거절하는 글에 폴더·확인 방법·조치가 들어 있다
  ④ 앞 서버가 끝나면 자물쇠는 **저절로** 풀린다(파일을 지워서 푸는 것이 아니다)
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))
from logtriage import runlock  # noqa: E402

# 자식 프로세스의 글을 **읽을 수 있는 부호로** 받는다. 윈도에서 돌리면 자식이 콘솔
# 부호(cp949)로 써서, UTF-8 로 읽는 이 시험에는 깨진 글자로 보인다 — 제품이 아니라
# 시험 환경의 문제다(리눅스 현장 기록에서는 한글이 제대로 나온다).
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def taken(port: int) -> bool:
    s = socket.socket()
    s.settimeout(0.6)
    try:
        s.connect(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


class SecondServerTests(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        self.port = free_port()
        self.first = subprocess.Popen(
            [sys.executable, "-m", "logtriage.server", "--base", str(self.base),
             "--port", str(self.port), "--host", "127.0.0.1"],
            cwd=str(ENG), env=ENV, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(60):                       # 첫 서버가 실제로 뜰 때까지
            if taken(self.port):
                break
            if self.first.poll() is not None:
                self.fail("첫 서버가 뜨지 않았습니다: "
                          + (self.first.stdout.read() or b"").decode("utf-8", "replace")[-800:])
            time.sleep(0.25)
        else:
            self.fail("첫 서버가 제한 시간 안에 뜨지 않았습니다")

    def tearDown(self):
        self.first.terminate()
        try:
            self.first.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.first.kill()
        self.td.cleanup()

    def run_second(self, *extra):
        port2 = free_port()
        p = subprocess.run(
            [sys.executable, "-m", "logtriage.server", "--base", str(self.base),
             "--port", str(port2), "--host", "127.0.0.1", *extra],
            cwd=str(ENG), env=ENV, capture_output=True, timeout=90)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        return p.returncode, out, err, port2

    def test_it_refuses_before_taking_the_port(self):
        rc, out, err, port2 = self.run_second()
        self.assertNotEqual(rc, 0, "같은 자료 폴더에 두 번째 서버가 떠 버렸습니다")
        self.assertFalse(taken(port2),
                         "거절하면서 포트는 잡았습니다 — 잡고 나서 죽으면 '떴다가 역추적' 이 됩니다")

    def test_it_does_not_die_with_a_traceback(self):
        rc, out, err, _ = self.run_second()
        both = out + err
        self.assertNotIn("Traceback", both,
                         "운영자에게 역추적을 보여 줍니다 — 왜 안 뜨는지 알 수 없습니다")
        self.assertNotIn("RuntimeError", both)

    def test_the_refusal_says_what_to_do(self):
        rc, out, err, _ = self.run_second()
        both = out + err
        self.assertIn("이미 다른 LogTriage 서버", both, "무엇에 막혔는지 말하지 않습니다")
        self.assertIn(str(self.base), both, "어느 자료 폴더인지 말하지 않습니다")
        self.assertIn("stop.sh", both, "어떻게 멈추는지 말하지 않습니다")
        self.assertIn("--base", both, "함께 띄우려면 어떻게 하는지 말하지 않습니다")

    def test_check_start_warns_before_anything_is_launched(self):
        """기동 스크립트는 이것을 보고 **띄우기 전에** 멈춘다."""
        rc, out, err, _ = self.run_second("--check-start")
        self.assertEqual(rc, 2, "--check-start 가 막지 않았습니다")
        d = json.loads(out.strip().splitlines()[-1])
        self.assertFalse(d["allowed"])
        self.assertIn("이미 다른 LogTriage 서버", err,
                      "까닭이 사람이 읽는 쪽(표준 오류)에 나오지 않습니다")

    def test_the_lock_frees_itself_when_the_holder_goes(self):
        """OS 자물쇠다 — 파일을 지워서 푸는 것이 아니다."""
        self.assertTrue(runlock.running(self.base), "첫 서버가 자물쇠를 쥐고 있지 않습니다")
        self.first.terminate()
        self.first.wait(timeout=20)
        for _ in range(40):
            if not runlock.running(self.base):
                break
            time.sleep(0.25)
        self.assertFalse(runlock.running(self.base),
                         "앞 서버가 끝났는데 자물쇠가 남아 있습니다 — 다시 못 띄웁니다")
        rc, out, err, port2 = self.run_second("--check-start")
        self.assertEqual(rc, 0, f"앞 서버가 없는데도 거절합니다: {err[-400:]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
