"""22차(2026-10-27) — GPT 153 P1 3건.
① 공통(리눅스 포함): 예시 자리 값뿐 아니라 추측 가능한 공용 비밀번호(12345678 · admin2026 · P@ssw0rd!! · qwerty 연속)도 LAN 수신 거부
   — 리눅스 설치가 만드는 무작위 12자(openssl rand -base64 12 에서 /+= 뺀 값)는 통과해야 한다(정상 현장 기동 보호)
② 창 모드가 LAN → 이 PC 안(127.0.0.1)으로 내려가면 화면 '환경 점검' 띠에 창을 닫을 때까지 남긴다(메시지 상자는 지나가면 잊힌다)
③ 토큰이 든 lt-agent.zip 을 USB 로 옮길 때 — 지우기 · 잃으면 폐기 안내(화면 · 사용법)"""
from __future__ import annotations

import base64
import re
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

from logtriage.server import make_server, weak_shared_password  # noqa: E402


class GuessablePasswordTest(unittest.TestCase):
    def test_guessable_refused_on_common_rule(self):
        for pw in ("12345678", "87654321", "aaaaaaaa", "zzzz9999", "admin2026", "Admin!2026", "logtriage1!", "qwerty123",
                   "abcdefgh", "1qaz2wsx", "P@ssw0rd!!", "r00t1234", "S3rver#2026", "short7c"):
            self.assertTrue(weak_shared_password(pw), pw)
            self.assertTrue(weak_shared_password(pw).startswith(("추측하기 쉬운 값", "예시 파일")), pw)

    def test_reasonable_values_pass(self):
        for pw in ("Lt-Strong-Pass-26", "k3Vq9TzpX2mA", "Monitoring-Team-07", "short9cha"):
            self.assertEqual(weak_shared_password(pw), "", pw)
        self.assertEqual(weak_shared_password("short9cha", strict=True), "10자 미만")   # exe 는 길이 규칙이 따로

    def test_linux_install_random_password_never_refused(self):
        for _ in range(3000):   # install.sh 264행과 같은 꼴
            pw = re.sub("[/+=]", "", base64.b64encode(secrets.token_bytes(12)).decode())[:12]
            self.assertEqual(weak_shared_password(pw), "", pw)

    def test_make_server_refuses_guessable_on_lan_only(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(SystemExit) as cm:
                make_server("0.0.0.0", 0, Path(td), "admin2026")
            self.assertIn("추측하기 쉬운 값", str(cm.exception))
        with tempfile.TemporaryDirectory() as td:   # 루프백은 그대로
            httpd, _ = make_server("127.0.0.1", 0, Path(td), "admin2026")
            httpd.server_close()


class DowngradeBandTest(unittest.TestCase):
    def setUp(self):
        self.src = (ENGINE / "logtriage" / "gui" / "app.py").read_text(encoding="utf-8")

    def test_reasons_recorded_for_all_three_downgrades(self):
        self.assertIn('_down = "127.0.0.1", 0, "PASSWORD 가 없어"', self.src.replace("listen, port, _down", "_down"))
        self.assertIn('"PASSWORD 가 " + _weak + "라"', self.src)
        self.assertIn('_down = _down or ("PORT:주소 %s:%s 를 열 수 없어', self.src)

    def test_band_reaches_diag(self):
        with tempfile.TemporaryDirectory() as td:   # 창 모드와 같은 길: make_server 가 만든 api 에 붙인다
            httpd, handler = make_server("127.0.0.1", 0, Path(td), None)
            try:
                api = handler.api
                api.__dict__["_boot_warns"] = [{"code": "lan_downgraded", "text": "시험 띠", "clears": "다시 실행하면"}]
                d = api.diag()
            finally:
                httpd.server_close()
        self.assertNotIn("error", d)
        codes = [i["code"] for i in d["warn_items"]]
        self.assertEqual(codes[0], "lan_downgraded")       # 맨 위에
        self.assertIn("시험 띠", d["warnings"])

    def test_band_only_when_lan_was_asked(self):
        self.assertIn('if _down and _asked not in ("127.0.0.1", "localhost", "::1"):', self.src)
        self.assertIn("다른 서버의 에이전트 보고(자원 사용률)와 다른 PC 의 브라우저 접속이 들어오지 않습니다", self.src)
        self.assertIn("핑 · 포트 · 웹 감시는 그대로", self.src)          # GPT 165: 관제 전체가 멈춘다고 과장하지 않는다
        self.assertIn("server.conf 의 PORT 를 비어 있는 번호로", self.src)   # 포트 오류는 비밀번호와 다른 해결


class ServerTypeFrontProxyTest(unittest.TestCase):
    """GPT 165: 정식 설치는 nginx 뒤 127.0.0.1 — 주소로는 노출을 모른다. 서버형 기동은 주소와 관계없이 거부 · 패치 전 사전 진단."""
    def test_start_decision_refuses_weak_even_on_loopback(self):
        from logtriage.server import start_decision
        with tempfile.TemporaryDirectory() as td:
            d = start_decision("127.0.0.1", Path(td), "admin2026")
            self.assertFalse(d["allowed"])
            self.assertIn("nginx", d["reason"])
            self.assertTrue(start_decision("127.0.0.1", Path(td), "k3Vq9TzpX2mA")["allowed"])

    def test_check_password_cli(self):
        import json, os, subprocess
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        for pw, rc in (("admin2026", 2), ("k3Vq9TzpX2mA", 0)):
            r = subprocess.run([sys.executable, "-m", "logtriage.server", "--check-password", "--password-stdin"], cwd=str(ENGINE),
                               input=pw + "\n", capture_output=True, text=True, encoding="utf-8", env=env)
            self.assertEqual(r.returncode, rc, r.stderr)
            j = json.loads(r.stdout.strip().splitlines()[0])
            self.assertEqual(j["weak"], rc == 2)
            self.assertNotIn(pw, r.stdout + r.stderr)          # 원문은 찍지 않는다

    def test_apply_patch_precheck_before_any_change(self):
        src = (ENGINE / "tools" / "build" / "build_linux_pkgs.py").read_text(encoding="utf-8")
        i = src.index('(P / "apply_patch.sh")')
        body = src[i:]
        pre, one = body.index("pw_precheck()"), body.index("[1/3] 소스 교체")
        self.assertLess(pre, one)                                # 바꾸기 전에 진단
        self.assertIn("--check-password --password-stdin", body[pre:one])
        self.assertIn("exit 3", body[pre:one])
        blk = body[body.index("# 22차(GPT 165 P1-01)"):one]
        # 파이썬 일반 문자열 안이라 셸 역슬래시는 소스에서 두 겹이어야 한다(한 겹이면 CR · 줄바꿈 · \1 이 제어 문자로 들어감)
        self.assertIn("tr -d '\\\\r'", blk)
        self.assertIn("printf '%s\\\\n'", blk)
        self.assertNotIn("tr -d '\\r'", blk.replace("tr -d '\\\\r'", ""))


class ProxiedNoLoginTest(unittest.TestCase):
    """GPT 166 조건부 P0: 로그인 없는(비밀번호 없음 · mode off) 서버는 '이 PC 안'이라 허용한 것 — 앞단(nginx)을 거친 요청은 막는다."""
    def test_direct_ok_proxied_refused(self):
        import threading
        import urllib.error
        import urllib.request
        with tempfile.TemporaryDirectory() as td:
            httpd, _ = make_server("127.0.0.1", 0, Path(td), None)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            try:
                u = f"http://127.0.0.1:{httpd.server_address[1]}/api/nms/status"
                self.assertEqual(urllib.request.urlopen(u).status, 200)
                for h in ({"X-Forwarded-For": "10.0.0.9"}, {"X-Real-IP": "10.0.0.9"}, {"X-Forwarded-Proto": "https"}):
                    with self.assertRaises(urllib.error.HTTPError) as cm:
                        urllib.request.urlopen(urllib.request.Request(u, headers=h))
                    self.assertEqual(cm.exception.code, 401, h)
            finally:
                httpd.shutdown()
                httpd.server_close()

    def test_no_login_server_needs_explicit_local_only(self):
        """GPT 167: 머리글은 인증 경계가 아니다 — 서버형 '로그인 없음'은 --local-only + 루프백일 때만(systemd 는 안 붙임)."""
        from logtriage.server import no_login_stop
        off = {"mode": "off"}
        self.assertTrue(no_login_stop("127.0.0.1", off, None, False))          # nginx 뒤 systemd 와 같은 꼴 — 거부
        self.assertEqual(no_login_stop("127.0.0.1", off, None, True), "")
        self.assertEqual(no_login_stop("127.0.0.1", {"mode": "local"}, None, False), "")
        self.assertEqual(no_login_stop("127.0.0.1", off, "k3Vq9TzpX2mA", False), "")
        unit = (ENGINE / "deploy" / "server" / "logtriage-server.service").read_text(encoding="utf-8")
        self.assertNotIn("--local-only", unit)
        f = ENGINE.parent / "반출" / "_run.sh"
        if not f.exists():   # 리눅스 묶음 안: run.sh 갱신본은 개발 트리에만 있다(묶음에는 run.sh 로 들어감)
            f = ENGINE.parent / "run.sh"
        if not f.exists():
            self.skipTest("run.sh 원본 없음")
        run = f.read_text(encoding="utf-8")
        self.assertIn('[ "$LOOPBACK" = 1 ] && PWARGS+=(--local-only)', run)
        self.assertIn('[ "$LOOPBACK" = 1 ] && ARGS+=(--local-only)', run)

    def test_apply_patch_refuses_password_argument_first(self):
        src = (ENGINE / "tools" / "build" / "build_linux_pkgs.py").read_text(encoding="utf-8")
        body = src[src.index('(P / "apply_patch.sh")'):]
        refuse = body.index("비밀번호를 명령행 인자로 받지 않습니다")
        self.assertLess(refuse, body.index("[1/3] 소스 교체"))      # 아무것도 바꾸기 전에
        self.assertNotIn('run.sh" "$PORT" $PW', body)                 # run.sh 로 넘기던 옛 길 제거
        self.assertNotIn("[비밀번호]", body)


class UsbTokenNoticeTest(unittest.TestCase):
    def test_screen_and_manual(self):
        nms = (ENGINE / "logtriage" / "gui" / "nms.html").read_text(encoding="utf-8")
        self.assertIn('id="agusb"', nms)
        self.assertIn("[폐기]", nms[nms.index('id="agusb"'):nms.index('id="agusb"') + 400])
        man = (ENGINE / "deploy" / "local" / "사용법.txt").read_text(encoding="utf-8")
        self.assertIn("USB 로 옮길 때", man)
        self.assertIn("추측하기 어려운 값", man)


if __name__ == "__main__":
    unittest.main()
