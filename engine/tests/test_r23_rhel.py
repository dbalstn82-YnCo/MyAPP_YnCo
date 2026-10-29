# -*- coding: utf-8 -*-
"""23차(2026-10-27 마스터: '사내망 HTTPS 는 일단 보류하고 RHEL 서버 검증 내용 매뉴얼 작성') — 매뉴얼을 쓰며 드러난 정식 설치 결함.

A. --tls 없는 정식 설치(nginx 80 → 앱 127.0.0.1)는 첫 기동 기본값(계정 로그인)에서 로그인 화면부터 모두 403 이었다
   — nginx 가 X-Forwarded-Proto: http 를 붙이고 앱은 '앞단이 평문이라 하면 언제나 거절' 이었기 때문(HTTPS 보류 결정과 충돌).
   이제 auto 면 run.sh 직접 접속과 같은 규칙: **우리 nginx** 가 적어 준 접속자 주소가 사내망이면 받는다(평문 경고는 그대로).
B. nginx 뒤 접속자 주소를 X-Forwarded-For **첫** 값으로 읽어 위조할 수 있었다(로그인 시도 제한 우회 · 다른 감시 대상 IP 행세).
   이제 루프백 + 설치 때 nginx 와 나눈 비밀 머리글 + X-Real-IP 만 믿는다(GPT 177 조건부 P0: 같은 서버의 다른 계정이 앱 포트에 직접 붙는 경우).
C. install.sh: 설치 기록 0644 에 공용 비밀번호를 찍었다 · --password 인자를 받았다(ps 노출) · nginx 설정이 0644.

막는 것만 보면 '늘 막힘' 도 통과한다 — 되는 쪽(사내망 평문 로그인 성공)을 실제 왕복으로 함께 본다."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import server as S  # noqa: E402
from test_enterprise import Srv, cookie_of, prep_base  # noqa: E402

SECRET = "9f1c" * 16          # 시험 안에서만 쓰는 가상 앞단 비밀(64자)
PWA = "Bq7-Zrt2!wVm"
DEPLOY = ENGINE / "deploy" / "server"
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"


def nginx(real, xff=None, proto="http", secret=SECRET):
    """우리 nginx 설정(logtriage.conf)이 붙이는 머리글 그대로."""
    h = {"X-Real-IP": real, "X-Forwarded-For": xff if xff is not None else real, "X-Forwarded-Proto": proto}
    if secret:
        h[S.PROXY_HEADER] = secret
    return h


def form(**kw):
    return urllib.parse.urlencode(kw), {"Content-Type": "application/x-www-form-urlencoded"}


class ForwardedClientTest(unittest.TestCase):
    def test_trusts_only_our_nginx(self):
        with mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": SECRET}):
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3")), "10.1.2.3")
            self.assertEqual(S.forwarded_client("::1", nginx("10.1.2.3")), "10.1.2.3")
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3", secret="x" * 64)), "", "비밀이 틀린 머리글을 믿었습니다")
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3", secret="")), "", "비밀 없는 루프백 요청을 믿었습니다")
            self.assertEqual(S.forwarded_client("10.0.0.5", nginx("10.1.2.3")), "", "다른 PC 가 보낸 머리글을 믿었습니다")
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3; rm")), "")
        with mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": "short"}):
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3", secret="short")), "", "짧은 비밀을 받아들였습니다")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("LOGTRIAGE_PROXY_SECRET", None)
            self.assertEqual(S.forwarded_client("127.0.0.1", nginx("10.1.2.3")), "", "비밀이 설정되지 않았는데 머리글을 믿었습니다")

    def _fake(self, sock, hdr):
        class Fake:
            client_address = (sock, 5000)
            headers = hdr
            _fail: dict = {}
            api = type("A", (), {"auth": type("U", (), {"audit": staticmethod(lambda *a, **k: None)})()})()
        for m in ("_ip", "_too_many", "_failed", "_loopback_peer"):
            setattr(Fake, m, getattr(S.Handler, m))
        return Fake()

    def test_spoofed_first_xff_does_not_change_the_address(self):
        """nginx 는 접속자가 보낸 X-Forwarded-For 뒤에 붙인다 — 첫 값을 바꿔 가며 보내도 주소는 하나."""
        with mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": SECRET}):
            f = self._fake("127.0.0.1", {})
            for n in range(12):
                f.headers = nginx("10.1.2.3", xff=f"198.51.100.{n}, 10.1.2.3")
                self.assertEqual(f._ip(), "10.1.2.3")
                f._failed("hong@solideos.com", "local", "비밀번호 틀림")
            self.assertTrue(f._too_many("hong@solideos.com"), "가짜 주소를 바꿔 가며 로그인 시도 제한을 피했습니다")

    def test_without_trust_the_socket_address_is_used(self):
        os.environ.pop("LOGTRIAGE_PROXY_SECRET", None)
        f = self._fake("127.0.0.1", {"X-Forwarded-For": "10.9.9.9", "X-Real-IP": "10.9.9.9"})
        self.assertEqual(f._ip(), "127.0.0.1", "믿을 수 없는 머리글로 출발지 주소를 바꿨습니다")
        f = self._fake("10.0.0.7", {"X-Real-IP": "10.9.9.9"})
        self.assertEqual(f._ip(), "10.0.0.7")


class NginxPlaintextTest(unittest.TestCase):
    """정식 설치 그대로: 계정 로그인(첫 기동 기본값) · require_https auto · nginx 80(평문)."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": SECRET})
        self.env.start()
        S.Handler._fail.clear()
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth={"mode": "local", "first_admin": "",
                                                         "local": {"domain": "solideos.com", "scrypt_n": 12, "signup": "approve"}})
        self.s = Srv(self.base)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()
        self.env.stop()

    def test_inside_plaintext_works_end_to_end(self):
        """양성 대조 — 사내망 PC 가 nginx 80 으로: 첫 관리자 만들기 → 로그인 → 화면. 평문 경고는 뜬다."""
        h = nginx("10.20.30.40")
        r, b = self.s.req("GET", "/login", headers=h)
        self.assertNotEqual(r.status, 403, "정식 설치(평문 nginx)가 로그인 화면부터 막힙니다 — 결함 A 재발")
        body, fh = form(email="boss@solideos.com", name="관리자", password=PWA, confirm=PWA, t=self.s.api.setup_token)
        r, _ = self.s.req("POST", "/setup", body, dict(fh, **h))
        self.assertEqual(r.status, 302, "nginx 뒤에서 첫 관리자를 만들지 못했습니다")
        body, fh = form(email="boss@solideos.com", password=PWA)
        r, _ = self.s.req("POST", "/login", body, dict(fh, **h))
        self.assertEqual(r.status, 302)
        ck = cookie_of(r)
        self.assertTrue(ck)
        r, b = self.s.req("GET", "/api/me", headers=h, cookie=ck)
        self.assertEqual(r.status, 200, b[:200])
        r, b = self.s.req("GET", "/login", headers=h)
        self.assertIn('id="ltplain"', b.decode("utf-8", "replace"), "평문 경고가 사라졌습니다")

    def test_outside_or_untrusted_plaintext_is_refused(self):
        cases = {
            "인터넷 주소": nginx("8.8.8.8"),
            "앞단이 둘(바깥 부하분산기 · 위조 XFF)": nginx("10.20.30.40", xff="198.51.100.9, 10.20.30.40"),
            "비밀 없는 루프백(같은 서버 다른 계정)": nginx("10.20.30.40", secret=""),
            "틀린 비밀": nginx("10.20.30.40", secret="0" * 64),
            "접속자 주소 없음": {"X-Forwarded-Proto": "http", S.PROXY_HEADER: SECRET},
        }
        for why, h in cases.items():
            with self.subTest(why=why):
                r, b = self.s.req("GET", "/login", headers=h)
                self.assertEqual(r.status, 403, why + " — 평문을 받았습니다")
                self.assertIn("HTTPS", b.decode("utf-8", "replace"))
        r, _ = self.s.req("GET", "/healthz", headers=nginx("8.8.8.8"))
        self.assertEqual(r.status, 200, "상태 확인은 막지 않습니다")

    def test_require_https_true_still_refuses_inside_plaintext(self):
        self.s.api.auth_conf["require_https"] = True
        try:
            r, _ = self.s.req("GET", "/login", headers=nginx("10.20.30.40"))
            self.assertEqual(r.status, 403)
            r, _ = self.s.req("GET", "/login", headers=nginx("10.20.30.40", proto="https"))
            self.assertNotEqual(r.status, 403, "같은 PC 의 TLS 앞단을 못 믿으면 정상 구성이 막힙니다")
            # GPT 178: 같은 서버의 다른 계정이 앱 포트에 직접 'https' 라고 적어 보내도 HTTPS 강제를 넘지 못한다
            r, _ = self.s.req("GET", "/login", headers=nginx("10.20.30.40", proto="https", secret=""))
            self.assertEqual(r.status, 403, "비밀 없는 'https' 표시를 믿었습니다")
        finally:
            self.s.api.auth_conf["require_https"] = "auto"


class EmailLoginLimitTest(unittest.TestCase):
    """이메일 로그인 실패 제한 — 적는 열쇠(주소|이메일)와 세는 열쇠가 달라 계정마다 10회가 아니라 주소마다 60회에야 막혔다(23차)."""

    def setUp(self):
        S.Handler._fail.clear()
        self.td = tempfile.TemporaryDirectory()
        self.base = prep_base(Path(self.td.name), auth={"mode": "local", "first_admin": "",
                                                         "local": {"domain": "solideos.com", "scrypt_n": 12, "signup": "approve"}})
        self.s = Srv(self.base)

    def tearDown(self):
        self.s.close()
        self.td.cleanup()
        S.Handler._fail.clear()

    def test_ten_failures_on_one_account_lock_it(self):
        body, fh = form(email="boss@solideos.com", name="관리자", password=PWA, confirm=PWA, t=self.s.api.setup_token)
        self.assertEqual(self.s.req("POST", "/setup", body, fh)[0].status, 302)
        codes = []
        for _ in range(11):
            body, fh = form(email="boss@solideos.com", password="wrong-Pass-1")
            codes.append(self.s.req("POST", "/login", body, fh)[0].status)
        self.assertEqual(codes[:10], [401] * 10, codes)
        self.assertEqual(codes[10], 429, "열 번 틀린 계정을 막지 않습니다: %s" % codes)
        body, fh = form(email="boss@solideos.com", password=PWA)
        self.assertEqual(self.s.req("POST", "/login", body, fh)[0].status, 429, "막힌 동안 맞는 비밀번호도 받지 않아야 합니다(추측 차단)")
        body, fh = form(email="other@solideos.com", password="wrong-Pass-1")   # 양성 대조 — 다른 계정은 아직 막히지 않음
        self.assertEqual(self.s.req("POST", "/login", body, fh)[0].status, 401)


class NginxConfTest(unittest.TestCase):
    conf = (DEPLOY / "nginx" / "logtriage.conf").read_text(encoding="utf-8")

    def test_client_cannot_choose_the_scheme_or_the_address(self):
        """nginx 가 접속자가 보낸 X-Forwarded-Proto · X-Real-IP 를 **덮어쓴다** — 80 은 $scheme, 443 은 https 고정."""
        for blk, proto in ((self.conf.split("__TLS_BLOCK_BEGIN__")[0], "$scheme"), (self.conf.split("__TLS_BLOCK_BEGIN__")[1], "https")):
            with self.subTest(proto=proto):
                self.assertRegex(blk, r"proxy_set_header\s+X-Forwarded-Proto\s+" + re.escape(proto) + ";")
                self.assertRegex(blk, r"proxy_set_header\s+X-Real-IP\s+\$remote_addr;")

    def test_access_log_has_no_query(self):
        """1회용 코드(/setup?t=) · 내려받기 표(?ticket=)가 nginx 접속 기록에 남지 않게 — 두 블록 모두 경로만 적는 형식."""
        self.assertIn("log_format logtriage_noquery", self.conf)
        fmt = self.conf[self.conf.index("log_format logtriage_noquery"):].split(";")[0]
        self.assertNotIn("$request ", fmt.replace("$request_method", "").replace("$request_time", ""))
        self.assertNotIn("$request_uri", fmt)
        self.assertNotIn("$args", fmt)
        self.assertEqual(self.conf.count("logtriage_access.log logtriage_noquery;"), 2)


class AgentInstallerTest(unittest.TestCase):
    """예전 설치형(lt-agent-install.sh)은 토큰을 서비스 실행 줄 인자로 넣어 ps · systemctl show 로 누구나 봤다(23차)."""
    sh = (ENGINE / "tools" / "agent" / "lt-agent-install.sh").read_text(encoding="utf-8")

    def test_token_never_on_a_command_line(self):
        exec_line = [ln for ln in self.sh.splitlines() if ln.startswith("ExecStart=")]
        self.assertEqual(len(exec_line), 1)
        self.assertNotIn("$TOKEN", exec_line[0])
        self.assertIn(" - $INTERVAL", exec_line[0], "토큰 자리는 '-'(환경변수 LT_AGENT_TOKEN)여야 합니다")
        self.assertIn("EnvironmentFile=/etc/lt-agent/agent.env", self.sh)
        self.assertIn("chmod 600 /etc/lt-agent/agent.env", self.sh)
        for ln in self.sh.splitlines():
            if ("curl " in ln or "wget " in ln) and "$TOKEN" in ln and '"$TOKEN" > "$WR"' not in ln:   # wget 은 0600 임시 설정 파일로
                self.assertIn("curl -K -", ln, "토큰을 curl/wget 명령행에 실었습니다: " + ln.strip()[:80])
        self.assertIn('if [ "$TOKEN" = "-" ]; then IFS= read -r TOKEN', self.sh, "토큰을 표준 입력으로 받는 길이 없습니다")
        self.assertNotIn(b"\r", (ENGINE / "tools" / "agent" / "lt-agent-install.sh").read_bytes())

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_bad_token_is_refused_before_install(self):
        with tempfile.TemporaryDirectory() as td:
            for tok in ("bad token", "a;rm"):
                r = subprocess.run([BASH, (ENGINE / "tools" / "agent" / "lt-agent-install.sh").as_posix(), "http://10.0.0.5:8088", "-"],
                                   input=tok + "\n", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, cwd=td)
                self.assertEqual(r.returncode, 1)
                self.assertIn("토큰 형식", r.stdout)


class InstallScriptTest(unittest.TestCase):
    sh = (DEPLOY / "install.sh").read_text(encoding="utf-8")
    conf = (DEPLOY / "nginx" / "logtriage.conf").read_text(encoding="utf-8")

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_password_argument_is_refused_before_anything(self):
        for arg in (["--password", "Abcd-1234-xyz"], ["--password=Abcd-1234-xyz"]):
            with self.subTest(arg=arg[0][:10]):
                r = subprocess.run([BASH, (DEPLOY / "install.sh").as_posix(), *arg], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=60)
                self.assertEqual(r.returncode, 1)
                self.assertIn("명령행 인자로 받지 않습니다", r.stdout)
                self.assertNotIn("root 권한", r.stdout, "인자 검사보다 다른 단계가 먼저 돌았습니다")

    def test_log_is_private_before_anything_is_written(self):
        i_chmod = self.sh.index('chmod 600 "$LOG"')
        i_tee = self.sh.index('exec > >(tee -a "$LOG")')
        self.assertLess(i_chmod, i_tee, "설치 기록을 0600 으로 만들기 전에 쓰기 시작합니다")
        self.assertIn('[ -L "$LOG" ]', self.sh, "링크로 바꿔 둔 설치 기록을 따라 씁니다")
        tail = self.sh[self.sh.index("══ 설치 완료"):]
        self.assertNotIn("$PASSWORD", tail, "완료 화면(= 설치 기록)에 비밀번호를 찍습니다")
        self.assertIn("setup-code.txt", tail, "첫 관리자 만드는 법을 알려 주지 않습니다")

    def test_proxy_secret_is_shared_and_private(self):
        self.assertEqual(self.conf.count("X-LogTriage-Proxy __PROXY_SECRET__"), 2, "80 · 443 두 블록 모두 비밀을 실어야 합니다")
        self.assertIn("s#__PROXY_SECRET__#$PROXY_SECRET#g", self.sh)
        self.assertIn("LOGTRIAGE_PROXY_SECRET=$PROXY_SECRET", self.sh)
        self.assertRegex(self.sh, r"\( umask 077; cat > /etc/logtriage/server\.env")
        self.assertEqual(len(re.findall(r'install -m 600 -o root -g root "\$CONF" /etc/nginx/', self.sh)), 2,
                         "nginx 설정(비밀 포함)을 0644 로 복사합니다")
        self.assertNotRegex(self.sh, r'cp "\$CONF" /etc/nginx')

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_nginx_template_renders_without_placeholders(self):
        """install.sh 의 **그 줄들**을 그대로 꺼내 실제로 찍어 본다(평문 · --tls 둘 다). 23차에 이렇게 돌려 보고서야
        --tls 의 80→443 sed 가 구분자(#) 충돌로 멈추는 것(설치가 nginx 단계에서 중단)을 찾았다."""
        render = self.sh[self.sh.index('CONF="$(mktemp)"; ') + len('CONF="$(mktemp)"; '):].splitlines()[0]
        tls_lines = [ln.strip() for ln in self.sh.splitlines() if ln.strip().startswith("sed -i") and '"$CONF"' in ln]
        self.assertEqual(len(tls_lines), 2, tls_lines)
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "c.conf"
            for tls in (0, 1):
                cmd = 'set -e; HERE="%s"; CONF="%s"; APP_PORT=8099; PROXY_SECRET=%s; %s' % (DEPLOY.as_posix(), out.as_posix(), SECRET, render)
                if tls:
                    cmd += "; " + "; ".join(tls_lines)
                r = subprocess.run([BASH, "-c", cmd], capture_output=True, text=True, encoding="utf-8", errors="replace")
                self.assertEqual(r.returncode, 0, r.stderr)
                t = out.read_text(encoding="utf-8")
                self.assertNotIn("__PROXY_SECRET__", t)
                live = [ln for ln in t.splitlines() if ln.strip().startswith("proxy_set_header") and "X-LogTriage-Proxy" in ln]
                self.assertEqual(len(live), 1 + tls, t)
                self.assertTrue(all(SECRET in ln for ln in live))
                self.assertIn("127.0.0.1:8099", t)
                if tls:
                    self.assertIn("return 301 https://$host$request_uri;", t)
                    self.assertNotIn("__TLS_REDIRECT__", t)
                    self.assertTrue(any(ln.strip() == "listen 443 ssl;" for ln in t.splitlines()))


def _msys(p: Path) -> str:
    """Git Bash 의 tar 는 'C:/…' 를 원격 주소로 읽는다 — /c/… 로."""
    s = p.as_posix()
    return "/" + s[0].lower() + s[2:] if len(s) > 1 and s[1] == ":" else s


class PythonPickTest(unittest.TestCase):
    """install.sh 의 '파이썬 고르기' 블록을 **그대로 꺼내** 돌린다. RHEL 9 은 시스템 python3 가 3.9 라 전에는
    '3.10 이상 필요' 로 멈췄다(동봉 Python 은 run.sh 를 먼저 돌려 풀어 둔 경우에만 쓰였다)."""
    sh = (DEPLOY / "install.sh").read_text(encoding="utf-8")

    def _run(self, have: dict, tgz: bool):
        blk = self.sh[self.sh.index("# >>> 파이썬 고르기"):self.sh.index("# <<< 파이썬 고르기")]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            shim = td / "shim"
            shim.mkdir()
            for name, ok in have.items():   # 가짜 파이썬: 3.10 이상이면 0, 아니면 1
                f = shim / name
                f.write_bytes(("#!/bin/sh\nexit %d\n" % (0 if ok else 1)).encode())
                f.chmod(0o755)
            (td / "pkg" / "engine").mkdir(parents=True)
            if tgz:
                import io
                import tarfile
                data = b"#!/bin/sh\nexit 0\n"
                with tarfile.open(td / "pkg" / "python-3.11-linux-x86_64.tar.gz", "w:gz") as tf:
                    ti = tarfile.TarInfo("python/bin/python3.11")
                    ti.size, ti.mode = len(data), 0o755
                    tf.addfile(ti, io.BytesIO(data))
            inst = td / "opt"
            cmd = ('set -euo pipefail; export PATH="%s:/usr/bin:/bin"; SRC_DIR="%s"; INSTALL_DIR="%s"\n%s\necho "PICK=$PYBIN"'
                   % (_msys(shim), _msys(td / "pkg" / "engine"), _msys(inst), blk))
            r = subprocess.run([BASH, "-c", cmd], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
            return r, inst.exists() and (inst / "python" / "bin" / "python3.11").exists()

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_rhel9_system_python39_uses_the_bundled_311(self):
        r, unpacked = self._run({"python3": False}, tgz=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(unpacked, "동봉 Python 을 풀지 않았습니다")
        self.assertRegex(r.stdout, r"PICK=.*/opt/python/bin/python3\.11")

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_system_311_is_used_first(self):
        r, unpacked = self._run({"python3.11": True, "python3": False}, tgz=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PICK=python3.11", r.stdout)
        self.assertFalse(unpacked, "시스템 3.11 이 있는데 동봉본을 풀었습니다")

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_nothing_usable_stops_with_a_reason(self):
        r, _ = self._run({"python3": False}, tgz=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("python 3.10 이상을 찾지 못했습니다", r.stdout)

    def test_bundled_python_is_root_owned(self):
        self.assertIn("for d in logtriage tools samples python; do", self.sh)

    @unittest.skipUnless(Path(BASH).exists(), "bash 없음")
    def test_reinstall_without_tls_keeps_https(self):
        """GPT 180: --tls 로 깐 서버에서 --tls 없이 다시 설치해도 HTTPS 를 평문으로 내리지 않는다 — 블록을 그대로 꺼내 가짜 /etc 로 돌린다."""
        blk = self.sh[self.sh.index("# >>> HTTPS 유지"):self.sh.index("# <<< HTTPS 유지")]
        for live, want in ((True, "TLS=1"), (False, "TLS=0")):
            with self.subTest(live=live), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "etc/logtriage/tls").mkdir(parents=True)
                (root / "etc/logtriage/tls/server.crt").write_text("x", encoding="utf-8")
                (root / "etc/nginx/conf.d").mkdir(parents=True)
                conf = render = (DEPLOY / "nginx" / "logtriage.conf").read_text(encoding="utf-8")
                if live:   # install.sh --tls 가 주석을 푼 상태
                    render = "\n".join(ln[2:] if ln.startswith("# ") else ln for ln in conf.splitlines())
                (root / "etc/nginx/conf.d/logtriage.conf").write_text(render, encoding="utf-8")
                cmd = 'set -euo pipefail; TLS=0\n%s\necho "TLS=$TLS"' % blk.replace("/etc/", _msys(root) + "/etc/")
                r = subprocess.run([BASH, "-c", cmd], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(want, r.stdout, "HTTPS 서버를 평문으로 내렸습니다" if live else "평문 서버를 HTTPS 로 오판했습니다")
        self.assertLess(self.sh.index("# >>> HTTPS 유지"), self.sh.index('if [ "$TLS" = 1 ]; then\n    mkdir -p /etc/logtriage/tls'))

    def test_reinstall_keeps_port_allow_and_secret(self):
        """패치 뒤 앞단 비밀을 넣으려고 install.sh 를 다시 돌려도 포트 · 로그 폴더 · 비밀이 예전 값 그대로(23차)."""
        self.assertIn('[ "$PORT_SET" = 0 ] && [ -n "$OLDPORT" ]', self.sh)
        self.assertIn('[ "$ALLOW_SET" = 0 ] && [ -n "$OLDALLOW" ] && ALLOW_ARG="$OLDALLOW"', self.sh)
        self.assertLess(self.sh.index('ALLOW_ARG=""; for d in'), self.sh.index('ALLOW_ARG="$OLDALLOW"'), "예전 값을 덮어씁니다")
        self.assertIn('PROXY_SECRET="${OLDPS:-}"', self.sh)
        b = (ENGINE / "tools" / "build" / "build_linux_pkgs.py").read_text(encoding="utf-8")
        self.assertIn("정식 설치는 nginx ↔ 앱 비밀(LOGTRIAGE_PROXY_SECRET)이 필요합니다", b, "패치가 비밀 없는 정식 설치를 알리지 않습니다")


if __name__ == "__main__":
    unittest.main()
