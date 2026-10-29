# -*- coding: utf-8 -*-
"""23차 — 정식 설치 점검 도구(logtriage.install_check · deploy/server/check_install.sh).

RHEL 실기가 이 PC 에 없다. 그래서 두 겹으로 본다.
① 정상 설치를 흉내 낸 가짜 뿌리(파일 · 권한 · 명령 출력)에서 실패 0, 고장을 하나씩 넣으면 **그 항목이** 실패로 잡히는지
② 평문 접속 · 위조 반례(R52~R55)는 **진짜 서버**를 띄우고, 우리 nginx 설정과 같은 머리글을 붙이는 작은 앞단을 그 앞에 두어 왕복
   — 점검 도구가 맞다고 한 것이 실제 서버 동작과 같은지(도구만 맞고 서버는 다른 경우를 막는다)."""
from __future__ import annotations

import http.client
import http.server
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from logtriage import install_check as IC  # noqa: E402
from logtriage import server as S  # noqa: E402
from test_enterprise import Srv, prep_base  # noqa: E402

SECRET = "5be1" * 16
DEPLOY = ENGINE / "deploy" / "server"


def render_conf(secret=SECRET, port=8088):
    t = (DEPLOY / "nginx" / "logtriage.conf").read_text(encoding="utf-8")
    return t.replace("127.0.0.1:8088", f"127.0.0.1:{port}").replace("__PROXY_SECRET__", secret)


class Fake(IC.Checker):
    """시스템과 닿는 세 곳(run · meta · http)을 표로 바꿔 끼운다."""

    def __init__(self, root):
        super().__init__(root=root)
        self.machine = "x86_64"
        self.cmds = {
            ("getenforce",): (0, "Enforcing\n"),
            ("systemctl", "is-active", "firewalld"): (0, "active\n"),
            ("firewall-cmd", "--list-services"): (0, "cockpit dhcpv6-client http ssh\n"),
            ("getsebool", "httpd_can_network_connect"): (0, "httpd_can_network_connect --> on\n"),
            ("nginx", "-t"): (0, "nginx: configuration file /etc/nginx/nginx.conf test is successful\n"),
            ("ss", "-Hlnt"): (0, "LISTEN 0 128 127.0.0.1:8088 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\nLISTEN 0 511 [::]:80 [::]:*\n"),
            ("hostname", "-I"): (0, "10.20.30.5 \n"),
            ("id", "-g", "logtriage"): (0, "990\n"),
            ("journalctl",): (0, "[LogTriage] 기동 완료\n"),
            ("ausearch",): (1, "<no matches>\n"),
            ("runuser",): (0, "0\n"),
            ("/opt/logtriage/venv/bin/python",): (0, "3.9\n"),
            ("systemctl", "show"): (0, "User=logtriage\nNoNewPrivileges=yes\nProtectSystem=full\nMainPID=1234\n"),
            ("systemctl", "is-active"): (0, "active\n"),
            ("systemctl", "is-enabled"): (0, "enabled\n"),
        }
        self.metas = {}
        self.urls = {
            "http://127.0.0.1:8088/healthz": (200, '{"ok": true, "version": "1.0.0", "build_id": "b", "code_id": "c"}'),
            "http://127.0.0.1/healthz": (200, "{}"),
            "http://10.20.30.5/login": (302, ""),
            "http://10.20.30.5/api/nms/metrics": (401, ""),
            "http://127.0.0.1:8088/login": (403, ""),
        }

    def run(self, cmd, timeout=30, cwd=None):
        for n in (len(cmd), 3, 2, 1):
            k = tuple(cmd[:n])
            if k in self.cmds:
                return self.cmds[k]
        return 127, ""

    def meta(self, path):
        pp = Path(path).as_posix()
        rel = pp[len(self.root):] if pp.startswith(self.root) else pp
        if rel in self.metas:
            return self.metas[rel]
        if not Path(path).exists() and not rel.startswith("/proc/"):
            return None
        return {"/opt/logtriage": ("1770", "root", "logtriage"), "/etc/logtriage": ("750", "root", "root"),
                "/etc/logtriage/server.env": ("640", "root", "logtriage"), "/var/log/logtriage-install.log": ("600", "root", "root"),
                "/etc/nginx/conf.d/logtriage.conf": ("600", "root", "root"),
                "/opt/logtriage/conf/secret.key": ("600", "logtriage", "logtriage"),
                "/proc/1234": ("555", "logtriage", "logtriage")}.get(rel, ("644", "root", "root"))

    def http(self, url, method="GET", headers=None, data=None):
        return self.urls.get(url, (0, "연결 거부"))


def build_root(td: Path) -> str:
    r = td.as_posix()
    files = {
        "/etc/os-release": 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="9.4"\nPRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"\n',
        "/opt/logtriage/logtriage/server.py": "#", "/opt/logtriage/tools/x.py": "#", "/opt/logtriage/samples/a.log": "x",
        "/opt/logtriage/venv/bin/python": "", "/opt/logtriage/venv/lt-import/.keep": "",
        "/opt/logtriage/backup.sh": "#", "/opt/logtriage/uninstall.sh": "#", "/opt/logtriage/check_install.sh": "#",
        "/opt/logtriage/conf/auth.json": '{"mode": "local"}', "/opt/logtriage/conf/secret.key": "k",
        "/etc/logtriage/server.env": f"LOGTRIAGE_HOST=127.0.0.1\nLOGTRIAGE_PORT=8088\nLOGTRIAGE_PASSWORD=Rk3vQ9zTx2mA\n"
                                     f"LOGTRIAGE_DB=sqlite:////opt/logtriage/data/logtriage.db\nLOGTRIAGE_PROXY_SECRET={SECRET}\n",
        "/var/log/logtriage-install.log": "  비밀번호 : 화면 · 설치 기록에 적지 않습니다\n",
        "/etc/nginx/conf.d/logtriage.conf": render_conf(),
        "/proc/sys/net/ipv4/ping_group_range": "990\t990\n",
        "/proc/1234/cmdline": "/opt/logtriage/venv/bin/python\x00-m\x00logtriage.server\x00--port\x008088\x00",
        "/var/log/nginx/logtriage_access.log": '10.20.30.40 - - [27/Oct/2026:10:00:00 +0900] "GET /login HTTP/1.1" 200 1 "x" 0.01\n',
    }
    for k, v in files.items():
        p = Path(r + k)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(v, encoding="utf-8")
    return r


class CheckerTableTest(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.root = build_root(Path(self.td.name))

    def tearDown(self):
        self.td.cleanup()

    def _run(self, mutate=None):
        f = Fake(self.root)
        if mutate:
            mutate(f)
        res = f.all()
        return f, {(k, c) for k, c, _, _ in res}, res

    def test_a_good_install_has_no_failure(self):
        f, got, res = self._run()
        fails = [r for r in res if r[0] == IC.FAIL]
        self.assertEqual(fails, [], fails)
        for cid in ("R01", "R03", "R04", "R10", "R11", "R12", "R14", "R15", "R16", "R19", "R20", "R21", "R22", "R23",
                    "R30", "R31", "R32", "R33", "R40", "R41", "R50", "R52", "R53", "R54", "R55", "R60", "R62", "R63", "R70", "R72"):
            self.assertIn((IC.PASS, cid), got, cid)
        out = io.StringIO()
        self.assertEqual(IC.report(res, out), 0)
        text = out.getvalue()
        for secret in (SECRET, "Rk3vQ9zTx2mA", "10.20.30.5"):
            self.assertNotIn(secret, text, "점검 결과에 비밀 값 · 서버 주소가 찍혔습니다")

    def test_each_fault_is_caught_by_its_own_item(self):
        def W(rel, txt):
            def w(f):
                Path(self.root + rel).parent.mkdir(parents=True, exist_ok=True)
                Path(self.root + rel).write_text(txt, encoding="utf-8")
            return w
        def meta(rel, m):
            return lambda f: f.metas.__setitem__(rel, m)
        def cmd(k, v):
            return lambda f: f.cmds.__setitem__(k, v)
        def url(u, v):
            return lambda f: f.urls.__setitem__(u, v)
        faults = {
            "R21": W("/etc/nginx/conf.d/logtriage.conf", render_conf(secret="0" * 64)),           # nginx 와 server.env 비밀이 다름
            "R14": meta("/etc/logtriage/server.env", ("644", "root", "root")),                     # 모두 읽기
            "R19": W("/var/log/logtriage-install.log", "  비밀번호 : Abcd1234xyz      (변경: …)\n"),   # 옛 판이 찍은 비밀번호
            "R18": meta("/var/log/logtriage-install.log", ("644", "root", "root")),
            "R20": meta("/etc/nginx/conf.d/logtriage.conf", ("644", "root", "root")),
            "R53": url("http://10.20.30.5/login", (403, "")),                                        # 결함 A 재발
            "R55": url("http://127.0.0.1:8088/login", (200, "")),                                    # 위조 머리글을 믿음
            "R54": url("http://10.20.30.5/api/nms/metrics", (301, "")),                              # --tls 일괄 전환
            "R04": cmd(("getsebool", "httpd_can_network_connect"), (0, "httpd_can_network_connect --> off\n")),
            "R40": cmd(("ss", "-Hlnt"), (0, "LISTEN 0 128 0.0.0.0:8088 0.0.0.0:*\nLISTEN 0 511 0.0.0.0:80 0.0.0.0:*\n")),
            "R11": meta("/opt/logtriage/backup.sh", ("644", "logtriage", "logtriage")),             # 서비스가 고칠 수 있는 root 스크립트
            "R12": cmd(("runuser",), (1, "1\n/opt/logtriage/venv/lt-import\n")),
            "R70": cmd(("journalctl",), (0, "Traceback (most recent call last):\n")),
            "R72": cmd(("ausearch",), (0, 'type=AVC msg=audit(1): avc: denied { name_connect } comm="nginx"\n')),
            "R32": cmd(("systemctl", "show"), (0, "User=root\nNoNewPrivileges=no\nProtectSystem=no\nMainPID=1234\n")),
            "R33": W("/proc/1234/cmdline", "python\x00-m\x00logtriage.server\x00--password\x00x\x00"),
            "R15": W("/etc/logtriage/server.env", "LOGTRIAGE_HOST=127.0.0.1\nLOGTRIAGE_PORT=8088\nLOGTRIAGE_PASSWORD=Rk3vQ9zTx2mA\n"),
            "R80": W("/etc/systemd/system/lt-agent.service", "[Service]\nExecStart=/bin/bash /opt/lt-agent/lt-agent.sh http://10.0.0.5:8088 abcTOKEN 30 all\n"),
        }
        for cid, mut in faults.items():
            with self.subTest(cid=cid):
                self.tearDown(); self.setUp()
                _, got, res = self._run(mut)
                self.assertIn((IC.FAIL, cid), got, [r for r in res if r[0] != IC.PASS])
                self.assertTrue(all(r[3] for r in res if r[0] == IC.FAIL), "실패 항목에 고치는 법이 없습니다")
                out = io.StringIO()
                self.assertEqual(IC.report(res, out), 1)
                self.assertNotIn("abcTOKEN", out.getvalue())

    def test_new_agent_unit_passes(self):
        p = Path(self.root + "/etc/systemd/system/lt-agent.service")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("[Service]\nEnvironmentFile=/etc/lt-agent/agent.env\nExecStart=/bin/bash /opt/lt-agent/lt-agent.sh http://10.0.0.5:8088 - 30 all\n", encoding="utf-8")
        e = Path(self.root + "/etc/lt-agent/agent.env")
        e.parent.mkdir(parents=True, exist_ok=True)
        e.write_text("LT_AGENT_TOKEN=x\n", encoding="utf-8")
        f, got, res = self._run(lambda f: f.metas.__setitem__("/etc/lt-agent/agent.env", ("600", "root", "root")))
        self.assertIn((IC.PASS, "R80"), got)
        self.assertIn((IC.PASS, "R81"), got)


class _MiniNginx(http.server.BaseHTTPRequestHandler):
    """우리 logtriage.conf 의 location / 와 같은 일: X-Real-IP = 접속 주소, XFF 는 뒤에 붙이고, Proto = http, 앞단 비밀."""
    app_port = 0
    secret = SECRET

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        h = {k: v for k, v in self.headers.items() if k.lower() not in ("x-real-ip", "x-forwarded-proto", "x-logtriage-proxy", "host", "connection")}
        xff = self.headers.get("X-Forwarded-For")
        h["X-Forwarded-For"] = (xff + ", " if xff else "") + self.client_address[0]
        h["X-Real-IP"] = self.client_address[0]
        h["X-Forwarded-Proto"] = "http"
        h["Host"] = self.headers.get("Host", "")
        h["X-LogTriage-Proxy"] = self.secret
        c = http.client.HTTPConnection("127.0.0.1", self.app_port, timeout=15)
        c.request(self.command, self.path, body, h)
        r = c.getresponse()
        data = r.read()
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = _go

    def log_message(self, *a):
        pass


class RealServerTest(unittest.TestCase):
    """R50~R55 를 진짜 서버 + nginx 흉내 앞단으로 — 도구의 판정이 실제 서버 동작과 같은가."""

    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"LOGTRIAGE_PROXY_SECRET": SECRET})
        self.env.start()
        self.td = tempfile.TemporaryDirectory()
        base = prep_base(Path(self.td.name) / "opt", auth={"mode": "local", "first_admin": "",
                                                           "local": {"domain": "solideos.com", "scrypt_n": 12, "signup": "approve"}})
        self.s = Srv(base)
        _MiniNginx.app_port = self.s.port
        self.px = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MiniNginx)
        threading.Thread(target=self.px.serve_forever, daemon=True).start()
        self.root = build_root(Path(self.td.name) / "root")
        shutil.copy(Path(base) / "conf" / "auth.json", self.root + "/opt/logtriage/conf/auth.json")

    def tearDown(self):
        self.px.shutdown(); self.px.server_close()
        self.s.close()
        self.td.cleanup()
        self.env.stop()

    def _checker(self):
        f = Fake(self.root)
        f.web = f":{self.px.server_address[1]}"
        f.cmds[("hostname", "-I")] = (0, "127.0.0.1\n")    # 이 PC 에서는 접속 주소가 루프백(사설 판정과 같은 갈래)
        f.http = IC.Checker.http.__get__(f)                 # http 만 진짜로
        return f

    def test_tool_agrees_with_the_real_server(self):
        f = self._checker()
        f.env = {"LOGTRIAGE_PORT": str(self.s.port), "LOGTRIAGE_PROXY_SECRET": SECRET}
        f.nginx_conf = lambda: "/etc/nginx/conf.d/logtriage.conf"
        f.http_checks(str(self.s.port))
        got = {(k, c): w for k, c, w, _ in f.res}
        for cid in ("R50", "R51", "R52", "R53", "R54", "R55"):
            self.assertIn((IC.PASS, cid), got, f.res)

    def test_tool_catches_a_mismatched_secret_on_the_real_server(self):
        _MiniNginx.secret = "1" * 64          # nginx 쪽 비밀이 server.env 와 다르면
        try:
            f = self._checker()
            f.env = {"LOGTRIAGE_PORT": str(self.s.port)}
            f.nginx_conf = lambda: "/etc/nginx/conf.d/logtriage.conf"
            f.http_checks(str(self.s.port))
            self.assertIn((IC.FAIL, "R53"), {(k, c) for k, c, _, _ in f.res}, f.res)   # 진짜 서버가 403 을 낸다
        finally:
            _MiniNginx.secret = SECRET


class WrapperTest(unittest.TestCase):
    def test_wrapper_is_read_only_and_lf(self):
        b = (DEPLOY / "check_install.sh").read_bytes()
        self.assertNotIn(b"\r", b)
        t = b.decode("utf-8")
        self.assertIn("-m logtriage.install_check", t)
        self.assertIn('[ "$(id -u)" -eq 0 ]', t)
        sh = (DEPLOY / "install.sh").read_text(encoding="utf-8")
        self.assertIn('"$HERE/check_install.sh" "$INSTALL_DIR/"', sh, "정식 설치에 점검 도구가 빠졌습니다")
        self.assertRegex(sh, r"for f in backup\.sh uninstall\.sh check_install\.sh[^\n]*; do\n\s+\[ -f \"\$INSTALL_DIR/\$f\" \] \|\| continue\n\s+chown root:root[^\n]*\*\.sh\) chmod 755")

    def test_never_writes(self):
        src = (ENGINE / "logtriage" / "install_check.py").read_text(encoding="utf-8")
        for bad in ("write_text(", "write_bytes(", "unlink(", "rmtree", "chmod(", "chown(", '"w"', "'w'", "setsebool -P", "os.remove"):
            code = "\n".join(ln for ln in src.splitlines() if "고치는 법" not in ln and not ln.lstrip().startswith("#"))
            if bad == "setsebool -P":
                continue            # 고치는 법 문구 안에만 있다(실행하지 않음)
            self.assertNotIn(bad, code, "점검 도구가 무언가를 바꿉니다: " + bad)
        self.assertNotRegex(src, r"self\.run\(\[\"(setsebool|chmod|chown|firewall-cmd\", \"--permanent|systemctl\", \"(start|restart|enable))")


if __name__ == "__main__":
    unittest.main()
