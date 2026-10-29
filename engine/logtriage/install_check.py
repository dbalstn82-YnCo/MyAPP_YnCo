"""정식 설치(install.sh) 점검 — 읽기만 한다(23차, 2026-10-27 RHEL 실서버 검증 매뉴얼).

사용:  sudo bash /opt/logtriage/check_install.sh        (종료 0 = 실패 없음, 1 = 실패 있음)
판정:  [통과] 기대한 대로 · [실패] 고쳐야 함(고치는 법 함께) · [확인] 사람이 보고 판단(환경에 따라 다름)

비밀 값(공용 비밀번호 · 앞단 비밀 · 1회용 코드 · 토큰)은 찍지 않는다 — 권한 · 있음/없음 · 길이 · 일치 여부만.
서버 주소도 찍지 않는다(결과를 그대로 회신해도 되게). 무엇도 고치지 않는다 — 고치는 명령은 사람이 읽고 실행한다.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import stat as st
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PASS, FAIL, LOOK = "통과", "실패", "확인"
RHEL_IDS = ("rhel", "rocky", "almalinux", "centos", "ol")

# install.sh 의 import 경로 점검과 같은 것 — 서비스 계정이 쓸 수 있는 import 경로가 하나라도 있으면 실패
IMPORT_CHECK = """import sys, os
bad = [p for p in (q or os.getcwd() for q in sys.path) if os.path.isdir(p) and os.access(p, os.W_OK)]
import logtriage
pk = os.path.dirname(os.path.realpath(logtriage.__file__))
for r, ds, fs in os.walk(pk):
    for n in ds + fs:
        q = os.path.join(r, n)
        if os.access(q, os.W_OK):
            bad.append(q)
print(len(bad))
for b in bad[:5]:
    print(b)
sys.exit(1 if bad else 0)"""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Checker:
    def __init__(self, inst: str = "/opt/logtriage", etc: str = "/etc/logtriage", svc: str = "logtriage",
                 log: str = "/var/log/logtriage-install.log", root: str = ""):
        self.root = root.rstrip("/")          # 시험용: 시스템 경로 앞에 붙는 가짜 뿌리
        self.inst, self.etc, self.svc, self.log = inst, etc, svc, log
        self.res: list[tuple[str, str, str, str]] = []
        self.env: dict = {}
        self.ip = ""
        self.mode = ""
        self.machine = platform.machine()
        self.web = ""                         # nginx 주소 뒤에 붙는 포트(시험용 — 실제는 80 이라 빈 값)

    # ── 바깥과 닿는 곳(시험에서 바꿔 끼운다) ──
    def P(self, path: str) -> Path:
        return Path(self.root + path) if self.root else Path(path)

    def run(self, cmd: list, timeout: int = 30, cwd: str | None = None) -> tuple:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, cwd=cwd)
        except FileNotFoundError:
            return 127, ""
        except (OSError, subprocess.TimeoutExpired) as e:
            return 126, str(e)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    def meta(self, path: Path):
        """(권한 8진수, 소유자, 그룹) — 없으면 None. 링크는 링크 자체를 본다."""
        try:
            s = os.lstat(path)
        except OSError:
            return None
        try:
            import grp
            import pwd
            u = pwd.getpwuid(s.st_uid).pw_name
            g = grp.getgrgid(s.st_gid).gr_name
        except (ImportError, KeyError):
            u, g = str(s.st_uid), str(s.st_gid)
        return format(st.S_IMODE(s.st_mode), "o"), u, g

    def http(self, url: str, method: str = "GET", headers: dict | None = None, data: bytes | None = None) -> tuple:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)   # 서버의 http_proxy 설정을 타지 않게
        try:
            r = op.open(urllib.request.Request(url, data=data, method=method, headers=headers or {}), timeout=8)
            return r.status, r.read(8192).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 — 연결 거부 · 시간 초과 · 이름 풀이 실패 모두 '닿지 않음'
            return 0, str(e)

    # ── 기록 ──
    def add(self, kind: str, cid: str, what: str, fix: str = ""):
        self.res.append((kind, cid, what, fix))

    def _read(self, path: str) -> str:
        try:
            return self.P(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def _want(self, cid: str, path: str, want: tuple, what: str, fix: str):
        m = self.meta(self.P(path))
        if m is None:
            self.add(FAIL, cid, f"{what}: 없음 ({path})", fix)
        elif m == want:
            self.add(PASS, cid, f"{what}: {m[0]} {m[1]}:{m[2]}")
        else:
            self.add(FAIL, cid, f"{what}: {m[0]} {m[1]}:{m[2]} (기대 {want[0]} {want[1]}:{want[2]})", fix)

    # ── 점검 ──
    def os_checks(self):
        osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', self._read("/etc/os-release"), re.M))
        name, oid, ver = osr.get("PRETTY_NAME", "알 수 없음"), osr.get("ID", ""), osr.get("VERSION_ID", "").split(".")[0]
        if oid in RHEL_IDS and ver in ("8", "9"):
            self.add(PASS, "R01", f"운영체제: {name}")
        else:
            self.add(LOOK, "R01", f"운영체제: {name} — 이 매뉴얼은 RHEL 계열 8 · 9 기준입니다")
        self.add(PASS if self.machine == "x86_64" else LOOK, "R02", f"CPU 구조: {self.machine}")
        rc, out = self.run(["getenforce"])
        se = out.strip()
        if rc == 127:
            self.add(LOOK, "R03", "SELinux: getenforce 없음(SELinux 미설치)")
        elif se == "Enforcing":
            self.add(PASS, "R03", "SELinux: Enforcing — 운영과 같은 조건에서 검증합니다")
        else:
            self.add(LOOK, "R03", f"SELinux: {se or '알 수 없음'} — 운영 서버가 Enforcing 이면 그 상태로 다시 검증하십시오")
        rc, out = self.run(["systemctl", "is-active", "firewalld"])
        if out.strip() == "active":
            rc, svcs = self.run(["firewall-cmd", "--list-services"])
            if re.search(r"(^|\s)http(\s|$)", svcs):
                self.add(PASS, "R05", "방화벽(firewalld): http(80) 열림")
            else:
                self.add(FAIL, "R05", "방화벽(firewalld): http(80) 이 목록에 없음",
                         "firewall-cmd --permanent --add-service=http && firewall-cmd --reload")
        else:
            self.add(LOOK, "R05", "방화벽(firewalld)이 꺼져 있음 — 사내 방화벽 정책상 문제가 없는지 확인")

    def file_checks(self):
        fix = "sudo bash <서버 묶음>/engine/deploy/server/install.sh --skip-pkgs 로 다시 설치(자료는 그대로)"
        self._want("R10", self.inst, ("1770", "root", self.svc), "설치 폴더", fix)
        bad, n = [], 0
        for d in ("logtriage", "tools", "samples", "venv", "python"):   # python = 동봉 Python(있을 때)
            top = self.P(f"{self.inst}/{d}")
            if not top.exists():
                continue
            for r, ds, fs in os.walk(top):
                for name in ds + fs:
                    q = Path(r) / name
                    m = self.meta(q)
                    n += 1
                    if m and not q.is_symlink() and (m[1] != "root" or int(m[0], 8) & 0o022):
                        bad.append(f"{q} {m[0]} {m[1]}")
        for f in ("backup.sh", "uninstall.sh", "check_install.sh"):   # root 가 sudo 로 돌리는 관리 스크립트
            q = self.P(f"{self.inst}/{f}")
            m = self.meta(q) if q.exists() else None
            n += 1 if m else 0
            if m and (m[1] != "root" or int(m[0], 8) & 0o022):
                bad.append(f"{q} {m[0]} {m[1]}")
        if bad:
            self.add(FAIL, "R11", f"코드 · 견본 · venv · 관리 스크립트 중 root 소유 · 쓰기 금지가 아닌 것 {len(bad)}개(첫 항목: {bad[0]})", fix)
        else:
            self.add(PASS, "R11", f"코드 · 견본 · venv · 관리 스크립트 {n}개 항목 모두 root 소유 · 그룹/기타 쓰기 금지")
        py = f"{self.inst}/venv/bin/python"
        rc, out = self.run(["runuser", "-u", self.svc, "--", py, "-E", "-s", "-c", IMPORT_CHECK],
                           cwd=str(self.P(f"{self.inst}/venv/lt-import")))
        if rc == 0:
            self.add(PASS, "R12", "서비스 계정이 고칠 수 있는 import 경로 0개")
        elif rc in (126, 127):     # 검사를 못 한 것은 실패가 아니라 확인(GPT 179)
            self.add(LOOK, "R12", "import 경로 점검을 돌리지 못함(runuser · venv 없음) — install.sh 설치 직후 화면의 'import 경로 점검' 줄을 보십시오")
        else:
            self.add(FAIL, "R12", "서비스 계정이 고칠 수 있는 import 경로가 있음: " + " ".join(out.split())[:200], fix)
        self._want("R13", self.etc, ("750", "root", "root"), "설정 폴더(/etc/logtriage)", f"chmod 750 {self.etc}; chown root:root {self.etc}")
        envp = f"{self.etc}/server.env"
        self._want("R14", envp, ("640", "root", self.svc), "server.env", f"chmod 640 {envp}; chown root:{self.svc} {envp}")
        self.env = dict(re.findall(r"^([A-Z_]+)=(.*)$", self._read(envp), re.M))
        sec = self.env.get("LOGTRIAGE_PROXY_SECRET", "")
        if self.nginx_conf():
            if len(sec) >= 32:
                self.add(PASS, "R15", f"앞단 비밀(LOGTRIAGE_PROXY_SECRET): 있음({len(sec)}자)")
            else:
                self.add(FAIL, "R15", "앞단 비밀(LOGTRIAGE_PROXY_SECRET)이 없거나 32자 미만 — nginx 뒤 사내망 평문 로그인이 403", fix)
            if self.env.get("LOGTRIAGE_HOST", "") != "127.0.0.1":
                self.add(FAIL, "R16", f"앱 수신 주소가 {self.env.get('LOGTRIAGE_HOST') or '(없음)'} — nginx 뒤에서는 127.0.0.1 이어야 합니다",
                         f"{envp} 의 LOGTRIAGE_HOST=127.0.0.1 → systemctl restart logtriage-server")
            else:
                self.add(PASS, "R16", "앱 수신 주소: 127.0.0.1(nginx 만 앱에 닿음)")
        if self.env.get("LOGTRIAGE_PASSWORD", "") in ("", "change-me"):
            self.add(LOOK, "R17", "공용 비밀번호가 비어 있거나 예시 값 — 계정 로그인(기본)이면 쓰지 않지만, 로그인 방식을 바꾸기 전에 바꾸십시오")
        if self.P(self.log).exists():
            self._want("R18", self.log, ("600", "root", "root"), "설치 기록", f"chmod 600 {self.log}; chown root:root {self.log}")
            if re.search(r"비밀번호 : (?!화면)", self._read(self.log)):
                self.add(FAIL, "R19", "설치 기록에 예전 판이 찍은 공용 비밀번호 줄이 있음",
                         f"server.env 의 LOGTRIAGE_PASSWORD 를 바꾸고 systemctl restart logtriage-server, 그 줄은 sed -i '/비밀번호 : /d' {self.log}")
            else:
                self.add(PASS, "R19", "설치 기록에 비밀번호 없음")
        else:
            self.add(LOOK, "R18", f"설치 기록 없음({self.log})")

    def nginx_conf(self) -> str:
        for c in ("/etc/nginx/conf.d/logtriage.conf", "/etc/nginx/sites-available/logtriage"):
            if self.P(c).exists():
                return c
        return ""

    def nginx_checks(self):
        c = self.nginx_conf()
        if not c:
            self.add(LOOK, "R20", "nginx 설정 없음 — --no-nginx 설치이면 정상, 아니면 install.sh 를 다시 실행")
            return
        self._want("R20", c, ("600", "root", "root"), "nginx 설정(앞단 비밀 포함)", f"chmod 600 {c}; chown root:root {c}")
        txt = self._read(c)
        live = [ln for ln in txt.splitlines() if not ln.lstrip().startswith("#")]
        got = [m.group(1) for ln in live for m in [re.search(r"proxy_set_header\s+X-LogTriage-Proxy\s+(\S+);", ln)] if m]
        sec = self.env.get("LOGTRIAGE_PROXY_SECRET", "")
        if "__PROXY_SECRET__" in "\n".join(live) or not got:
            self.add(FAIL, "R21", "nginx 가 앞단 비밀을 싣지 않음(자리표시 그대로이거나 줄 없음)", "install.sh --skip-pkgs 로 다시 설치")
        elif all(g == sec for g in got):
            self.add(PASS, "R21", f"nginx 앞단 비밀 = server.env 값(일치, {len(got)}곳)")
        else:
            self.add(FAIL, "R21", "nginx 앞단 비밀이 server.env 값과 다름 — 사내망 평문 로그인이 403 이 됩니다",
                     "두 곳을 같은 값으로(또는 install.sh --skip-pkgs 다시) → systemctl reload nginx")
        if any("logtriage_noquery" in ln and "access_log" in ln for ln in live):
            self.add(PASS, "R22", "nginx 접속 기록: 주소의 ? 뒤(1회용 코드 · 내려받기 표)를 적지 않는 형식")
        else:
            self.add(LOOK, "R22", "nginx 접속 기록이 기본 형식 — /setup?t= · ?ticket= 이 기록에 남습니다(설치매뉴얼 보안 점검표)")
        rc, out = self.run(["nginx", "-t"])
        self.add(PASS if rc == 0 else FAIL, "R23", "nginx 설정 문법(nginx -t): " + ("정상" if rc == 0 else " ".join(out.split())[-200:]),
                 "" if rc == 0 else "위 오류 줄을 고친 뒤 nginx -t → systemctl reload nginx")
        rc, out = self.run(["getsebool", "httpd_can_network_connect"])
        if rc == 127:
            self.add(LOOK, "R04", "SELinux 불리언: getsebool 없음")
        elif "--> on" in out:
            self.add(PASS, "R04", "SELinux: httpd_can_network_connect = on(nginx → 127.0.0.1 앱 연결 허용)")
        else:
            self.add(FAIL, "R04", "SELinux: httpd_can_network_connect = off — nginx 가 앱에 못 붙어 502", "setsebool -P httpd_can_network_connect 1")

    def service_checks(self):
        units = ["logtriage-server"] + (["nginx"] if self.nginx_conf() else [])
        if self.env.get("LOGTRIAGE_DB", "").startswith("postgresql://"):
            units.append("postgresql")
        for u in units:
            _, a = self.run(["systemctl", "is-active", u])
            _, e = self.run(["systemctl", "is-enabled", u])
            a, e = a.strip(), e.strip()
            if a == "active" and e == "enabled":
                self.add(PASS, "R30", f"서비스 {u}: 실행 중 · 부팅 시 자동 시작")
            else:
                self.add(FAIL, "R30", f"서비스 {u}: {a or '?'} · {e or '?'}", f"systemctl enable --now {u}; journalctl -u {u} -n 50 --no-pager")
        _, a = self.run(["systemctl", "is-active", "logtriage-cleanup.timer"])
        self.add(PASS if a.strip() == "active" else FAIL, "R31", f"업로드 원본 정리 타이머: {a.strip() or '?'}",
                 "" if a.strip() == "active" else "systemctl enable --now logtriage-cleanup.timer")
        _, out = self.run(["systemctl", "show", "logtriage-server", "-p", "User", "-p", "NoNewPrivileges", "-p", "ProtectSystem", "-p", "MainPID"])
        sh = dict(re.findall(r"^(\w+)=(.*)$", out, re.M))
        want = {"User": self.svc, "NoNewPrivileges": "yes", "ProtectSystem": "full"}
        diff = [f"{k}={sh.get(k, '?')}" for k, v in want.items() if sh.get(k) != v]
        self.add(PASS if not diff else FAIL, "R32", "서비스 격리(User · NoNewPrivileges · ProtectSystem): " + ("기대대로" if not diff else ", ".join(diff)),
                 "" if not diff else "install.sh --skip-pkgs 로 유닛 파일을 다시 쓰십시오(손으로 고친 유닛이면 되돌리기)")
        pid = sh.get("MainPID", "0")
        if pid.isdigit() and pid != "0":
            cmd = self._read(f"/proc/{pid}/cmdline").replace("\x00", " ")
            m = self.meta(self.P(f"/proc/{pid}"))
            if "--password " in cmd + " ":
                self.add(FAIL, "R33", "서버 실행 줄에 --password 가 있음(ps 로 누구나 봄)", "유닛 파일에서 빼고 server.env 로")
            else:
                self.add(PASS, "R33", f"서버 프로세스: 계정 {m[1] if m else '?'} · 실행 줄에 비밀번호 없음")

    def port_checks(self):
        port = self.env.get("LOGTRIAGE_PORT", "8088") or "8088"
        rc, out = self.run(["ss", "-Hlnt"])
        if rc == 127:
            self.add(LOOK, "R40", "ss 명령 없음 — netstat -lnt 로 직접 확인")
            return port
        loc = [ln.split()[3] for ln in out.splitlines() if len(ln.split()) >= 4]
        app = [a for a in loc if a.rsplit(":", 1)[-1] == port]
        if not app:
            self.add(FAIL, "R40", f"앱 포트 {port} 를 듣는 프로세스가 없음", "systemctl status logtriage-server; journalctl -u logtriage-server -n 50")
        elif self.nginx_conf() and any(not a.startswith(("127.0.0.1:", "[::1]:")) for a in app):
            self.add(FAIL, "R40", f"앱 포트 {port} 가 바깥에도 열려 있음(nginx 를 거치지 않는 길)", "server.env LOGTRIAGE_HOST=127.0.0.1 → 재시작")
        else:
            self.add(PASS, "R40", f"앱 포트 {port}: " + ", ".join(sorted(set(app))))
        if self.nginx_conf():
            web = [a for a in loc if a.rsplit(":", 1)[-1] == "80"]
            self.add(PASS if web else FAIL, "R41", "웹 포트 80: " + (", ".join(sorted(set(web))) if web else "듣는 곳 없음"),
                     "" if web else "systemctl status nginx")
        return port

    def http_checks(self, port: str):
        s, body = self.http(f"http://127.0.0.1:{port}/healthz")
        try:
            j = json.loads(body)
        except ValueError:
            j = {}
        if s == 200 and j.get("ok"):
            self.add(PASS, "R50", f"앱 상태(healthz): 정상 · 판 {j.get('version', '?')} · 판 지문 {j.get('build_id', '?')} · 코드 지문 {j.get('code_id', '?')}")
        else:
            self.add(FAIL, "R50", f"앱 상태(healthz) 응답 {s}", "journalctl -u logtriage-server -n 50 --no-pager")
        try:
            a = json.loads(self._read(f"{self.inst}/conf/auth.json") or "{}")
        except ValueError:
            a = {"mode": "(auth.json 형식 오류)"}
        self.mode = a.get("mode", "") if isinstance(a, dict) else ""
        self.add(PASS if self.mode in ("local", "portal") else LOOK, "R51",
                 "로그인 방식: " + {"local": "회사 이메일 계정(기본)", "portal": "통합 로그인", "off": "로그인 없음"}.get(self.mode, self.mode or "설정 없음"))
        if not self.nginx_conf():
            return
        s, _ = self.http(f"http://127.0.0.1{self.web}/healthz")
        self.add(PASS if s == 200 else FAIL, "R52", f"nginx 경유 상태 확인: {s}", "" if s == 200 else "systemctl status nginx; tail /var/log/nginx/logtriage_error.log")
        _, out = self.run(["hostname", "-I"])
        self.ip = (out.split() or [""])[0]
        if not self.ip:
            self.add(LOOK, "R53", "서버 주소를 못 찾음(hostname -I) — 다른 PC 에서 http://<서버>/login 을 직접 여십시오")
            return
        s, _ = self.http(f"http://{self.ip}{self.web}/login")
        if s in (200, 302, 303):
            self.add(PASS, "R53", f"사내망 평문 접속(서버 주소 → nginx 80 → /login): {s} — 막히지 않음")
        elif s == 403:
            self.add(FAIL, "R53", "사내망 평문 접속이 403 — 앞단 비밀 불일치이거나 옛 판", "R15 · R21 을 먼저 고치고 systemctl restart logtriage-server nginx")
        else:
            self.add(FAIL, "R53", f"사내망 평문 접속 응답 {s}", "systemctl status nginx logtriage-server")
        s, _ = self.http(f"http://{self.ip}{self.web}/api/nms/metrics", "POST", {"Content-Type": "application/json"}, b"{}")
        if s == 401:
            self.add(PASS, "R54", "에이전트 수치 받는 길(nginx 80 /api/nms/metrics): 열림(토큰 없이 보내 401)")
        else:
            self.add(FAIL, "R54", f"에이전트 수치 받는 길 응답 {s} — 에이전트 보고가 안 들어옵니다",
                     "301 이면 --tls 의 80→443 전환(HTTPS 보류 중에는 --tls 없이 설치), 0 이면 방화벽 · nginx")
        if self.mode in ("local", "portal"):
            s, _ = self.http(f"http://127.0.0.1:{port}/login", headers={"X-Forwarded-Proto": "http", "X-Real-IP": "10.0.0.1", "X-Forwarded-For": "10.0.0.1"})
            if s == 403:
                self.add(PASS, "R55", "위조 반례: 앱 포트에 직접 nginx 머리글을 꾸며 보내면 거절(403)")
            else:
                self.add(FAIL, "R55", f"위조 반례가 통과({s}) — 같은 서버의 다른 계정이 사내망 접속자로 행세할 수 있음", "옛 판이면 패치, 아니면 개발팀에 이 결과 전달")

    def data_checks(self):
        k = f"{self.inst}/conf/secret.key"
        if self.P(k).exists():
            self._want("R60", k, ("600", self.svc, self.svc), "서버 키(conf/secret.key)", f"chmod 600 {k}; chown {self.svc}:{self.svc} {k}")
        else:
            self.add(LOOK, "R60", "서버 키(conf/secret.key)가 아직 없음 — 첫 로그인 뒤에 생깁니다")
        sc = f"{self.inst}/conf/setup-code.txt"
        if self.P(sc).exists():
            m = self.meta(self.P(sc))
            self.add(LOOK, "R61", f"첫 관리자가 아직 없음 — 1회용 코드 파일 있음(권한 {m[0] if m else '?'}). 매뉴얼 '첫 관리자' 장으로")
        else:
            self.add(PASS, "R61", "첫 관리자 만들어짐(1회용 코드 파일 닫힘)")
        rng = self._read("/proc/sys/net/ipv4/ping_group_range").split()
        rc, gid = self.run(["id", "-g", self.svc])
        if len(rng) == 2 and gid.strip().isdigit() and int(rng[0]) <= int(gid) <= int(rng[1]):
            self.add(PASS, "R62", "ICMP(ping) 감시 허용 범위에 서비스 그룹 포함")
        else:
            self.add(LOOK, "R62", "ICMP(ping) 감시가 안 될 수 있음 — /etc/sysctl.d/90-logtriage-ping.conf 확인, 아니면 TCP 감시로")
        py = f"{self.inst}/venv/bin/python"
        rc, out = self.run([py, "-E", "-s", "-c", "import sys, yaml, lxml.etree, cryptography; print('%d.%d' % sys.version_info[:2])"])
        if rc == 0:
            self.add(PASS, "R63", f"파이썬 {out.strip()} · PyYAML · lxml · cryptography 가져오기 정상")
        else:
            self.add(FAIL, "R63", "파이썬 의존성 가져오기 실패: " + " ".join(out.split())[-160:], "install.sh --skip-pkgs 다시(동봉 wheel)")

    def log_checks(self):
        rc, out = self.run(["journalctl", "-u", "logtriage-server", "-b", "--no-pager", "-o", "cat"])
        if rc == 127:
            self.add(LOOK, "R70", "journalctl 없음")
        else:
            n = out.count("Traceback")
            self.add(PASS if n == 0 else FAIL, "R70", f"이번 부팅의 서버 기록에 Traceback {n}건",
                     "" if n == 0 else "journalctl -u logtriage-server -b --no-pager | grep -A20 Traceback 결과를 개발팀에 전달")
        # 접속 기록 · 오류 기록(요청 줄을 그대로 적는다) · 회전된 기록까지(GPT 179). 압축(.gz)된 것은 열지 않는다
        d = self.P("/var/log/nginx")
        logs = sorted(q for q in d.glob("logtriage_*.log*") if not q.name.endswith(".gz")) if d.is_dir() else []
        if logs:
            n = sum(len(re.findall(r"(\?t=|[?&]ticket=)", q.read_text(encoding="utf-8", errors="replace"))) for q in logs)
            self.add(PASS if n == 0 else LOOK, "R71", f"nginx 기록 {len(logs)}개(접속 · 오류 · 회전본)의 1회용 값 {n}건"
                     + ("" if n == 0 else " — 형식을 바꾸기 전 기록 또는 오류 기록입니다. 이미 쓴 값은 효력이 없지만 정리를 권합니다(.gz 회전본은 직접 확인)"))
        rc, out = self.run(["ausearch", "-m", "avc", "-ts", "boot"])
        if rc == 127:
            self.add(LOOK, "R72", "SELinux 거부 기록: ausearch 없음(audit 패키지)")
        else:
            n = len(re.findall(r'comm="(nginx|python[0-9.]*)"', out))
            self.add(PASS if n == 0 else FAIL, "R72", f"SELinux 거부(AVC, nginx · python) 이번 부팅 {n}건",
                     "" if n == 0 else "ausearch -m avc -ts boot | audit2why 결과를 개발팀에 전달")

    def agent_checks(self):
        u = self._read("/etc/systemd/system/lt-agent.service")
        if not u:
            return
        ex = next((ln for ln in u.splitlines() if ln.startswith("ExecStart=")), "")
        if "EnvironmentFile=" in u and re.search(r"\s-\s+\d+", ex):
            self.add(PASS, "R80", "이 서버의 에이전트 서비스: 토큰이 실행 줄에 없음(환경 파일)")
            env = next((ln.split("=", 1)[1].strip() for ln in u.splitlines() if ln.startswith("EnvironmentFile=")), "")
            if env:
                self._want("R81", env.lstrip("-"), ("600", "root", "root"), "에이전트 토큰 파일", f"chmod 600 {env}")
        else:
            self.add(FAIL, "R80", "이 서버의 에이전트 서비스가 토큰을 실행 줄에 넣은 예전 설치 — ps 로 누구나 봅니다",
                     "새 lt-agent-install.sh 로 다시 설치(토큰 자리 '-', 표준 입력)")

    def all(self):
        self.os_checks()
        self.file_checks()
        self.nginx_checks()
        self.service_checks()
        port = self.port_checks()
        self.http_checks(port)
        self.data_checks()
        self.log_checks()
        self.agent_checks()
        return self.res


def report(res, out=sys.stdout) -> int:
    for kind, cid, what, fix in res:
        print(f"[{kind}] {cid} {what}", file=out)
        if fix:
            print(f"         고치는 법: {fix}", file=out)
    n = {k: sum(1 for r in res if r[0] == k) for k in (PASS, FAIL, LOOK)}
    print(f"\n결과: 통과 {n[PASS]} · 실패 {n[FAIL]} · 확인 {n[LOOK]}"
          + ("  — 실패 항목의 '고치는 법' 을 실행한 뒤 다시 돌리십시오" if n[FAIL] else "  — 실패 없음"), file=out)
    return 1 if n[FAIL] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="LogTriage 정식 설치 점검(읽기만)")
    ap.add_argument("--install-dir", default=os.environ.get("INSTALL_DIR", "/opt/logtriage"))
    ap.add_argument("--etc", default="/etc/logtriage")
    ap.add_argument("--svc-user", default=os.environ.get("SVC_USER", "logtriage"))
    a = ap.parse_args(argv)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("root 로 실행하십시오: sudo bash check_install.sh   (권한 · 설정 파일을 읽어야 합니다)")
        return 2
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass
    try:
        from . import buildid
        tool = buildid.code()
    except Exception:  # noqa: BLE001 — 지문을 못 구해도 점검은 한다
        tool = "?"
    print(f"LogTriage 정식 설치 점검 — {socket.gethostname()} · {time.strftime('%Y-%m-%d %H:%M')} · 점검 도구 코드 지문 {tool} · 읽기만 합니다(아무것도 고치지 않음)")
    print("R52~R55 는 이 서버의 실제 nginx 를 거쳐 확인합니다(개발 PC 의 모의 시험과 다름). 서버 판 지문은 R50 줄에 있습니다.\n")
    return report(Checker(a.install_dir, a.etc, a.svc_user).all())


if __name__ == "__main__":
    sys.exit(main())
