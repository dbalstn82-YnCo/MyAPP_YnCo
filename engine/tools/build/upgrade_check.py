# -*- coding: utf-8 -*-
"""옛 설치 -> 새 패키지 업그레이드 시험 (GPT: "마지막 관문")

"신규 설치만 깨끗한 빌드는 지금처럼 패치가 많이 누적된 제품에서는 충분하지 않습니다."

그래서 **진짜 옛 판으로 자료를 쌓고, 그 자료 위에 새 판을 올린다.**
단위 시험이 아니라 **구버전 서버 상태 -> 새 서버 기동** 으로 본다(GPT 5차 권고).

  1 보존·승계   옛 판으로 자료를 쌓고 새 판으로 올려 자료·신원·잠금이 유지되는가
  2 중단 뒤 재개 승계가 중간에 끊겼다 다시 돌아도 결과가 같은가
  3 두 번 올림  같은 업그레이드를 두 번 해도 상태가 더 바뀌지 않는가(idempotence)
  4 옛 위험설정 없앤 설정(allow_http·verify_tls=false·평문 주소)이 새 판에서 되살아나는가
  5 옛 세션     옛 판에서 받은 로그인 쿠키가 새 판에서 끊기는가
  6 멈춤 상태   보내기 금지 표식을 들고 올라오면 그대로 멈춰 있는가
  7 묵은 ID     역할을 바꾸며 남은 사이트 ID 를 진짜 신원으로 못 박아 버리지 않는가

사용:  python tools/build/upgrade_check.py [작업폴더]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse as _up
import urllib.request
import zipfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
OUT = Path(r"C:\Users\dbals\Desktop\로그수집기\반출")
NEW_ENGINE = Path(r"C:\Users\dbals\Desktop\로그수집기\engine")
# 직접 업그레이드를 지원하는 **가장 오래된 판**. 지원 범위를 적어 두지 않으면 더 오래된
# 설치가 바로 올라오는 것이 가장 위험하다(GPT 5차). 릴리스 노트에도 같은 값을 적는다.
OLDEST = "2026.09.30"
OLD_ZIP = OUT / f"logtriage-linux-patch-{OLDEST}-py311.zip"
WORK = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.mkdtemp())
PORT = 8721
fails = []
_phase = [""]


def say(ok, what, extra=""):
    print(f"  {'OK ' if ok else '!! '} {what}{(' — ' + extra) if extra else ''}")
    if not ok:
        fails.append(f"[{_phase[0]}] {what}")


def phase(n, title):
    _phase[0] = title
    print()
    print(f"[{n}] {title}")


# ── 서버 다루기 ──────────────────────────────────────────────────────
def get(path, cookie="", timeout=10):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}")
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """로그인은 302 로 넘긴다 — **따라가면 Set-Cookie 를 놓친다.**"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_PLAIN = urllib.request.build_opener(_NoRedirect)


def post(path, body, cookie=""):
    data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    hd = {"Content-Type": "application/json", "X-NMS-Request": "1"}
    if isinstance(body, bytes):
        hd["Content-Type"] = "application/x-www-form-urlencoded"
    if cookie:
        hd["Cookie"] = cookie
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data,
                                 method="POST", headers=hd)
    try:
        with _PLAIN.open(req, timeout=25) as r:
            return r.status, r.read(), r.headers
    except urllib.error.HTTPError as e:
        return e.code, e.read(), e.headers
    except Exception as e:
        return 0, str(e).encode(), {}


def boot(engine_dir, base, expect=True, host="127.0.0.1", password=""):
    """서버를 띄운다 — **현장이 띄우는 주소로도** 띄워 볼 수 있어야 한다.

    전에는 늘 127.0.0.1 로만 띄웠다. 기동 관문은 loopback 을 그냥 보내 주므로 관문이
    한 번도 불리지 않았고, 그래서 현장에서 서버가 안 뜨는 것을 못 잡았다.
    """
    # 비밀번호는 **표준 입력으로** 넣는다 — 명령행에 적으면 /proc/<PID>/cmdline 에 보인다.
    # 현장이 쓰는 길과 같은 길로 띄워야 그 길이 실제로 되는지 알 수 있다(GPT 19차).
    cmd = [sys.executable, "-m", "logtriage.server", "--host", host,
           "--port", str(PORT), "--base", str(base)]
    if password:
        cmd += ["--password-stdin"]
    p = subprocess.Popen(cmd, cwd=str(engine_dir), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if password:
        p.stdin.write((password + chr(10)).encode("utf-8"))
    try:
        p.stdin.close()
    except OSError:
        pass
    for _ in range(40):
        time.sleep(0.5)
        st, d = get("/healthz", timeout=3)
        if st == 200:
            return p, json.loads(d)
        if p.poll() is not None:
            break
    p.kill()
    out = p.stdout.read().decode("utf-8", "replace")[-700:]
    # **한 단계가 못 떴다고 나머지를 건너뛰지 않는다.** 건너뛴 단계는 아무것도 지키지 못한다.
    if expect:
        say(False, "서버가 뜨지 않았습니다", out.strip().replace(os.linesep, " ")[-240:])
    return None, {}


def stop(p):
    if not p:
        return
    p.terminate()
    try:
        p.wait(timeout=20)
    except subprocess.TimeoutExpired:
        p.kill()
    time.sleep(1.0)


# ── 옛 판 풀기 / 새 판으로 바꾸기 ────────────────────────────────────
WORK.mkdir(parents=True, exist_ok=True)
print(f"작업 폴더: {WORK}")
print(f"직접 업그레이드 지원 최소 판: {OLDEST}")

OLD_ROOT = WORK / "old"
if not OLD_ROOT.exists():
    OLD_ROOT.mkdir(parents=True)
    with zipfile.ZipFile(OLD_ZIP) as z:
        z.extractall(OLD_ROOT)
OLD_ENGINE = OLD_ROOT / "logtriage-linux-patch" / "engine"
NEW_ROOT = WORK / "new"
if not NEW_ROOT.exists():
    shutil.copytree(OLD_ENGINE, NEW_ROOT / "engine")
    for d in ("logtriage", "rules", "rules-local", "errorcodes", "manuals", "tools"):
        src, dst = NEW_ENGINE / d, NEW_ROOT / "engine" / d
        if src.is_dir():
            shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "custom", "report_profile.json"))
NEW_ENG = NEW_ROOT / "engine"


def old_install(name, hub=None, state=None, extra=None, auth="off"):
    """옛 판이 남겨 둔 모습의 설치 폴더를 만든다.

    auth: 옛 설치의 conf/auth.json. 2026.09.30 판의 첫 기동 기본값은 off(로그인 없음)였다.
    None 을 주면 **설정 파일 자체가 없는** 설치가 된다 — 새 판은 그 폴더를 계정 로그인으로
    시작한다(2026-10-01 기본값 변경). 그 모습은 11단계에서 따로 본다.
    """
    b = WORK / name
    shutil.rmtree(b, ignore_errors=True)
    (b / "conf").mkdir(parents=True)
    (b / "data").mkdir(parents=True)
    if auth is not None:
        (b / "conf" / "auth.json").write_text(json.dumps({"mode": auth}), encoding="utf-8")
    (b / "conf" / "hub_allow.txt").write_text(
        "https://hq.example" + os.linesep + "https://evil.example" + os.linesep, encoding="utf-8")
    if hub is not None:
        (b / "conf" / "hub.json").write_text(json.dumps(hub, ensure_ascii=False), encoding="utf-8")
    if state is not None:
        (b / "data" / "hub_client.json").write_text(json.dumps(state), encoding="utf-8")
    for rel, body in (extra or {}).items():
        f = b / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(body, encoding="utf-8")
    return b


SITE_CONF = {"role": "site", "site_id": "BUSAN", "site_name": "부산센터",
             "hub_url": "https://hq.example", "hub_token": "t" * 24,
             "interval_sec": 3600, "send_reports": True}
SENT = {"last_ok": 1790000000.0, "last_try": 1790000000.0, "last_error": "",
        "sent": {"incidents": 42, "reports": 7, "cycles": 310}, "seq": 310}


# ══════════════════════════════════════════════════════════════════════
phase(1, "보존·승계 — 옛 판으로 자료를 쌓고 새 판으로 올린다")
BASE = old_install("ltdata", hub=SITE_CONF)
proc, health = boot(OLD_ENGINE, BASE)
try:
    if not proc:
        raise SystemExit(1)
    old_build = health.get("build")
    say(True, "옛 판 기동", f"빌드 {old_build}")
    # 게시판은 **경로 엔드포인트**라 사전을 받는다(/api/<이름> 만 위치 인자 목록이다)
    st, d, _ = post("/api/board/create",
                    {"kind": "question", "title": "옛 판에서 쓴 글", "body": "남아 있어야 합니다"})
    say(st == 200 and b"error" not in d, "게시판 글 작성", f"HTTP {st} {d[:60].decode('utf-8','replace')}")
    st, d = get("/api/board/list")
    posts_before = len(json.loads(d).get("posts", [])) if st == 200 else -1
    say(posts_before > 0, "게시판 글 수", str(posts_before))
    st, d, _ = post("/api/asset_field_add",
                    ["옛판항목", "text", "advised", "업그레이드 뒤 이 항목이 남는지 확인합니다"])
    say(st == 200 and b"error" not in d, "자산 항목 추가", f"HTTP {st}")
    st, d, _ = post("/api/asset_fields", [])
    before_fields = [f.get("label") for f in json.loads(d).get("custom", [])]
    say("옛판항목" in before_fields, "자산 항목이 보입니다", f"{len(before_fields)}개")
    (BASE / "data" / "hub_client.json").write_text(json.dumps(SENT), encoding="utf-8")
    say(not (BASE / "data" / "hub_identity.json").exists(),
        "옛 판에는 신원 파일이 없습니다", "이것이 승계 시험의 전제")
except SystemExit:
    pass
finally:
    stop(proc)

proc, health = boot(NEW_ENG, BASE)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    say(health.get("build") != old_build, "빌드가 바뀌었습니다",
        f"{old_build} -> {health.get('build')}")
    st, d = get("/api/board/list")
    say(len(json.loads(d).get("posts", [])) == posts_before, "게시판 글이 그대로입니다")
    st, d, _ = post("/api/asset_fields", [])
    say("옛판항목" in [f.get("label") for f in json.loads(d).get("custom", [])],
        "옛 판에서 더한 자산 항목이 남아 있습니다")
    ident = BASE / "data" / "hub_identity.json"
    got = json.loads(ident.read_text(encoding="utf-8")).get("site_id") if ident.exists() else ""
    say(got == "BUSAN", "사이트 신원을 승계했습니다", f"locked={got!r}")
    st, d = get("/api/hub/mode")
    say(json.loads(d)["mode"].get("locked_site_id") == "BUSAN", "화면에도 잠금이 보입니다")
    st, d, _ = post("/api/hub/admin/mode", {"role": "site", "site_id": "SEOUL",
                                            "hub_url": "https://evil.example",
                                            "hub_token": "u" * 24})
    say(st == 400 and b"BUSAN" in d, "사이트 ID 바꾸기가 거절됩니다", f"HTTP {st}")
    st, d = get("/api/hub/mode")
    m = json.loads(d)["mode"]
    say(m.get("site_id") == "BUSAN" and m.get("hub_url") == "https://hq.example",
        "설정이 바뀌지 않았습니다")
    bad = [p for p in ("/", "/hub", "/resources", "/nms", "/automation", "/board", "/admin")
           if get(p)[0] != 200]
    say(not bad, "모든 메뉴가 열립니다", f"안 열린 곳: {bad}" if bad else "7곳")
    CLEAN_IDENT = ident.read_bytes()
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(2, "중단 뒤 재개 — 승계가 끊겼다 다시 돌아도 결과가 같아야 한다")
# 신원을 적다가 죽은 모습: 임시 파일만 반쪽으로 남고 진짜 파일은 없다
B2 = old_install("ltdata2", hub=SITE_CONF, state=SENT,
                 extra={"data/hub_identity.json.tmp": '{"site_id": "BUS'})
proc, _ = boot(NEW_ENG, B2)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    ident2 = B2 / "data" / "hub_identity.json"
    say(ident2.exists(), "끊긴 뒤에도 신원을 제대로 적습니다")
    got = json.loads(ident2.read_text(encoding="utf-8")).get("site_id") if ident2.exists() else ""
    say(got == "BUSAN", "반쪽 파일에 속지 않습니다", f"locked={got!r}")
    say(not (B2 / "data" / "hub_identity.json.tmp").exists(), "남은 임시 파일을 치웁니다")
    st, d = get("/api/hub/mode")
    say(json.loads(d)["mode"].get("locked_site_id") == "BUSAN", "잠금이 걸려 있습니다")
    st, d, _ = post("/api/hub/admin/mode", {"role": "site", "site_id": "SEOUL",
                                            "hub_url": "https://hq.example",
                                            "hub_token": "u" * 24})
    say(st == 400, "그 상태에서 사이트 ID 바꾸기가 거절됩니다", f"HTTP {st}")
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(3, "두 번 올림 — 같은 업그레이드를 다시 해도 상태가 더 바뀌면 안 된다")
snap = {}
for f in ("data/hub_identity.json", "conf/hub.json"):
    p_ = BASE / f
    snap[f] = p_.read_bytes() if p_.exists() else None
proc, _ = boot(NEW_ENG, BASE)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    st, d = get("/api/hub/mode")
    mode_again = json.loads(d)["mode"]
    for f, was in snap.items():
        now = (BASE / f).read_bytes() if (BASE / f).exists() else None
        say(now == was, f"{f} 가 그대로입니다")
    say(mode_again.get("locked_site_id") == "BUSAN" and mode_again.get("site_id") == "BUSAN",
        "모드·잠금도 그대로입니다")
    st, d, _ = post("/api/asset_fields", [])
    say("옛판항목" in [f.get("label") for f in json.loads(d).get("custom", [])],
        "자산 항목도 그대로입니다")
except SystemExit:
    pass
finally:
    stop(proc)
say((BASE / "data" / "hub_identity.json").read_bytes() == CLEAN_IDENT,
    "신원 파일은 한 번만 적힙니다", "locked_at 이 바뀌지 않았습니다")


# ══════════════════════════════════════════════════════════════════════
phase(4, "옛 위험 설정 — 없앤 설정이 새 판에서 되살아나면 안 된다")
# ① 평문 주소 + 인증서 검사 끄기 — 받아 주면 그 자체가 후퇴다
B4 = old_install("ltdata4", state=SENT, hub={
    "role": "site", "site_id": "BUSAN", "site_name": "부산센터",
    "hub_url": "http://hq.example", "hub_token": "t" * 24,
    "allow_http": True, "verify_tls": False, "interval_sec": 3600, "send_reports": True})
proc, _ = boot(NEW_ENG, B4)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    st, d = get("/api/hub/mode")
    m = json.loads(d)["mode"]
    say(m.get("role") != "site", "평문 주소로는 사이트 서버가 되지 않습니다", f"role={m.get('role')!r}")
    say(bool(m.get("broken")), "멈춘 까닭을 남깁니다")
    say(not (B4 / "data" / "hub_identity.json").exists(),
        "쓸 수 없는 설정으로 신원을 못 박지 않습니다")
    say(b"verify_tls" not in d or b'"verify_tls": false' not in d.lower(),
        "인증서 검사 끄기가 응답에 살아나지 않습니다")
except SystemExit:
    pass
finally:
    stop(proc)
# ② https 인데 끄기만 켜 둔 경우 — 설정은 살되 **검사는 강제로 켜져야** 한다
B4b = old_install("ltdata4b", state=SENT, hub={
    "role": "site", "site_id": "BUSAN", "site_name": "부산센터",
    "hub_url": "https://hq.example", "hub_token": "t" * 24,
    "allow_http": True, "verify_tls": False, "interval_sec": 3600, "send_reports": True})
proc, _ = boot(NEW_ENG, B4b)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    st, d = get("/api/hub/mode")
    m = json.loads(d)["mode"]
    say(m.get("role") == "site", "https 설정은 그대로 삽니다", f"role={m.get('role')!r}")
    # **돌고 있는 설정**이 안전한지 먼저 본다 — 파일에 남은 글자가 아니라 동작이 기준이다
    say(m.get("hub_url", "").startswith("https://"), "평문으로 내려가지 않습니다")
    saved = json.loads((B4b / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
    say(saved.get("verify_tls") is True, "파일에서도 인증서 검사가 켜져 있습니다",
        f"verify_tls={saved.get('verify_tls')!r}")
    say("allow_http" not in saved, "없앤 항목이 설정 파일에서 지워집니다")
    say((B4b / "conf" / "hub.json.bak").exists(), "옛 파일은 .bak 으로 남습니다")
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(5, "옛 세션 — 옛 판에서 받은 쿠키는 새 판에서 끊겨야 한다")
B5 = old_install("ltdata5", hub=None)
(B5 / "conf" / "auth.json").write_text(json.dumps({
    "mode": "local", "session_idle_min": 60, "session_max_hours": 12,
    "default_role": "viewer", "default_sites": [], "auto_create": True,
    "require_https": "auto", "first_admin": "", "setup_scope": "private",
    "admin_allow": [], "portal": {"method": "ldap", "label": "통합 계정"}},
    ensure_ascii=False), encoding="utf-8")
PW, EMAIL = "Gm7-Qv2x-Rt9b", "up@solideos.com"
subprocess.run([sys.executable, "-m", "logtriage.accounts", "--base", str(B5), "add",
                "--email", EMAIL, "--role", "admin", "--password", PW,
                "--sites", "*", "--asset-sites", "LOCAL"],
               cwd=str(OLD_ENGINE), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proc, _ = boot(OLD_ENGINE, B5)
old_cookie = ""
try:
    import urllib.parse as _up
    body = ("email=" + _up.quote(EMAIL) + "&password=" + _up.quote(PW)).encode()
    st, d, hdr = post("/login", body)
    for k, v in (hdr.items() if hasattr(hdr, "items") else []):
        if k.lower() == "set-cookie" and v.startswith("lt_sid="):
            old_cookie = v.split(";")[0]
    say(bool(old_cookie), "옛 판에서 로그인했습니다", f"HTTP {st}")
    say(get("/api/me", old_cookie)[0] == 200, "옛 판에서는 그 쿠키가 통합니다")
except SystemExit:
    pass
finally:
    stop(proc)
proc, _ = boot(NEW_ENG, B5)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    st, _ = get("/api/me", old_cookie)
    say(st in (401, 403), "새 판에서는 옛 쿠키가 끊깁니다", f"HTTP {st}")
    say((B5 / "data" / "cookie_policy").exists(), "쿠키 정책 표식을 남깁니다")
except SystemExit:
    pass
finally:
    stop(proc)
proc, _ = boot(NEW_ENG, B5)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    import urllib.parse as _up
    body = ("email=" + _up.quote(EMAIL) + "&password=" + _up.quote(PW)).encode()
    st, d, hdr = post("/login", body)
    ck = ""
    for k, v in (hdr.items() if hasattr(hdr, "items") else []):
        if k.lower() == "set-cookie" and v.startswith("lt_sid="):
            ck = v
    say("SameSite=Strict" in ck, "새로 받는 쿠키는 Strict 입니다", ck.split(";", 1)[-1][:60])
    say(get("/api/me", ck.split(";")[0])[0] == 200, "다시 로그인하면 됩니다")
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(6, "멈춤 상태 — 보내기 금지 표식을 들고 올라오면 그대로 멈춰 있어야 한다")
B6 = old_install("ltdata6", hub=SITE_CONF, state=SENT,
                 extra={"data/hub_recovery_required": "지난 변경이 어긋난 채로 남았습니다"})
proc, _ = boot(NEW_ENG, B6)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    st, d = get("/api/hub/mode")
    m = json.loads(d)["mode"]
    say(bool(m.get("broken")), "멈춘 상태가 그대로입니다")
    st, d, _ = post("/api/hub/admin/mode", {"role": "none"})
    say(st == 409, "그 상태에서는 모드를 바꾸지 않습니다", f"HTTP {st}")
    body = get("/hub")[1].decode("utf-8", "replace")
    say("hub_recovery_required" in body or "brokenBox" in body, "화면이 그 사실을 들고 있습니다")
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(7, "묵은 사이트 ID — 역할을 바꾸며 남은 ID 를 진짜 신원으로 못 박으면 안 된다")
# GPT 5차 지적: 옛 설정에 role 을 바꾸면서 지우지 않은 site_id 가 남아 있을 수 있다.
# 그것을 신원으로 확정하면, 이 서버는 쓴 적도 없는 이름에 영영 묶인다.
B7 = old_install("ltdata7", hub={"role": "none", "site_id": "OLD-BUSAN"})
proc, health = boot(NEW_ENG, B7)
try:
    if not proc:                      # 못 떴으면 이 단계는 더 볼 것이 없다
        raise SystemExit(0)
    say(bool(health.get("build")), "읽을 수 없는 설정이어도 서버는 뜹니다",
        "업그레이드가 서비스 중단이 되면 안 됩니다")
    say(not (B7 / "data" / "hub_identity.json").exists(),
        "묵은 ID 를 신원으로 못 박지 않습니다")
    st, d = get("/api/hub/mode")
    m = json.loads(d)["mode"]
    say(m.get("role") == "none" and not m.get("site_id"), "단독으로 돕니다", f"role={m.get('role')!r}")
    say(bool(m.get("broken")), "사람이 보도록 까닭을 남깁니다")
    say("OLD-BUSAN" not in d.decode("utf-8", "replace"), "묵은 ID 가 화면에 살아나지 않습니다")
except SystemExit:
    pass
finally:
    stop(proc)



# ══════════════════════════════════════════════════════════════════════
phase(8, "옛 설정 정리 2회 — 다시 적은 뒤 또 바뀌면 안 된다")
B8 = old_install("ltdata8", state=SENT, hub={
    "role": "site", "site_id": "BUSAN", "site_name": "부산센터",
    "hub_url": "https://hq.example", "hub_token": "t" * 24,
    "allow_http": True, "verify_tls": False, "interval_sec": 3600, "send_reports": True})
proc, _ = boot(NEW_ENG, B8)
try:
    if not proc:
        raise SystemExit(0)
    first = (B8 / "conf" / "hub.json").read_bytes()
    say(b"allow_http" not in first, "첫 기동에서 옛 항목이 지워집니다")
except SystemExit:
    pass
finally:
    stop(proc)
proc, _ = boot(NEW_ENG, B8)
try:
    if not proc:
        raise SystemExit(0)
    second = (B8 / "conf" / "hub.json").read_bytes()
    say(second == first, "두 번째 기동에서 **더 바뀌지 않습니다**",
        "바뀌면 기동할 때마다 파일이 흔들립니다")
    baks = sorted((B8 / "conf").glob("hub.json.bak*"))
    say(len(baks) <= 1, "쓸데없는 백업이 쌓이지 않습니다", f"{len(baks)}개")
except SystemExit:
    pass
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(9, "깨진 설정 왕복 — 로컬은 살고 바깥으로는 한 줄도 나가지 않는다")
# GPT: "재빌드 직전 마지막 관문은 정상 경로보다 '깨진 설정을 넣어도 로컬 서비스는 살고
#       외부 송신은 절대 시작되지 않는다' 는 패키지 왕복 시험입니다."
for label, broken in (("깨진 JSON", "{깨진"),
                      ("모르는 역할", json.dumps({"role": "spaceship", "site_id": "X"})),
                      ("미래 설정 틀", json.dumps({"role": "site", "site_id": "BUSAN",
                                                   "hub_url": "https://hq.example",
                                                   "hub_token": "t" * 24,
                                                   "schema_version": 99,
                                                   "new_security_option": True}))):
    B9 = old_install("ltdata9", state=SENT)
    (B9 / "conf" / "hub.json").write_text(broken, encoding="utf-8")
    before = (B9 / "conf" / "hub.json").read_bytes()
    proc, health = boot(NEW_ENG, B9)
    try:
        if not proc:
            raise SystemExit(0)
        say(bool(health.get("build")), f"[{label}] 서버는 뜹니다")
        bad = [x for x in ("/", "/resources", "/nms", "/automation", "/board")
               if get(x)[0] != 200]
        say(not bad, f"[{label}] 로컬 기능은 그대로입니다", f"안 열린 곳: {bad}" if bad else "5곳")
        st, d = get("/api/hub/mode")
        m = json.loads(d)["mode"] if st == 200 else {}
        say(m.get("hub_state") == "degraded",
            f"[{label}] 단독이 아니라 '연동 차단' 으로 보입니다", f"hub_state={m.get('hub_state')!r}")
        say(bool(m.get("broken_reason")), f"[{label}] 멈춘 까닭이 남습니다",
            str(m.get("broken_reason")))
        say(m.get("role") != "site" and not m.get("hub_url"),
            f"[{label}] 보내는 곳이 서지 않습니다")
        say((B9 / "conf" / "hub.json").read_bytes() == before,
            f"[{label}] **원본 설정을 건드리지 않습니다**")
        say(not (B9 / "data" / "hub_identity.json").exists(),
            f"[{label}] 쓸 수 없는 설정으로 신원을 못 박지 않습니다")
        st, d, _ = post("/api/hub/admin/mode", {"role": "none"})
        say(st == 409, f"[{label}] 그 상태에서는 모드를 바꾸지 않습니다", f"HTTP {st}")
    except SystemExit:
        pass
    finally:
        stop(proc)



# ══════════════════════════════════════════════════════════════════════
phase(10, "현장이 띄우는 방식 — run.sh 는 언제나 0.0.0.0 이다")
# 이 단계가 없어서 9단계가 전부 통과하는데도 현장에서는 서버가 안 떴다.
# 기동 관문은 loopback 을 그냥 보내 주므로, 127.0.0.1 로만 띄워 보면 관문이 안 불린다.
B10 = old_install("ltdata10")
proc, health = boot(NEW_ENG, B10, expect=False, host="0.0.0.0")
say(proc is None, "로그인 없이 0.0.0.0 이면 **뜨지 않습니다**",
    "뜨면 접속할 수 있는 사람이 모두 관리자가 됩니다")
stop(proc)
log = ""
try:
    log = (B10 / "server.log").read_text(encoding="utf-8", errors="replace")
except OSError:
    pass

proc, health = boot(NEW_ENG, B10, expect=False, host="0.0.0.0", password="Gm7-Qv2x-Rt9b")
try:
    say(proc is not None and bool(health.get("build")), "비밀번호를 걸면 **뜹니다**",
        "막기만 보면 '늘 막힘' 도 통과합니다")
    if proc:
        say(get("/healthz")[0] == 200, "그 상태로 쓸 수 있습니다")
finally:
    stop(proc)

# 계정 로그인을 켜면 비밀번호 없이도 떠야 한다
subprocess.run([sys.executable, "-m", "logtriage.authmode", "--base", str(B10), "local"],
               cwd=str(NEW_ENG), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
proc, health = boot(NEW_ENG, B10, expect=False, host="0.0.0.0")
try:
    say(proc is not None and bool(health.get("build")), "계정 로그인을 켜면 **뜹니다**")
finally:
    stop(proc)

# run.sh 가 **띄우기 전에** 알려 주는가 — 네 걸음을 밟고 실패하면 사람이 헤맨다
RUN = NEW_ROOT / "engine"
sh = None
for cand in (NEW_ROOT.parent / "old" / "logtriage-patch" / "run.sh",
             OUT / "_run.sh"):
    if cand.exists():
        sh = cand.read_text(encoding="utf-8", errors="replace")
        break
if sh is None:
    say(False, "run.sh 를 찾지 못했습니다")
else:
    say("--check-start" in sh, "run.sh 가 **서버에게 물어** 막습니다(규칙을 다시 적지 않습니다)")
    say("--password-stdin" in sh and 'ARGS+=(--password "' not in sh,
        "비밀번호를 명령행에 적지 않습니다(/proc/<PID>/cmdline 노출)")
    say("read -rs" in sh, "필요하면 그 자리에서 가려서 물어봅니다")
    say('kill -0 "$NEWPID"' in sh and "pid=$NEWPID" in sh,
        "기동 성공을 **그 프로세스로** 확인합니다(옛 서버가 200 을 돌려주는 일)")
    say("비밀번호 없음(테스트용)" not in sh, "되지도 않는 길을 안내하지 않습니다")

# 기동 관문 판정을 **서버에게 묻는 길**이 실제로 도는가 — run.sh 가 이것을 쓴다
def decide(base, host, pw_stdin=None):
    c = [sys.executable, "-m", "logtriage.server", "--check-start", "--host", host, "--base", str(base)]
    if pw_stdin:
        c += ["--password-stdin"]
    r = subprocess.run(c, cwd=str(NEW_ENG), input=(pw_stdin or "").encode("utf-8"),
                       capture_output=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    out = r.stdout.decode("utf-8", "replace").strip().splitlines()
    return r.returncode, (json.loads(out[0]) if out else {})

B11 = old_install("ltdata11")
rc, d = decide(B11, "0.0.0.0")
say(rc == 2 and d.get("allowed") is False, "--check-start: 로그인 없이 망에 열면 **막습니다**")
rc, d = decide(B11, "127.0.0.1")
say(rc == 0 and d.get("allowed") is True, "--check-start: 이 PC 안에서는 **됩니다**")
rc, d = decide(B11, "0.0.0.0", pw_stdin="Gm7-Qv2x-Rt9b" + chr(10))
say(rc == 0 and d.get("allowed") is True, "--check-start: 비밀번호를 표준 입력으로 주면 **됩니다**")


# ══════════════════════════════════════════════════════════════════════
phase(11, "설정 파일이 없던 설치 — 새 판은 **계정 로그인**으로 시작한다")
# 2026-10-01 사용자 지시로 첫 기동 기본값이 계정 로그인으로 돌아왔다. 설정 파일을 한 번도
# 만든 적 없는 폴더를 올리면 **로그인 화면이 먼저 뜬다** — 자료는 그대로 두고 문만 잠근다.
B11b = old_install("ltdata11b", auth=None)
(B11b / "data").mkdir(parents=True, exist_ok=True)
proc, health = boot(NEW_ENG, B11b, expect=False, host="127.0.0.1")
try:
    say(proc is not None, "서버는 뜹니다(자료를 막지 않습니다)")
    if proc:
        conf = json.loads((B11b / "conf" / "auth.json").read_text(encoding="utf-8-sig"))
        say(conf.get("mode") == "local", "로그인 설정을 계정 로그인으로 만듭니다", f"mode={conf.get('mode')}")
        say((conf.get("local") or {}).get("signup") == "approve",
            "직접 가입은 **승인 뒤 사용**이 기본입니다", f"signup={(conf.get('local') or {}).get('signup')}")
        # 계정이 없으면 첫 화면은 [관리자 계정 만들기] 로 보내고, 그 화면은 **1회용 코드**로만
        # 열린다(2026-10-01 — 첫 관리자 자리를 남이 먼저 차지하지 못하게).
        st, d = get("/")
        page = d.decode("utf-8", "replace")
        say(st == 403 and "초기 설정 코드" in page, "첫 화면이 초기 설정으로 보냅니다", f"HTTP {st}")
        code_txt = ""
        try:
            code_txt = (B11b / "conf" / "setup-code.txt").read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        import re as _re2
        m2 = _re2.search(r"코드\s*:\s*([A-Za-z0-9_-]{8,})", code_txt)
        say(bool(m2), "1회용 설정 코드가 파일에 적힙니다")
        st, d = get("/setup?t=" + (m2.group(1) if m2 else "x"))
        say(st == 200 and "관리자 계정 만들기" in d.decode("utf-8", "replace"),
            "코드를 들고 가면 [관리자 계정 만들기] 가 뜹니다", f"HTTP {st}")
        st, d, _ = post("/api/history", [])   # 이 API 는 위치 인자 배열을 받는다
        say(st == 401, "로그인 전에는 자료 API 가 막힙니다", f"HTTP {st}")
finally:
    stop(proc)

# 이미 로그인 설정이 있던 서버는 **그대로** 둔다 — 말없이 바꾸지 않는다
B11c = old_install("ltdata11c", auth="off")
proc, health = boot(NEW_ENG, B11c, expect=False, host="127.0.0.1")
try:
    say(proc is not None, "로그인 없이 쓰던 서버도 그대로 뜹니다")
    if proc:
        conf = json.loads((B11c / "conf" / "auth.json").read_text(encoding="utf-8-sig"))
        say(conf.get("mode") == "off", "쓰던 로그인 설정을 바꾸지 않습니다", f"mode={conf.get('mode')}")
        st, d, _ = post("/api/history", [])
        say(st == 200, "쓰던 대로 바로 씁니다", f"HTTP {st}")
finally:
    stop(proc)


# ══════════════════════════════════════════════════════════════════════
phase(12, "최종 ZIP 으로 계정 전 과정 — 가입 → 승인 → 로그인 → 권한 요청 → 승인 → 세션 무효화")
# 여기까지의 '새 판' 은 개발 트리에서 복사한 것이었다. 포장한 **그 파일**로도 같은지 본다.
ZIP = OUT / "logtriage-patch-py311-1.0.0.zip"
if not ZIP.exists():
    say(False, f"{ZIP.name} 이 없습니다 — 먼저 빌드하십시오")
else:
    ZROOT = WORK / "zipeng"
    if not ZROOT.exists():
        with zipfile.ZipFile(ZIP) as z:
            z.extractall(ZROOT)
    ZENG = ZROOT / "logtriage-patch" / "engine"
    want_id = ""
    vtxt = ZROOT / "logtriage-patch" / "VERSION.txt"
    if vtxt.exists():
        for line in vtxt.read_text(encoding="utf-8").splitlines():
            if line.startswith("Build:"):
                want_id = line.split(":", 1)[1].strip()
    B12 = old_install("ltdata12", auth=None)      # 설정 파일 없이 — 새 판이 계정 로그인으로 만든다
    proc, health = boot(ZENG, B12, expect=False, host="127.0.0.1")
    try:
        say(proc is not None, "포장본으로 뜹니다")
        if proc:
            say(bool(want_id) and health.get("build_id") == want_id,
                "포장본의 판 지문이 VERSION.txt 와 같습니다", f"{health.get('build_id')} / {want_id}")
            say(health.get("code_id") and not health.get("code_modified"),
                "설치 뒤에 손댄 흔적이 없습니다", f"code_id={health.get('code_id')}")

            def form_post(path, cookie="", **kv):
                body = "&".join(f"{k}={_up.quote(str(v))}" for k, v in kv.items()).encode()
                return post(path, body, cookie)

            def cookie_of(h):
                for k, v in (h or {}).items() if isinstance(h, dict) else (h.items() if h else []):
                    if k.lower() == "set-cookie" and str(v).startswith("lt_sid="):
                        return str(v).split(";")[0]
                return ""

            def cookie_from(hdrs):
                if not hdrs:
                    return ""
                for k, v in hdrs.items():
                    if k.lower() == "set-cookie" and v.startswith("lt_sid="):
                        return v.split(";")[0]
                return ""

            AP, AE = "Bq7-Zrt2!wVm", "boss12@solideos.com"
            UP, UE = "Hn4#kXc9$zRp", "user12@solideos.com"

            # ① 첫 관리자 — 계정이 없으면 이 화면이 먼저 뜬다
            st, d = get("/setup")
            say(st == 403 and "초기 설정 코드" in d.decode("utf-8", "replace"),
                "계정이 없으면 코드를 먼저 묻습니다", f"HTTP {st}")
            # 첫 계정 만들기에는 1회용 코드가 필요하다(2026-10-01). 코드는 기동할 때 화면과
            # conf/setup-code.txt 에 나온다 — 현장 담당자가 읽는 그 자리에서 읽는다.
            import re as _re
            code_txt = (B12 / "conf" / "setup-code.txt").read_text(encoding="utf-8", errors="replace")
            m = _re.search(r"코드\s*:\s*([A-Za-z0-9_-]{8,})", code_txt)
            say(bool(m), "1회용 설정 코드가 파일에 적힙니다")
            setup_code = m.group(1) if m else ""
            st, d = get("/setup")
            say(st == 403, "코드 없이는 [관리자 계정 만들기] 가 열리지 않습니다", f"HTTP {st}")
            st, d, _ = form_post("/setup", email="sneak@solideos.com", name="x", password=AP, confirm=AP)
            say(st == 403, "코드 없이 보낸 요청은 계정을 만들지 않습니다", f"HTTP {st}")
            st, d, h = form_post("/setup", email=AE, name="관리자", password=AP, confirm=AP, t=setup_code)
            admin_ck = cookie_from(h)
            say(st == 302 and bool(admin_ck), "첫 관리자를 만들고 바로 들어갑니다", f"HTTP {st}")
            # get() 은 넘김(302)을 따라간다 — 닫혔다면 **로그인 화면**이 나온다
            st, d = get("/setup")
            page = d.decode("utf-8", "replace")
            say(st == 200 and "관리자 계정 만들기" not in page,
                "그 뒤로는 이 화면이 닫힙니다", f"HTTP {st}")

            # ② 직접 가입 — 기본값은 승인 뒤 사용
            st, d = get("/join")
            say(st == 200 and "계정 만들기" in d.decode("utf-8", "replace"), "가입 화면이 열립니다", f"HTTP {st}")
            st, d, _ = form_post("/join", email=UE, name="신청자", dept="운영팀",
                                 password=UP, confirm=UP)
            say(st == 200 and "접수" in d.decode("utf-8", "replace"), "가입 신청이 접수됩니다", f"HTTP {st}")

            # ③ 승인 전에는 맞는 비밀번호로도 못 들어온다
            st, d, h = form_post("/login", email=UE, password=UP)
            say(st == 401 and not cookie_from(h), "승인 전에는 들어오지 못합니다", f"HTTP {st}")
            say("승인" in d.decode("utf-8", "replace"), "까닭을 알려 줍니다")

            # ④ 관리자가 승인
            st, d = get("/api/admin/accounts", admin_ck)
            pend = json.loads(d).get("pending", []) if st == 200 else []
            say([p["email"] for p in pend] == [UE], "관리자 화면에 신청이 보입니다")
            st, d, _ = post("/api/admin/account_approve", {"email": UE, "role": "viewer"}, admin_ck)
            say(st == 200, "승인했습니다", f"HTTP {st}")

            # ⑤ 최초 로그인
            st, d, h = form_post("/login", email=UE, password=UP)
            user_ck = cookie_from(h)
            say(st == 302 and bool(user_ck), "승인 뒤에는 들어옵니다", f"HTTP {st}")
            st, d = get("/api/me", user_ck)
            me = json.loads(d) if st == 200 else {}
            say(me.get("role") == "viewer", "조회 권한으로 시작합니다", f"role={me.get('role')}")

            # ⑥ 막힌 명령 → 승인 요청
            st, d, _ = post("/api/analyze", [], user_ck)
            body = json.loads(d) if d else {}
            say(st == 403 and body.get("request", {}).get("want") == "operator",
                "막힌 명령이 요청할 길을 알려 줍니다", f"HTTP {st}")
            st, d, _ = post("/api/access/request",
                            {"kind": "role", "want": "operator", "action": "POST /api/analyze",
                             "reason": "1차 대응을 맡았습니다"}, user_ck)
            say(st == 200, "요청을 보냈습니다", f"HTTP {st}")
            st, d, _ = post("/api/access/request", {"kind": "role", "want": "admin", "reason": "x"}, user_ck)
            say(st == 400, "관리자 권한은 요청으로 주지 않습니다", f"HTTP {st}")

            # ⑦ 관리자가 승인 → 권한이 실제로 올라가고 세션이 끊긴다
            st, d = get("/api/admin/requests", admin_ck)
            reqs = json.loads(d).get("requests", []) if st == 200 else []
            say(len(reqs) == 1 and reqs[0]["login"] == UE and "1차 대응" in reqs[0]["reason"],
                "관리자 화면에 요청과 사유가 보입니다")
            if reqs:
                st, d, _ = post("/api/admin/request_decide", {"id": reqs[0]["id"], "approve": True}, admin_ck)
                say(st == 200, "요청을 승인했습니다", f"HTTP {st}")
            st, d = get("/api/me", user_ck)
            say(st == 401, "권한이 바뀌면 쓰던 접속이 끊깁니다", f"HTTP {st}")
            st, d, h = form_post("/login", email=UE, password=UP)
            user_ck2 = cookie_from(h)
            st, d = get("/api/me", user_ck2)
            me2 = json.loads(d) if st == 200 else {}
            say(me2.get("role") == "operator", "다시 로그인하면 올라간 권한입니다", f"role={me2.get('role')}")
            st, d, _ = post("/api/analyze", [], user_ck2)
            say(st != 403, "막혔던 명령이 열렸습니다", f"HTTP {st}")
    finally:
        stop(proc)

print()
if fails:
    print(f"== 업그레이드 시험 실패 {len(fails)}건 ==")
    for f in fails:
        print("  !!", f)
else:
    print("== 업그레이드 시험 전부 통과 ==")
sys.exit(1 if fails else 0)
