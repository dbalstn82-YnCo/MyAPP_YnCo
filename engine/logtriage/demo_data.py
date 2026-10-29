# -*- coding: utf-8 -*-
"""시연 자료 — 빈 화면으로 보여 주지 않기 위한 표본 (2026-09-23)

처음 설치한 서버는 분석 이력도 보고서도 없어 화면이 전부 0 이다. 제품이 무엇을 하는지
보여 줄 수가 없다. 그렇다고 화면에 숫자를 박아 넣으면 그건 거짓말이다.

그래서 **표본 로그를 만들어 진짜 분석기에 태운다.** 판정·심각도·보고서·게시판 글이
모두 실제 규칙이 만들어 낸 결과다 — 화면에 보이는 것과 같은 길을 지난다.

지키는 것
  · 시연 자료임이 한눈에 보인다 — 분석 ID 는 `DEMO-`, 이름·글 제목은 `[시연]` 으로 시작
  · 지울 수 있다 — `DEMO-` 가 붙은 것만 지우고 실제 자료는 건드리지 않는다
  · 실제 자료가 이미 있으면 기본으로 거절한다(운영 중인 서버를 시연 자료로 어지럽히지 않게)
"""
from __future__ import annotations

import shutil
import time
import re
import uuid
from datetime import datetime, timedelta
from pathlib import Path

PREFIX = "DEMO-"
MARK = "[시연]"

# 표본 한 건 = (파일, 제품, 호스트, 며칠 전, 줄 목록)
# 줄에는 {t} 자리에 그 제품이 쓰는 시각 형식이 들어간다.
# 제품마다 로그 형식이 다르다 — 여기에 syslog 접두사를 일률로 붙이면 줄 해석이 0이 된다(실제로 그랬다).
SYSLOG, DB_T, WEB_T, JEUS_T = "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S +0900", "%Y.%m.%d %H:%M:%S"

SAMPLES = [
    ("was_oom.log", "linux", "was01", 0, SYSLOG, [
        "{t} was01 kernel: Out of memory: Killed process 4412 (java) total-vm:8123456kB",
        "{t} was01 systemd[1]: jeus.service: Main process exited, code=killed, status=9/KILL",
        "{t} was01 systemd[1]: jeus.service: Failed with result 'signal'.",
    ]),
    ("db_deadlock.log", "altibase", "db01", 0, DB_T, [
        "[{t}] [ERR-31022] Deadlock detected. Transaction rolled back.",
        "[{t}] [ERR-31022] Deadlock detected while waiting for lock on table ORDERS.",
        "[{t}] maximum number of sessions exceeded",
    ]),
    ("web_5xx.log", "accesslog", "web01", 1, WEB_T, [
        '10.20.1.41 - - [{t}] "GET /api/order HTTP/1.1" 503 219',
        '10.20.1.42 - - [{t}] "POST /api/pay HTTP/1.1" 502 118',
        '10.20.1.43 - - [{t}] "GET /api/user HTTP/1.1" 500 431',
    ]),
    ("jeus_hub.log", "jeus", "was02", 2, JEUS_T, [
        "[{t}][2][was02] [Network-0708] Exception occurred during trying to connect to the server",
        "[{t}][2][was02] [Network-0403] SocketStreamImpl connection reset by peer",
    ]),
    ("os_disk.log", "linux", "app01", 3, SYSLOG, [
        "{t} app01 kernel: EXT4-fs error (device sda1): ext4_journal_check_start:61: Detected aborted journal",
        "{t} app01 dd: writing to '/data/tmp/x': No space left on device",
    ]),
]


def _dirs(base: Path):
    return Path(base) / "uploads" / "demo"


def status(api) -> dict:
    """시연 자료가 얼마나 들어 있는지."""
    hist = []
    try:
        hist = api.store.history(limit=5000) or []
    except Exception:
        pass
    demo = [h for h in hist if str(h.get("id", "")).startswith(PREFIX)]
    posts = 0
    try:
        for p in (api.board.list(limit=200).get("posts") or []):
            if str(p.get("title", "")).startswith(MARK):
                posts += 1
    except Exception:
        pass
    return {"incidents": len(demo), "real": len(hist) - len(demo), "posts": posts}


def seed(api, force: bool = False) -> dict:
    """표본 로그를 만들어 실제 분석기에 태운다."""
    from .service import run_analysis

    st = status(api)
    if st["real"] and not force:
        return {"error": f"이미 실제 분석 이력이 {st['real']}건 있습니다 — 시연 자료를 섞지 않으려면"
                         " 비어 있는 서버에서 쓰십시오(정말 넣으려면 '강제'를 선택)."}
    if st["incidents"]:
        return {"error": f"시연 자료가 이미 {st['incidents']}건 있습니다 — 먼저 지우십시오."}

    base = Path(api._base)
    work = _dirs(base)
    work.mkdir(parents=True, exist_ok=True)
    made, failed = [], []
    for name, product, host, ago, tfmt, lines in SAMPLES:
        when = datetime.now() - timedelta(days=ago, minutes=17 * (ago + 1))
        path = work / name
        body = []
        for i, ln in enumerate(lines):
            t = (when + timedelta(seconds=i)).strftime(tfmt)
            body.append(ln.replace("{t}", t))
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
        try:
            result = run_analysis([{"path": str(path), "product": product, "host": host}], None, 30, 10,
                                  base / "rules", base / "rules-local", base / "errorcodes")
            inc_id = PREFIX + uuid.uuid4().hex[:16]
            result.pop("learn", None)   # 시연 자료는 룰 학습에 넣지 않는다
            result.update(id=inc_id, name=f"{MARK} {host} — {name}", demo=True)
            result["analyzed_at"] = when.strftime("%Y-%m-%d %H:%M:%S")
            api._save_history(result)
            made.append({"id": inc_id, "name": result["name"],
                         "layer": (result.get("first") or {}).get("layer_ko", ""),
                         "verdict": (result.get("first") or {}).get("verdict", ""),
                         "sev": result.get("sev_totals") or {}})
        except Exception as exc:
            failed.append(f"{name}: {exc}")

    posts = 0
    for m in made[:3]:
        try:
            sev = m["sev"]
            api.board.create({"login": "demo@logtriage", "name": "시연 자료"}, "share",
                             f"{MARK} {m['layer']} — {m['verdict']}"[:120],
                             "시연용 표본입니다. 실제 장애 기록이 아닙니다.\n\n"
                             f"· 판정 계층 : {m['layer']}\n· 원인 추정 : {m['verdict']}\n"
                             f"· 치명 / 오류 : {sev.get('critical', 0)} / {sev.get('error', 0)}\n"
                             f"· 분석 이력 : {m['id']}\n",
                             incidents=[m["id"]])
            posts += 1
        except Exception as exc:
            failed.append(f"게시판: {exc}")

    blank = [m["name"] for m in made if not m["verdict"]]
    out = {"ok": True, "incidents": len(made), "posts": posts, "made": made}
    if blank:
        out["blank"] = blank     # 판정이 안 난 표본 — 그대로 두면 시연 화면에 빈 줄로 남는다
    if failed:
        out["failed"] = failed
    return out


def clear(api) -> dict:
    """`DEMO-` 가 붙고 시연 표시(demo=True)가 있는 것만 지운다 — 접두어·이름만으로 지우지 않는다(GPT 81~83차)."""
    removed = {"incidents": 0, "posts": 0, "reports": 0}
    try:
        for h in list(api.store.history(limit=5000) or []):
            hid = str(h.get("id", ""))
            # GPT 82·83차: 생성 출처를 입증할 수 있는 것(분석 본문의 demo=true — 견본 분석·시연 자료 생성기가 남김)만 지운다.
            # 표시 없는 옛 시연 자료는 ID 형식·이름이 맞아도 실제 이력과 가를 수 없어 자동 삭제에서 뺀다(설치본에는 옛 시연 자료 0건 확인).
            if hid.startswith(PREFIX) and h.get("demo") is True:
                try:
                    api.store.delete_incident(h["id"])
                    removed["incidents"] += 1
                    try:   # 19차: 그 분석의 보고서 기본 정보(개인정보)도 함께
                        from .report_forms import profile_delete
                        profile_delete(api._base / "report-template", hid)
                    except Exception:   # noqa: BLE001
                        pass
                except Exception:
                    pass
    except Exception:
        pass
    try:
        for p in (api.board.list(limit=200).get("posts") or []):
            if str(p.get("title", "")).startswith(MARK):
                try:
                    api.board.delete({"login": "demo@logtriage"}, p["id"], is_admin=True)
                    removed["posts"] += 1
                except Exception:
                    pass
    except Exception:
        pass
    try:
        for d in (api.reports_dir() if hasattr(api, "reports_dir") else Path(api._base) / "reports",):
            for f in Path(d).glob(f"*{PREFIX}*"):
                f.unlink(missing_ok=True)
                removed["reports"] += 1
    except Exception:
        pass
    shutil.rmtree(_dirs(api._base), ignore_errors=True)
    return {"ok": True, "removed": removed}
