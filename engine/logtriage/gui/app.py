"""LogTriage 데스크톱 GUI — pywebview(WebView2) 위에 다크 UI + 분석 엔진 직결."""
from __future__ import annotations

import json
import logging
import os
import re

import yaml
import sys
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

try:  # 데스크톱(Windows)에서만 필요 — Linux 서버형(server.py)은 pywebview 없이 Api 를 재사용
    import webview
except ImportError:  # pragma: no cover
    webview = None

from .. import __version__, rulepack
from ..detect import detect_product
from ..rules import load_rules
from ..service import CATEGORY_KO, run_analysis


_DIAG_LOCK = threading.RLock()   # 10차 자기진단 캐시 — 화면과 기동 기록 스레드가 동시에 불러도 한 번만(이력 감소 판정이 둘로 갈리지 않게)


def friendly_error(e: BaseException) -> str:
    """11차 ⑨: 분석 실패를 사람이 다음에 할 일로 — 파이썬 예외 이름만 보여 주지 않는다(원문은 실행 기록에)."""
    from ..service import NoKnowledgeError
    name = getattr(e, "filename", "") or ""
    short = Path(str(name)).name if name else ""
    if isinstance(e, NoKnowledgeError):
        return str(e)
    if isinstance(e, FileNotFoundError):
        return f"로그 파일을 찾을 수 없습니다{(': ' + short) if short else ''} — 옮겨졌거나 지워졌습니다. 목록에서 빼고 다시 넣으십시오."
    if isinstance(e, PermissionError):
        return f"로그 파일을 읽을 권한이 없습니다{(': ' + short) if short else ''} — 다른 프로그램이 잡고 있거나 관리자 권한 폴더입니다. 복사본을 넣으십시오."
    if isinstance(e, MemoryError):
        return "로그가 너무 커서 메모리가 모자랍니다 — 장애 시각 전후 구간만 잘라서 넣으십시오(1회 합계 600MB 이하)."
    if isinstance(e, IsADirectoryError):
        return f"폴더가 아니라 로그 파일을 넣으십시오{(': ' + short) if short else ''}."
    return str(e)


def window_title() -> str:
    t = "LogTriage — 장애 로그 1차 대응 분석기"
    return ("[시험 실행 · 업무 사용 금지] " + t) if os.environ.get("LOGTRIAGE_TEST_RUN") == "1" else t   # 10차 ⑨


AUTO_LEGACY_ONCE = "incidents.json.migrated.auto-done"


def _auto_legacy(api) -> dict:
    """13차(마스터: 다른 PC 에서 '예전 분석 N건' 띠가 매번 뜸 — 왜 저절로 안 되나): 설치 폴더를 자료(data) 없이 옮긴 새 PC 의 첫 기동이면
    이관 파일의 예전 분석을 저절로 가져온다. 조건을 좁힌다 — 이력 0건 · 읽기 오류 없음 · 그 자리에 이력이 있던 표시가 없음(있으면 '줄어듦'이라
    사람이 판단) · 이관 파일에 빠진 건 있음 · 폴더에 쓸 수 있음. 가져오기 전에 DB 백업(restore_legacy_history 가 함). 결과는 경고가 아니라 알림."""
    out = {"done": False}
    try:
        if not _writable(api._base) or not hasattr(api, "restore_legacy_history"):
            return out
        once = api._base / AUTO_LEGACY_ONCE   # GPT 98차 P0-02: 저절로는 그 자리에서 한 번만 — 사용자가 이력을 비운 뒤 되살리지 않는다
        if once.exists():
            return out
        hs = api._history_status()
        if hs.get("error") or hs.get("count") != 0:
            return out
        m = api._read_mark()
        if isinstance(m.get("high"), int) and m["high"] > 0:
            return out
        lg = api._legacy_status()
        if not lg.get("missing"):
            return out
        r = api.restore_legacy_history()
        if r.get("error"):
            logging.warning("auto legacy restore failed: %s", r.get("error"))
            return {"done": False, "error": r.get("error")}
        try:
            once.write_text(json.dumps({"at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "restored": r.get("restored", 0),
                                        "backup": r.get("backup", "")}, ensure_ascii=False), encoding="utf-8")
        except OSError:
            logging.warning("auto legacy once-mark not written")
        msg = (f"이 PC 첫 기동 — 이관 파일의 예전 분석 {r.get('restored', 0)}건을 분석 이력으로 저절로 가져왔습니다"
               f"(가져오기 전 백업: backups\\{r.get('backup', '')} · 원문 이벤트는 없어 로그 검색은 되지 않음)")
        api.__dict__.setdefault("_notices", []).append(msg)
        logging.info("auto legacy restore: restored=%s skipped=%s backup=%s", r.get("restored"), r.get("skipped"), r.get("backup"))
        return {"done": True, **r}
    except Exception:   # noqa: BLE001
        logging.exception("auto legacy restore failed")
        return out


def _diag_log(api) -> None:
    """10차 ⑦: 기동 자기진단 한 줄 — 판 해시·지식·이력·자가 점검을 실행 기록(logtriage_gui.log)에. 화면을 막지 않게 별도 스레드."""
    try:
        d = api.diag()
        ic = api.install_check() if hasattr(api, "install_check") else {}
        # 13차: 경고 '건수'만으로는 다른 PC 에서 무엇이 떴는지 알 수 없었다 — 경고 코드를 함께(원격 지원 때 실행 기록 한 줄로 원인 확인)
        logging.info("self-diagnosis exe=%s install=%s rules=%s codes=%s history=%s(%s) legacy_missing=%s drop=%s self_check=%s/%s warnings=%d codes=%s",
                     (ic or {}).get("sha", "dev"), (ic or {}).get("state"), d.get("rules"), d.get("codes"),
                     (d.get("history") or {}).get("count"), (d.get("history") or {}).get("error") or "ok",
                     (d.get("legacy") or {}).get("missing"), (d.get("drop") or {}).get("dropped"),
                     (d.get("self_check") or {}).get("state"), (d.get("self_check") or {}).get("findings"), len(d.get("warnings") or []),
                     ",".join(i.get("code", "") for i in d.get("warn_items") or []) or "-")
    except Exception:   # noqa: BLE001
        logging.exception("self-diagnosis failed")


_BASE: list = []          # [자리, 까닭] — 한 번 정하면 프로세스가 끝날 때까지 같은 자리(기록·인스턴스·DB 가 갈라지지 않게)
USER_HOME_MARK = ".lt-user-home"
# 압축 프로그램이 '압축 안에서 바로 실행'할 때 푸는 임시 폴더 이름(탐색기 Temp1_x.zip · 7-Zip 7zO… · 반디집 BNZ.… · 알집 · WinRAR Rar$EX…)
_ARCHIVE_TMP = re.compile(r"^(Temp\d+_.+|.+\.zip|7z[OS].+|BNZ\..+|Bandizip.*|_?ALZ.*|Rar\$EX.+)$", re.I)


def user_home() -> Path:
    """사용자별 자료 자리 — 어느 PC·어느 계정이든 이 사용자는 쓸 수 있다(%LOCALAPPDATA%\\LogTriage\\home)."""
    return Path(os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")) / "LogTriage" / "home"


def _in_archive_tmp(d: Path) -> bool:
    """압축 안에서 바로 실행 · 메일 첨부를 바로 실행(Outlook 은 INetCache\\Content.Outlook 에 두고 정리한다) — 사라질 자리."""
    try:
        d = d.resolve()
    except OSError:
        return False
    if any(p.lower() in ("content.outlook", "inetcache") for p in d.parts):
        return True
    try:
        rel = d.relative_to(Path(tempfile.gettempdir()).resolve())
    except (ValueError, OSError):
        return False
    return any(_ARCHIVE_TMP.match(p) for p in rel.parts)


def _onedrive_new(exe: Path) -> bool:
    """GPT 98차 6-③: OneDrive 동기화 폴더(회사 PC 는 바탕화면이 흔히 여기) — SQLite 는 동기화 중 잠금이 어긋날 수 있다.
    **새로** 푼 것(exe 옆에 이력 DB 가 아직 없음)만 사용자 자리로 — 이미 거기서 쓰던 이력은 옮기지 않고 그대로 쓴다."""
    if (exe / "data" / "logtriage.db").exists():
        return False
    for k in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer"):
        v = os.environ.get(k)
        if v:
            try:
                exe.relative_to(Path(v).resolve())
                return True
            except (ValueError, OSError):
                pass
    return False


def base_why() -> str:
    """exe 옆이 아닌 사용자 자리를 쓰는 까닭: '' | 'readonly' | 'archive' | 'onedrive'."""
    base_dir()
    return _BASE[1]


def base_dir() -> Path:
    """룰·분석 이력이 놓이는 위치 — exe 옆(frozen) 또는 engine 루트.
    14차(2026-10-22 마스터 '불특정 다수 PC·개인 설정에서 기본값으로 동작'): exe 옆에 쓸 수 없거나(Program Files·읽기 전용 USB·권한 없는 공유 폴더)
    압축 파일 안에서 바로 실행한 것(창을 닫으면 지워지는 임시 폴더)이면 사용자 자리(user_home)를 쓴다 — 거기도 못 쓰면 exe 옆(경고가 남음)."""
    if _BASE:
        return _BASE[0]
    if not getattr(sys, "frozen", False):
        _BASE[:] = [Path(__file__).resolve().parents[2], ""]
        return _BASE[0]
    exe = Path(sys.executable).resolve().parent
    why = "archive" if _in_archive_tmp(exe) else ("readonly" if not _writable(exe) else ("onedrive" if _onedrive_new(exe) else ""))
    alt = user_home()
    if why and _writable(alt):
        try:
            (alt / USER_HOME_MARK).write_text(str(exe), encoding="utf-8")   # 이 자리는 앱이 만든 것 — 지식 새로 펼치기(판 올림)를 허용하는 표시
        except OSError:
            pass
        _BASE[:] = [alt, why]
    else:
        _BASE[:] = [exe, ""]
    return _BASE[0]


def ui_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS) / "logtriage" / "gui" / "ui.html"
    return Path(__file__).resolve().parent / "ui.html"


def _writable(d: Path) -> bool:
    try:
        d.mkdir(parents=True, exist_ok=True)
        t = d / ".write_test"
        t.write_text("ok", encoding="utf-8")
        t.unlink()
        return True
    except Exception:
        return False


_EID_Q = re.compile(r"^E-?([0-9A-F]{4,12})$", re.I)


def quickfind_rows(hist: list, q: str, limit: int = 20) -> list[dict]:
    """Ctrl+K 찾기용 서버 검색(GPT UI 19차) — 서버 화면이 이력 전체를 내려받지 않도록 최대 20건, 꼭 필요한 칸만.
    hist 는 **이미 보는 사람 기준으로 가려진** 이력이어야 한다(가리기 전에 거르면 가려진 호스트로도 걸려 존재가 새어 나간다)."""
    q = str(q or "").strip()[:80]
    if len(q) < 2:
        return []
    ql, out = q.lower(), []
    def row(h, ev=None):
        f = h.get("first") or {}
        r = {"id": h.get("id", ""), "name": h.get("name", ""), "verdict": f.get("verdict", ""),
             "severity": f.get("severity", ""), "at": str(h.get("analyzed_at", ""))[:16]}
        if ev:
            r["eid"], r["ev_verdict"], r["ev_ts"] = ev.get("eid", ""), ev.get("verdict", ""), str(ev.get("ts", ""))[:19]
        return r
    m = _EID_Q.match(q)
    if m:                                               # 근거 ID — 분석 ID 와 함께 돌려준다(근거 ID 는 분석 안에서만 유일)
        pre = "E-" + m.group(1).upper()
        for h in hist:
            for t in h.get("timeline") or []:
                if str(t.get("eid", "")).startswith(pre):
                    out.append(row(h, t))
                    if len(out) >= limit:
                        return out
    exact = [h for h in hist if str(h.get("id", "")).lower() == ql]
    out += [row(h) for h in exact]
    for h in hist:
        if len(out) >= limit:
            break
        if exact and h.get("id") == exact[0].get("id"):
            continue
        f = h.get("first") or {}
        hay = " ".join(str(x or "") for x in (h.get("id"), h.get("name"), f.get("verdict"), f.get("layer_ko"), f.get("rule_id"))).lower()
        if ql in hay:
            out.append(row(h))
    return out[:limit]


class Api:
    def __init__(self):
        self._window: Any = None
        self._base = base_dir()
        self._history_file = self._base / "incidents.json"

    def _base_notice(self) -> list:
        """14차: 사용자 자리를 쓰는 까닭을 경고가 아닌 알림으로 — 사람이 고칠 것이 없다(그 자리에서 정상 동작)."""
        why = base_why() if self._base == base_dir() else ""
        if not why:
            return []
        exe = Path(sys.executable).resolve().parent
        old = (exe / "data" / "logtriage.db").exists()
        tail = [f"exe 폴더에 예전 분석 이력(data\\logtriage.db)이 있습니다 — 그 이력을 이어 쓰려면 exe 폴더째 쓸 수 있는 곳(바탕화면·D:\\ 등)으로 옮겨 실행하십시오."] \
            if old and why != "onedrive" else []
        if why == "onedrive":
            return [f"exe 가 OneDrive 동기화 폴더({exe})에 있어 이력 DB 가 동기화와 부딪히지 않도록 자료를 사용자 자리 {self._base} 에 둡니다 — 그대로 쓰면 됩니다."]
        if why == "archive":
            return tail + [f"압축 파일 안에서 바로 실행했습니다 — 창을 닫으면 지워지는 임시 폴더라 자료(분석 이력·보고서·설정)를 사용자 자리 {self._base} 에 둡니다. "
                    "압축을 풀어 원하는 폴더에서 실행해도 되고, 그대로 써도 이 계정에서는 같은 자리를 계속 씁니다."]
        return tail + [f"exe 폴더({exe})에 쓸 수 없어(보호 폴더·읽기 전용) 자료를 사용자 자리 {self._base} 에 둡니다 — 그대로 쓰면 됩니다. "
                "이 PC 의 다른 계정은 각자 자기 자리를 씁니다."]

    # ── 설정(보고서 저장 폴더 등) — exe 옆 settings.json, 쓸 수 없으면 %LOCALAPPDATA%/LogTriage ──
    def _settings_path(self) -> Path:
        if _writable(self._base):
            return self._base / "settings.json"
        import os
        return Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "LogTriage" / "settings.json"

    def _settings(self) -> dict:
        try:
            import json
            p = self._settings_path()
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        except Exception:
            return {}

    def _save_settings(self, d: dict) -> None:
        import json
        p = self._settings_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")

    def reports_dir(self) -> Path:
        """보고서 저장 폴더: 설정값 → exe 옆 reports → (쓸 수 없으면) 내 문서/LogTriage/reports"""
        s = self._settings()
        cand = [Path(s["report_dir"])] if s.get("report_dir") else []
        cand.append(self._base / "reports")
        cand.append(Path.home() / "Documents" / "LogTriage" / "reports")
        for d in cand:
            if _writable(d):
                return d
        return cand[-1]

    def pick_report_dir(self):
        """보고서 저장 폴더 선택(폴더 대화상자) → 설정 저장"""
        try:
            sel = self._window.create_file_dialog(webview.FileDialog.FOLDER) or []
            if not sel:
                return {"cancel": True, "report_dir": str(self.reports_dir())}
            return self.set_report_dir(sel[0] if isinstance(sel, (list, tuple)) else sel)
        except Exception as e:
            return {"error": str(e)}

    def set_report_dir(self, path: str):
        try:
            d = Path(path).expanduser()
            if not _writable(d):
                return {"error": f"이 폴더에 쓸 수 없습니다: {d}"}
            s = self._settings()
            s["report_dir"] = str(d)
            self._save_settings(s)
            return {"ok": True, "report_dir": str(d)}
        except Exception as e:
            return {"error": str(e)}

    def diag(self):
        """환경 점검 — exe 옆 필수 폴더(rules/errorcodes/report-template)·보고서 폴더 쓰기 가능 여부. 다른 PC 배포 시 원인 진단용"""
        try:
            from ..report_forms import FORMS
            rules_n = 0
            try:
                rules_n = len(load_rules(self._base / "rules", self._base / "rules-local"))
            except Exception:
                pass
            from ..codes import load_codes
            try:
                codes_n = len({k for k in load_codes(self._base / "errorcodes") if ":" in k})
            except Exception:
                codes_n = 0
            forms = {f["file"]: (self._base / "report-template" / f["file"]).exists() for f in FORMS}
            rd = self.reports_dir()
            warns, items = [], []

            def add(code, text, clears, action="", first=False):
                """13차(마스터: 다른 PC 에서 '환경 점검' 띠 — 왜 뜨고·어떻게 하고·왜 저절로 안 되나): 경고마다 무엇이 원인이고
                언제 사라지며 무엇을 누르면 되는지를 함께 낸다. warnings(글 목록)는 예전 화면·기록과 같게 유지."""
                (warns.insert(0, text) if first else warns.append(text))
                it = {"code": code, "text": text, "clears": clears, "action": action}
                (items.insert(0, it) if first else items.append(it))

            if not (self._base / "rules").is_dir() or rules_n == 0:
                add("rules_missing", f"룰 폴더(rules)가 없거나 비어 있습니다 — 룰 0개로는 판정이 되지 않습니다. LogTriage.exe 와 같은 폴더에 배포본의 rules·errorcodes·manuals·report-template 폴더를 함께 두십시오. (현재 위치: {self._base})",
                    "exe 옆에 rules 폴더가 채워지면(빈 폴더에 exe 하나만 두면 첫 기동 때 내장 지식이 저절로 펼쳐짐)")
            elif codes_n == 0:
                add("codes_missing", f"에러코드 폴더(errorcodes)가 없거나 비어 있습니다 — 제조사 코드 판정이 빠집니다. (현재 위치: {self._base})",
                    "errorcodes 폴더가 채워지면")
            missing = [k for k, ok in forms.items() if not ok]
            if missing:
                add("forms_missing", "보고서 서식 파일이 없습니다: " + ", ".join(missing) + f" — report-template 폴더를 exe 옆에 두십시오. (현재 위치: {self._base})",
                    "report-template 폴더에 서식이 있으면")
            if not _writable(self._base):
                add("not_writable", f"exe 폴더에 쓸 수 없어 분석 이력·보고서를 다른 위치에 저장합니다: {rd}",
                    "쓸 수 있는 폴더(예: 바탕화면·D:\\LogTriage)로 exe 를 옮기면 — Program Files 같은 보호 폴더에서는 계속 뜸")
            # 10차(10-19 마스터 보고 '어떤 로그도 분석이 안 되고 장애 이력이 없다'): 화면의 '없음'이 진짜 0건인지 · 판정이 실제로 나는지를 증거로
            test_run = os.environ.get("LOGTRIAGE_TEST_RUN") == "1"
            hs, lg, drop, sc = self._history_status(), self._legacy_status(), self._history_drop(), self._self_check()
            if test_run:
                add("test_run", "이 창은 점검 도구가 띄운 시험 실행입니다 — 업무에 쓰지 마십시오(점검이 끝나면 저절로 닫힙니다).",
                    "점검이 끝나 창이 닫히면", first=True)
            if sc.get("state") != "ok":
                add("self_check_failed", f"판정 자가 점검 실패 — 합성 로그(커넥션 풀 고갈)에서 판정이 나오지 않았습니다: {sc.get('note', '')} "
                    "이 상태의 '미검출'은 믿을 수 없습니다.", "판정 지식(rules)을 배포본으로 되돌려 다음 기동에서 자가 점검이 통과하면")
            if hs.get("error"):
                add("history_unreadable", f"분석 이력을 읽지 못했습니다({hs['error']}) — 화면의 '이력 없음'은 실제로 0건이라는 뜻이 아닙니다. 위치: {hs.get('where', '')}",
                    "이력 파일·DB 를 읽을 수 있게 되면(다른 프로그램이 잠갔거나 권한 문제)")
            if drop.get("dropped"):
                add("history_dropped", f"분석 이력이 지난번 {drop['prev']}건 → 지금 {drop['now']}건으로 줄었습니다 — 앱 밖에서 자료가 바뀌었을 수 있습니다. "
                    "backups 폴더의 백업을 확인하고, 의도한 것이면 관리자가 '확인함'을 누르십시오(그 전까지 이 안내는 남습니다).",
                    "관리자가 [확인함]을 누르면 — 자료 유실·바꿔치기를 놓치지 않으려고 저절로 지우지 않음", "ackHistory")
            if drop.get("replaced"):
                add("history_replaced", f"분석 이력 구성이 바뀌었습니다(지난번 {drop['prev']}건 · 지금 {drop['now']}건, 지난번 있던 기록이 지금 이력에 없음) — 앱 밖에서 이력이 바꿔치기됐을 수 있습니다. "
                    "의도한 것이면 관리자가 '확인함'을 누르십시오.", "관리자가 [확인함]을 누르면", "ackHistory")
            if drop.get("db_changed"):
                add("db_changed", f"분석 이력 DB 위치가 지난번과 다릅니다 — 지금 {hs.get('where', '')}. 다른 자료를 보고 있을 수 있습니다.",
                    "한 번만 알림 — 다음 기동부터는 지금 위치가 기준(설치 폴더째 옮긴 것은 경고하지 않음)")
            for w in self.__dict__.get("_boot_warns") or []:   # 22차(GPT 153 P1-02): 기동 때 내려간 설정(창 모드 LAN → 이 PC 안)
                add(w["code"], w["text"], w["clears"], first=True)
            if lg.get("missing"):
                add("legacy_missing", f"예전 분석 {lg['missing']}건이 이관 파일(incidents.json.migrated)에만 있고 지금 이력에는 없습니다 — "
                    "[분석 이력] 화면에서 가져올 수 있습니다(관리자, 원문 이벤트는 없음).",
                    "[가져오기]를 누르면(가져오기 전 자동 백업) — 이력이 이미 있는 PC 에서는 섞일 수 있어 저절로 가져오지 않음", "restoreLegacy")
            return {"base": str(self._base), "exe": sys.executable if getattr(sys, "frozen", False) else "",
                    "rules": rules_n, "codes": codes_n, "forms": forms, "report_dir": str(rd),
                    "base_writable": _writable(self._base), "warnings": warns, "warn_items": items,
                    "notices": self._base_notice() + list(self.__dict__.get("_notices") or []),
                    "history": hs, "legacy": lg, "drop": drop, "self_check": sc, "test_run": test_run,
                    "knowledge_source": self._knowledge_source(), "engine_perf": self._engine_perf()}
        except Exception as e:
            return {"error": str(e)}

    # ── 메타 ──────────────────────────────────────────────
    _rc_lock = threading.RLock()   # 룰·코드 캐시와 룰팩 파일 교체를 모두 이 락 하나로 직렬화(락 순서 문제 없음)

    def _dir_stamp(self):
        """rules·rules-learned·rules-local·errorcodes 의 모든 YAML (상대경로, mtime_ns, size) — 어느 파일이 바뀌어도 달라진다"""
        items = []
        for d in (self._base / "rules", self._base / "rules-learned", self._base / "rules-local", self._base / "errorcodes"):
            if d.exists():
                for f in sorted(d.rglob("*.yaml")):
                    try:
                        st = f.stat(); items.append((str(f.relative_to(self._base)), st.st_mtime_ns, st.st_size))
                    except OSError:
                        pass
        return tuple(items)

    def _load_rules_codes(self):
        """룰·에러코드 사전을 한 번만 파싱해 재사용(수 초 절약). 파일이 바뀌면 자동 재로드, 실패하면 직전 정상 캐시 유지."""
        from ..codes import load_codes
        with Api._rc_lock:
            stamp = self._dir_stamp()
            c = getattr(self, "_rc_cache", None)
            if c and c[0] == stamp:
                return c[1], c[2]
            try:
                rules = load_rules(self._base / "rules", self._base / "rules-local")
                codes = load_codes(self._base / "errorcodes")
            except Exception as e:
                import sys; sys.stderr.write(f"[rules] load failed: {e}\n")
                if c:
                    return c[1], c[2]   # 직전 정상 캐시 유지(빈 결과를 캐시하지 않음)
                raise
            self._rc_cache = (stamp, rules, codes); self._codes_cache_v = None
            return rules, codes

    def _invalidate_rules_cache(self):
        with Api._rc_lock:
            self._rc_cache = None; self._codes_cache_v = None

    def warm_up(self):
        """기동 직후 백그라운드에서 룰·코드 캐시와 대시보드 요약을 미리 계산(첫 화면이 느리지 않게). 실패해도 캐시를 건드리지 않는다."""
        def run():
            try:
                self._load_rules_codes(); self._codes_summary()
            except Exception:
                pass
        threading.Thread(target=run, name="warm-up", daemon=True).start()

    def meta(self):
        rules, codes = self._load_rules_codes()
        from ..parsers import supported_products
        return {"version": __version__, "rule_count": len(rules),
                "code_count": len({k for k in codes if ":" in k}),
                "products": supported_products()}

    # ── 파일 선택 ─────────────────────────────────────────
    def pick_logs(self):
        try:
            paths = self._window.create_file_dialog(
                webview.FileDialog.OPEN, allow_multiple=True,
                file_types=("Log files (*.log;*.out;*.txt;*.csv)",
                            "All files (*.*)")) or []
            out = []
            for p in paths:
                path = Path(p)
                out.append({"path": str(path), "name": path.name,
                            "product": detect_product(path), "size": self._fsize(path)})
            return out
        except Exception as e:  # 실패 원인을 화면에 그대로 보여준다
            return {"error": f"{type(e).__name__}: {e}"}

    SAMPLE_PICK = ("catalina.out", "alert_orcl.log", "SystemOut.log", "listener.log")

    @staticmethod
    def _samples_root() -> Path:
        return (Path(getattr(sys, "_MEIPASS", "")) if getattr(sys, "frozen", False) else base_dir()) / "samples"

    def _sample_bytes(self, inputs):
        """입력 전체가 exe 안 합성 견본이면 그 **검증한 바이트** 목록, 아니면 None.
        조건: 견본 폴더 바로 아래 · 정해진 이름 · 링크 아님 · 읽은 바이트의 지문이 견본 목록(SHA256SUMS.json)과 같음.
        GPT 81차: 경로만 보면 같은 자리에 실제 로그를 덮어써도 시연(DEMO-)으로 분류돼 '체험 기록 지우기'에 실제 분석이 지워질 수 있다.
        GPT 82차: 확인한 뒤 다시 열면 그 사이 바뀔 수 있다(TOCTOU) — 분석은 이 바이트 그대로 쓴 임시 사본으로 한다."""
        import hashlib
        try:
            root = self._samples_root().resolve()
            man = json.loads((root / "SHA256SUMS.json").read_text(encoding="utf-8"))
            if not inputs:
                return None
            out = []
            for i in inputs:
                p = Path(i["path"])
                if p.is_symlink() or p.resolve().parent != root or p.name not in self.SAMPLE_PICK:
                    return None
                data = p.read_bytes()
                if hashlib.sha256(data).hexdigest() != man.get(p.name):
                    return None
                out.append(data)
            return out
        except (OSError, KeyError, TypeError, ValueError):
            return None

    def _is_sample_run(self, inputs) -> bool:
        return self._sample_bytes(inputs) is not None

    def sample_logs(self):
        """10차 UX(대회 심사 첫 5분 · GPT 79차): 로그가 없어도 바로 분석해 보게 — exe 안 합성 견본(실로그 아님) 4종을 목록으로.
        서버형에서 허용 경로가 아니면 비운다(남의 경로를 열어 주지 않음)."""
        root = self._samples_root()
        ok = getattr(self, "_allowed", None)
        out = []
        for n in self.SAMPLE_PICK:
            p = root / n
            if p.is_file() and (ok is None or ok(p)):
                out.append({"path": str(p), "name": n, "product": detect_product(p), "size": self._fsize(p), "sample": True})
        return out

    def default_time(self):
        return datetime.now().strftime("%Y-%m-%dT%H:%M")

    def detect(self, paths):
        """드래그&드롭된 파일들의 제품 자동 감지."""
        out = []
        for p in paths:
            path = Path(p)
            if path.exists():
                out.append({"path": str(path), "name": path.name,
                            "product": detect_product(path), "size": self._fsize(path)})
        return out

    @staticmethod
    def _fsize(path: Path) -> int:
        try:
            return path.stat().st_size
        except OSError:
            return 0

    def save_html(self, html: str, default_name: str):
        """분석 리포트를 단독 HTML 파일로 저장."""
        try:
            ftype = ("CSV file (*.csv)",) if str(default_name).lower().endswith(".csv") else ("HTML file (*.html)",)
            dest = self._window.create_file_dialog(
                webview.FileDialog.SAVE, save_filename=default_name, file_types=ftype)
            if not dest:
                return {"cancelled": True}
            p = Path(dest if isinstance(dest, str) else dest[0])
            p.write_text(html, encoding="utf-8-sig" if p.suffix.lower() == ".csv" else "utf-8")
            return {"saved": str(p)}
        except Exception as e:
            return {"error": str(e)}

    # ── 분석 ─────────────────────────────────────────────
    def analyze(self, payload):
        sample_tmp = None
        # 호출자의 입력을 고쳐 쓰지 않는다 — 견본 경로를 임시 사본으로 바꾼 것이 밖에 남으면 같은 입력의 다음 분석이 지워진 사본을 가리킨다(11차 시험에서 발견)
        payload = dict(payload or {})
        payload["inputs"] = [dict(i) for i in (payload.get("inputs") or [])]
        try:
            raw = (payload.get("incident_time") or "").replace("T", " ")[:16]
            t = raw if raw.strip() else None  # 비우면 장애 시간 자동 탐지
            # 제품 미지정 파일은 여기서 한 번 더 자동 판별
            for item in payload["inputs"]:
                if not item.get("product"):
                    item["product"] = detect_product(Path(item["path"]))
                if not item.get("product"):
                    return {"error": f"제품 자동 판별 실패: {Path(item['path']).name} "
                                     "— 목록에서 제품을 직접 선택해 주세요."}
            verified = self._sample_bytes(payload["inputs"])   # 11차 ①⑩: 견본만으로 한 분석은 시연 자료(DEMO-) — '체험 기록 지우기'로 지운다
            sample_run = verified is not None
            if sample_run:   # GPT 82차 P0-02: 검증한 바이트 그대로 임시 사본에 써서 분석 — 확인과 분석 사이 바꿔치기 차단
                import tempfile
                sample_tmp = tempfile.mkdtemp(prefix="lt-sample-")
                for k, item in enumerate(payload["inputs"]):
                    q = Path(sample_tmp) / Path(item["path"]).name
                    q.write_bytes(verified[k])
                    item["path"] = str(q)
            inc_id = ("DEMO-" if sample_run else "INC-") + datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            if sample_run and not (payload.get("name") or "").strip():
                payload["name"] = "견본 체험 분석"
            inc_dir = self._base / "incidents"
            job = str(payload.get("job") or "")
            prog = None
            if re.fullmatch(r"[0-9a-f]{16,32}", job):            # 화면이 만든 무작위 작업 번호 — 진행 단계 조회용
                prog = self._job_progress(job)
            import time as _tm
            _t0 = _tm.perf_counter()
            result = run_analysis(
                payload["inputs"], t,
                int(payload.get("before", 30)), int(payload.get("after", 10)),
                self._base / "rules", self._base / "rules-local",
                self._base / "errorcodes",
                events_export=inc_dir / f"{inc_id}.jsonl",
                os_hint=(payload.get("os") or "") or None, progress=prog)
            result["elapsed_sec"] = round(_tm.perf_counter() - _t0, 2)   # 실제로 잰 분석 시간(전체 현황 평균은 잰 건만)
            if result.get("kb_skipped"):   # 지식 파일 손상 — 재시작 뒤에도 남는 기록(바뀔 때만 한 줄, 2026-10-15)
                try:
                    from .. import kbaudit
                    kbaudit.sync(self._base, self._unreadable())
                except Exception:
                    pass
            if prog:
                prog({"stage": "done", "id": inc_id})
            result["name"] = (payload.get("name") or "").strip()  # 비우면 분석 ID 로 표시
            result["id"] = inc_id
            if sample_run:
                result["demo"] = True   # GPT 81차 잠재 P0-02: 시연 정리는 ID 접두어 + 이 표시가 함께 있을 때만 지운다
            learn_items = result.pop("learn", None) or []   # 룰 학습 후보 — 결과·이력에는 남기지 않는다
            try:
                from ..learn import LearnStore
                result["learn_new"] = LearnStore(self._base).record(learn_items, inc_id)
            except Exception:
                result["learn_new"] = 0
            self._save_history(result)
            # 이벤트 원본은 최근 20건만 보관
            try:
                for old in sorted(list(inc_dir.glob("INC-*.jsonl")) + list(inc_dir.glob("DEMO-*.jsonl")))[:-20]:
                    old.unlink()
            except Exception:
                pass
            # 10차 ⑧: 분석 결과를 실행 기록에 한 줄(로그 내용은 남기지 않음) — '분석이 안 된다' 보고를 증거로 따질 수 있게
            logging.info("analysis %s files=%d products=%s events=%s findings=%s sec=%s", inc_id, len(payload["inputs"]),
                         ",".join(sorted({str(i.get("product") or "") for i in payload["inputs"]})),
                         result.get("events_total"), result.get("findings_total"), result.get("elapsed_sec"))
            return result
        except Exception as e:
            logging.warning("analysis failed: %s: %s", type(e).__name__, str(e).split("\n")[0])
            return {"error": friendly_error(e)}
        finally:
            if sample_tmp:
                import shutil as _sh
                _sh.rmtree(sample_tmp, ignore_errors=True)

    def _job_progress(self, job):
        """진행 단계 기록 함수 — 최근 20개 작업만 기억(작업 번호는 화면이 만든 무작위 값)."""
        import threading as _th
        import time as _tm
        if not hasattr(self, "_jobs_lock"):
            self._jobs_lock = _th.Lock()
            self._jobs = {}
        # 작업을 만든 계정을 적어 두고, 진행 조회는 같은 계정만(작업 번호만 알아서는 못 본다 — GPT UI 3차 P0)
        st = {"t0": _tm.time(), "steps": [], "owner": getattr(getattr(self, "actor", None), "login", "") or ""}
        with self._jobs_lock:
            self._jobs[job] = st
            for k in sorted(self._jobs, key=lambda k: self._jobs[k]["t0"])[:-20]:
                self._jobs.pop(k, None)

        def put(d):
            d = dict(d)
            d["sec"] = round(_tm.time() - st["t0"], 1)
            with self._jobs_lock:
                st["steps"].append(d)
                del st["steps"][:-40]
        return put

    def analyze_progress(self, job: str = ""):
        """분석 진행 단계(시안 02) — 엔진이 보고한 단계와 실측 수치만."""
        lock = getattr(self, "_jobs_lock", None)
        if lock is None:
            return {"steps": []}
        who = getattr(getattr(self, "actor", None), "login", "") or ""
        with lock:
            st = self._jobs.get(str(job))
            if not st or st.get("owner", "") != who:
                return {"steps": []}
            return {"steps": list(st["steps"])}

    # ── 분석 이력 ─────────────────────────────────────────
    def _save_history(self, result):
        hist = self.history()
        hist.insert(0, result)
        self._history_file.write_text(
            json.dumps(hist[:50], ensure_ascii=False, indent=1), encoding="utf-8")

    _LEGACY_NAME = "이름 없는 " + "사" + "건"  # 구버전 기본 이름 — 표시하지 않음

    # ── 10차 자기진단(10-19) ──────────────────────────────
    _SELF_SAMPLE = ("2026-01-01 10:00:00,000 INFO  [main] c.e.selfcheck.App - self check start\n"
                    "2026-01-01 10:00:05,120 ERROR [http-nio-8080-exec-7] c.z.h.pool.HikariPool - HikariPool-1 - "
                    "Connection is not available, request timed out after 30001ms.\n"
                    "java.sql.SQLTransientConnectionException: HikariPool-1 - Connection is not available, request timed out after 30001ms.\n"
                    "\tat com.zaxxer.hikari.pool.HikariPool.createTimeoutException(HikariPool.java:696)\n"
                    "2026-01-01 10:00:09,338 ERROR [http-nio-8080-exec-9] c.z.h.pool.HikariPool - HikariPool-1 - "
                    "Connection is not available, request timed out after 30002ms.\n")   # 합성 견본 — 실로그 아님

    SELF_CHECK_SEC = 30

    @staticmethod
    def _engine_perf() -> dict:
        """12차(GPT 90차): 포장본에서도 C YAML 파서·병렬 작업자 수가 실제로 쓰이는지 상태 창·점검이 확인한다."""
        try:
            from .. import BUILD, buildid, parallel, yamlsafe
            # 12차: code_id 는 리눅스 서버 /healthz 의 code_id 와 같은 값이어야 같은 판이다(빌드가 원본에서 센 코드 지문)
            return {"yaml_c": yamlsafe.LOADER.__name__ == "CSafeLoader", "workers": parallel.workers(),
                    "avail_mb": parallel.avail_mb(), "par_min_mb": parallel.PAR_MIN_TOTAL // (1024 * 1024),
                    "build": BUILD, "code_id": buildid.code(), "stamp_scope": buildid.stamped().get("scope", "")}
        except Exception as e:   # noqa: BLE001
            return {"error": f"{type(e).__name__}: {e}"}

    def _knowledge_source(self) -> str:
        """지금 판정 지식이 어디서 왔나 — 세대 기록의 출처(지식 출시·룰팩·exe 내장 지식)와 시각. 기록이 없으면 '설치 폴더(세대 기록 없음)'."""
        try:
            g = json.loads((self._base / "knowledge-gen.json").read_text(encoding="utf-8"))
            return f"{g.get('source', '')} · {g.get('at', '')}".strip(" ·")
        except (OSError, ValueError, AttributeError):
            return "설치 폴더(세대 기록 없음)"

    def _history_status(self):
        """이력 건수·읽기 오류·위치(파일 방식) — 서버형(DB)은 server.ServerApi 가 덮어쓴다."""
        f = self._history_file
        try:
            n = len(json.loads(f.read_text(encoding="utf-8"))) if f.exists() else 0
            return {"count": n, "error": "", "where": str(f)}
        except Exception as e:   # noqa: BLE001
            return {"count": None, "error": f"{type(e).__name__}: {e}", "where": str(f)}

    def _history_ids(self) -> set:
        return {h.get("id") for h in self.history() if isinstance(h, dict)}

    def _legacy_status(self):
        """데스크톱 시절 이관 파일(incidents.json.migrated)에만 남은 분석 — 지금 이력에 없는 id 수."""
        p = self._base / "incidents.json.migrated"
        if not p.is_file():
            return {"total": 0, "missing": 0}
        try:
            rows = json.loads(p.read_text(encoding="utf-8"))
            ids = {r.get("id") for r in rows if isinstance(r, dict) and r.get("id")}
            return {"total": len(ids), "missing": len(ids - self._history_ids())}
        except Exception as e:   # noqa: BLE001
            return {"total": 0, "missing": 0, "error": f"{type(e).__name__}: {e}"}

    def _history_fp(self, ids=None) -> str:
        import hashlib
        ids = self._history_ids() if ids is None else ids
        return hashlib.sha256("\n".join(sorted(str(x) for x in ids if x)).encode()).hexdigest()[:16]

    def _read_mark(self) -> dict:
        try:
            m = json.loads((self._base / "data" / "history-mark.json").read_text(encoding="utf-8"))
            return m if isinstance(m, dict) else {}
        except (OSError, ValueError):
            return {}

    def _write_mark(self, m: dict) -> None:
        mark = self._base / "data" / "history-mark.json"
        try:
            mark.parent.mkdir(parents=True, exist_ok=True)
            tmp = mark.with_suffix(".json.new")
            tmp.write_text(json.dumps({**m, "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, mark)
        except OSError:
            pass

    def _mark_history(self, n=None, force: bool = False):
        """이력 표시(data/history-mark.json) = 앱이 본 최고 건수(high)·그때의 ID 지문(fp)·DB 위치(db).
        GPT 76차: 줄었다고 기준을 저절로 낮추지 않는다 — 앱 안에서 지운 경우·관리자 확인(force)만 다시 맞춘다. 읽기 실패면 손대지 않는다."""
        st = self._history_status()
        n = st.get("count") if n is None else n
        if n is None or st.get("error"):
            return
        try:
            ids = self._history_ids()   # 한 번만 읽는다(지문·닻이 같은 목록 — 이력이 많은 PC 의 기동 시간)
            fp = self._history_fp(ids)
        except Exception:   # noqa: BLE001
            return
        m = self._read_mark()
        same = self._same_db(m, st.get("where"))
        if not force and same and isinstance(m.get("high"), int) and n < m["high"]:
            return                                             # 줄어든 채로는 기준을 내리지 않는다
        rel = self._db_rel(st.get("where"))
        anc = self._anchors(m if (same and not force) else {}, ids)
        if m.get("high") == n and m.get("fp") == fp and m.get("db") == st.get("where") and m.get("db_rel", "") == rel \
                and m.get("anc") == anc:
            return
        self._write_mark({"db": st.get("where"), "db_rel": rel, "high": n, "fp": fp, "anc": anc})

    _ANC_N = 8

    def _anchors(self, m: dict, ids=None) -> list:
        """14차 · GPT 98차 P0-01: DB 를 경로가 아니라 **내용**으로 알아본다 — 지난번 이력에 있던 ID 몇 개(닻)를 표시에 두고,
        다음에 그 닻이 지금 이력에 없으면 같은 자리라도 다른 DB(바꿔치기). 닻은 남아 있는 것을 유지하고 모자라면 지금 ID 로 채운다."""
        ids = self._history_ids() if ids is None else ids
        keep = [x for x in (m.get("anc") or []) if x in ids][:self._ANC_N]
        return keep + sorted(str(x) for x in ids if x and x not in keep)[:self._ANC_N - len(keep)]

    def _db_rel(self, where) -> str:
        """이력 DB 가 설치 폴더 안이면 설치 폴더 기준 상대 경로(posix), 밖이면 ''."""
        try:
            return Path(str(where)).resolve().relative_to(self._base.resolve()).as_posix()
        except (ValueError, OSError, TypeError):
            return ""

    def _same_db(self, m: dict, where) -> bool:
        """지난번 표시와 같은 이력 DB 인가 — 13차(마스터: 다른 PC 에서 '환경 점검' 띠): 설치 폴더를 통째로 다른 경로·다른 PC 로 옮기면
        절대 경로만 바뀌고 자료는 그대로다. 그것까지 'DB 위치가 다릅니다'로 경고해 매번 띠가 떴다(사람이 할 일이 없는 거짓 경보).
        설치 폴더 기준 상대 위치가 같으면 같은 DB. 상대 위치가 다르거나(예: 쓰기 불가로 LOCALAPPDATA 로 빠짐) 폴더 밖이면 다른 DB."""
        if not m.get("db") or m.get("db") == where:
            return True
        rel = self._db_rel(where)
        if not rel:
            return False
        if m.get("db_rel"):
            return m["db_rel"] == rel
        return str(m["db"]).replace("\\", "/").lower().endswith("/" + rel.lower())   # 12차 이전 표시(상대 위치 없음)

    def ack_history_change(self):
        """관리자가 이력 감소·바뀜을 확인했다 — 기준을 지금 상태로(10차 · GPT 76차: 명시적 재설정만)."""
        self._mark_history(force=True)
        self.__dict__.pop("_drop_cache", None)
        return {"ok": True, "drop": self._history_drop()}

    def _history_drop(self):
        """기동 뒤 첫 확인 때 한 번 판정해 고정 — 화면이 이력을 먼저 읽어도(그때 기준 갱신) 판정이 지워지지 않게.
        dropped: 지난 최고 건수보다 적음 · replaced: 건수는 같은데 ID 구성이 다름(같은 건수로 바꿔치기) · db_changed: 이력 DB 위치가 바뀜."""
        with _DIAG_LOCK:
            hit = self.__dict__.get("_drop_cache")
            if hit is not None:
                return hit
            st = self._history_status()
            now, m = st.get("count"), self._read_mark()
            prev = m.get("high") if isinstance(m.get("high"), int) else None
            res = {"prev": prev, "now": now, "dropped": False, "replaced": False, "db_changed": False}
            if now is not None and not st.get("error") and prev is not None:
                if not self._same_db(m, st.get("where")):
                    res["db_changed"] = True
                elif now < prev:
                    res["dropped"] = True
                else:
                    try:
                        ids = self._history_ids()
                        res["replaced"] = now == prev and bool(m.get("fp")) and self._history_fp(ids) != m.get("fp")
                        if not res["replaced"] and m.get("anc"):   # GPT 98차 P0-01: 건수가 늘었어도 지난번 기록(닻)이 없으면 다른 DB
                            res["replaced"] = any(a not in ids for a in m["anc"])
                    except Exception:   # noqa: BLE001
                        pass
            if not (res["dropped"] or res["replaced"]):
                self._mark_history(now)
            self.__dict__["_drop_cache"] = res
            return res

    def _self_check(self):
        """판정 자가 점검 — 합성 로그를 지금 지식으로 분석해 판정이 1건 이상 나오는지(이력·DB 에 남기지 않음). 기동 뒤 한 번."""
        with _DIAG_LOCK:
            hit = self.__dict__.get("_self_cache")
            if hit is not None:
                return hit
            import tempfile
            from ..service import NoKnowledgeError
            try:
                with tempfile.TemporaryDirectory(prefix="lt-selfcheck-") as td:
                    p = Path(td) / "selfcheck-catalina.out"
                    p.write_text(self._SELF_SAMPLE, encoding="utf-8")
                    box: dict = {}

                    def work():
                        try:
                            box["r"] = run_analysis([{"path": str(p), "product": "tomcat", "host": "self-check"}], None, 30, 10,
                                                    self._base / "rules", self._base / "rules-local", self._base / "errorcodes",
                                                    events_export=Path(td) / "ev.jsonl")
                        except BaseException as e:   # noqa: BLE001
                            box["e"] = e
                    w = threading.Thread(target=work, name="lt-selfcheck", daemon=True)
                    w.start()
                    w.join(self.SELF_CHECK_SEC)   # GPT 76차 P1-02: 자가 점검이 화면을 무기한 막지 않게
                    if w.is_alive():
                        raise TimeoutError(f"{self.SELF_CHECK_SEC}초 안에 끝나지 않았습니다")
                    if "e" in box:
                        raise box["e"]
                    r = box["r"]
                # 룰 층을 따로 본다 — 벤더 에러코드만으로도 '발견'이 생겨 룰이 망가져도 통과하던 것을 시험이 잡았다(10차)
                n = sum(1 for c in (r.get("checklist") or []) if c.get("source") == "시그니처 룰")
                res = {"state": "ok" if n > 0 else "fail", "findings": n,
                       "note": "" if n > 0 else "커넥션 풀 고갈 견본에서 시그니처 룰 판정 0건 — 룰이 바뀌었거나 읽히지 않았습니다"}
            except NoKnowledgeError as e:
                res = {"state": "fail", "findings": 0, "note": str(e).split("\n")[0]}
            except TimeoutError as e:
                res = {"state": "timeout", "findings": 0, "note": str(e)}
            except Exception as e:   # noqa: BLE001
                res = {"state": "error", "findings": 0, "note": f"{type(e).__name__}: {e}"}
            self.__dict__["_self_cache"] = res
            return res

    def history(self):
        try:
            hist = json.loads(self._history_file.read_text(encoding="utf-8"))
            for h in hist:
                if h.get("name") == self._LEGACY_NAME:
                    h["name"] = ""
            return hist
        except Exception:
            return []

    def quickfind(self, q=""):
        """Ctrl+K 찾기(이 PC 창) — 서버형은 server.py 가 보는 사람 기준으로 가린 이력으로 같은 함수를 부른다."""
        return quickfind_rows(self.history(), q)

    # ── 룰 ───────────────────────────────────────────────
    def rules_list(self):
        try:
            rules = load_rules(self._base / "rules", self._base / "rules-local")
            return [{"id": r.id, "layer": r.layer, "products": r.products,
                     "verdict": r.verdict, "severity": r.severity,
                     "source": r.source} for r in rules]
        except Exception as e:
            return {"error": str(e)}

    # ── 누적 장애 현황 (분석 이력 통계) ──
    # ── 대시보드 요약(서버형·exe 내장 서버: nms/docs 가 있을 때만) ──
    def _monitor_summary(self):
        nms = getattr(self, "nms", None)
        if not nms:
            return None
        try:
            from collections import Counter
            snap = nms.snapshot(); T = snap.get("targets", [])
            kinds = Counter(str(x.get("kind") or "other") for x in T)
            on = [x for x in T if x.get("enabled")]   # 정상/장애/확인 필요는 모두 '활성 대상' 기준 — 일시 중지와 겹치지 않음
            alerts = sorted(snap.get("alerts", []), key=lambda a: a.get("opened") or 0, reverse=True)
            return {"total": len(T), "up": sum(1 for x in on if x.get("status") == "up" and not x.get("stale")),
                    "down": sum(1 for x in on if x.get("status") == "down"), "paused": len(T) - len(on),
                    "attention": sum(1 for x in on if x.get("stale") or x.get("status") not in ("up", "down")),
                    "usage_over": sum(1 for a in snap.get("usage_alarms", []) if a.get("over")),
                    "metrics": sum(1 for x in on if x.get("metrics") not in (None, "none") and x.get("usage") and not x["usage"].get("stale")),   # 지금 수집되는 대상
                    "by_kind": [{"kind": k, "n": n} for k, n in kinds.most_common()],
                    "recent_alerts": [{"name": a.get("name"), "opened": a.get("opened"), "closed": a.get("closed")} for a in alerts[:5]]}
        except Exception as e:   # 기능 미지원(None)과 구분해 화면에 오류를 보이고 서버 로그에 남김
            import sys, traceback; sys.stderr.write("[dash] monitor summary: " + traceback.format_exc()); return {"error": f"모니터링 요약 실패: {e}"}

    def _inventory_summary(self):
        docs = getattr(self, "docs", None)
        if not docs:
            return None
        try:
            L = docs.list()
            return {"docs": len(L), "sheets": sum(int(d.get("sheets") or 0) for d in L), "rows": sum(int(d.get("rows") or 0) for d in L),
                    "edits": sum(int(d.get("edits") or 0) for d in L), "last_at": max((d.get("at") or 0 for d in L), default=None),
                    "recent": [{"id": d["id"], "name": d["name"], "rows": d.get("rows") or 0, "sheets": d.get("sheets") or 0, "at": d.get("at"), "edits": d.get("edits") or 0} for d in L[:4]]}
        except Exception as e:
            import sys, traceback; sys.stderr.write("[dash] inventory summary: " + traceback.format_exc()); return {"error": f"자원 요약 실패: {e}"}

    def _codes_summary(self):
        """코드 등록 현황 — 캐시된 룰·코드 스냅샷(같은 세대)으로 계산, 파일이 바뀌면 자동 갱신. 실패 결과는 캐시하지 않음."""
        with Api._rc_lock:
            rules, codes = self._load_rules_codes()
            stamp = self._rc_cache[0]
            c = getattr(self, "_codes_cache_v", None)
            if c and c[0] == (str(self._base), stamp):
                return c[1]
            r = self._codes_summary_calc(rules, codes)
            if r and not r.get("error"):
                self._codes_cache_v = ((str(self._base), stamp), r)
            return r

    def _codes_summary_calc(self, rules, codes):
        try:
            from collections import Counter
            by_product, by_layer = Counter(), Counter()
            for k, e in codes.items():
                if ":" not in k:
                    continue
                by_product[(e.product or "?").upper()] += 1; by_layer[str(e.layer or "sw").upper()] += 1
            rule_layers = Counter(str(getattr(r, "layer", "") or "?").upper() for r in rules)
            rule_count = len(rules)
            return {"total": sum(by_product.values()), "products": len(by_product), "layers": len(by_layer), "rules": rule_count,
                    "by_product": [{"name": k, "n": n} for k, n in by_product.most_common(8)],
                    "by_layer": [{"name": k, "n": n} for k, n in by_layer.most_common()],
                    "rules_by_layer": [{"name": k, "n": n} for k, n in rule_layers.most_common()]}
        except Exception as e:
            import sys, traceback; sys.stderr.write("[dash] codes summary: " + traceback.format_exc()); return {"error": f"코드 요약 실패: {e}"}

    STATS_DAYS = (0, 7, 30, 90)   # 전체 현황 기간 칩(0 = 전체)

    def stats(self, days=0, *, _hist=None):
        """_hist: 서버형이 보는 사람 기준으로 가린 이력을 넘긴다(10-23 — 다른 부서 분석의 호스트가 '최근 분석'·TOP5 로 새지 않게).
        키워드 전용이라 화면이 보내는 인자(위치 인자)로는 채울 수 없다."""
        try:
            from collections import Counter
            from datetime import timedelta
            try:
                days = int(days or 0)
            except (TypeError, ValueError):
                days = 0
            if days not in self.STATS_DAYS:
                days = 0
            hist = self.history() if _hist is None else _hist

            def _fsev(h):   # 최초 관측 판정의 등급 — 옛 이력은 first.severity 가 없어 checklist 의 같은 룰에서
                f = h.get("first") or {}
                if f.get("severity"):
                    return f["severity"]
                for c in h.get("checklist") or []:
                    if c.get("rule_id") == f.get("rule_id") and c.get("severity"):
                        return c["severity"]
                return ""
            # 시연(체험) 분석은 통계에서 뺀다 — 정식 통계가 시연 자료로 부풀지 않게(GPT UI 3차). 뺀 건수는 화면에 밝힌다
            from ..demo_data import PREFIX as _DEMO
            demo_n = sum(1 for h in hist if str(h.get("id", "")).startswith(_DEMO))
            hist = [h for h in hist if not str(h.get("id", "")).startswith(_DEMO)]
            now = datetime.now()
            if days:   # 기간 칩 — 분석 시각 기준으로 자른다(시각이 없는 옛 기록은 기간 집계에서 빠진다)
                since = (now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                hist = [h for h in hist if str(h.get("analyzed_at", "")).replace("T", " ")[:19] >= since]
            daily = {}  # 실제 분석한 날짜만(전체 이력, 최신순) — 상시 발생이 아니므로 날짜 나열 없음
            by_layer, by_type = Counter(), {}
            crit_total = 0
            sev = {"critical": 0, "error": 0, "warn": 0, "info": 0}
            secs = [float(h["elapsed_sec"]) for h in hist if isinstance(h.get("elapsed_sec"), (int, float))]
            for h in hist:
                ts = h.get("analyzed_at", "")[:10]
                key = ts if len(ts) == 10 else ""
                is_crit = bool(h.get("sev_totals", {}).get("critical")) or (
                    h.get("first") and any(
                        t.get("severity") == "critical" for t in h.get("timeline", [])))
                if key:
                    dd = daily.setdefault(key, {"n": 0, "crit": 0, "verdicts": []})
                    dd["n"] += 1
                    if is_crit:
                        dd["crit"] += 1
                    v = (h.get("first") or {}).get("verdict")
                    if v and v not in dd["verdicts"] and len(dd["verdicts"]) < 3:
                        dd["verdicts"].append(v)
                for k in sev:
                    sev[k] += int((h.get("sev_totals") or {}).get(k, 0) or 0)
                if is_crit:
                    crit_total += 1
                f = h.get("first")
                if f:
                    by_layer[f.get("layer_ko", "?")] += 1
                    t = by_type.setdefault(f.get("verdict", "?"), {
                        "n": 0, "category": f.get("category_ko", ""), "severity": _fsev(h),
                        "layer_ko": f.get("layer_ko", ""), "rule_id": f.get("rule_id", ""),
                        "last_id": h.get("id", ""), "last": h.get("analyzed_at", "")[:16],
                        "immediate": [], "short": [], "vendor_action": "", "hosts": []})
                    t["n"] += 1
                    if not t["immediate"]:  # 가장 최근 분석(이력은 최신순)의 조치 요약
                        for c in h.get("checklist", []):
                            if c.get("rule_id") == f.get("rule_id"):
                                t["immediate"] = c.get("immediate", [])[:4]
                                t["short"] = c.get("short", [])[:3]
                                t["vendor_action"] = c.get("vendor_action", "")
                                break
                else:
                    by_layer["CLEAR"] += 1
            top_types = sorted(
                ({"verdict": k, **v} for k, v in by_type.items()),
                key=lambda x: -x["n"])[:5]
            return {
                "monitor": self._monitor_summary(), "inventory": self._inventory_summary(), "codes": self._codes_summary(),
                "total": len(hist), "critical": crit_total, "sev": sev,
                "elapsed_avg": (round(sum(secs) / len(secs), 1) if secs else None), "elapsed_n": len(secs),
                "demo_excluded": demo_n, "days": days,
                "last_at": (hist[0].get("analyzed_at", "") if hist else ""),
                "daily": [{"d": k, **v} for k, v in sorted(daily.items(), reverse=True)][:30],
                "by_layer": [{"layer": k, "n": v} for k, v in by_layer.most_common()],
                "top_types": top_types,
                "recent": [dict(self._brief(h), severity=_fsev(h)) for h in hist[:6]],
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def _brief(h):
        """대시보드 '최근 분석' 요약 — 판정·규모·첫 조치 한 줄씩."""
        f = h.get("first") or {}
        files = h.get("files") or []
        crit = (h.get("sev_totals") or {}).get("critical", 0)
        scale = f"파일 {len(files)} · 이벤트 {h.get('events_total', 0):,} · 근거 {h.get('match_count', 0):,}"
        if crit:
            scale += f" · critical {crit}"
        action = ""
        for c in h.get("checklist", []):
            if c.get("rule_id") == f.get("rule_id") and c.get("immediate"):
                action = c["immediate"][0]
                break
        if not action and h.get("checklist"):
            action = (h["checklist"][0].get("immediate") or [""])[0]
        name = (h.get("name") or "").strip()
        return {"id": h.get("id"), "name": name,
                "verdict": f.get("verdict", "알려진 장애 패턴 미검출(전 계층 CLEAR)"),
                "category": f.get("category_ko", ""), "layer_ko": f.get("layer_ko", "CLEAR"),
                "rule_id": f.get("rule_id", ""), "ongoing": bool(f.get("ongoing_at_start")),
                "severity": f.get("severity", ""), "kb_skipped": bool(h.get("kb_skipped")),
                "incident_time": h.get("incident_time", ""), "scale": scale, "action": action,
                "at": h.get("analyzed_at", "")}

    # ── 로그 검색 (분석 건의 원본 이벤트 검색) ──
    def log_incidents(self):
        """검색 가능한 분석 건 목록 (이벤트 원본이 보관된 것만)."""
        hist = self.history()
        avail = {p.stem for p in (self._base / "incidents").glob("*.jsonl") if p.stem.startswith(("INC-", "DEMO-"))}
        return [{"id": h["id"], "name": h.get("name", ""),
                 "at": h.get("analyzed_at", "")}
                for h in hist if h.get("id") in avail]

    def search_logs(self, incident_id: str, query: str = "",
                    severity: str = "", layer: str = "", limit: int = 300,
                    t_from: str = "", t_to: str = ""):
        """t_from/t_to: 'YYYY-MM-DD HH:MM:SS' — 이벤트 발생 추이 막대·타임라인 요점에서 넘어온 시간 구간."""
        try:
            path = self._base / "incidents" / f"{incident_id}.jsonl"
            if not path.exists():
                return {"error": "이 분석 건의 이벤트 원본이 없습니다 (최근 20건만 보관)."}
            terms = [t.lower() for t in (query or "").split() if t.strip()]
            t_from = (t_from or "").strip()[:19]
            t_to = (t_to or "").strip()[:19]
            rows, total = [], 0
            from collections import Counter
            hours, codes_c, sev_c = [0] * 24, Counter(), Counter()
            with open(path, encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if severity and e.get("severity") != severity:
                        continue
                    if layer and e.get("layer") != layer:
                        continue
                    ets = str(e.get("ts", ""))
                    if t_from and ets < t_from:
                        continue
                    if t_to and ets > t_to:
                        continue
                    if terms:
                        blob = " ".join(str(e.get(k, "")) for k in
                                        ("message", "code", "host", "product")).lower()
                        if not all(t in blob for t in terms):
                            continue
                    total += 1
                    try:
                        hours[int(str(e.get("ts", ""))[11:13])] += 1
                    except (ValueError, IndexError):
                        pass
                    if e.get("code"):
                        codes_c[e["code"]] += 1
                    sev_c[e.get("severity", "")] += 1
                    if len(rows) < limit:
                        rows.append(e)
            return {"total": total, "shown": len(rows), "rows": rows, "hours": hours,
                    "codes": [{"code": k, "n": v} for k, v in codes_c.most_common(5)], "sev": dict(sev_c)}
        except Exception as e:
            return {"error": str(e)}

    # ── 장애 보고서 생성 (사내 양식 템플릿 + 판정 데이터 → DOCX/HTML, 로컬 저장) ──
    def generate_report(self, incident_id: str = "", values: dict | None = None):
        """values(3차 아이디어 5): 확인 목록에서 담당자가 넣은 값 {항목 이름: 값} — 같은 이름 자리를 모든 서식에 함께 채운다."""
        try:
            from ..report import generate
            hist = self.history()
            inc = next((h for h in hist if h.get("id") == incident_id), None) \
                if incident_id else (hist[0] if hist else None)
            if not inc:
                return {"error": "보고서를 만들 분석 건이 없습니다 — 먼저 분석을 실행하세요."}
            rd = self.reports_dir()
            from ..report_forms import use_profile
            prof, psrc, _meta = self._profile_for(inc.get("id", ""))   # 19차: 이 분석 > 내 기본값 > 없음
            with use_profile(prof):
                r = generate(self._base / "report-template" / "template.yaml", inc, rd, values)
            if isinstance(r, dict):
                r["report_dir"] = str(rd)
                r["profile_source"] = psrc
            return r
        except Exception as e:
            return {"error": str(e)}

    def _me_login(self) -> tuple[str, str]:
        """요청한 계정(서버형) — 로그인 없는 PC 단독이면 빈 값."""
        a = getattr(self, "actor", None)
        return (str(getattr(a, "login", "") or ""), str(getattr(a, "name", "") or ""))

    def _profile_for(self, incident_id: str = "") -> tuple[dict, str, dict]:
        """보고서 기본 정보 고르기. 요청한 계정이 없으면(자동 1차 대응·예약 보고서) 그 분석을 등록한 계정 기준(GPT 119 P0-02) —
        계정 서버에서 예전 공용 값이 남의 분석 보고서에 저절로 들어가지 않게. 등록자가 없는 분석(PC 단독·자동 반입)만 공용 값."""
        from ..report_forms import resolve_profile
        login = self._me_login()[0]
        if not login and incident_id:
            inc = next((h for h in self.history() if h.get("id") == incident_id), None)
            login = str((inc or {}).get("owner") or "")
        return resolve_profile(self._base / "report-template", login, incident_id or "")

    def report_profile(self, incident_id: str = ""):
        """보고서 기본 정보(기관명·시스템명·담당자 등). 19차: 이 분석 저장값 > 내 기본값 > 없음 — 다른 사람·다른 분석 값이 저절로 들어가지 않는다."""
        from ..report_forms import PROFILE_FIELDS, profile_read
        tdir = self._base / "report-template"
        login = self._me_login()[0]
        values, source, meta = self._profile_for(incident_id)
        mine = profile_read(tdir, "user", login)
        return {"fields": [list(x) for x in PROFILE_FIELDS], "values": values, "source": source,
                "saved_by": meta.get("by_name", ""), "saved_at": meta.get("at"), "incident_id": incident_id or "",
                "has_mine": mine is not None, "server": bool(login),
                "has_shared": bool(login) and (tdir / "report_profile.json").exists()}

    def save_report_profile(self, values: dict, incident_id: str = "", scope: str = ""):
        """scope: incident(이 분석에) / mine(내 기본값). 예전 화면처럼 값만 오면 내 기본값."""
        try:
            from ..report_forms import profile_write
            login, name = self._me_login()
            scope = scope or ("incident" if incident_id else "mine")
            if scope == "incident":
                if not incident_id or not any(h.get("id") == incident_id for h in self.history()):
                    return {"error": "저장할 분석을 찾을 수 없습니다 — 판정 리포트를 다시 열어 주십시오"}
                rec = profile_write(self._base / "report-template", "inc", incident_id, values or {}, login, name)
                aud = getattr(getattr(self, "auth", None), "audit", None)   # GPT 119 P1-04: 같은 부서가 고친 기록을 남긴다
                if aud and login:
                    try:
                        aud(login, "", "report_profile.save", incident_id)
                    except Exception:   # noqa: BLE001
                        pass
            elif scope == "mine":
                rec = profile_write(self._base / "report-template", "user", login, values or {}, login, name)
            else:
                return {"error": "저장 자리는 incident / mine 중 하나입니다"}
            return {"ok": True, "scope": scope, "values": rec["values"], "at": rec.get("at")}
        except Exception as e:
            return {"error": str(e)}

    def report_profile_sources(self, incident_id: str = ""):
        """[불러오기] 후보 — 내 기본값·공용 값(이전 판)·다른 분석에 저장한 값(값은 빼고 누가·언제). 서버가 볼 수 있는 분석만 남긴다."""
        from ..report_forms import profile_incidents, profile_read
        tdir = self._base / "report-template"
        login = self._me_login()[0]
        names = {h.get("id"): (h.get("name") or "") for h in self.history()}
        incs = [{"id": x["id"], "name": names.get(x["id"], ""), "by_name": x["by_name"], "at": x["at"], "n": x["n"]}
                for x in profile_incidents(tdir) if x["id"] != incident_id and x["id"] in names]
        return {"mine": profile_read(tdir, "user", login) is not None,
                "shared": bool(login) and (tdir / "report_profile.json").exists(), "incidents": incs}

    def report_profile_get(self, source: str = ""):
        """[불러오기] 한 곳의 값 — mine / shared / inc:<분석 ID>. 화면 칸만 채우고 저장은 사람이 [저장]으로 한다."""
        from ..report_forms import _legacy_profile, clean_profile, profile_read
        tdir = self._base / "report-template"
        login = self._me_login()[0]
        src = str(source or "")
        if src == "mine":
            d = profile_read(tdir, "user", login)
        elif src == "shared":
            d = {"values": clean_profile(_legacy_profile(tdir))} if (tdir / "report_profile.json").exists() else None
        elif src.startswith("inc:"):
            d = profile_read(tdir, "inc", src[4:])
        else:
            return {"error": "불러올 곳을 고르십시오"}
        if d is None:
            return {"error": "저장된 값이 없습니다"}
        return {"values": d["values"], "source": src}

    # ── 서식 학습(실 보고서 → 서식 통계 프로필) ──
    def report_style_info(self):
        """style_profile.json 요약(학습 문서 수·학습일·항목 수). 내용은 없다."""
        try:
            from ..report_forms import style_info
            return style_info(self._base / "report-template")
        except Exception as e:
            return {"error": str(e)}

    def pick_style_source(self):
        """실 보고서 zip 또는 폴더 선택 → {path}"""
        try:
            sel = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False,
                                                  file_types=("보고서 묶음 ZIP (*.zip)", "All files (*.*)")) or []
            if not sel:
                return {"cancel": True}
            return {"path": sel[0] if isinstance(sel, (list, tuple)) else sel}
        except Exception as e:
            return {"error": str(e)}

    def learn_report_style(self, path: str = ""):
        """실제 제출된 보고서(HWP/HWPX/DOCX zip 또는 폴더)에서 서식 통계만 학습해 report-template/style_profile.json 에 저장.
        이 PC 안에서만 처리하며 문서의 문장·이름은 저장하지 않는다(통계·글꼴·크기·줄 수·표기 형식만)."""
        try:
            from ..report_style import learn
            src = Path(path or "")
            if not path or not src.exists():
                return {"error": "보고서 zip 또는 폴더 경로가 없습니다"}
            r = learn(src, self._base / "report-template")
            r["ok"] = True
            return r
        except Exception as e:
            return {"error": str(e)}

    # ── 사용자 서식(HWPX) 등록·매핑 ──
    def _tdir(self) -> Path:
        return self._base / "report-template"

    def custom_forms(self):
        try:
            from ..report_custom import list_templates
            return {"items": list_templates(self._tdir())}
        except Exception as e:
            return {"error": str(e)}

    def pick_form_file(self):
        """서식 파일 선택(HWPX) → {path}"""
        try:
            sel = self._window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False,
                                                  file_types=("한글 문서 HWPX (*.hwpx)", "All files (*.*)")) or []
            if not sel:
                return {"cancel": True}
            return {"path": sel[0] if isinstance(sel, (list, tuple)) else sel}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_analyze(self, path: str, tpl_id: str = "", *, _hist=None):
        """서식 구조 분석 → 값 자리 후보 + 추천 매핑 + 예시 값. tpl_id 가 있으면 저장된 매핑을 덮어 씌워 편집용으로 반환
        _hist: 서버형은 보는 계정이 쓸 수 있는 분석만 넘긴다(10-23 — 예시 값에 다른 부서 분석의 원본이 나가지 않게)."""
        try:
            from ..report_custom import FIELDS, analyze_form, load_template, sample_values
            p = Path(path) if path else (self._tdir() / "custom" / (tpl_id or "") / "form.hwpx")
            if p.suffix.lower() != ".hwpx":
                return {"error": "HWPX 파일만 등록할 수 있습니다 — 한글에서 [다른 이름으로 저장] → HWPX 로 저장하십시오."}
            if not p.exists():
                return {"error": f"파일이 없습니다: {p}"}
            if not tpl_id:
                from ..report_custom import same_form
                dup = same_form(self._tdir(), p)
                if dup:
                    return {"error": f"이미 {dup}(으)로 등록돼 있는 서식과 같은 파일입니다 — 다시 등록하지 않아도 "
                                     "보고서를 만들 때 함께 만들어집니다(같은 문서가 두 벌 나오지 않게 막았습니다)."}
            a = analyze_form(p)
            name = p.stem
            if tpl_id:
                t = load_template(self._tdir(), tpl_id)
                name = t.get("name", name)
                saved = {f["id"]: f.get("field") for f in t.get("fields", [])}
                for f in a["fields"]:
                    if f["id"] in saved:
                        f["field"] = saved[f["id"]]
            hist = self.history() if _hist is None else _hist
            inc = hist[0] if hist else {}
            return {"temp": str(p), "name": name, "tpl_id": tpl_id or None, "fields": a["fields"], "tables": a["tables"],
                    "paragraphs": a["paragraphs"], "catalog": [list(x) for x in FIELDS],
                    "sample": sample_values(inc, self._profile_for(inc.get("id", ""))[0]), "sample_id": inc.get("id", "")}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_save(self, temp: str, name: str, fields: list, tpl_id: str = ""):
        try:
            from ..report_custom import save_template
            return {"ok": True, **save_template(self._tdir(), Path(temp), name, fields or [], tpl_id or None)}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_delete(self, tpl_id: str):
        try:
            from ..report_custom import delete_template
            return {"ok": delete_template(self._tdir(), tpl_id)}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_ledger(self):
        """서식 원장 내보내기 — reports 폴더에 서식원장.json(이름·지문·자리 수만) + 글 그대로 돌려준다(서버형은 화면이 내려받기로)."""
        try:
            import json as _json
            from ..report_custom import ledger_export
            d = ledger_export(self._tdir())
            text = _json.dumps(d, ensure_ascii=False, indent=1)
            out = self.reports_dir() / "서식원장.json"
            out.write_text(text, encoding="utf-8")
            return {"ok": True, "path": str(out), "text": text, "count": len(d["forms"])}
        except Exception as e:
            return {"error": str(e)}

    def custom_form_ledger_check(self, text: str):
        """다른 곳의 서식 원장(글)과 이 PC 서식을 지문으로 대조"""
        try:
            from ..report_custom import ledger_check
            return ledger_check(self._tdir(), text)
        except Exception as e:
            return {"error": str(e)}

    def custom_form_pin(self, tpl_id: str):
        """지문 없는 예전 등록에 원본 지문을 남긴다(담당자가 원본을 확인한 뒤)."""
        try:
            from ..report_custom import pin_form
            return pin_form(self._tdir(), tpl_id)
        except Exception as e:
            return {"error": str(e)}

    def custom_form_preview(self, tpl_id: str, *, _hist=None):
        """최근 분석 건으로 시험 생성 → reports 폴더.  _hist: 서버형은 보는 계정이 쓸 수 있는 분석만 넘긴다(10-23)"""
        try:
            from ..report_custom import fill_template, load_template
            hist = self.history() if _hist is None else _hist
            if not hist:
                return {"error": "미리보기에 쓸 분석 건이 없습니다 — 먼저 로그를 분석하세요."}
            inc = hist[0]
            t = load_template(self._tdir(), tpl_id)
            from ..report_custom import form_block
            if form_block(t):
                return {"error": form_block(t)}
            rd = self.reports_dir()
            import re as _re
            safe_name = _re.sub(r'[\\/:*?"<>|]+', '_', t['name'])  # Python 3.11 호환: f-string 표현식 안에 백슬래시 금지
            out = rd / f"미리보기_{safe_name}_{inc.get('id', 'INC')}.hwpx"
            r = fill_template(Path(t["form"]), t.get("fields", []), inc, self._profile_for(inc.get("id", ""))[0], out)
            r["report_dir"] = str(rd)
            r["incident"] = inc.get("id", "")
            return r
        except Exception as e:
            return {"error": str(e)}

    def open_live(self):
        """14차(마스터: '실시간 관제는 새 창에서 열기'): 데스크톱 창에서 실시간 관제를 **새 프로그램 창**으로 연다.
        기본 브라우저로 넘기면 세션 쿠키가 없어 입장할 수 없다 — 같은 창 엔진(같은 저장소)의 새 창이라 로그인 상태가 이어진다.
        주소는 지금 창의 주소에서 뽑되 이 PC 안(127.0.0.1·localhost)일 때만. 이미 열려 있으면 앞으로 가져온다."""
        import urllib.parse
        try:
            # GPT 105차 P0: 지금 창 주소만 보면, 창이 이 PC 의 **다른** 서버(127.0.0.1:다른 포트)로 옮겨 갔을 때 그 서버를 새 창으로 연다.
            # 기준은 이 프로그램이 띄운 내장 서버 주소(_origin) — 지금 창이 그 서버의 화면일 때만, 그 주소로만 연다.
            origin = self.__dict__.get("_origin") or ""
            cur = self._window.get_current_url() if self._window else ""
            o = urllib.parse.urlsplit(cur or "")
            if not origin or f"{o.scheme}://{o.netloc}" != origin:
                return {"error": "이 창에서는 새 창을 열 수 없습니다 — 화면에서 바로 엽니다"}
            w = self.__dict__.get("_live_win")
            if w is not None:
                try:
                    w.restore()
                    w.show()
                    return {"ok": True, "reused": True}
                except Exception:   # noqa: BLE001 — 이미 닫힌 창
                    self.__dict__.pop("_live_win", None)
            w = webview.create_window("LogTriage · 실시간 관제", origin + "/nms/live", width=1600, height=920,
                                      min_size=(900, 560), background_color="#0B1220", text_select=True)
            self.__dict__["_live_win"] = w
            try:
                w.events.closed += lambda: self.__dict__.pop("_live_win", None)
            except Exception:   # noqa: BLE001
                pass
            return {"ok": True}
        except Exception as e:   # noqa: BLE001
            logging.exception("open_live failed")
            return {"error": str(e)}

    def open_folder(self, path: str):
        """생성된 보고서 폴더를 탐색기로 연다 (로컬)."""
        import os
        import subprocess
        p = Path(path)
        d = p if p.is_dir() else p.parent
        if not d.exists():
            return {"error": f"폴더가 없습니다: {d}"}
        try:
            os.startfile(str(d))
            return {"ok": True, "path": str(d)}
        except Exception:
            try:
                subprocess.Popen(["explorer.exe", str(d)])
                return {"ok": True, "path": str(d)}
            except Exception as e:
                return {"error": f"폴더를 열 수 없습니다({e}). 경로: {d}"}

    # ── 지식 검색 (룰·에러코드·매뉴얼 — 완전 오프라인) ──
    def search_kb(self, query: str = ""):
        try:
            from ..codes import load_codes
            from ..kb import load_manuals, search_kb
            rules = load_rules(self._base / "rules", self._base / "rules-local")
            codes = load_codes(self._base / "errorcodes")
            manuals = load_manuals(self._base / "manuals")
            return search_kb(query or "", rules, codes, manuals, limit=200)
        except Exception as e:
            return {"error": str(e)}

    # ── 제품 지식 (제품별 룰·에러코드·매뉴얼 관리 화면) ──
    def _kb_load(self):
        from ..codes import load_codes
        from ..kb import load_manuals
        rules = load_rules(self._base / "rules", self._base / "rules-local")
        codes = load_codes(self._base / "errorcodes")
        manuals = load_manuals(self._base / "manuals")
        return rules, codes, manuals

    @staticmethod
    def _kb_layers(rules, codes):
        from ..parsers import _REGISTRY
        lay = {}
        for name, v in _REGISTRY.items():
            lay[name] = v[0] if isinstance(v, tuple) else getattr(v, "layer", "sw")
        for r in rules:
            for pr in r.products:
                lay.setdefault(pr, r.layer)
        for k, e in codes.items():
            if ":" in k:
                lay.setdefault(e.product, e.layer)
        return lay

    def kb_overview(self):
        """제품별 룰·코드·매뉴얼·파서 보유 현황."""
        try:
            from ..parsers import supported_products
            rules, codes, manuals = self._kb_load()
            lay = self._kb_layers(rules, codes)
            parsers = set(supported_products())
            prods = {}
            def P(name):
                return prods.setdefault(name, {"product": name, "layer": lay.get(name, "sw"), "rules": 0, "local_rules": 0,
                                               "codes": 0, "codes_vendor": 0, "codes_verified": 0, "manuals": 0, "parser": name in parsers})
            for r in rules:
                for pr in r.products:
                    x = P(pr); x["rules"] += 1
                    if r.source == "local":
                        x["local_rules"] += 1
            for k, e in codes.items():
                if ":" not in k:
                    continue
                x = P(e.product); x["codes"] += 1
                if e.ref and (e.cause or e.action):   # 제조사 문서(URL)로 대조된 것만 '제조사 원인·조치'
                    x["codes_vendor"] += 1
                if "대조 완료" in (e.source or "") or "실로그" in (e.source or "") or (e.source or "").startswith("vendor"):
                    x["codes_verified"] += 1
            for m in manuals:
                P(str(m.get("product", "")))["manuals"] += 1
            for name in parsers:
                P(name)
            order = {"os": 0, "db": 1, "was": 2, "web": 3, "sw": 4}
            # 파서 전용 별칭(룰·코드·매뉴얼이 전혀 없는 로그 종류 이름)은 목록에서 제외 — 총계의 parsers 에는 포함
            items = sorted((x for x in prods.values() if (x["rules"] or x["codes"] or x["manuals"]) and x["product"] not in ("*", "")),
                           key=lambda x: (order.get(x["layer"], 9), -(x["rules"] + x["codes"]), x["product"]))
            return {"products": items,
                    "totals": {"products": len(items), "rules": len(rules),
                               "local_rules": sum(1 for r in rules if r.source == "local"),
                               "codes": sum(1 for k in codes if ":" in k),
                               "codes_vendor": sum(1 for k, e in codes.items() if ":" in k and e.ref and (e.cause or e.action)),
                               "manuals": len(manuals), "parsers": len(parsers)}}
        except Exception as e:
            return {"error": str(e)}

    def kb_product(self, product: str):
        """한 제품의 룰·에러코드·매뉴얼 전체(관리 화면 상세)."""
        try:
            rules, codes, manuals = self._kb_load()
            product = (product or "").lower()
            rl = [{"id": r.id, "layer": r.layer, "products": r.products, "severity": r.severity, "category": r.category,
                   "category_ko": CATEGORY_KO.get(r.category, r.category), "verdict": r.verdict,
                   "pattern": r.pattern.pattern, "source": r.source,
                   "immediate": r.immediate, "short": r.short, "mid": r.mid, "long": r.long,
                   "versions": r.versions, "version_note": r.version_note}
                  for r in rules if product in [x.lower() for x in r.products]]
            cl = []
            for k, e in codes.items():
                if ":" in k and e.product == product:
                    cl.append({"code": e.code, "severity": e.severity, "category": e.category,
                               "category_ko": CATEGORY_KO.get(e.category, e.category), "title": e.title,
                               "cause": e.cause, "action": e.action, "ref": e.ref, "source": e.source,
                               "immediate": e.immediate, "short": e.short, "mid": e.mid, "long": e.long,
                               "versions": e.versions, "version_note": e.version_note})
            sev_order = {"critical": 0, "error": 1, "warn": 2, "info": 3}
            cl.sort(key=lambda c: (sev_order.get(c["severity"], 9), c["code"]))
            ml = [{"title": m.get("title", m.get("product")), "sections": [
                    {"heading": sct.get("heading", ""), "body": sct.get("body", "")} for sct in m.get("sections", [])]}
                  for m in manuals if str(m.get("product", "")).lower() == product]
            return {"product": product, "rules": rl, "codes": cl, "manuals": ml,
                    "versions": self._version_catalog(product)}
        except Exception as e:
            return {"error": str(e)}

    def code_solution(self, product: str = "", code: str = "", os_name: str = ""):
        """12차: 에러코드 하나 × OS 하나의 해법(1차 확인·2차 조치·3차 의뢰 — 명령어 포함). 로그 없이도 코드 조회에서.
        os_name 을 비우면 그 제품이 도는 첫 OS. 읽기 전용(명령은 보여 주기만 — 실행하지 않는다)."""
        try:
            from ..os_solution import applicable_os, load_matrix, solution
            from ..procedures import load_procedures
            _, codes, _ = self._kb_load()
            product, code = str(product or "").lower().strip(), str(code or "").strip()
            e = codes.get(f"{product}:{code}") or codes.get(f"{product}:{code.upper()}")
            if e is None:
                return {"error": f"코드를 찾지 못했습니다: {product}:{code}"}
            m = load_matrix(self._base / "manuals")
            oses = applicable_os(m, product)
            os_name = (os_name or (oses[0] if oses else "")).lower()
            if not hasattr(self, "_procs_cache"):
                self._procs_cache = load_procedures(self._base / "manuals")
            return solution(e, os_name, self._base / "manuals", self._procs_cache)
        except Exception as ex:   # noqa: BLE001
            return {"error": f"{type(ex).__name__}: {ex}"}

    def _version_catalog(self, product: str) -> dict:
        """manuals/*_versions.yaml — 제품별 버전 카탈로그(출시·지원 종료·로그 체계). 없으면 {}"""
        import yaml
        out = {}
        for f in sorted((self._base / "manuals").glob("*_versions.yaml")):
            try:
                d = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
            except Exception:
                continue
            p = d.get("products") or {}
            if product in p:
                out = dict(p[product])
                out["file"] = f.name
                break
        return out

    # ── 기존 도구 이관: 유사 과거 분석 · 사이트 룰(초안→미리보기→저장→삭제) ──
    def similar_cases(self, incident_id: str = "", rule_id: str = "", codes=None, limit: int = 5):
        """같은 대표 룰 또는 같은 판정 코드가 나온 과거 분석 건 (조치는 참고용)."""
        try:
            codes = set(codes or [])
            out = []
            for h in self.history():
                if not h.get("id") or h.get("id") == incident_id:
                    continue
                f = h.get("first") or {}
                hit = "대표 판정 동일" if rule_id and f.get("rule_id") == rule_id else ""
                if not hit and codes:
                    hc = {c.get("code") for c in ((h.get("plan") or {}).get("analysis") or {}).get("codes", [])}
                    common = codes & hc
                    if common:
                        hit = "코드 일치: " + ", ".join(sorted(common)[:3])
                if not hit:
                    continue
                action = ""
                for c in h.get("checklist", []):
                    if c.get("rule_id") == f.get("rule_id") and c.get("immediate"):
                        action = c["immediate"][0]; break
                out.append({"id": h["id"], "at": h.get("analyzed_at", ""), "name": h.get("name", ""),
                            "verdict": f.get("verdict", "전 계층 CLEAR"), "layer_ko": f.get("layer_ko", "CLEAR"),
                            "files": len(h.get("files") or []), "events": h.get("events_total", 0),
                            "why": hit, "action": action})
                if len(out) >= int(limit):
                    break
            return out
        except Exception as e:
            return {"error": str(e)}

    def _iter_events(self, incident_id: str):
        path = self._base / "incidents" / f"{incident_id}.jsonl"
        if not path.exists():
            return
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    yield json.loads(line)
                except Exception:
                    continue

    def preview_rule(self, spec: dict, incident_id: str = ""):
        """사이트 룰 초안 미리보기 — 정규식 검증 + 해당 분석 건에서 예상 매칭 건수·샘플."""
        import re
        try:
            rx = re.compile(spec.get("regex", ""), re.IGNORECASE)
            ex = re.compile(spec["exclude"], re.IGNORECASE) if spec.get("exclude") else None
        except re.error as e:
            return {"error": f"정규식 오류: {e}"}
        n, samples, hosts = 0, [], set()
        if incident_id:
            for e in self._iter_events(incident_id):
                if spec.get("layer") and e.get("layer") != spec["layer"]:
                    continue
                if spec.get("product") and spec["product"] != "*" and e.get("product") != spec["product"]:
                    continue
                msg = e.get("message", "")
                if rx.search(msg) and not (ex and ex.search(msg)):
                    n += 1; hosts.add(e.get("host", ""))
                    if len(samples) < 5:
                        samples.append({"ts": e.get("ts"), "host": e.get("host"), "message": msg[:200]})
        return {"matches": n, "hosts": len(hosts), "samples": samples}

    def add_local_rule(self, spec: dict):
        """rules-local/site_rules.yaml 에 사이트 룰 추가(서명 룰팩과 별도 계층, 즉시 반영)."""
        import re
        try:
            re.compile(spec.get("regex", ""))
            if spec.get("exclude"):
                re.compile(spec["exclude"])
        except re.error as e:
            return {"error": f"정규식 오류: {e}"}
        if not spec.get("regex") or not spec.get("verdict"):
            return {"error": "정규식과 판정 제목은 필수입니다"}
        f = self._base / "rules-local" / "site_rules.yaml"
        f.parent.mkdir(parents=True, exist_ok=True)
        doc = {"rules": []}
        if f.exists():
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {"rules": []}
            except Exception:
                doc = {"rules": []}
        rid = "SITE-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        rule = {"id": rid, "layer": spec.get("layer") or "sw", "product": [spec.get("product") or "*"],
                "match": {"regex": spec["regex"]}, "severity": spec.get("severity") or "error",
                "category": spec.get("category") or "internal", "verdict": spec["verdict"][:140],
                "immediate": [x for x in (spec.get("immediate") or []) if x][:5],
                "short": [x for x in (spec.get("short") or []) if x][:3], "mid": [], "long": [],
                "note": f"사이트 룰 · {datetime.now():%Y-%m-%d %H:%M} · 근거 분석 건 {spec.get('incident_id', '')}"}
        if spec.get("exclude"):
            rule["exclude"] = spec["exclude"]
        from ..rules import check_rule_fields
        try:
            check_rule_fields(rule)
        except ValueError as e:
            return {"error": str(e)}
        doc.setdefault("rules", []).append(rule)
        f.write_text("# 사이트 룰 — 로그 검색에서 추가(서명 룰팩과 별도, 룰팩 갱신에 영향 없음)\n" +
                     yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
        return {"id": rid, "file": str(f), "rule_count": len(load_rules(self._base / "rules", self._base / "rules-local"))}

    def delete_local_rule(self, rule_id: str):
        f = self._base / "rules-local" / "site_rules.yaml"
        if not f.exists():
            return {"error": "사이트 룰 파일이 없습니다"}
        doc = yaml.safe_load(f.read_text(encoding="utf-8")) or {"rules": []}
        before = len(doc.get("rules", []))
        doc["rules"] = [r for r in doc.get("rules", []) if r.get("id") != rule_id]
        if len(doc["rules"]) == before:
            return {"error": "해당 사이트 룰이 없습니다(룰팩 룰은 삭제 불가)"}
        f.write_text("# 사이트 룰 — 로그 검색에서 추가(서명 룰팩과 별도, 룰팩 갱신에 영향 없음)\n" +
                     yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
        return {"deleted": rule_id, "rule_count": len(load_rules(self._base / "rules", self._base / "rules-local"))}

    # ── 룰 학습(2026-10-13): 룰·코드에 안 걸린 문구 → 후보 → 검증 → 화면 승인 → 학습 룰·룰팩 ──
    def learn_list(self, status: str = "new", product: str = ""):
        from ..learn import LearnStore, learned_rules
        st = LearnStore(self._base)
        allx = st.items()
        items = [x for x in allx if (not status or x.get("status") == status) and (not product or x.get("product") == product)]
        cnt = {}
        for x in allx:
            cnt[x.get("status", "new")] = cnt.get(x.get("status", "new"), 0) + 1
        return {"items": items[:300], "total": len(items), "counts": cnt,
                "products": sorted({x["product"] for x in allx}), "learned": len(learned_rules(self._base))}

    def learn_suggest(self, key: str):
        from ..learn import LearnStore, check, suggest
        item = LearnStore(self._base).get(key)
        if not item:
            return {"error": "후보를 찾지 못했습니다"}
        spec = suggest(item)
        rules, codes = self._load_rules_codes()          # 캐시 — 검증마다 전체를 다시 읽지 않는다
        return {"item": item, "spec": spec, "check": check(spec, self._base, rules=rules, codedb=codes)}

    def learn_check(self, spec: dict):
        from ..learn import check
        rules, codes = self._load_rules_codes()
        return check(spec or {}, self._base, rules=rules, codedb=codes)

    def learn_approve(self, spec: dict):
        from ..learn import approve
        rules, codes = self._load_rules_codes()
        with Api._rc_lock:
            try:
                r = approve(spec or {}, self._base, who=str((spec or {}).get("_who") or ""), rules=rules, codedb=codes)
            finally:
                self._invalidate_rules_cache()
        return r

    def learn_dismiss(self, key: str):
        from ..learn import LearnStore
        r = LearnStore(self._base).set_status(key, "dismissed")
        return {"ok": True} if r else {"error": "후보를 찾지 못했습니다"}

    def learn_restore(self, key: str):
        from ..learn import LearnStore
        r = LearnStore(self._base).set_status(key, "new")
        return {"ok": True} if r else {"error": "후보를 찾지 못했습니다"}

    def learn_rules(self):
        from ..learn import learned_rules
        return {"rules": learned_rules(self._base)}

    def learn_remove_rule(self, rule_id: str):
        from ..learn import remove_learned
        with Api._rc_lock:
            try:
                return remove_learned(self._base, rule_id)
            finally:
                self._invalidate_rules_cache()

    def learn_build_pack(self, make_key: bool = False):
        """인터넷망: 기존 룰 + 승인한 학습 룰 + 코드·매뉴얼을 Ed25519 서명 룰팩으로(reports/ 에 저장, 공개키 rulepack-signing.pub 함께).
        개인키 conf/rulepack_signing.pem 은 이 PC 에만 — 없으면 make_key 로만 만든다(폐쇄망은 공개키를 처음 적용할 때 등록·고정)."""
        from ..learn import build_pack
        kp = self._base / "conf" / "rulepack_signing.pem"
        existed = kp.exists()
        if not existed and not make_key:
            return {"need_key": True, "error": "서명 키(conf/rulepack_signing.pem)가 없습니다 — 새로 만들거나 기존 키를 그 자리에 두십시오"}
        try:
            signer = rulepack.load_signing_key(kp, create=True)
            r = build_pack(self._base, signer, self._base / "reports")
        except Exception as e:
            return {"error": f"룰팩을 만들지 못했습니다: {e}"}
        r["new_key"] = not existed
        return r

    # ── 룰팩 적용 기록·현황 ──
    def _record_pack(self, manifest: dict, filename: str):
        try:
            f = self._base / "rulepack_applied.json"
            hist = json.loads(f.read_text(encoding="utf-8")) if f.exists() else []
            hist.insert(0, {"version": manifest.get("version"), "file": filename,
                            "rule_count": manifest.get("rule_count"), "created": manifest.get("created"),
                            "applied_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            f.write_text(json.dumps(hist[:30], ensure_ascii=False, indent=1), encoding="utf-8")
        except Exception:
            pass

    def pack_info(self):
        """룰팩 화면: 현재 지식베이스 규모 + 적용 이력."""
        try:
            from ..codes import load_codes
            from ..kb import load_manuals
            rules = load_rules(self._base / "rules", self._base / "rules-local")
            codes = load_codes(self._base / "errorcodes")
            manuals = load_manuals(self._base / "manuals")
            f = self._base / "rulepack_applied.json"
            hist = json.loads(f.read_text(encoding="utf-8")) if f.exists() else []
            newest = max((x.stat().st_mtime for x in (self._base / "rules").rglob("*.yaml")), default=0)
            bad = self._unreadable()
            from .. import kbaudit   # 손상 기록(재시작 뒤에도 남음) — 상태가 바뀔 때만 한 줄
            try:
                kbaudit.sync(self._base, bad)
            except Exception:
                pass
            damage = kbaudit.recent(self._base, 20)
            return {"rules": len(rules), "local_rules": sum(1 for r in rules if r.source == "local"),
                    "codes": len({k for k in codes if ":" in k}),
                    "codes_vendor": sum(1 for k, e in codes.items() if ":" in k and e.ref and (e.cause or e.action)),
                    "manuals": len(manuals), "products": len({p for r in rules for p in r.products} | {e.product for k, e in codes.items() if ":" in k} | {str(m.get("product", "")) for m in manuals}),
                    "rules_mtime": datetime.fromtimestamp(newest).strftime("%Y-%m-%d %H:%M") if newest else "-",
                    "current": hist[0] if hist else None, "history": hist[:10],
                    "backup": (self._base / "rules.bak").exists(), **self._pack_trust(),
                    "unreadable": bad, "damage_log": damage}
        except Exception as e:
            return {"error": str(e)}

    def _unreadable(self) -> list:
        """읽지 못해 건너뛰는 룰·코드 파일 — 건너뛰기만 하면 조용히 누락되니 화면에 알린다."""
        try:
            from ..codes import unreadable_files as _uc
            from ..rules import unreadable_files as _ur
            return (_ur(self._base / "rules", self._base / "rules-local", self._base / "rules-learned")
                    + _uc(self._base / "errorcodes"))[:50]
        except Exception as e:
            return [{"file": "(검사 실패)", "why": str(e)[:120]}]

    def _pack_trust(self) -> dict:
        """지금 적용 상태(새 반입 검증과 별개): 등록된 서명 키 지문·서명 방식·마지막 적용 판 — 디스크 기록 그대로."""
        out = {"trust_fp": "", "sign_mode": "", "applied_version": ""}
        try:
            tp = self._base.joinpath(*rulepack.TRUST_FILE)
            if tp.exists():
                out["trust_fp"] = rulepack.fingerprint(tp.read_bytes())
            pp = self._base.joinpath(*rulepack.POLICY_FILE)
            if pp.exists():
                pol = json.loads(pp.read_text(encoding="utf-8"))
                out["sign_mode"] = str(pol.get("mode") or "")
                out["applied_version"] = str(pol.get("last_version") or "")
        except Exception:
            pass
        return out

    # ── 룰팩 ─────────────────────────────────────────────
    def apply_rulepack(self, confirm_fp: str = ""):
        try:
            pend = getattr(self, "_pack_pending", None)
            if confirm_fp and pend:                       # 처음 보는 서명 키 — 지문을 받았으니 같은 파일로 다시
                self._pack_pending = None
                import hashlib as _h
                now = (_h.sha256(Path(pend[0]).read_bytes()).hexdigest(), _h.sha256(Path(pend[1]).read_bytes()).hexdigest())
                if now != pend[2]:                        # 지문을 확인하는 사이 파일이 바뀌었다
                    return {"error": "지문을 확인하는 사이 룰팩·공개키 파일이 바뀌었습니다 — 처음부터 다시 고르십시오(아무것도 바뀌지 않음)"}
                return self._apply_rulepack_paths(pend[0], pend[1], confirm_fp)
            rpk = self._window.create_file_dialog(
                webview.FileDialog.OPEN,
                file_types=("Rulepack (*.rpk)", "All files (*.*)"))
            if not rpk:
                return {"cancelled": True}
            key = self._window.create_file_dialog(
                webview.FileDialog.OPEN,
                file_types=("Signing public key (*.pub)", "All files (*.*)"))   # 옛 HMAC 배포 키(.key)는 더 받지 않는다(2026-10-15)
            if not key:
                return {"cancelled": True}
            return self._apply_rulepack_paths(rpk[0], key[0], "")
        except Exception as e:
            return {"error": str(e)}

    def _apply_rulepack_paths(self, rpk_path: str, key_path: str, confirm_fp: str):
        try:
            with Api._rc_lock:   # 로더와 직렬화: 교체 중인 파일을 반쯤 읽지 않게
                try:
                    m = rulepack.apply(Path(rpk_path), self._base / "rules",
                                       Path(key_path).read_bytes(),
                                       self._base / "errorcodes", self._base / "manuals", confirm_fp=confirm_fp or None)
                finally:
                    self._invalidate_rules_cache()
            self._record_pack(m, Path(rpk_path).name)
            return {"version": m.get("version"), "rule_count": m.get("rule_count"), "signature": m.get("_signature"),
                    "signer_fp": m.get("_signer_fp"), "trust_new": bool(m.get("_trust_new"))}
        except rulepack.TrustNeeded as e:
            import hashlib as _h
            self._pack_pending = (rpk_path, key_path, (_h.sha256(Path(rpk_path).read_bytes()).hexdigest(),
                                                       _h.sha256(Path(key_path).read_bytes()).hexdigest()))
            return {"need_trust": True, "error": str(e)}
        except Exception as e:
            return {"error": str(e)}


def _server_conf() -> dict:
    """exe 옆 server.conf(선택) — LISTEN=0.0.0.0 / PORT=8088 / PASSWORD=... : LAN 의 에이전트 푸시·브라우저 접속을 받으려면 설정(리눅스 설치형과 같은 역할)."""
    conf = {}
    p = base_dir() / "server.conf"
    try:
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("="); k = k.strip().upper()
                    conf[k] = v.strip() if k == "PASSWORD" else v.strip().strip('"')   # 비밀번호는 원문 유지(따옴표도 값의 일부)
    except OSError:
        pass
    return conf


def _server_args():
    """CLI 가 server.conf 보다 우선: --serve(창 없이) --listen --port --password. pywebview/pyinstaller 의 다른 인자는 무시."""
    import argparse
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--serve", action="store_true"); ap.add_argument("--listen"); ap.add_argument("--port", type=int); ap.add_argument("--password")
    a, unknown = ap.parse_known_args(sys.argv[1:])
    if a.serve and unknown:   # 서버 모드는 오타 인자를 조용히 무시하지 않는다
        _msgbox("알 수 없는 인자: %s\n사용: LogTriage.exe --serve [--listen 0.0.0.0] [--port 8088] [--password ...]" % " ".join(unknown), flags=0x10)
        sys.exit(2)
    c = _server_conf()
    listen = (a.listen or c.get("LISTEN") or "127.0.0.1").strip()
    try:
        port = int(a.port if a.port is not None else (c.get("PORT") or (8088 if a.serve else 0)))
    except ValueError:
        port = -1
    if not (0 <= port <= 65535) or (a.serve and port == 0):
        _msgbox("PORT 값이 올바르지 않습니다(서버 모드 1~65535): %s" % (a.port if a.port is not None else c.get("PORT")), flags=0x10)
        sys.exit(2)
    password = (a.password if a.password is not None else c.get("PASSWORD", "")).strip() or None
    return a.serve, listen, port, password


def _write_instance(mode: str, listen: str, port: int) -> None:
    """instance.json 원자 기록(pid·exe·mode·listen·port) — helper cmd 와 두 번째 실행이 정체성·주소를 확인하는 데 사용"""
    import json, os, time
    base = base_dir()
    try:
        tmp = base / "instance.json.tmp"
        tmp.write_text(json.dumps({"mode": mode, "listen": listen, "port": port, "pid": os.getpid(), "exe": sys.executable,
                                   "started": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, base / "instance.json")
    except OSError:
        pass


def _clear_instance() -> None:
    for n in ("instance.json", "server.pid"):
        try:
            (base_dir() / n).unlink()
        except OSError:
            pass


def _running_instance() -> dict | None:
    """instance.json 의 인스턴스가 실제로 살아 있고 LogTriage 인지(healthz app) 확인"""
    import json, urllib.request
    try:
        info = json.loads((base_dir() / "instance.json").read_text(encoding="utf-8"))
        host = "127.0.0.1" if info.get("listen") in ("0.0.0.0", "127.0.0.1", "localhost", "", "::") else info["listen"]
        r = json.loads(urllib.request.urlopen(f"http://{host}:{info['port']}/healthz", timeout=2).read().decode())
        return info if r.get("app") == "LogTriage" else None
    except Exception:
        return None


def _msgbox(text: str, title: str = "LogTriage", flags: int = 0x40, wait: bool = True) -> None:
    """안내 창. wait=False 면 따로 띄워 두고 바로 돌아온다.

    MessageBoxW 는 닫힐 때까지 그 자리에서 멈췄다. 서버를 여는 길에서 막히면 포트만 열린 채
    요청을 하나도 처리하지 못해 화면이 계속 돌기만 한다 — 기동을 이어가야 하는 안내는 wait=False."""
    def _show():
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(None, text, title, flags)
        except Exception:
            pass
    if wait:
        _show()
        return
    try:
        threading.Thread(target=_show, name="lt-msgbox", daemon=True).start()
    except Exception:
        pass


def _serve_headless(listen: str, port: int, password: str | None) -> int:
    """창 없이 서버만 기동(LogTriage.exe --serve) — 로그 logtriage_server.log, pid 파일 server.pid. 리눅스 설치형과 같은 서비스 역할."""
    import os
    from ..server import ServerApi, make_server
    base = base_dir()
    log = open(base / "logtriage_server.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stderr = log   # windowed exe 에는 콘솔이 없다
    if listen not in ("127.0.0.1", "localhost", "::1") and not password and not _portal_auth(base_dir()):
        _msgbox("LAN 수신(LISTEN=%s)에는 비밀번호가 필요합니다.\nserver.conf 의 PASSWORD 를 설정하십시오." % listen, flags=0x10)
        print("[serve] PASSWORD 없이 LAN 수신은 거부", flush=True); return 2
    from ..server import weak_shared_password
    _weak = weak_shared_password(password, strict=True) if listen not in ("127.0.0.1", "localhost", "::1") else ""
    if _weak:   # 21차: server.conf.example 의 '바꾸세요' 를 그대로 두거나 짧은 비밀번호로 LAN 에 열지 않는다
        _msgbox("server.conf 의 PASSWORD 가 %s입니다.\n10자 이상으로 바꾼 뒤 다시 실행하십시오(LAN 수신 거부)." % _weak, flags=0x10)
        print("[serve] 약한 PASSWORD(%s) — LAN 수신 거부" % _weak, flush=True); return 2
    from ..server import prepare_base
    _left = prepare_base(base)   # 10차: 내장 지식 펼치기 + 기동 거부 검사
    if _left:
        _msgbox(_left, flags=0x10)
        print("[serve] " + _left.splitlines()[0], flush=True); return 2
    try:
        from ..auth import ensure_conf
        ensure_conf(base)       # 설정이 없으면 만들어 준다(2026-09-30 기본값: 로그인 없음 — 그래서 LAN 수신은 위에서 비밀번호를 요구한다)
        httpd, handler = make_server(listen, port, base, password, [], None, api_cls=ServerApi, desktop=False)
    except OSError as e:
        _msgbox("서버를 열 수 없습니다: %s:%s\n%s\n(포트 사용 중이면 server.conf 의 PORT 를 바꾸십시오)" % (listen, port, e), flags=0x10)
        print(f"[serve] bind 실패 {listen}:{port}: {e}", flush=True); return 1
    api = handler.api
    (base / "server.pid").write_text(str(os.getpid()), encoding="utf-8"); _write_instance("serve", listen, port)
    from ..server import setup_hint
    hint = setup_hint(api, listen, port)
    if hint:
        print(hint, flush=True)
        _fa = (getattr(api, "auth_conf", None) or {}).get("first_admin", "")
        _msgbox("아직 계정이 없습니다." + "\n\n" +
                "브라우저에서 아래 주소로 접속해 관리자 계정을 만드십시오:" + "\n" +
                f"http://127.0.0.1:{port}/setup" + "\n\n" +
                (f"첫 관리자로 지정된 계정: {_fa}\n(이 계정의 비밀번호만 정하면 됩니다)\n\n" if _fa else "") +
                "사내망·VPN 의 다른 PC 에서도 그대로 만들 수 있고,\n"
                "인터넷 구간에서는 conf/setup-code.txt 의 초기 설정 코드가 필요합니다.", wait=False)
    print(f"[LogTriage server(Windows)] http://{listen}:{port}  base={base}  auth={'on' if password else 'off'}  pid={os.getpid()}", flush=True)
    api.collector.start(); api.warm_up()
    _automation_start(api)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _automation_stop(api); api.collector.stop(); httpd.server_close(); _clear_instance()
    return 0


def _portal_auth(base: Path) -> bool:
    """conf/auth.json 이 포털 인증(mode=portal)이면 비밀번호 없이 LAN 수신을 허용한다(r4) — 포털 로그인이 접속을 보호한다."""
    try:
        from ..auth import load_conf
        c = load_conf(base)
        return bool(c and c["mode"] == "portal")
    except Exception:
        return False


def _automation_start(api) -> None:
    """예약 작업 실행기(백업·자동 분석·알림·정기 보고서) — 리눅스 서버형 serve() 와 같은 역할. 실패해도 화면은 뜬다."""
    import logging
    try:
        api.automation.start()
        print("[automation] 예약 실행기 시작", flush=True)
        if getattr(api, "hub_client", None):   # 전사(r4): 본사로 상태·분석 요약·보고서 전송
            api.hub_client.start()
            print(f"[hub] 본사 연동 시작 ({api.hub_conf['role']} · {api.hub_conf['site_id']})", flush=True)
    except Exception as e:
        logging.exception("automation start failed")
        print(f"[automation] 시작 실패: {e}", flush=True)


def _automation_stop(api) -> None:
    try:
        api.automation.stop()
    except Exception:
        pass
    try:
        if getattr(api, "hub_client", None):
            api.hub_client.stop()
    except Exception:
        pass


def _single_instance(name: str = "Local\\LogTriageGUI") -> bool:
    """중복 실행 방지 — GUI 는 로그온 세션별(Local\\), 서버 모드는 PC 전체(Global\\LogTriageServer) mutex 를 따로 쓴다."""
    import ctypes
    ctypes.windll.kernel32.CreateMutexW(None, False, name)
    return ctypes.windll.kernel32.GetLastError() != 183  # ERROR_ALREADY_EXISTS


def _cli_console() -> None:
    """콘솔 코드페이지(cp949)에 없는 글자(— 등) 때문에 명령 출력이 죽지 않게 한다 — exe 의 관리 명령 공통."""
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(errors="replace")
        except Exception:
            pass


# 창 크기: 노트북·모니터 어느 쪽이든 작업 영역에 꽉 차게 연다(마스터 2026-10-14 "사양에 맞게 자동으로").
# 고정 1320×860 은 1366×768 노트북(작업 영역 높이 약 728)에서 아래가 화면 밖으로 잘렸다. 최소 크기도
# 125% 배율 노트북의 논리 크기(약 1093×614)보다 작아야 창이 화면 안에 들어온다.
WINDOW_FIT = dict(width=1320, height=860, maximized=True, min_size=(900, 560), background_color="#F4F7F9")


def main() -> int:
    import ctypes
    import logging
    import os
    # frozen(GUI) 실행 진단용 — 문제 발생 시 logtriage_gui.log 확인
    try:
        logging.basicConfig(
            filename=str(base_dir() / "logtriage_gui.log"), level=logging.DEBUG,
            format="%(asctime)s %(levelname)s %(name)s %(message)s", force=True)
    except Exception:
        pass
    if len(sys.argv) > 1 and sys.argv[1] == "--account-admin":
        # 사내 이메일 계정 관리(2026-09-21): LogTriage.exe --account-admin add --email ○○@solideos.com --role operator
        _cli_console()
        from ..accounts import main as acc_main
        rest = sys.argv[2:]
        if "--base" not in rest:
            rest = ["--base", str(base_dir())] + rest
        try:
            return acc_main(rest)
        except SystemExit as e:
            return int(e.code or 0)
        except Exception as e:
            print(f"ACCOUNT ADMIN ERROR: {e}", file=sys.stderr)
            return 1
    if len(sys.argv) > 1 and sys.argv[1] == "--auth-admin":
        # 전사 인증 관리(r4): 비상용 로컬 관리자 — LogTriage.exe --auth-admin set-admin [--login admin]
        _cli_console()
        from ..auth import main as auth_main
        rest = sys.argv[2:]
        if "--base" not in rest:
            rest = ["--base", str(base_dir())] + rest
        try:
            return auth_main(rest)
        except SystemExit as e:
            return int(e.code or 0)
        except Exception as e:
            print(f"AUTH ADMIN ERROR: {e}", file=sys.stderr)
            return 1
    if len(sys.argv) > 1 and sys.argv[1] == "--automation-admin":
        # 백업·검증·복원 관리 도구(프로그램 종료 후 실행): LogTriage.exe --automation-admin verify --archive <zip>
        _cli_console()
        from ..automation_admin import main as admin_main
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        if "--base" not in sys.argv:
            sys.argv += ["--base", str(base_dir())]
        try:
            admin_main()
            return 0
        except SystemExit as e:
            return int(e.code or 0)
        except Exception as e:
            print(f"ADMIN ERROR: {e}", file=sys.stderr)
            return 1
    serve_mode, listen, port, password = _server_args()
    if sys.platform == "win32":
        if serve_mode and not _single_instance("Global\\LogTriageServer"):
            _msgbox("LogTriage 서버 모드가 이미 실행 중입니다."); return 0
        if not serve_mode:
            inst = _running_instance()   # 같은 데이터 폴더를 두 프로세스가 쓰지 않게: 서버 모드가 떠 있으면 브라우저로 그 화면을 연다
            if inst and inst.get("mode") == "serve":
                import webbrowser
                host = "127.0.0.1" if inst.get("listen") in ("0.0.0.0", "127.0.0.1", "localhost", "", "::") else inst["listen"]
                webbrowser.open(f"http://{host}:{inst['port']}/"); return 0
            if not _single_instance():
                ctypes.windll.user32.MessageBoxW(None, "LogTriage가 이미 실행 중입니다.\n열려 있는 창을 사용하세요.", "LogTriage", 0x40)
                return 0
    if serve_mode:
        return _serve_headless(listen, port, password)

    # 내장 HTTP 서버(127.0.0.1:임의 포트, 인증 없음) 위에서 서버형과 같은 화면·기능(인프라 감시·자원 관리 포함)을 사용.
    # 파일 대화상자·폴더 열기·저장은 pywebview 네이티브(js_api)로 유지 — ui.html 의 API() 가 HTTP API 위에 병합한다.
    import threading
    from ..server import ServerApi, make_server

    from ..server import _req
    lan_bind = listen not in ("127.0.0.1", "localhost", "::1")

    class LocalServerApi(ServerApi):
        """데스크톱: 이 PC 의 모든 경로를 직접 분석할 수 있다(--allow-dir 제한 없음) — 단, LAN 수신 중에는 같은 PC(루프백)에서 온 요청에만."""
        def _allowed(self, p: Path) -> bool:
            if not lan_bind:
                return True
            return bool(getattr(_req, "loopback", False))

    # 창 모드도 server.conf 로 고정 포트·LAN 수신 가능(에이전트 푸시 수신). LAN 수신은 비밀번호 필수 — 없으면 127.0.0.1 로만 연다.
    _asked, _down = listen, ""   # 22차: 내려간 까닭을 화면 띠에도 남긴다(메시지 상자는 지나가면 잊힌다)
    if listen not in ("127.0.0.1", "localhost", "::1") and not password and not _portal_auth(base_dir()):
        _msgbox("server.conf 의 LISTEN=%s 에는 PASSWORD 가 필요합니다.\n이번에는 이 PC 안에서만(127.0.0.1) 엽니다." % listen, flags=0x30, wait=False)
        listen, port, _down = "127.0.0.1", 0, "PASSWORD 가 없어"
    from ..server import weak_shared_password
    _weak = weak_shared_password(password, strict=True) if listen not in ("127.0.0.1", "localhost", "::1") else ""
    if _weak:   # 21차: 약한 PASSWORD 로는 LAN 에 열지 않고 이 PC 안에서만(로그인 없는 창 그대로)
        _msgbox("server.conf 의 PASSWORD 가 %s입니다 — 10자 이상으로 바꾸십시오.\n이번에는 이 PC 안에서만(127.0.0.1) 엽니다." % _weak, flags=0x30, wait=False)
        listen, port, password, _down = "127.0.0.1", 0, None, "PASSWORD 가 " + _weak + "라"
    from ..server import prepare_base
    _left = prepare_base(base_dir())   # 8차 ④: 지식 출시가 전환 도중 멈췄으면 혼합 지식으로 뜨지 않는다(파일 방식 대체 기동도 하지 않음)
    if _left:
        _msgbox(_left, flags=0x10)
        return
    try:
        from ..auth import ensure_conf
        ensure_conf(base_dir())   # 창으로 열 때도 같은 규칙. 이 PC 안에서만 열므로 로그인 없이도 안전하다
        try:
            httpd, handler = make_server(listen, port, base_dir(), password, [], None, api_cls=LocalServerApi, desktop=True,
                                         local_only=True)   # 실제로 켤지는 make_server 가 수신 주소·비밀번호로 정한다
        except OSError as e:
            if listen == "127.0.0.1" and port == 0:
                raise
            logging.warning("bind %s:%s failed (%s) → 127.0.0.1:0", listen, port, e)
            _msgbox("서버 주소 %s:%s 를 열 수 없어(포트 사용 중?) 이 PC 안에서만 엽니다.\n%s" % (listen, port, e), flags=0x30, wait=False)
            _down = _down or ("PORT:주소 %s:%s 를 열 수 없어(포트 사용 중?)" % (listen, port))
            listen, port = "127.0.0.1", 0
            httpd, handler = make_server(listen, port, base_dir(), None, [], None, api_cls=LocalServerApi, desktop=True,
                                         local_only=True)
    except Exception as e:  # 내장 서버 실패 시 이전 방식(파일 URI + js_api)으로 기동
        logging.exception("embedded server failed; fallback to file mode")
        api = Api()
        api._window = webview.create_window(window_title(), ui_path().as_uri(), js_api=api,
                                            **WINDOW_FIT)
        storage = Path(os.environ.get("LOCALAPPDATA", str(base_dir()))) / "LogTriage"; storage.mkdir(parents=True, exist_ok=True)
        webview.start(func=_bind_dnd, args=(api,), private_mode=False, storage_path=str(storage))
        return 0
    api = handler.api
    if _down and _asked not in ("127.0.0.1", "localhost", "::1"):   # 22차(GPT 153 P1-02 · 165): 끊기는 것을 창을 닫을 때까지 띠로
        _port = _down.startswith("PORT:")
        api.__dict__["_boot_warns"] = [{
            "code": "lan_downgraded",
            "text": f"server.conf 의 LISTEN={_asked} 로 LAN 수신을 요청했지만 {_down[5:] if _port else _down} 이 PC 안에서만(127.0.0.1) 열었습니다 — "
                    "다른 서버의 에이전트 보고(자원 사용률)와 다른 PC 의 브라우저 접속이 들어오지 않습니다. "
                    "이 PC 가 직접 하는 핑 · 포트 · 웹 감시는 그대로 돕니다.",
            "clears": ("server.conf 의 PORT 를 비어 있는 번호로 바꾸거나 그 포트를 쓰는 프로그램을 끄고 LogTriage 를 다시 실행하면" if _port
                       else "server.conf 의 PASSWORD 를 10자 이상 · 추측하기 어려운 값으로 바꾸고 LogTriage 를 다시 실행하면")}]
    _auto_legacy(api)   # 13차: 새 PC 첫 기동이면 예전 분석을 저절로 가져온다(창이 진단을 읽기 전에 — 띠가 떴다 사라지지 않게)
    api.warm_up()  # 룰·코드 캐시·대시보드 요약 예열
    port = httpd.server_address[1]
    api.__dict__["_origin"] = f"http://127.0.0.1:{port}"   # 14차: 새 창(실시간 관제)은 이 주소로만 연다(GPT 105차 P0)
    _write_instance("window", listen, port)
    threading.Thread(target=httpd.serve_forever, name="lt-embedded-http", daemon=True).start()
    api.collector.start()
    _automation_start(api)   # 창이 떠 있는 동안 예약 작업(백업·폴더 자동 분석·알림·정기 보고서)도 수행
    logging.info("embedded server http://%s:%s base=%s auth=%s", listen, port, base_dir(), "on" if password else "off")
    threading.Thread(target=_diag_log, args=(api,), name="lt-diag", daemon=True).start()
    why = _no_webview2()
    if why:   # 14차: 창을 그릴 엔진이 없는 PC — 옛 IE 엔진으로 깨진 화면을 띄우지 않고 기본 브라우저로 같은 화면을 연다
        try:
            _browser_mode(handler, port, why)
        finally:
            _clear_instance()
            _automation_stop(api)
            try:
                api.collector.stop()
                httpd.shutdown()
            except Exception:
                pass
        return 0
    api._window = webview.create_window(
        window_title(),
        # 창은 언제나 부트스트랩으로 세션을 받는다(토큰 없이 루프백이면 들이던 갈래는 없앴다 — 2026-10-13)
        f"http://127.0.0.1:{port}/auth/bootstrap?t={handler.boot_token}", js_api=api,
        text_select=True,   # 창이 nonce 없는 <style> 을 넣지 않게 — 같은 '글자 선택 끔' 규칙은 서버가 표를 달아 넣는다(server._html)
        **WINDOW_FIT)
    storage = Path(os.environ.get("LOCALAPPDATA", str(base_dir()))) / "LogTriage"
    storage.mkdir(parents=True, exist_ok=True)
    try:
        try:
            webview.start(func=_bind_dnd, args=(api,), private_mode=False,
                          storage_path=str(storage))
        except Exception as e:   # 14차: 창 엔진이 기동 중에 실패(런타임 손상·정책 차단 등) — 서버는 살아 있으니 브라우저로 잇는다
            logging.exception("window failed; browser mode")
            _browser_mode(handler, port, f"프로그램 창을 열지 못했습니다({type(e).__name__}).")
    finally:
        _clear_instance()
        _automation_stop(api)
        try:
            api.collector.stop()
            httpd.shutdown()
        except Exception:
            pass
    return 0


def _no_webview2() -> str:
    """창 엔진(Microsoft Edge WebView2 · .NET 4.6.2+)이 없으면 그 까닭, 있으면 ''. pywebview 는 없으면 옛 IE 엔진으로 내려가
    지금 화면이 깨진 채 뜬다. 읽기만 한다(레지스트리 조회) — 설치·설정을 바꾸지 않는다."""
    if os.environ.get("LOGTRIAGE_FORCE_BROWSER") == "1":
        return "브라우저 모드로 실행하도록 지정됐습니다(LOGTRIAGE_FORCE_BROWSER=1)."
    if sys.platform != "win32" or webview is None:
        return ""
    try:
        from webview.platforms.winforms import _is_chromium
        if _is_chromium():
            return ""
    except Exception as e:   # noqa: BLE001 — .NET·pythonnet 을 못 불러온 것도 '창을 못 그림'
        logging.warning("webview2 check failed: %s", e)
    return ("이 PC 에는 프로그램 창을 그리는 Microsoft Edge WebView2 런타임(또는 .NET Framework 4.6.2 이상)이 없습니다.\n"
            "설치하면 다음부터 프로그램 창으로 열립니다(Microsoft 'WebView2 Runtime' 무료 배포본 — 관리자 PC 정책에 따름).")


def _browser_mode(handler, port: int, why: str) -> None:
    """같은 화면을 이 PC 의 기본 브라우저로 — 1회용 입장 토큰을 새로 만들어 넘긴다(127.0.0.1 전용, 한 번 쓰면 끝).
    안내 창이 프로그램의 '켜짐' 표시 — [확인]을 누르면 끝낸다. 파일 끌어 놓기·폴더 열기 같은 창 전용 기능은 브라우저에서는 올리기로 대신."""
    import secrets
    import webbrowser
    handler.boot_token = secrets.token_hex(16)   # handler 는 make_server 가 돌려준 처리기 클래스 — 클래스 값을 바꿔야 요청이 본다
    url = f"http://127.0.0.1:{port}/auth/bootstrap?t={handler.boot_token}"
    logging.warning("browser mode: %s", why.replace("\n", " "))
    if not webbrowser.open(url):
        _msgbox(f"{why}\n\n기본 브라우저를 열지 못했습니다. 브라우저 주소창에 다음을 넣으십시오(이 PC 에서만 열림):\n{url}", flags=0x30)
        return
    _msgbox(f"{why}\n\n그동안은 기본 웹 브라우저로 LogTriage 화면을 열었습니다(이 PC 안에서만 열림).\n\n"
            "LogTriage 를 쓰는 동안 이 안내 창을 닫지 마십시오 — [확인]을 누르면 LogTriage 를 끝냅니다.", flags=0x40)


def _bind_dnd(api: Api):
    """기동 후 초기화: ① js_api 재노출(간헐적 주입 실패 대비) ② 드롭 이벤트 구독.
    드래그&드롭 파일의 전체 경로는 pywebview 파이썬 DOM 핸들러에만 주입된다."""
    import json
    import time
    # ① frozen 환경에서 js_api 주입이 간헐적으로 누락되는 문제 보완 — 명시적 재노출
    try:
        api._window.expose(api.meta, api.default_time, api.pick_logs, api.detect,
                          api.analyze, api.history, api.rules_list,
                          api.apply_rulepack, api.save_html, api.search_kb,
                          api.stats, api.log_incidents, api.search_logs,
                          api.generate_report, api.open_folder)
    except Exception:
        pass
    try:
        from webview.dom import DOMEventHandler

        def on_drop(e):
            files = (e or {}).get("dataTransfer", {}).get("files", [])
            paths = [f.get("pywebviewFullPath") for f in files
                     if f.get("pywebviewFullPath")]
            if paths:
                api._window.evaluate_js(
                    "window.__onNativeDrop("
                    + json.dumps(api.detect(paths), ensure_ascii=False) + ")")

        for _ in range(50):  # 페이지 로드 대기
            try:
                el = api._window.dom.get_element("#dropzone")
            except Exception:
                el = None
            if el:
                el.events.drop += DOMEventHandler(on_drop, True, True)
                break
            time.sleep(0.2)
    except Exception:
        pass  # DnD 미지원 환경에서도 클릭 선택은 동작


if __name__ == "__main__":
    sys.exit(main())
