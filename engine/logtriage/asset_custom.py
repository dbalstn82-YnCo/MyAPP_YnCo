# -*- coding: utf-8 -*-
"""자산 기준을 현장이 넓힐 수 있게 — 사용자 항목 추가·등급 조정 (2026-09-30)

사용자 지시: "반드시 또는 기본적으로 들어가야 하는 항목을 기준으로 세우되, 사용자가 추가로
필요로 할 때 항목을 추가할 수 있어야 한다. 단정 짓듯 결정하는 건 배제한다."

그래서 기준은 **코드에 둔 기본값 + 현장이 얹는 조정** 으로 나눈다.
  · 기본 기준(asset_spec) — 우리가 대는 최소한. 바뀌어도 자산은 깨지지 않게 id 가 고정이다.
  · 현장 조정(여기)     — 새 항목을 더하고, 기본 항목의 등급을 올리거나 내린다.

지키는 것
  · **항목 id 는 한 번 정하면 바꾸지 않는다.** 이름은 바꿀 수 있다 — 그래야 나중에 말이 바뀌어도
    이미 등록된 자산이 깨지지 않는다.
  · 사용자가 만든 항목 id 는 `x_` 로 시작한다 — 기본 항목과 영영 겹치지 않는다.
  · **비밀번호·키 같은 항목은 사용자가 만들어도 거절한다.** 기본 기준에서 받지 않기로 한 것을
    옆문으로 들이면 그 결정이 무의미해진다.
  · 뜻이 겹치는 이름(동의어)은 거절한다 — 파일을 읽을 때 어느 항목에 넣을지 모르게 된다.
  · 무엇을 언제 누가 바꿨는지 남긴다(기준은 앞으로도 바뀔 것이므로).
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import asset_spec

# 우리가 세운 기준의 바닥 — 관리자도 이 아래로는 내릴 수 없다.
# 한 사람이 '자산ID' 를 '선택' 으로 내리면 그 뒤 전사의 대장이 조용히 헐거워진다(GPT 10차).
FLOOR = {"asset_id": "required", "name": "required", "type": "required",
         "site": "required", "service": "required", "criticality": "required",
         "env": "required", "state": "required", "owner_team": "required"}
RANK = {"optional": 0, "advised": 1, "conditional": 2, "required": 3}

MAX_FIELDS = 100          # 사이트당 사용자 항목
MAX_LABEL = 40
MAX_WHY = 200
MAX_ALIAS = 40
MAX_ALIASES = 20
KINDS = ("code", "ip", "date", "text", "multiline")
# 파일에서 **자동으로** 채울 수 있는 종류 — 값의 모양을 검사할 수 있는 것만.
# 자유 서술 칸에 들어온 'Adm!n1234' 가 비밀번호인지 장비 이름인지는 글자만 보고 알 수 없다.
# 막을 수 없는 경로는 없앤다(지시: 보안 강화로 구현 불가능한 기능은 없앤다 · GPT 10차 상).
FROM_FILE = ("code", "ip", "date")

# 기준을 손보는 속도 제한 — 탈취된 관리자 세션이 개칭·등급 변경을 되풀이해 기록을 불릴 수 있다.
# GPT 는 60회/10분을 권했지만, 그러면 **항목 상한(100개)까지 채우는 정상적인 최초 설정이 막힌다.**
# 두 수를 맞춘다: 상한을 한 번에 채울 수는 있고, 되풀이 남용은 여전히 막힌다
# (기록 한 줄이 100바이트 남짓이므로 이 속도로도 하루 2MB 안쪽이다).
WRITE_WINDOW = 600.0
WRITE_MAX = MAX_FIELDS + 20
KIND_KO = {"code": "코드·번호", "ip": "IP", "date": "날짜",
           "text": "글자(파일에서 자동으로 채우지 않음)",
           "multiline": "여러 줄(파일에서 자동으로 채우지 않음)"}

# 이름·별칭에 받는 글자 — 한글·라틴·숫자·공백과 몇 개의 기호.
# NFKC 로도 키릴 'а' 는 라틴 'a' 가 되지 않아 'pаssword' 로 검사를 비켜 갈 수 있다(GPT 10차).
OK_CHARS = re.compile(
    "^[0-9A-Za-z" + chr(0xAC00) + "-" + chr(0xD7A3) + chr(0x3131) + "-" + chr(0x318E)
    + r" ._\-/()]+$")
# '고르기' 는 선택지를 받을 길이 없어 넣지 않는다 — 빈 드롭다운을 만드는 반쪽 기능보다 없는 편이 낫다
ID_RE = re.compile(r"^x_[a-z0-9_]{1,40}$")
MAX_DEFS = 1000           # 쓰지 않는 것까지 합친 전체 상한 — 만들고 내리기를 되풀이해 표를 불리지 못하게


_CTRL = chr(9) + chr(10) + chr(13) + chr(11) + chr(12)


def _clean(t, limit: int) -> str:
    """사람이 적은 글자를 받을 수 있는 모양으로 — 조작 문자·줄바꿈을 걷고 길이를 묶는다."""
    t = str(t or "")
    # 여기도 같은 순서다 — 바꾸고 나서 걸러낸다
    t = "".join(" " if ch in _CTRL else ch for ch in t)
    t = "".join(ch for ch in t if ch == " " or ch.isprintable())
    return " ".join(t.split())[:limit].strip()


def _new_id() -> str:
    """이름과 **무관한** id.

    전에는 이름에서 계산했다(sha1). 그러면 사이트 A 의 '운영주소' 와 사이트 B 의 '운영주소' 가
    같은 id 가 되어, 본사로 모을 때 **뜻이 다른 두 항목이 조용히 하나로 합쳐진다.**
    이름은 바뀌고 같아지고 겹치는 것이므로 id 의 근거가 될 수 없다(GPT 10차 상).
    """
    import uuid
    # 자르지 않는다. 설치 id 는 32자를 다 쓰면서 항목 id 만 48비트로 줄일 이유가 없고,
    # 허브에서 여러 설치를 합치고 오래 보관할 것이다. 화면에서만 짧게 보인다(GPT 12차).
    return "x_" + uuid.uuid4().hex


class Store:
    """<설치경로>/data/assets/fields.sqlite3 — 사용자 항목과 등급 조정."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._paced_lock = threading.Lock()
        self._paced = {}
        with self.db() as db:
            db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS fields(
              id TEXT PRIMARY KEY, label TEXT NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL,
              why TEXT NOT NULL, aliases TEXT, apply_to TEXT, example TEXT,
              created REAL, actor TEXT, active INTEGER DEFAULT 1);
            CREATE TABLE IF NOT EXISTS levels(
              field_id TEXT PRIMARY KEY, level TEXT NOT NULL, at REAL, actor TEXT);
            CREATE TABLE IF NOT EXISTS changes(
              id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL, actor TEXT, what TEXT, detail TEXT);
            -- 오래된 기록은 지우지 않고 여기로 옮긴다(자산 원칙: 지우지 않는다)
            CREATE TABLE IF NOT EXISTS changes_old(
              id INTEGER PRIMARY KEY, at REAL, actor TEXT, what TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            ''')
        self.installation = self._installation()

    def _installation(self) -> str:
        """이 설치의 고정 id — 본사로 모을 때 사이트를 가르는 근거.

        전역 열쇠는 `<설치 id>:<항목 id>` 다. 이름이 같아도 자동으로 합쳐지지 않는다.
        """
        import uuid
        with self._lock, self.db() as db:
            r = db.execute("SELECT v FROM meta WHERE k='installation'").fetchone()
            if r and r["v"]:
                return r["v"]
            new = uuid.uuid4().hex
            db.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('installation',?)", (new,))
            return new

    def global_id(self, field_id: str) -> str:
        return self.installation + ":" + str(field_id)

    @contextmanager
    def db(self):
        c = sqlite3.connect(str(self.path), timeout=20, check_same_thread=False)
        try:
            c.row_factory = sqlite3.Row
            yield c
            c.commit()
        finally:
            c.close()

    # ── 읽기 ────────────────────────────────────────────────────────────
    def fields(self, active_only: bool = True) -> list[dict]:
        with self.db() as db:
            q = "SELECT * FROM fields" + (" WHERE active=1" if active_only else "") + " ORDER BY created"
            out = []
            for r in db.execute(q):
                d = dict(r)
                d["aliases"] = json.loads(d.get("aliases") or "[]")
                d["apply_to"] = json.loads(d.get("apply_to") or '["*"]')
                d["custom"] = True
                # 파일에서 자동으로 채울 수 있는 종류인가 — 자유 서술은 아니다(GPT 10차 상)
                d["from_file"] = d.get("kind") in FROM_FILE
                # **지금** 규칙으로 다시 본다. 보안 사전은 앞으로 계속 늘어나고, 새 검사가
                # 새로 만들 때만 돌면 옛 항목이 그 사전을 비켜 간다(GPT 11차 중상).
                # 지우지 않는다 — 자동 채움에서만 빼고 '확인 필요' 로 표시한다.
                bad = ""
                for word in [d["label"]] + list(d["aliases"] or []):
                    hit = asset_spec.dropped_because(word)
                    if hit:
                        bad = hit.get("word") or hit.get("key") or "?"
                        break
                if bad:
                    d["quarantined"] = bad
                    d["from_file"] = False
                    d["needs_review"] = True
                out.append(d)
            return out

    def levels(self) -> dict:
        with self.db() as db:
            return {r["field_id"]: r["level"] for r in db.execute("SELECT * FROM levels")}

    CHANGES_HOT = 2000          # 이만큼만 곁에 두고, 넘치면 옮긴다(지우지 않는다)

    def changes(self, limit: int = 50) -> list[dict]:
        with self.db() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM changes ORDER BY id DESC LIMIT ?", (int(limit),))]

    def _archive(self, db) -> None:
        """기록이 불어나면 옆 표로 옮긴다 — **지우는 것이 아니다.**

        '지우지 않는다' 와 '쓰는 표를 영원히 키운다' 는 다른 말이다(GPT 10차).
        """
        n = db.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
        if n <= self.CHANGES_HOT:
            return
        cut = db.execute("SELECT id FROM changes ORDER BY id DESC LIMIT 1 OFFSET ?",
                         (self.CHANGES_HOT // 2,)).fetchone()
        if not cut:
            return
        db.execute("INSERT OR IGNORE INTO changes_old SELECT * FROM changes WHERE id<=?", (cut[0],))
        db.execute("DELETE FROM changes WHERE id<=?", (cut[0],))

    # ── 속도 ────────────────────────────────────────────────────────────
    def _pace(self, actor: str) -> None:
        """한 사람이 짧은 사이에 기준을 너무 많이 고치지 못하게.

        기록을 지우지 않는 구조이므로, 되풀이해 고치면 디스크를 채울 수 있다(GPT 11차).
        """
        now = time.time()
        with self._paced_lock:
            q = self._paced.setdefault(actor or "(알 수 없음)", [])
            q[:] = [t for t in q if now - t < WRITE_WINDOW]
            if len(q) >= WRITE_MAX:
                raise ValueError(
                    f"짧은 사이에 기준을 너무 많이 고쳤습니다({WRITE_MAX}회/"
                    f"{int(WRITE_WINDOW // 60)}분) — 잠시 뒤에 다시 해 주십시오")
            q.append(now)

    # ── 검사 ────────────────────────────────────────────────────────────
    def _guard(self, words, skip_id: str = "") -> None:
        """이름·별칭을 받아도 되는지 — **만들 때와 바꿀 때 똑같이** 지난다.

        전에는 이 검사가 add_field 에만 있었다. 그래서 '물리 위치' 로 만들어 두고
        '비밀번호' 로 이름만 바꾸면 받지 않기로 한 것이 옆문으로 들어왔다.
        """
        for word in words:
            hit = asset_spec.is_dropped(word)
            if hit:
                d = asset_spec.dropped_because(word)
                raise ValueError(
                    f"'{word}' 는 {asset_spec.DROP[hit]['label']} 계열('{d.get('word')}')이라"
                    f" 항목으로 만들 수 없습니다 — " + asset_spec.DROP[hit]["why"])
        taken = {}
        for t in list(asset_spec.types()) + [""]:
            for f in asset_spec.fields(t):
                for key in [f["label"]] + list(f.get("aliases") or []):
                    taken[asset_spec._norm(key)] = f["label"]
        for f in self.fields(active_only=False):
            if f["id"] == skip_id:
                continue
            for key in [f["label"]] + list(f.get("aliases") or []):
                taken[asset_spec._norm(key)] = f["label"]
        for word in words:
            if not OK_CHARS.match(word or ""):
                raise ValueError(
                    f"'{word}' 에 우리가 받지 않는 글자가 있습니다 — 한글·영문·숫자와"
                    " 공백 · . _ - / ( ) 만 씁니다."
                    " (겉보기가 같은 다른 문자로 검사를 비켜 가는 것을 막기 위해서입니다)")
            n = asset_spec._norm(word)
            if not n:
                raise ValueError(f"'{word}' 에는 쓸 수 있는 글자가 없습니다")
            if n in taken:
                raise ValueError(f"'{word}' 는 이미 있는 항목 '{taken[n]}' 과 뜻이 겹칩니다 —"
                                 " 다른 이름을 쓰거나 그 항목의 등급을 바꾸십시오")

    # ── 쓰기 ────────────────────────────────────────────────────────────
    def add_field(self, label: str, kind: str = "text", level: str = "advised", why: str = "",
                  aliases=None, apply_to=None, example: str = "", actor: str = "") -> dict:
        self._pace(actor)
        label = _clean(label, MAX_LABEL)
        why = _clean(why, MAX_WHY)
        if not label:
            raise ValueError(f"항목 이름을 적어 주십시오(최대 {MAX_LABEL}자)")
        if len(why) < 10:
            raise ValueError("이 항목이 없으면 장애 때 무엇을 못 하는지 적어 주십시오"
                             " — 그 답이 없는 항목은 요구하지 않는 것이 우리 기준입니다")
        if kind not in KINDS:
            raise ValueError("항목 종류는 " + " · ".join(KIND_KO[k] for k in KINDS)
                             + " 중 하나여야 합니다")
        if level == "conditional":
            # 조건부 필수는 '이 묶음에서 하나는' 이라는 뜻이고, 묶음은 기본 기준만 정한다
            raise ValueError("조건부 필수는 기본 기준의 묶음에만 쓰는 등급입니다 —"
                             " 필수·권장·선택 중에 고르십시오")
        if level not in asset_spec.LEVEL:
            raise ValueError("등급은 필수·권장·선택 중 하나여야 합니다")

        aliases = [x for x in (_clean(a, MAX_ALIAS) for a in (aliases or [])) if x][:MAX_ALIASES]
        apply_to = [str(t) for t in (apply_to or ["*"]) if str(t)]
        known = set(asset_spec.types()) | {"*"}
        bad = [t for t in apply_to if t not in known]
        if bad:
            raise ValueError("모르는 자산 유형입니다: " + ", ".join(bad))

        self._guard([label] + aliases)

        with self._lock, self.db() as db:
            n = db.execute("SELECT COUNT(*) FROM fields WHERE active=1").fetchone()[0]
            if n >= MAX_FIELDS:
                raise ValueError(f"쓰고 있는 사용자 항목은 {MAX_FIELDS}개까지입니다")
            # 만들고 내리기를 되풀이하면 '쓰는 것' 은 늘 100개 아래여도 표는 무한히 커진다.
            # 그렇다고 전체를 100개로 막으면 몇 년 뒤 정상적인 폐기 이력 때문에 새 항목을 못 만든다
            total = db.execute("SELECT COUNT(*) FROM fields").fetchone()[0]
            if total >= MAX_DEFS:
                raise ValueError(
                    f"지금까지 만든 항목이 {MAX_DEFS}개에 이르렀습니다 — 쓰지 않는 항목을 정리해"
                    " 주십시오(이 표는 지우지 않으므로 관리자가 직접 확인해야 합니다)")
            fid = ""
            for _ in range(20):
                cand = _new_id()
                if not db.execute("SELECT 1 FROM fields WHERE id=?", (cand,)).fetchone():
                    fid = cand
                    break
            if not fid or not ID_RE.match(fid):
                raise ValueError("항목 id 를 만들지 못했습니다 — 다시 해 주십시오")
            db.execute("INSERT INTO fields(id,label,kind,level,why,aliases,apply_to,example,created,actor,active)"
                       " VALUES(?,?,?,?,?,?,?,?,?,?,1)",
                       (fid, label, kind, level, why, json.dumps(aliases, ensure_ascii=False),
                        json.dumps(apply_to, ensure_ascii=False), (example or "").strip()[:100],
                        time.time(), actor or ""))
            self._archive(db)
            db.execute("INSERT INTO changes(at,actor,what,detail) VALUES(?,?,?,?)",
                       (time.time(), actor or "", "항목 추가", f"{label}({fid}) · {asset_spec.LEVEL[level]}"))
        return {"id": fid, "label": label}

    def rename_field(self, field_id: str, label: str, actor: str = "") -> dict:
        """이름은 바꿀 수 있다 — id 는 바꾸지 않는다. 그래야 등록된 자산이 깨지지 않는다."""
        self._pace(actor)
        label = _clean(label, MAX_LABEL)
        if not label:
            raise ValueError(f"항목 이름을 적어 주십시오(최대 {MAX_LABEL}자)")
        # 만들 때와 **같은 검사**를 지난다 — 이름만 바꿔 받지 않기로 한 것을 들이지 못하게
        self._guard([label], skip_id=field_id)
        with self._lock, self.db() as db:
            r = db.execute("SELECT label FROM fields WHERE id=?", (field_id,)).fetchone()
            if not r:
                raise ValueError("그런 사용자 항목이 없습니다")
            if r["label"] == label:
                return {"id": field_id, "label": label, "unchanged": True}   # 기록을 불리지 않는다
            db.execute("UPDATE fields SET label=? WHERE id=?", (label, field_id))
            self._archive(db)
            db.execute("INSERT INTO changes(at,actor,what,detail) VALUES(?,?,?,?)",
                       (time.time(), actor or "", "이름 변경", f"{r['label']} → {label} ({field_id})"))
        return {"id": field_id, "label": label}

    def set_level(self, field_id: str, level: str, actor: str = "") -> dict:
        """기본 항목의 등급도 현장이 올리거나 내릴 수 있다 — 무엇을 왜 바꿨는지 남긴다."""
        self._pace(actor)
        if level not in asset_spec.LEVEL:
            raise ValueError("등급은 필수·권장·선택 중 하나여야 합니다")
        one_of = {f["id"] for t in list(asset_spec.types()) + [""]
                  for f in asset_spec.fields(t) if f.get("one_of")}
        if level == "conditional" and field_id not in one_of:
            raise ValueError("조건부 필수는 '이 중 하나는' 묶음이 있는 항목에만 매길 수 있습니다")
        known = {f["id"] for t in list(asset_spec.types()) + [""] for f in asset_spec.fields(t)}
        custom = {f["id"] for f in self.fields()}
        if field_id not in known and field_id not in custom:
            raise ValueError("그런 항목이 없습니다")
        floor = FLOOR.get(field_id)
        if floor and RANK.get(level, 0) < RANK[floor]:
            raise ValueError(
                f"'{field_id}' 는 우리 기준의 핵심 항목이라 {asset_spec.LEVEL[floor]} 아래로는"
                " 내릴 수 없습니다 — 올리는 것은 됩니다."
                " 기준을 세운 쪽이 우리이므로 그 바닥은 우리가 지킵니다")
        # 지금 실제로 매겨져 있는 등급과 같으면 아무 일도 하지 않는다 —
        # 기본값으로 되돌리는 것도 '조정 없음' 이므로 얹어 둔 값을 걷어낸다(기록을 불리지 않는다)
        base = {}
        for t in list(asset_spec.types()) + [""]:
            for f in asset_spec.fields(t):
                base.setdefault(f["id"], f["level"])
        if field_id in custom:
            now = {f["id"]: f["level"] for f in self.fields()}.get(field_id)
        else:
            now = self.levels().get(field_id, base.get(field_id))
        if now == level:
            return {"id": field_id, "level": level, "unchanged": True}
        if field_id not in custom and base.get(field_id) == level:
            with self._lock, self.db() as db:
                db.execute("DELETE FROM levels WHERE field_id=?", (field_id,))
                self._archive(db)
                db.execute("INSERT INTO changes(at,actor,what,detail) VALUES(?,?,?,?)",
                           (time.time(), actor or "", "등급 되돌림",
                            f"{field_id} → 기본값({asset_spec.LEVEL[level]})"))
            return {"id": field_id, "level": level, "reverted": True}
        with self._lock, self.db() as db:
            if field_id in custom:
                db.execute("UPDATE fields SET level=? WHERE id=?", (level, field_id))
            else:
                db.execute("INSERT OR REPLACE INTO levels(field_id,level,at,actor) VALUES(?,?,?,?)",
                           (field_id, level, time.time(), actor or ""))
            self._archive(db)
            db.execute("INSERT INTO changes(at,actor,what,detail) VALUES(?,?,?,?)",
                       (time.time(), actor or "", "등급 변경", f"{field_id} → {asset_spec.LEVEL[level]}"))
        return {"id": field_id, "level": level}

    def remove_field(self, field_id: str, actor: str = "") -> dict:
        """지우지 않고 '쓰지 않음' 으로 둔다 — 이미 그 항목으로 등록된 자산이 있을 수 있다."""
        self._pace(actor)
        with self._lock, self.db() as db:
            r = db.execute("SELECT label FROM fields WHERE id=?", (field_id,)).fetchone()
            if not r:
                raise ValueError("그런 사용자 항목이 없습니다")
            db.execute("UPDATE fields SET active=0 WHERE id=?", (field_id,))
            self._archive(db)
            db.execute("INSERT INTO changes(at,actor,what,detail) VALUES(?,?,?,?)",
                       (time.time(), actor or "", "항목 사용 중지", f"{r['label']} ({field_id})"))
        return {"id": field_id, "active": False}

    # ── 합치기 ──────────────────────────────────────────────────────────
    def spec(self, asset_type: str = "") -> dict:
        """기본 기준 + 현장 조정 = 이 사이트가 실제로 요구하는 것."""
        extra = [f for f in self.fields()
                 if "*" in f["apply_to"] or (asset_type and asset_type in f["apply_to"])]
        return asset_spec.spec(asset_type, extra=extra, levels=self.levels())
