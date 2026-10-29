# -*- coding: utf-8 -*-
"""게시판(2026-09-22) — 같은 장애·이슈를 두고 서로 묻고 답하고, 분석 이력을 붙여 함께 보는 공간.

· 글 종류: 질문 / 분석 공유 / 분석 요청
· 글에 분석 이력 ID 를 붙이면 목록에서 눌러 그 분석의 요약·이벤트·로그를 바로 볼 수 있다.
· 붙인 분석의 IP·호스트명은 기본으로 가려진다(`privacy`). 등록한 담당자 본인이 글에서 '원문 공개'를 켠 경우에만
  그 글을 읽는 사람에게 원문이 보인다 — 공유 여부를 글쓴이가 스스로 정하도록 한 것.
· 글쓴이 신원은 사용자 표와 같은 방식으로 보관한다(조회용 색인 + 암호화). DB 에 이메일이 평문으로 남지 않는다.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

KINDS = {"question": "질문", "share": "분석 공유", "request": "분석 요청"}
MAX_TITLE = 120
MAX_BODY = 20000
MAX_ATTACH = 10


class BoardError(ValueError):
    """화면에 그대로 보여도 되는 게시판 오류."""


class Board:
    def __init__(self, base: Path, auth):
        self.base = Path(base)
        self.auth = auth                      # AuthStore — 신원 색인·암호화를 그대로 쓴다
        self.path = self.base / "data" / "board" / "board.sqlite3"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS posts(
              id INTEGER PRIMARY KEY, at REAL, updated REAL, author TEXT, enc BLOB,
              kind TEXT DEFAULT 'question', title TEXT, body TEXT, incidents TEXT DEFAULT '[]',
              share_raw INTEGER DEFAULT 0, solved INTEGER DEFAULT 0, views INTEGER DEFAULT 0, site TEXT DEFAULT '');
            CREATE TABLE IF NOT EXISTS replies(
              id INTEGER PRIMARY KEY, post_id INTEGER, at REAL, author TEXT, enc BLOB, body TEXT,
              accepted INTEGER DEFAULT 0);
            CREATE INDEX IF NOT EXISTS ix_posts_at ON posts(at);
            CREATE INDEX IF NOT EXISTS ix_replies_post ON replies(post_id);
            """)

    @contextmanager
    def db(self):
        c = sqlite3.connect(str(self.path), timeout=30)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ── 글쓴이 신원(색인 + 암호화) ──
    def _who(self, user: dict) -> tuple:
        login = (user or {}).get("login", "")
        return self.auth._idx(login), self.auth._enc({"login": login, "name": (user or {}).get("name", "")},
                                                     "board", "enc", self.auth._idx(login))

    def _name(self, row, table: str = "board") -> dict:
        ident = self.auth._dec(row["enc"], table, "enc", row["author"]) or {}
        login = ident.get("login", "")
        return {"login": login, "name": ident.get("name", "") or login}

    # ── 글 ──
    def _clean(self, kind: str, title: str, body: str, incidents) -> tuple:
        if kind not in KINDS:
            raise BoardError("글 종류는 질문·분석 공유·분석 요청 중 하나입니다")
        title = (title or "").strip()
        body = (body or "").strip()
        if not (2 <= len(title) <= MAX_TITLE):
            raise BoardError(f"제목은 2자 이상 {MAX_TITLE}자 이하로 적으십시오")
        if not (1 <= len(body) <= MAX_BODY):
            raise BoardError(f"내용은 {MAX_BODY}자 이하로 적으십시오")
        ids = [str(x).strip() for x in (incidents or []) if str(x).strip()]
        if len(ids) > MAX_ATTACH:
            raise BoardError(f"분석 이력은 한 글에 {MAX_ATTACH}건까지 붙일 수 있습니다")
        for i in ids:
            if not re.fullmatch(r"[A-Za-z0-9._\-]{1,64}", i):
                raise BoardError(f"분석 이력 ID 형식이 아닙니다: {i[:24]}")
        return kind, title, body, ids

    def create(self, user: dict, kind: str, title: str, body: str, incidents=None,
               share_raw: bool = False, site: str = "") -> dict:
        kind, title, body, ids = self._clean(kind, title, body, incidents)
        idx, enc = self._who(user)
        now = time.time()
        with self.db() as db:
            cur = db.execute("""INSERT INTO posts(at,updated,author,enc,kind,title,body,incidents,share_raw,site)
                                VALUES(?,?,?,?,?,?,?,?,?,?)""",
                             (now, now, idx, enc, kind, title, body, json.dumps(ids),
                              1 if share_raw else 0, str(site or "")[:32]))
            return {"id": cur.lastrowid}

    def update(self, user: dict, post_id: int, **kw) -> dict:
        p = self._row(post_id)
        if self._name(p)["login"] != (user or {}).get("login"):
            raise BoardError("글쓴이만 고칠 수 있습니다")
        kind, title, body, ids = self._clean(kw.get("kind", p["kind"]), kw.get("title", p["title"]),
                                             kw.get("body", p["body"]), kw.get("incidents", json.loads(p["incidents"] or "[]")))
        share = kw.get("share_raw", bool(p["share_raw"]))
        with self.db() as db:
            db.execute("""UPDATE posts SET kind=?, title=?, body=?, incidents=?, share_raw=?, solved=?, updated=? WHERE id=?""",
                       (kind, title, body, json.dumps(ids), 1 if share else 0,
                        1 if kw.get("solved", bool(p["solved"])) else 0, time.time(), post_id))
        return {"ok": True}

    def delete(self, user: dict, post_id: int, is_admin: bool = False) -> dict:
        p = self._row(post_id)
        if not is_admin and self._name(p)["login"] != (user or {}).get("login"):
            raise BoardError("글쓴이 또는 관리자만 지울 수 있습니다")
        with self.db() as db:
            db.execute("DELETE FROM replies WHERE post_id=?", (post_id,))
            db.execute("DELETE FROM posts WHERE id=?", (post_id,))
        return {"ok": True}

    def _row(self, post_id: int):
        with self.db() as db:
            r = db.execute("SELECT * FROM posts WHERE id=?", (int(post_id),)).fetchone()
        if not r:
            raise BoardError("없는 글입니다")
        return r

    def list(self, kind: str = "", query: str = "", mine: str = "", limit: int = 100, offset: int = 0) -> dict:
        q, a = "SELECT * FROM posts WHERE 1=1", []
        if kind in KINDS:
            q += " AND kind=?"; a.append(kind)
        if mine:
            q += " AND author=?"; a.append(self.auth._idx(mine))
        q += " ORDER BY id DESC LIMIT ? OFFSET ?"
        a += [max(1, min(int(limit), 200)), max(0, int(offset))]
        out = []
        with self.db() as db:
            rows = db.execute(q, a).fetchall()
            counts = {r["post_id"]: r["n"] for r in db.execute("SELECT post_id, count(*) n FROM replies GROUP BY post_id")}
        for r in rows:
            who = self._name(r)
            item = {"id": r["id"], "at": r["at"], "kind": r["kind"], "kind_ko": KINDS.get(r["kind"], r["kind"]),
                    "title": r["title"], "author": who["login"], "author_name": who["name"],
                    "incidents": json.loads(r["incidents"] or "[]"), "replies": counts.get(r["id"], 0),
                    "solved": bool(r["solved"]), "views": r["views"], "share_raw": bool(r["share_raw"]),
                    "site": r["site"] or ""}
            if query:
                hay = (item["title"] + " " + (r["body"] or "") + " " + who["name"]).lower()
                if query.lower() not in hay:
                    continue
            out.append(item)
        with self.db() as db:
            total = db.execute("SELECT count(*) FROM posts").fetchone()[0]
        return {"posts": out, "total": total, "kinds": KINDS, "stats": self.stats()}

    def get(self, post_id: int, bump: bool = True) -> dict:
        r = self._row(post_id)
        if bump:
            with self.db() as db:
                db.execute("UPDATE posts SET views=views+1 WHERE id=?", (int(post_id),))
        who = self._name(r)
        with self.db() as db:
            reps = db.execute("SELECT * FROM replies WHERE post_id=? ORDER BY id", (int(post_id),)).fetchall()
        return {"id": r["id"], "at": r["at"], "updated": r["updated"], "kind": r["kind"],
                "kind_ko": KINDS.get(r["kind"], r["kind"]), "title": r["title"], "body": r["body"],
                "author": who["login"], "author_name": who["name"], "incidents": json.loads(r["incidents"] or "[]"),
                "share_raw": bool(r["share_raw"]), "solved": bool(r["solved"]), "views": r["views"] + (1 if bump else 0),
                "site": r["site"] or "",
                "replies": [{"id": x["id"], "at": x["at"], "body": x["body"], "accepted": bool(x["accepted"]),
                             **{"author": self._name(x, "reply")["login"], "author_name": self._name(x, "reply")["name"]}}
                            for x in reps]}

    # ── 댓글 ──
    def reply(self, user: dict, post_id: int, body: str) -> dict:
        self._row(post_id)
        body = (body or "").strip()
        if not (1 <= len(body) <= MAX_BODY):
            raise BoardError(f"답글은 {MAX_BODY}자 이하로 적으십시오")
        login = (user or {}).get("login", "")
        idx = self.auth._idx(login)
        enc = self.auth._enc({"login": login, "name": (user or {}).get("name", "")}, "reply", "enc", idx)
        with self.db() as db:
            cur = db.execute("INSERT INTO replies(post_id,at,author,enc,body) VALUES(?,?,?,?,?)",
                             (int(post_id), time.time(), idx, enc, body))
            db.execute("UPDATE posts SET updated=? WHERE id=?", (time.time(), int(post_id)))
        return {"id": cur.lastrowid}

    def accept(self, user: dict, post_id: int, reply_id: int) -> dict:
        p = self._row(post_id)
        if self._name(p)["login"] != (user or {}).get("login"):
            raise BoardError("채택은 글쓴이만 할 수 있습니다")
        with self.db() as db:
            db.execute("UPDATE replies SET accepted=0 WHERE post_id=?", (int(post_id),))
            db.execute("UPDATE replies SET accepted=1 WHERE id=? AND post_id=?", (int(reply_id), int(post_id)))
            db.execute("UPDATE posts SET solved=1, updated=? WHERE id=?", (time.time(), int(post_id)))
        return {"ok": True}

    def delete_reply(self, user: dict, reply_id: int, is_admin: bool = False) -> dict:
        with self.db() as db:
            r = db.execute("SELECT * FROM replies WHERE id=?", (int(reply_id),)).fetchone()
            if not r:
                raise BoardError("없는 답글입니다")
            if not is_admin and self._name(r, "reply")["login"] != (user or {}).get("login"):
                raise BoardError("글쓴이 또는 관리자만 지울 수 있습니다")
            db.execute("DELETE FROM replies WHERE id=?", (int(reply_id),))
        return {"ok": True}

    def stats(self) -> dict:
        with self.db() as db:
            return {"posts": db.execute("SELECT count(*) FROM posts").fetchone()[0],
                    # 미해결은 답을 기다리는 글(질문·분석 요청)만 — '분석 공유'는 풀 문제가 아니다(2026-10-14 실측: 공유 글이 미해결로 세어짐)
                    "open": db.execute("SELECT count(*) FROM posts WHERE solved=0 AND kind IN ('question','request')").fetchone()[0],
                    "replies": db.execute("SELECT count(*) FROM replies").fetchone()[0]}
