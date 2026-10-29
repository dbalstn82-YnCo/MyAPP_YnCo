"""공식 서식(HWPX) 기반 장애 보고서 생성 — 서식 원본을 그대로 복제해 값만 채우고, 같은 내용을 DOCX 로도 동일하게 만든다.

서식 2종 (report-template/):
  form_status.hwpx      [별지 제2호 서식] 정보시스템 장애 상황관리 종료(일일) 보고서
  form_postmortem.hwpx  정보시스템 장애 사후관리 보고서
두 파일은 기관명·인명이 비어 있는 공식 서식이다(반출 허용). 다른 HWP 파일은 report-template 에 두지 않는다.

원칙
  · HWPX: 서식 zip 을 복제하고 section XML 의 지정 문단/셀 텍스트만 바꾼다 → 글꼴·표·여백 등 서식 100% 보존.
  · 서식 학습(style_profile.json, logtriage/report_style.py): 실제 제출된 보고서에서 배운 '서식 통계'(값 칸 글꼴·크기·굵기,
    항목별 줄 수·글자 수, 글머리 기호, 날짜·시간 표기 형식)로 값 run 의 글자 모양과 문장 길이·줄 수를 맞춘다.
    프로필에는 문장·기관명·인명이 없고 통계만 있다. 프로필이 없으면 서식 자체의 모양을 그대로 쓴다.
  · 담당자 기재 항목은 '[기재: …]' 표시(파란 글자)로 통일하고, 생성 결과에 확인 목록(todo)으로 돌려준다 → 최소 수정으로 제출.
  · DOCX: 채워진 HWPX 를 구조 그대로 변환한다(용지·여백·문단 정렬/들여쓰기/줄간격·글꼴·크기·굵기·색·표 열폭·병합·테두리·음영).
  · 값은 분석 판정 데이터와 담당자가 저장한 '보고서 기본 정보(profile)' 만 사용한다. 추정 문구는 넣지 않고 [기재] 로 둔다.
  · 네트워크 미사용. stdout 에 보고서 내용을 출력하지 않는다.
"""
from __future__ import annotations

import copy
import io
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path

from lxml import etree

HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"
HH = "http://www.hancom.co.kr/hwpml/2011/head"
HC = "http://www.hancom.co.kr/hwpml/2011/core"
NS = {"hp": HP, "hh": HH, "hc": HC}
_WS = re.compile(r"\s+")

FORMS = [
    {"key": "status", "file": "form_status.hwpx", "title": "장애 상황관리 종료(일일) 보고서"},
    {"key": "postmortem", "file": "form_postmortem.hwpx", "title": "장애 사후관리 보고서"},
]
PROFILE_FIELDS = [  # 담당자가 한 번 저장해 두는 보고서 기본 정보 (키, 라벨)
    ("org", "기관명"), ("parent_org", "상위기관"), ("system", "시스템명(IRM 등록 명칭)"), ("service", "서비스명"),
    ("grade", "등급"), ("location", "설치 위치/서버위치"), ("operator", "관리주체(운영주체)"),
    ("dept", "소관 부서"), ("person", "담당자"), ("rank", "직위/직급"), ("phone", "담당자 연락처"),
    ("vendor", "제조사"), ("model", "모델/사양"), ("intro_year", "도입년도 및 내용연수"), ("ha", "이중화 구성 여부"),
    # 3차 아이디어 12·13 — 보고서 만들기 선택(글로 '켬'/'끔'). 비우면 기본값
    ("fit_endings", "문장 끝 자동 다듬기 (기본 켬 · 끄려면 '끔')"),
    ("evidence_index", "근거 색인 쪽 붙이기 (기본 끔 · 붙이려면 '켬')"),
]
OPTION_KEYS = ("fit_endings", "evidence_index")


def _mask_tail(t: str) -> str:
    """자동 변경 내역에 싣는 끝 몇 글자 — 숫자 4자리 이상·긴 영숫자(토큰)·이메일·IP·경로는 가린다(GPT 37차)."""
    t = re.sub(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", "***", t)
    t = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "***", t)
    t = re.sub(r"[A-Za-z0-9+/=_-]{12,}", "***", t)
    t = re.sub(r"\d{4,}", "***", t)
    return re.sub(r"[A-Za-z]:\\[^\s]*|/[\w./-]{6,}", "***", t)


def option_on(profile: dict, key: str, default: bool) -> bool:
    v = norm(str((profile or {}).get(key, ""))).lower()
    if v in ("끔", "off", "no", "0", "false", "아니오"):
        return False
    if v in ("켬", "on", "yes", "1", "true", "예"):
        return True
    return default
PRODUCT_VENDOR = {
    "jeus": "TmaxSoft JEUS", "webtob": "TmaxSoft WebtoB", "tibero": "TmaxSoft Tibero", "bizmaster-adapter": "TmaxSoft BizMaster",
    "bizmaster-app": "TmaxSoft BizMaster", "mesim-esb": "MESIM ESB", "mesim-eai": "MESIM EAI", "mesim-apig": "MESIM API G/W",
    "oracle": "Oracle Database", "mysql": "Oracle MySQL", "mssql": "Microsoft SQL Server", "postgresql": "PostgreSQL",
    "altibase": "Altibase", "cubrid": "CUBRID", "goldilocks": "SUNJESOFT Goldilocks", "weblogic": "Oracle WebLogic",
    "websphere": "IBM WebSphere", "jboss": "Red Hat JBoss", "tomcat": "Apache Tomcat", "apache": "Apache HTTP Server",
    "nginx": "NGINX", "iis": "Microsoft IIS", "java": "Java 애플리케이션", "linux": "Linux", "aix": "IBM AIX",
    "hpux": "HPE HP-UX", "solaris": "Oracle Solaris", "windows": "Microsoft Windows",
}
_WEEK = "월화수목금토일"

# ── 담당자 기재 표시 ──────────────────────────────────────────────────────────
MARK_COLOR = "#1F5FBF"          # 한글에서 눈에 띄는 파란 글자(인쇄 시에도 식별 가능)
_MARK_RE = re.compile(r"\[기재:[^\]]*\]")
_MARK_SPLIT = re.compile(r"(\[기재:[^\]]*\])")


import contextvars
# 3차 아이디어 5: 담당자가 확인 목록에서 한 번 넣은 값 — 같은 이름의 [기재] 자리를 모든 서식(기본·사용자)에 함께 채운다.
# (한글 누름틀은 서로 다른 문서끼리 함께 바뀌지 않아, 값을 LogTriage 에서 받아 다시 만든다.)
_VALUES: contextvars.ContextVar = contextvars.ContextVar("lt_todo_values", default=None)
VALUE_MAX, VALUES_MAX = 100, 100


def item_key(what: str) -> str:
    """확인 목록 묶음 이름 — '복구 시각 — 로그상 마지막…' → '복구 시각' (summarize_todo 와 같은 규칙)."""
    w = norm(what)
    return re.split(r"\s*[—(]", w, maxsplit=1)[0].strip() or w


def clean_values(values) -> dict:
    """화면에서 온 값 — 글자만, 100자·100개까지, 제어 문자·'[기재' 안 됨. 빈 값은 버린다(표시 그대로)."""
    out = {}
    if not isinstance(values, dict):
        return out
    for k, v in list(values.items())[:VALUES_MAX]:
        k, v = norm(str(k))[:60], norm(str(v))
        if not k or not v:
            continue
        if len(v) > VALUE_MAX or "[기재" in v or re.search(r"[\x00-\x1f]", v):
            raise ValueError(f"'{k}' 값이 너무 길거나 쓸 수 없는 글자가 있습니다(100자 이하)")
        out[k] = v
    return out


def mark(what: str) -> str:
    """담당자가 채울 자리 — 한글에서 Ctrl+F '[기재' 로 찾고, 생성 결과의 확인 목록에도 오른다.
    담당자가 확인 목록에서 값을 넣었으면 표시 대신 그 값(보통 글자 모양)으로 채운다."""
    vals = _VALUES.get()
    if vals:
        v = vals.get(item_key(what))
        if v:
            return v
    return f"[기재: {norm(what)}]"


def marks_in(text: str) -> list[str]:
    return [m[5:-1].strip() for m in _MARK_RE.findall(text or "")]


# ───────────────────────── 공통 도우미 ─────────────────────────
def norm(s: str) -> str:
    return _WS.sub(" ", s or "").strip()


def own_runs(p):
    """문단 직속 run (표 안 문단 제외)."""
    return [r for r in p.findall("hp:run", NS)]


def para_text(p) -> str:
    out = []
    for r in own_runs(p):
        for t in r.findall("hp:t", NS):
            out.append("".join(t.itertext()))
    return norm("".join(out))


def body_paragraphs(root):
    """표 밖 본문 문단(순서대로)."""
    return [p for p in root.iter("{%s}p" % HP) if not any(a.tag == "{%s}tc" % HP for a in p.iterancestors())]


def top_tables(root):
    return [t for t in root.iter("{%s}tbl" % HP) if not any(a.tag == "{%s}tbl" % HP for a in t.iterancestors())]


def find_cell(tbl, col: int, row: int):
    for tc in tbl.iter("{%s}tc" % HP):
        a = tc.find("hp:cellAddr", NS)
        if a is not None and int(a.get("colAddr")) == col and int(a.get("rowAddr")) == row:
            return tc
    return None


def cell_run_ref(tc) -> str | None:
    """셀 안 첫 텍스트 run 의 charPrIDRef (라벨 칸의 글자 모양 — 값 칸의 기준 모양으로 쓴다)."""
    if tc is None:
        return None
    for r in tc.iter("{%s}run" % HP):
        if r.find("hp:t", NS) is not None:
            return r.get("charPrIDRef")
    return None


def _relayout(p):
    """수정한 문단의 줄 배치 캐시(linesegarray)를 지운다 — 남겨 두면 한글이 옛 배치로 그려 글자가 뒤섞인다."""
    if p is None:
        return
    for ls in p.findall("hp:linesegarray", NS):
        p.remove(ls)


def set_run_text(run, text: str):
    _relayout(run.getparent())
    ts = run.findall("hp:t", NS)
    for t in ts[1:]:
        run.remove(t)
    if ts:
        t = ts[0]
        for ch in list(t):
            t.remove(ch)
        t.text = text
    else:
        t = etree.SubElement(run, "{%s}t" % HP)
        t.text = text


def write_run(run, text: str, ctx: "HeaderCtx | None" = None, cp: str | None = None):
    """run 에 텍스트 기록. cp 가 있으면 글자 모양 지정. '[기재: …]' 조각은 파란 글자 run 으로 분리(ctx 필요)."""
    if cp:
        run.set("charPrIDRef", cp)
    segs = [s for s in _MARK_SPLIT.split(text or "") if s]
    if ctx is None or not any(_MARK_RE.fullmatch(s) for s in segs):
        set_run_text(run, text)
        return
    p = run.getparent()
    idx = list(p).index(run)
    base = run.get("charPrIDRef", "0")
    # 복제용 원형: 텍스트 외 요소(ctrl·tbl 등) 제거본
    proto = copy.deepcopy(run)
    for ch in list(proto):
        if etree.QName(ch).localname != "t":
            proto.remove(ch)
    for k, seg in enumerate(segs):
        r = run if k == 0 else copy.deepcopy(proto)
        if k > 0:
            p.insert(idx + k, r)
        set_run_text(r, seg)
        r.set("charPrIDRef", ctx.mark_ref(base) if _MARK_RE.fullmatch(seg) else base)


def _lead(run) -> str:
    """run 텍스트의 앞 공백(서식이 들여쓰기 대신 공백으로 맞춘 자리) — 값을 넣을 때 그대로 유지한다."""
    t = "".join(x.text or "" for x in run.findall("hp:t", NS))
    return re.match(r"\s*", t).group(0)


def set_para(p, text: str, keep_runs: int = 1, black_ref: str | None = None, keep_lead: bool = True, ctx=None):
    """문단 텍스트 교체: 첫 run(들)만 남기고 텍스트 지정. black_ref 가 있으면 값 run 의 charPr 를 그 값으로."""
    runs = own_runs(p)
    keep = [r for r in runs if r.find("hp:tbl", NS) is None and r.find("hp:secPr", NS) is None]
    if not keep:
        return
    proto = keep[0]
    for r in keep[1:]:
        if r.find("hp:ctrl", NS) is None:
            p.remove(r)
    lead = _lead(proto) if keep_lead else ""
    write_run(proto, lead + text.lstrip() if lead else text, ctx, black_ref)


def set_para_value(p, value: str, sep: str = "", ctx=None, cp: str | None = None):
    """'○ 기관명 : ' 처럼 라벨 run + (회색) 예시 run 구조 — 라벨은 두고 예시 run 을 값으로 바꾼다.
    cp: 값 run 글자 모양(학습 프로필). 없으면 라벨 run 과 같은 모양(검정)."""
    runs = [r for r in own_runs(p) if r.find("hp:t", NS) is not None]
    if not runs:
        return
    label = runs[0]
    if len(runs) >= 2:
        val = runs[1]
        for r in runs[2:]:
            p.remove(r)
        write_run(val, value, ctx, cp or label.get("charPrIDRef"))  # 예시(회색) → 본문 모양
    else:
        lt = "".join(t.text or "" for t in label.findall("hp:t", NS))
        write_run(label, lt.rstrip() + sep + value, ctx)


def replace_following(paras, anchor_idx: int, count: int, lines: list[str], prefix: str = "- ", ctx=None,
                      cp: str | None = None, sub_prefix: str = "· "):
    """anchor 다음 count 개 문단(예시 '-' 줄)을 lines 로 교체. 첫 예시 문단의 서식(첫 run)을 복제해 줄 수를 맞춘다.
    줄이 '·' 로 시작하면 하위 줄(sub_prefix), '-' 로 시작하면 prefix 를 붙인다. cp: 값 글자 모양(학습 프로필)."""
    targets = paras[anchor_idx + 1: anchor_idx + 1 + count]
    if not targets:
        return
    proto = targets[0]
    parent = proto.getparent()
    lines = lines or ["-"]
    # 원형 문단: 첫 run(검정)만 남김. 서식이 '    - ' 처럼 공백으로 들여쓴 자리는 그대로 유지
    runs = [r for r in own_runs(proto) if r.find("hp:t", NS) is not None]
    lead = _lead(runs[0]) if runs else ""
    for r in runs[1:]:
        proto.remove(r)
    for r in own_runs(proto):  # 예시 문단의 표·컨트롤 run 은 값 줄에 남기지 않는다
        if r.find("hp:t", NS) is None and r.find("hp:secPr", NS) is None:
            proto.remove(r)
    idx = list(parent).index(proto)
    for t in targets[1:]:
        parent.remove(t)
    template = copy.deepcopy(proto)   # 값을 쓰기 전의 깨끗한 원형(줄마다 복제)
    for k, line in enumerate(lines):
        p = proto if k == 0 else copy.deepcopy(template)
        r = [x for x in own_runs(p) if x.find("hp:t", NS) is not None][0]
        body = line.lstrip()
        if body.startswith("·"):
            txt = lead + "  " + sub_prefix + body[1:].lstrip()
        elif body.startswith("-"):
            txt = lead + prefix + body[1:].lstrip()
        else:
            txt = lead + prefix + body
        write_run(r, txt, ctx, cp)
        if k > 0:
            parent.insert(idx + k, p)


def set_cell_lines(tc, lines: list[str], ctx=None, cp: str | None = None):
    """표 셀 문단을 lines 로 교체. cp: 값 글자 모양(라벨 칸 모양 + 학습 프로필)."""
    ps = tc.findall(".//hp:p", NS)
    if not ps:
        return
    proto = ps[0]
    parent = proto.getparent()
    for p in ps[1:]:
        p.getparent().remove(p)
    idx = list(parent).index(proto)
    runs = [r for r in proto.findall("hp:run", NS) if r.find("hp:tbl", NS) is None]
    for r in runs[1:]:
        proto.remove(r)
    if not runs:
        runs = [etree.SubElement(proto, "{%s}run" % HP)]
        if cp:
            runs[0].set("charPrIDRef", cp)
    template = copy.deepcopy(proto)
    for k, line in enumerate(lines or [""]):
        p = proto if k == 0 else copy.deepcopy(template)
        write_run(p.find("hp:run", NS), line, ctx, cp)
        if k > 0:
            parent.insert(idx + k, p)


# ───────────────────────── 서식 학습 프로필 ─────────────────────────
class StyleProfile:
    """report-template/style_profile.json — 실 보고서에서 배운 서식 통계(문장 없음). 없으면 빈 프로필(서식 그대로)."""

    def __init__(self, data: dict | None = None, form: str = ""):
        self.d = data or {}
        self.fit_on = True      # 3차 아이디어 12: 보고서 기본 정보 '문장 끝 자동 다듬기 = 끔' 이면 False
        self.log: list = []     # 자동으로 다듬은 줄(항목·끝 몇 글자만) — 확인 목록·화면에 공개
        self.form = form if form in (self.d.get("by_form") or {}) else ""
        self.f = (self.d.get("by_form") or {}).get(self.form) or {}

    def for_form(self, key: str) -> "StyleProfile":
        """아이디어 2: 그 서식의 실 보고서 통계를 먼저 쓴다. 서식별 표본이 모자란 값은 전체 통계로 채운다."""
        sp = StyleProfile(self.d, key or "")
        sp.fit_on, sp.log = self.fit_on, self.log   # 서식이 달라도 같은 기록·같은 선택
        return sp

    @staticmethod
    def _enough(k: str, v) -> bool:
        if not v:
            return False
        if k == "char":
            return v.get("n", 0) >= 3 and v.get("share", 0) >= 0.4
        if k in ("lines", "chars"):
            return v.get("n", 0) >= 3
        if k in ("bullet", "sub_bullet", "date", "time", "ending"):
            return sum(v.values()) >= 3
        return False   # fill_rate·duration_paren 등은 전체 통계

    @classmethod
    def _merge(cls, own: dict, base: dict) -> dict:
        if not own:
            return base
        out = dict(base or {})
        for k, v in own.items():
            if cls._enough(k, v):
                out[k] = v
        return out

    @classmethod
    def load(cls, tdir: Path) -> "StyleProfile":
        p = Path(tdir) / "style_profile.json"
        try:
            return cls(json.loads(p.read_text(encoding="utf-8")) if p.exists() else {})
        except Exception:
            return cls({})

    @property
    def empty(self) -> bool:
        return not (self.d.get("fields") or self.d.get("cells"))

    def info(self) -> dict:
        return {"loaded": not self.empty, "generated": self.d.get("generated"), "docs": self.d.get("docs", {}),
                "by_form": {k: sum((v.get("docs") or {}).values()) for k, v in (self.d.get("by_form") or {}).items()},
                "ceiling": self.d.get("ceiling"),
                "input_files": self.d.get("input_files", 0), "fields": len(self.d.get("fields", {})),
                "cells": len(self.d.get("cells", {}))}

    @staticmethod
    def _pick(table: dict, label: str) -> dict:
        label = norm(label)
        if not table or not label:
            return {}
        if label in table:
            return table[label]
        for k, v in table.items():   # '조치내용(시간대별 기재)' ↔ '조치내용'
            if label.startswith(k) or k.startswith(label):
                return v
        return {}

    def field(self, label: str) -> dict:
        return self._merge(self._pick(self.f.get("fields", {}), label), self._pick(self.d.get("fields", {}), label))

    def cell(self, label: str) -> dict:
        return self._merge(self._pick(self.f.get("cells", {}), label), self._pick(self.d.get("cells", {}), label))

    @staticmethod
    def _stat(entry: dict, key: str, which: str = "p75"):
        s = (entry or {}).get(key) or {}
        return s.get(which) if s.get(which) is not None else s.get("median")

    def lines_limit(self, label: str, default: int, lo: int = 1, hi: int = 15) -> int:
        v = self._stat(self.field(label), "lines")
        return int(min(hi, max(lo, v))) if v else default

    def chars_budget(self, label: str, default: int, lo: int = 40, hi: int = 160, kind: str = "field") -> int:
        v = self._stat(self.field(label) if kind == "field" else self.cell(label), "chars")
        return int(min(hi, max(lo, v))) if v else default

    @staticmethod
    def _style(entry: dict) -> dict | None:
        c = (entry or {}).get("char") or {}
        if not c or c.get("n", 0) < 3 or c.get("share", 0) < 0.4 or not c.get("size"):
            return None
        return {"face": c.get("face"), "size": float(c["size"]), "bold": bool(c.get("bold")),
                "color": "#000000" if not c.get("color") or c["color"] in ("#808080", "#999999") else c["color"],
                # 자간·장평(2026-10-15) — 근거가 충분할 때만(표본 5+, 최빈 60%+, 2위와 20%p+, GPT 21차). 아니면 None = 서식 모양 그대로
                **(StyleProfile._sr(c))}

    @staticmethod
    def _sr(c: dict) -> dict:
        strong = c.get("n", 0) >= 5 and c.get("sr_share", 0) >= 0.6 and c.get("sr_margin", 0) >= 0.2
        return {"spacing": c.get("spacing") if strong else None, "ratio": c.get("ratio") if strong else None}

    def field_style(self, label: str) -> dict | None:
        return self._style(self.field(label))

    def cell_style(self, label: str) -> dict | None:
        return self._style(self.cell(label))

    def table_style(self, labels: list[str]) -> dict | None:
        """한 표의 값 칸들에 같은 모양을 쓴다 — 라벨별 학습 모양 중 최빈 (글꼴, 크기), 굵기 없음."""
        votes: dict[tuple, int] = {}
        for lb in labels:
            c = (self.cell(lb) or {}).get("char") or {}
            if c.get("size") and c.get("n", 0) >= 2:
                sr = StyleProfile._sr(c)
                k = (c.get("face"), float(c["size"]), sr["spacing"], sr["ratio"])
                # 표본 수로 가중(최대 10) — 칸마다 한 표면 표본 2건짜리와 10건짜리가 같고 동점이면 큰 글자를 골랐다.
                # 상한 10: 다른 서식에서 섞여 들어온 큰 표본(예 '시스템명' 202건)이 한 표의 모양을 끌고 가지 않게(2026-10-15 적합도 실증)
                votes[k] = votes.get(k, 0) + min(int(c.get("n", 0)), 10)
        if not votes:
            return None
        face, size, spacing, ratio = max(votes.items(), key=lambda kv: (kv[1], kv[0][1]))[0]
        return {"face": face, "size": size, "bold": False, "color": "#000000", "spacing": spacing, "ratio": ratio}

    # 아이디어 11: 실보고서가 그 항목에서 주로 쓰는 문장 끝(명사로 끝·…함·…다)에 맞춰 생성 줄의 '마지막 한 마디'만 고친다.
    # 높임 끝맺음(하십시오·합니다·됩니다·입니다·하세요)만 바꾼다 — '포함'처럼 함·됨으로 끝나는 명사를 깨뜨리지 않게 맨 '함/됨'은 건드리지 않는다.
    _POLITE = re.compile(r"(?<=[가-힣])(하십시오|하세요|합니다|됩니다|입니다)(\.?)$")

    def ending_top(self, label: str) -> str:
        e = {k: v for k, v in ((self.field(label) or {}).get("ending") or {}).items() if k in ("noun", "eum", "da")}
        if not e or sum(e.values()) < 3:
            return ""
        k, v = max(e.items(), key=lambda kv: kv[1])
        return k if v / sum(e.values()) >= 0.6 else ""      # 뚜렷할 때만(60%+)

    def fit_endings(self, label: str, lines: list[str], kind: str = "") -> list[str]:
        # 시간대별 조치·조치 경위 줄에는 로그에서 온 판정·메시지 글이 섞인다 — 근거 원문은 한 글자도 바꾸지 않는다(GPT 33차)
        if not self.fit_on or kind == "timeline" or any(k in label.replace(" ", "") for k in ("조치내용", "시간대별", "경위")):
            return lines
        top = self.ending_top(label)
        if top not in ("noun", "eum"):
            return lines
        to = {"noun": {"하십시오": "", "하세요": "", "합니다": "", "됩니다": "", "입니다": ""},
              "eum": {"하십시오": "함", "하세요": "함", "합니다": "함", "됩니다": "됨", "입니다": "임"}}[top]
        out = []
        for ln in lines:
            if "[기재" in ln[-20:] or any(q in ln for q in ('"', "'", "“", "”", "‘", "’", "「", "」")):   # 인용문이 든 줄은 그대로
                out.append(ln)
                continue
            new = self._POLITE.sub(lambda m: to[m.group(1)], ln.rstrip())
            if new != ln.rstrip():
                self.log.append({"label": norm(label)[:30], "before": "…" + _mask_tail(ln.rstrip()[-12:]), "after": "…" + _mask_tail(new[-10:])})
            out.append(new)
        return out

    def bullet(self, label: str) -> str:
        b = {k: v for k, v in ((self.field(label) or {}).get("bullet") or {}).items() if k != "none"}
        if not b:
            return "- "
        top = max(b.items(), key=lambda kv: kv[1])[0]
        return {"dash": "- ", "dot": "· ", "arrow": "▸ ", "number": "- "}.get(top, "- ")

    def sub_bullet(self, label: str) -> str:
        b = (self.field(label) or {}).get("sub_bullet") or {}
        if not b:
            return "· "
        top = max(b.items(), key=lambda kv: kv[1])[0]
        return {"dot": "· ", "arrow": "▸ ", "dash": "- "}.get(top, "· ")

    def date_style(self, label: str, kind: str = "cell") -> str:
        d = (self.cell(label) if kind == "cell" else self.field(label)).get("date") or {}
        return max(d.items(), key=lambda kv: kv[1])[0] if d else ""


def fmt_date(ts: str, style: str) -> str:
    """분석 시각 'YYYY-MM-DD HH:MM[:SS]' → 학습된 날짜 표기 형식."""
    try:
        d = datetime.strptime(ts[:16], "%Y-%m-%d %H:%M")
    except Exception:
        return (ts or "")[:10]
    w = _WEEK[d.weekday()]
    if style == "’YY.M.D.(요일)":
        return f"’{d:%y}.{d.month}.{d.day}.({w})"
    if style == "’YY.M.D.":
        return f"’{d:%y}.{d.month}.{d.day}."
    if style == "YYYY.M.D.(요일)":
        return f"{d.year}. {d.month}. {d.day}.({w})"
    if style == "YYYY-MM-DD":
        return f"{d:%Y-%m-%d}"
    if style == "YY.M.D.":
        return f"{d:%y}.{d.month}.{d.day}."
    if style == "M월 D일":
        return f"{d.month}월 {d.day}일"
    return f"{d.year}. {d.month}. {d.day}."


# ───────────────────────── 분석 결과 → 문장 ─────────────────────────
def _kdate(ts: str) -> tuple[str, str]:
    """'2026-09-10 14:32:00' → ('’26.9.10.(목)', '14:32')"""
    try:
        d = datetime.strptime(ts[:16], "%Y-%m-%d %H:%M")
    except Exception:
        return ts or "", ""
    return f"’{d:%y}.{d.month}.{d.day}.({_WEEK[d.weekday()]})", f"{d:%H:%M}"


def _hhmm(ts: str) -> str:
    """'YYYY-MM-DD HH:MM:SS' / 'HH:MM:SS' / 'MM-DD HH:MM:SS' → 실 보고서 표기(HH:MM, 여러 날이면 MM-DD HH:MM)."""
    ts = ts or ""
    if len(ts) >= 16 and ts[4] == "-":
        return ts[11:16]
    m = re.match(r"^(\d{2}-\d{2} )?(\d{2}:\d{2})(:\d{2})?$", ts)
    return (m.group(1) or "") + m.group(2) if m else ts


def _fit(text: str, budget: int) -> str:
    """글자 수 예산에 맞춰 자른다(단어 중간 회피, 말줄임)."""
    text = norm(text)
    if len(text) <= budget:
        return text
    cut = text[:max(8, budget - 1)]
    sp = cut.rfind(" ")
    if sp > budget * 0.6:
        cut = cut[:sp]
    return cut.rstrip(" ,;:·-—") + "…"


class HeaderCtx:
    """header.xml 의 글자 모양(charPr)·글꼴 목록 — 값 run 에 맞는 모양(검정/학습 프로필/기재 표시)을 만들어 준다."""

    def __init__(self, root):
        self.root = root
        self.props = root.find(".//hh:charProperties", NS) if root is not None else None
        self._cache: dict[tuple, str] = {}
        self.fonts: dict[str, dict[str, str]] = {}   # lang → {face: id}
        if root is not None:
            for ff in root.iter("{%s}fontface" % HH):
                self.fonts[ff.get("lang")] = {f.get("face"): f.get("id") for f in ff.findall("hh:font", NS)}

    def _get(self, cp_id: str):
        if self.props is None:
            return None
        return next((c for c in self.props.findall("hh:charPr", NS) if c.get("id") == cp_id), None)

    def _add(self, el) -> str:
        nid = str(max(int(c.get("id", 0)) for c in self.props.findall("hh:charPr", NS)) + 1)
        el.set("id", nid)
        self.props.append(el)
        self.props.set("itemCnt", str(len(self.props.findall("hh:charPr", NS))))
        return nid

    def font_id(self, face: str, lang: str = "HANGUL") -> str | None:
        return (self.fonts.get(lang) or {}).get(face)

    def styled(self, cp_id: str, face: str | None = None, size: float | None = None, bold: bool | None = None,
               color: str | None = "#000000", italic: bool | None = False, spacing: int | None = None, ratio: int | None = None) -> str:
        """cp_id 를 바탕으로 글꼴/크기/굵기/색/자간/장평을 바꾼 charPr 의 id (없으면 만들어 header 에 추가, 같은 요청은 재사용)."""
        key = (cp_id, face, size, bold, color, italic, spacing, ratio)
        if key in self._cache:
            return self._cache[key]
        src = self._get(cp_id)
        if src is None:
            self._cache[key] = cp_id
            return cp_id
        new = copy.deepcopy(src)
        changed = False
        if face and self.font_id(face) is not None:
            fr = new.find("hh:fontRef", NS)
            if fr is not None:
                for lang, attr in (("HANGUL", "hangul"), ("LATIN", "latin"), ("HANJA", "hanja"), ("JAPANESE", "japanese"),
                                   ("OTHER", "other"), ("SYMBOL", "symbol"), ("USER", "user")):
                    fid = self.font_id(face, lang)
                    if fid is not None and fr.get(attr) != fid:
                        fr.set(attr, fid)
                        changed = True
        if size and int(round(size * 100)) != int(new.get("height", "1000")):
            new.set("height", str(int(round(size * 100))))
            changed = True
        if bold is not None:
            has = new.find("hh:bold", NS)
            if bold and has is None:
                b = etree.Element("{%s}bold" % HH)
                fr = new.find("hh:offset", NS)
                (fr.addnext(b) if fr is not None else new.append(b))
                changed = True
            elif not bold and has is not None:
                new.remove(has)
                changed = True
        if italic is not None:
            has = new.find("hh:italic", NS)
            if italic and has is None:
                new.append(etree.Element("{%s}italic" % HH))
                changed = True
            elif not italic and has is not None:
                new.remove(has)
                changed = True
        if color and new.get("textColor", "#000000").lower() != color.lower():
            new.set("textColor", color)
            changed = True
        # 자간(hh:spacing)·장평(hh:ratio) — 실보고서에서 배운 값(언어 7종 모두 같은 값으로). 서식에 요소가 없으면 만든다
        for tag, val in (("spacing", spacing), ("ratio", ratio)):
            if val is None:
                continue
            el = new.find("hh:" + tag, NS)
            if el is None:     # 요소 순서(fontRef → ratio → spacing → relSz …)를 지킨다 — 끝에 붙이면 한글이 문서를 거부할 수 있다
                el = etree.Element("{%s}%s" % (HH, tag))
                prev = new.find("hh:ratio", NS) if tag == "spacing" else None
                prev = prev if prev is not None else new.find("hh:fontRef", NS)
                (prev.addnext(el) if prev is not None else new.insert(0, el))
            for lang in ("hangul", "latin", "hanja", "japanese", "other", "symbol", "user"):
                if el.get(lang) != str(int(val)):
                    el.set(lang, str(int(val)))
                    changed = True
        nid = self._add(new) if changed else cp_id
        self._cache[key] = nid
        return nid

    def black(self, cp_id: str) -> str:
        """회색 안내문 모양 → 검정 본문 모양(기울임 제거)."""
        return self.styled(cp_id, color="#000000", italic=False)

    def mark_ref(self, cp_id: str) -> str:
        """'[기재: …]' 표시용 파란 글자 모양(굵기·크기는 그대로)."""
        return self.styled(cp_id, color=MARK_COLOR, italic=False)

    def value_ref(self, cp_id: str, style: dict | None) -> str:
        """값 run 모양: 학습 프로필 style 이 있으면 적용, 없으면 검정 본문."""
        if not style:
            return self.black(cp_id)
        return self.styled(cp_id, face=style.get("face"), size=style.get("size"), bold=style.get("bold"),
                           color=style.get("color") or "#000000", italic=False,
                           spacing=style.get("spacing"), ratio=style.get("ratio"))


class Facts:
    """보고서에 쓰는 판정 데이터 (임의 추정 없음). 문장 길이·줄 수는 학습 프로필(sp)을 따른다."""

    def __init__(self, inc: dict, profile: dict, ctx: HeaderCtx | None = None, sp: StyleProfile | None = None):
        self.inc, self.pf, self.ctx = inc, profile or {}, ctx
        self.sp = sp or StyleProfile()
        self.first = inc.get("first") or {}
        self.plan = inc.get("plan") or {}
        self.t = inc.get("incident_time") or ""
        self.date_k, self.time_k = _kdate(self.t)

    def p(self, k: str) -> str:
        return norm(str(self.pf.get(k, "") or ""))

    def pm(self, k: str, label: str | None = None) -> str:
        """기본 정보 값, 없으면 [기재: 라벨]"""
        v = self.p(k)
        return v if v else mark(label or dict(PROFILE_FIELDS).get(k, k))

    def service(self) -> str:
        return self.p("service") or self.p("system") or ""

    # ── 시각 ──
    def last_anomaly(self) -> str:
        """로그상 마지막 이상 시각(HH:MM) — 복구 시각의 참고값(확정 아님)."""
        last = ""
        for t in self.inc.get("timeline_key") or []:
            v = t.get("last_full") or t.get("ts_full") or ""
            if v > last:
                last = v
        if not last:
            for t in self.inc.get("timeline") or []:
                v = t.get("ts") or ""
                if v > last:
                    last = v
        return _hhmm(last) if len(last) >= 16 else last[-5:] if last else ""

    def recovery_mark(self, short: bool = False) -> str:
        la = self.last_anomaly()
        if short or not la:
            return mark("복구 시각")
        return mark(f"복구 시각 — 로그상 마지막 이상 {la}")

    def period(self) -> str:
        if not self.t:
            return f"{mark('발생 일시')} ~ {mark('복구 시각')} ({mark('소요')}분)"
        return f"{self.date_k} {self.time_k} ~ {self.recovery_mark()} ({mark('소요')}분)"

    # ── 본문 ──
    def content_lines(self) -> list[str]:
        f = self.first
        budget = self.sp.chars_budget("장애내용", 60)
        if not f:
            scope = f"분석 범위: 파일 {len(self.inc.get('files', []))}개 · 이벤트 {self.inc.get('events_window', 0):,}건"
            if self.sp.lines_limit("장애내용", 2) <= 1:      # 실보고서 장애내용은 한 줄
                return [f"{mark('장애 현상 — 로그에서 알려진 장애 패턴 미검출')} ({scope})"]
            return [mark("장애 현상 — 로그에서 알려진 장애 패턴 미검출"), scope]
        svc = self.service()
        head = f"{svc + ' ' if svc else ''}{f.get('category_ko', '')} — {f.get('verdict', '')}".strip(" —")
        tail = f" (최초 이상 {f.get('layer_ko', '')} 계층 {_hhmm(f.get('ts', ''))})"
        line = head + tail if len(head + tail) <= budget else _fit(head, budget)
        # 실보고서 장애내용은 한 줄(46건 통계 1~1줄) — 이용자 불편 기재 표시를 같은 줄 끝에(줄을 지우는 수정이 없게)
        if self.sp.lines_limit("장애내용", 2) <= 1:
            return [f"{line} — {mark('이용자 불편 내용·범위')}"]
        return [line, mark("이용자(국민) 불편 내용·범위")]

    def cause_lines(self, root: bool = False) -> list[str]:
        f = self.first
        budget = self.sp.chars_budget("장애 근본원인" if root else "장애원인", 100)
        if not f:
            return [mark("장애 원인 — 로그 분석에서 원인 패턴 미검출(파악중)")]
        budget = max(70, budget)
        out = [_fit(f"{f.get('verdict', '')} — {f.get('category_ko', '')}({f.get('layer_ko', '')} 계층, 판정 근거 {f.get('rule_id', '')})", budget)]
        for c in self.inc.get("checklist", []):
            if c.get("vendor_cause"):
                from .codes import cause_label
                out.append("· " + _fit(f"{cause_label(c.get('vendor_url', ''))}: {c['vendor_cause']}", budget))
                break
        if f.get("origin") == "legacy" or "가능성" in (f.get("verdict") or ""):
            out.append(mark("원인 확정 여부 — 현재 1차 추정 단계(확정 전에는 '파악중')"))
        # 실보고서 줄 수(학습 p75)에 맞추되 내용은 자르지 않는다(GPT 21차) — 넘치면 판정 줄과 제조사 원인 줄을 한 줄로 합친다.
        # '[기재: …]' 줄(원인 확정 여부 등)은 담당자 확인 항목이라 늘 따로 남긴다
        lim = max(1, self.sp.lines_limit("장애 근본원인" if root else "장애원인", len(out)))
        if len(out) > lim and len(out) >= 2 and out[1].startswith("· ") and not out[1].startswith("· [기재"):
            out = [out[0] + " " + out[1]] + out[2:]
        return out

    def timeline_lines(self, label: str = "조치내용", limit: int | None = None) -> list[str]:
        """인과 타임라인 요점(판정별 최초 발생·횟수·구간) 우선, 없으면 판정 근거 앞 N건. 줄 수·글자 수는 학습값."""
        limit = limit or max(3, self.sp.lines_limit(label, 8) - 3)
        budget = max(56, self.sp.chars_budget(label, 60) + 20)
        out = []
        key = self.inc.get("timeline_key") or []
        def line(prefix: str, msg: str) -> str:
            room = budget - len(prefix) - 3
            return f"{prefix} — {_fit(msg, room)}" if msg and room >= 24 else prefix

        if key:
            for t in key[:limit]:
                n = int(t.get("count", 1) or 1)
                cnt = f" ({n:,}회, ~{_hhmm(t.get('last', ''))})" if n > 1 else ""
                first = " (최초 이상)" if any("최초" in m for m in t.get("marks", [])) else ""
                out.append(line(f"{_hhmm(t.get('ts', ''))} : [{t.get('layer_ko', '')}] {t.get('verdict', '')} 발생{first}{cnt}", norm(t.get("message", ""))))
            rest = key[limit:]
            if rest:
                # 줄 수를 실보고서에 맞추되 내용은 버리지 않는다(GPT 21차) — 남은 판정은 한 줄에 이어 적고 전체 근거 파일을 가리킨다
                shown = "; ".join(f"{_hhmm(t.get('ts', ''))} [{t.get('layer_ko', '')}] {t.get('verdict', '')}" + (f" {t['eid']}" if t.get("eid") else "")
                                  for t in rest[:20])   # 근거 ID 로 분석요약의 같은 줄을 찾는다(아이디어 6)
                more = f" 외 {len(rest) - 20}건" if len(rest) > 20 else ""
                out.append(f"그 밖의 관측 {len(rest)}건: {shown}{more} — 전체 근거는 분석요약_{self.inc.get('id', 'INC')}.html(첨부)")
            return out
        tl = self.inc.get("timeline", [])
        for t in tl[:limit]:
            out.append(line(f"{_hhmm(t.get('ts', ''))} : [{t.get('layer_ko', '')}] {t.get('verdict', '')} 발생", norm(t.get("message", ""))))
        if len(tl) > limit:
            out.append(f"그 밖의 근거 {len(tl) - limit:,}줄 — 전체는 분석요약_{self.inc.get('id', 'INC')}.html(첨부)")
        return out

    def action_lines(self, limit: int = 3) -> list[str]:
        # 아이디어 5: '시각' 표시에 조치 번호를 붙인다 — 상황관리·사후관리 보고서의 같은 조치는 같은 번호라
        # 확인 목록이 '시각 · 조치1 — 2곳'처럼 같은 값끼리 짝을 지어 준다(줄마다 다른 값이 한 값으로 묶이지 않게)
        return [f"{mark(f'시각 · 조치{i}')} : (1차 조치) {a}" for i, a in enumerate(self._immediate(limit), 1)]

    def _immediate(self, limit: int) -> list[str]:
        out = []
        for c in self.inc.get("checklist", []):
            for a in c.get("immediate", []):
                out.append(norm(a))
                if len(out) >= limit:
                    return out
        return out

    def fix_lines(self, label: str = "장애 근본원인 조치 여부") -> list[str]:
        """근본원인 조치 여부 — 1차 조치마다 '수행 여부·일시' 기재 표시. 줄 수는 실보고서 상한(학습 p75) 안에서.
        내장 사후관리 채우기와 사용자 서식('조치 여부' 칸)이 같은 함수를 쓴다."""
        # 1차 조치는 자르지 않는다(GPT 21차 — 줄 수 상한으로 내용을 잘라내지 않는다). 실보고서보다 길면 담당자가 고르는 편이 빠뜨리는 것보다 안전
        # 조치 번호는 표시 문구에서 거꾸로 읽지 않는다 — 담당자가 시각 값을 넣으면 표시가 값으로 바뀐다(3차 아이디어 5에서 발견)
        acts = [f"(1차 조치) {a} — {mark(f'수행 여부·일시 · 조치{i}')}" for i, a in enumerate(self._immediate(4), 1)]
        return acts or [mark(("근본원인 " if "근본원인" in label.replace(" ", "") else "") + "조치 내용·완료 여부")]

    def escalation_lines(self) -> list[str]:
        t1 = self.plan.get("tier1", {}) if self.plan else {}
        esc = t1.get("escalate", {}) if t1 else {}
        out = []
        if esc.get("when"):
            out.append("2차(유지보수 엔지니어) 이관 기준: " + " / ".join(esc["when"][:3]))
        t3 = self.plan.get("tier3", {}) if self.plan else {}
        if t3.get("summary"):
            s3 = re.sub(r"((?:[^\s\[\]:/]+ ){0,2}[^\s\[\]:/]+) \[담당자 기재\]", lambda m: mark(m.group(1)), norm(t3["summary"][0])[:140])
            out.append("3차(제조사) 의뢰: " + s3.replace("[담당자 기재]", mark("내용")))
        out.append(mark("이관 여부(문제관리 등록 번호·일자)"))
        # 실보고서 '문제관리 이관 여부' 는 한 줄(학습 1~1줄) — 기재 표시를 앞에, 이관 기준은 짧게 덧붙인다
        if self.sp.lines_limit("문제관리 이관 여부", len(out)) <= 1 and len(out) > 1:
            # 우선순위: 이관 여부 표시 → 3차(제조사) 의뢰 정보(버전·패치 레벨 표시) → 자리가 남으면 2차 기준
            budget = max(90, self.sp.chars_budget("문제관리 이관 여부", 80) + 20)
            line = out[-1]
            s3 = next((x for x in out if x.startswith("3차(제조사) 의뢰: ")), "")
            if s3:
                line += " · " + s3
            crit = " / ".join(esc.get("when", [])[:3]) if esc.get("when") else ""
            if crit and len(line) + len(crit) + 16 <= budget:
                return [line + f" · 2차 이관 기준: {crit}"]
            return [line] + ([f"2차(유지보수 엔지니어) 이관 기준: {crit}"] if crit else [])   # 자리가 없으면 줄을 늘린다(내용은 그대로)
        return out

    def vendors(self) -> str:
        if self.p("vendor"):
            return self.p("vendor")
        prods = []
        for fobj in self.inc.get("files", []):
            v = PRODUCT_VENDOR.get(str(fobj.get("product", "")).lower())
            if v and v not in prods:
                prods.append(v)
        return ", ".join(prods) or mark("제조사")

    def model(self) -> str:
        if self.p("model"):
            return self.p("model")
        prods = sorted({str(f.get("product", "")) for f in self.inc.get("files", []) if f.get("product")})
        return ("로그 감지 제품: " + ", ".join(prods) + " " if prods else "") + mark("모델/사양")

    def related(self, keys: tuple[str, ...], cats: tuple[str, ...] = ()) -> list[str]:
        out = []
        for c in self.inc.get("checklist", []):
            rid = str(c.get("rule_id", "")).upper()
            if any(k in rid for k in keys) or (cats and c.get("category") in cats):
                out.append(f"로그 분석 관측: {c.get('verdict', '')} ({c.get('rule_id')}) — {mark('현황·조치')}")
        return out[:3]


# ───────────────────────── 서식별 채우기 ─────────────────────────
def _fill_status(root, F: Facts) -> int:
    n = 0
    ctx, sp = F.ctx, F.sp
    tbls = top_tables(root)
    # 제목 표: (기관명: )
    if tbls:
        for p in tbls[0].iter("{%s}p" % HP):
            if para_text(p).startswith("(기관명"):
                set_para(p, f"(기관명: {F.pm('org')})", ctx=ctx); n += 1
    paras = body_paragraphs(root)
    texts = [para_text(p) for p in paras]

    def idx(prefix: str) -> int:
        return next((i for i, t in enumerate(texts) if t.startswith(prefix)), -1)

    def vref(p, label: str) -> str | None:
        """'라벨 : 값' 문단의 값 run 모양 — 라벨 run 기준 + 학습 프로필."""
        if ctx is None:
            return None
        runs = [r for r in own_runs(p) if r.find("hp:t", NS) is not None]
        base = runs[0].get("charPrIDRef", "0") if runs else "0"
        return ctx.value_ref(base, sp.field_style(label))

    def lref(p, label: str) -> str | None:
        """항목 아래 '-' 줄의 값 모양 — 예시 줄의 첫 run 기준 + 학습 프로필."""
        if ctx is None:
            return None
        runs = [r for r in own_runs(p) if r.find("hp:t", NS) is not None]
        base = runs[0].get("charPrIDRef", "0") if runs else "0"
        return ctx.value_ref(base, sp.field_style(label))

    i = idx("□ 장애 개요")
    if i >= 0:
        set_para(paras[i], "□ 장애 개요", ctx=ctx); n += 1
    i = idx("○ 기관명")
    if i >= 0:
        set_para_value(paras[i], F.pm("org"), sep=" ", ctx=ctx, cp=vref(paras[i], "기관명")); n += 1
    i = idx("○ 장애시간")
    if i >= 0:
        set_para_value(paras[i], F.period(), ctx=ctx, cp=vref(paras[i], "장애시간")); n += 1
    i = idx("○ 서비스명")
    if i >= 0:
        svc = F.service() or mark("서비스명(제공 기능 설명)")
        set_para_value(paras[i], svc, ctx=ctx, cp=vref(paras[i], "서비스명")); n += 1
    i = idx("※ 서버위치")
    if i >= 0:
        parts = [x for x in (("서버위치: " + F.p("location")) if F.p("location") else "",
                             ("관리주체: " + F.p("operator")) if F.p("operator") else "") if x]
        if parts:
            set_para(paras[i], "※ " + " / ".join(parts),
                     black_ref=ctx.black(own_runs(paras[i])[0].get("charPrIDRef", "0")) if ctx else None, ctx=ctx)
        else:
            paras[i].getparent().remove(paras[i])
        n += 1
        paras = body_paragraphs(root); texts = [para_text(p) for p in paras]
    i = idx("○ 장애내용")
    if i >= 0 and i + 1 < len(paras):
        replace_following(paras, i, 1, sp.fit_endings("장애내용", F.content_lines()), prefix=sp.bullet("장애내용"), ctx=ctx,
                          cp=lref(paras[i + 1], "장애내용"), sub_prefix=sp.sub_bullet("장애내용")); n += 1
        paras = body_paragraphs(root); texts = [para_text(p) for p in paras]
    i = idx("○ 장애원인")
    if i >= 0 and i + 1 < len(paras):
        replace_following(paras, i, 1, sp.fit_endings("장애원인", F.cause_lines()), prefix=sp.bullet("장애원인"), ctx=ctx,
                          cp=lref(paras[i + 1], "장애원인"), sub_prefix=sp.sub_bullet("장애원인")); n += 1
        paras = body_paragraphs(root); texts = [para_text(p) for p in paras]
    i = idx("○ 조치내용")
    if i >= 0 and i + 1 < len(paras):
        cnt = sum(1 for t in texts[i + 1:i + 3] if t.startswith("-"))
        lim = sp.lines_limit("조치내용", 8)
        acts = F.action_lines(3)
        lines = F.timeline_lines("조치내용", max(3, lim - len(acts))) + acts
        lines.append(f"{F.recovery_mark()} : 서비스 정상화 확인")
        replace_following(paras, i, cnt or 1, sp.fit_endings("조치내용", lines), prefix=sp.bullet("조치내용"), ctx=ctx,
                          cp=lref(paras[i + 1], "조치내용"), sub_prefix=sp.sub_bullet("조치내용")); n += 1
    # 담당자 표 (소속/직급/담당자/연락처)
    for tb in tbls:
        c = find_cell(tb, 0, 0)
        if c is not None and norm("".join(c.itertext())) == "소속":
            cols = (("dept", "소속"), ("rank", "직급"), ("person", "담당자"), ("phone", "연락처"))
            tstyle = sp.table_style([lb for _, lb in cols]) or {"bold": False}
            for col, (key, label) in enumerate(cols):
                tc = find_cell(tb, col, 1)
                if tc is not None:
                    base = cell_run_ref(find_cell(tb, col, 0)) or "0"
                    cp = ctx.value_ref(base, tstyle) if ctx else None
                    set_cell_lines(tc, [F.pm(key, label)], ctx=ctx, cp=cp); n += 1
    return n


def _fill_postmortem(root, F: Facts) -> int:
    n = 0
    ctx, sp = F.ctx, F.sp
    tbls = top_tables(root)
    for tb in tbls:
        c00 = norm("".join(find_cell(tb, 0, 0).itertext())) if find_cell(tb, 0, 0) is not None else ""
        if c00 == "시스템명":
            date_txt = fmt_date(F.t, sp.date_style("장애 발생일자") or "YYYY.M.D.(요일)") if F.t else mark("장애 발생일자")
            time_txt = f"{F.time_k} ~ {F.recovery_mark(short=True)}" if F.t else f"{mark('발생 시각')} ~ {mark('복구 시각')}"
            cells = {(1, 0): ("시스템명", F.pm("system", "시스템명(IRM 등록 명칭)")), (1, 1): ("등급", F.pm("grade")),
                     (3, 1): ("설치 위치", F.pm("location", "설치 위치")), (1, 2): ("장애 발생일자", date_txt),
                     (3, 2): ("발생/복구 시간", time_txt), (1, 3): ("상위기관", F.pm("parent_org")), (3, 3): ("기관명", F.pm("org")),
                     (1, 4): ("소관 부서", F.pm("dept")), (3, 4): ("담당자", F.pm("person")), (1, 5): ("직위/직급", F.pm("rank")),
                     (3, 5): ("담당자 연락처", F.pm("phone"))}
            tstyle = sp.table_style([lb for lb, _ in cells.values()]) or {"bold": False}
            for (col, row), (label, val) in cells.items():
                tc = find_cell(tb, col, row)
                if tc is not None:
                    base = cell_run_ref(find_cell(tb, col - 1, row)) or "0"
                    cp = ctx.value_ref(base, tstyle) if ctx else None
                    set_cell_lines(tc, [val], ctx=ctx, cp=cp); n += 1
        elif c00 == "항 목":
            contact = " ".join(x for x in (F.p("person"), f"({F.p('phone')})" if F.p("phone") else "") if x) or mark("운영 담당자(연락처)")
            rows = {1: ("정보시스템명", F.pm("system", "정보시스템명")), 2: ("제조사", F.vendors()), 3: ("모델/사양", F.model()),
                    4: ("도입년도 및 내용연수", F.pm("intro_year")), 5: ("시스템 운영부서", F.pm("dept", "시스템 운영부서")),
                    6: ("운영 담당자", contact), 7: ("이중화 구성 여부", F.pm("ha"))}
            tstyle = sp.table_style([lb for lb, _ in rows.values()]) or {"bold": False}
            for row, (label, val) in rows.items():
                tc = find_cell(tb, 1, row)
                if tc is not None:
                    base = cell_run_ref(find_cell(tb, 0, row)) or "0"
                    cp = ctx.value_ref(base, tstyle) if ctx else None
                    set_cell_lines(tc, [val], ctx=ctx, cp=cp); n += 1
    paras = body_paragraphs(root)

    def fill_after(prefix: str, lines: list[str], max_count: int = 3, label: str | None = None):
        nonlocal paras, n
        texts = [para_text(p) for p in paras]
        i = next((k for k, t in enumerate(texts) if t.startswith(prefix)), -1)
        if i < 0 or not lines or i + 1 >= len(paras):
            return
        cnt = 0
        for t in texts[i + 1:i + 1 + max_count]:
            if t == "-" or t.startswith("- "):
                cnt += 1
            else:
                break
        label = label or prefix.lstrip("○ ")
        cp = None
        if ctx is not None:
            runs = [r for r in own_runs(paras[i + 1]) if r.find("hp:t", NS) is not None]
            cp = ctx.value_ref(runs[0].get("charPrIDRef", "0") if runs else "0", sp.field_style(label))
        replace_following(paras, i, cnt or 1, sp.fit_endings(label, lines), prefix=sp.bullet(label), ctx=ctx, cp=cp,
                          sub_prefix=sp.sub_bullet(label)); n += 1
        paras = body_paragraphs(root)

    fill_after("○ 장애 근본원인", F.cause_lines(root=True), label="장애 근본원인")
    fill_after("○ 문제관리 이관 여부", F.escalation_lines(), label="문제관리 이관 여부")
    fill_after("○ 장애 근본원인 조치 여부", F.fix_lines("장애 근본원인 조치 여부"), label="장애 근본원인 조치 여부")
    fill_after("○ (사용 기한 지정) 인증서", F.related(("SSL", "CERT", "LICENSE", "LIC-")), label="인증서, 라이선스 등 사용권한 관리 현황")
    fill_after("○ (사용 기한 지정) 장비 노후화", F.related(("EOS", "EOL"), ("eos",)), label="장비 노후화 또는 제조사 기술지원 중단 여부")
    fill_after("○ (무중단 운영) 시스템 임계치", F.related(("POOL", "THREAD", "MEM", "DISK", "CPU", "OOM", "HEAP"), ("resource", "performance")),
               label="시스템 임계치 관리 현황")
    fill_after("○ 변경작업 관리 현황", F.related(("DEPLOY", "CHANGE"), ("deploy",)), label="변경작업 관리 현황")
    fill_after("○ (트래픽 집중) 백업·배치", F.related(("BATCH", "BACKUP")), label="백업·배치작업 등 정기 자동수행 작업 관리현황")
    lim = sp.lines_limit("시간대별 장애 조치 세부내용", 10)
    acts = F.action_lines(3)
    tl = F.timeline_lines("시간대별 장애 조치 세부내용", max(3, lim - len(acts))) + acts
    tl.append(f"{F.recovery_mark()} : 서비스 정상화 확인")
    fill_after("○ 시간대별 장애 조치 세부내용", tl, max_count=5, label="시간대별 장애 조치 세부내용")
    return n


FILLERS = {"status": _fill_status, "postmortem": _fill_postmortem}
INDEX_MAX = 30


def append_evidence_index(root, F: "Facts") -> int:
    """3차 아이디어 13(선택, 기본 끔): 사후관리 보고서 끝에 '근거 색인' — 근거 ID · 시각 · 계층 · 판정.
    종이 보고서만으로 '이 문장은 어느 로그 줄에서 왔나'를 분석요약 HTML 에서 찾아갈 수 있게. 서식의 '시간대별 조치' 문단 모양을 복제한다."""
    key = [k for k in (F.inc.get("timeline_key") or []) if k.get("eid")]
    body = body_paragraphs(root)
    head = next((x for x in body if para_text(x).startswith("○ 시간대별 장애 조치")), None)
    if head is None or not key:
        return 0
    item = body[body.index(head) + 1] if body.index(head) + 1 < len(body) else head
    last = body[-1]
    parent = last.getparent()
    at = list(parent).index(last) + 1
    lines = [f"- {k['eid']} · {_hhmm(k.get('ts_full') or k.get('ts', ''))} · [{k.get('layer_ko', '')}] {norm(k.get('verdict', ''))[:60]}"
             for k in key[:INDEX_MAX]]
    if len(key) > INDEX_MAX:
        lines.append(f"- 그 밖의 근거 {len(key) - INDEX_MAX}건")
    lines.append(f"- 근거 줄 전체: 분석요약_{F.inc.get('id', 'INC')}.html(첨부)에서 같은 근거 ID 로 찾음")
    new = []
    h = copy.deepcopy(head)
    for r in own_runs(h):
        if r.find("hp:secPr", NS) is not None or r.find("hp:ctrl", NS) is not None:
            h.remove(r)
    set_para(h, "○ 근거 색인 (근거 ID · 시각 · 계층 · 판정)", keep_lead=False, ctx=F.ctx)
    new.append(h)
    for ln in lines:
        q = copy.deepcopy(item)
        for r in own_runs(q):
            if r.find("hp:secPr", NS) is not None or r.find("hp:ctrl", NS) is not None or r.find("hp:tbl", NS) is not None:
                q.remove(r)
        set_para(q, ln, keep_lead=False, ctx=F.ctx)
        new.append(q)
    for i, x in enumerate(new):
        parent.insert(at + i, x)
    return len(lines)


# ───────────────────────── 확인 목록(담당자 기재 항목) ─────────────────────────
def collect_todo(root, form_title: str) -> list[dict]:
    """채워진 section 에서 '[기재: …]' 표시를 위치(항목/표 라벨)와 함께 모은다 — 서식 라벨과 표시 문구만 담긴다."""
    out = []
    heading = ""
    for p in root.iter("{%s}p" % HP):
        in_cell = next((a for a in p.iterancestors() if a.tag == "{%s}tc" % HP), None)
        text = "".join("".join(t.itertext()) for r in own_runs(p) for t in r.findall("hp:t", NS))
        text = norm(text)
        if not text:
            continue
        if in_cell is None and text[:1] in "□○※":
            heading = text.split(":")[0].split("(")[0].strip("□○※ ")[:30]
        where = heading
        if in_cell is not None:
            tbl = next((a for a in in_cell.iterancestors() if a.tag == "{%s}tbl" % HP), None)
            addr = in_cell.find("hp:cellAddr", NS)
            lab = None
            if tbl is not None and addr is not None:
                c, r = int(addr.get("colAddr")), int(addr.get("rowAddr"))
                left = find_cell(tbl, c - 1, r) if c > 0 else None
                up = find_cell(tbl, c, r - 1) if r > 0 else None
                for cand in (left, up):
                    t = norm("".join(cand.itertext())) if cand is not None else ""
                    if t and not _MARK_RE.search(t) and len(t) <= 24:
                        lab = t
                        break
            where = f"표 · {lab}" if lab else "표"
        for m in marks_in(text):
            out.append({"form": form_title, "where": where, "item": m})
    return out


def fill_hwpx(form: Path, inc: dict, profile: dict, key: str, out: Path, sp: StyleProfile | None = None) -> dict:
    """서식 HWPX 복제 + 값 채움 → out. 반환 {hwpx, filled, todo:[{form,where,item}]}"""
    src = zipfile.ZipFile(form)
    names = src.namelist()
    header_root = etree.fromstring(src.read("Contents/header.xml")) if "Contents/header.xml" in names else None
    title = next((f["title"] for f in FORMS if f["key"] == key), key)
    F = Facts(inc, profile, HeaderCtx(header_root) if header_root is not None else None, (sp or StyleProfile.load(form.parent)).for_form(key))
    sections = {}
    filled = 0
    todo: list[dict] = []
    for name in names:
        if re.match(r"Contents/section\d+\.xml", name):
            root = etree.fromstring(src.read(name))
            filled += FILLERS[key](root, F)
            if key == "postmortem" and option_on(profile, "evidence_index", False) and name.endswith("section0.xml"):
                filled += append_evidence_index(root, F)
            todo += collect_todo(root, title)
            sections[name] = root
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        if "mimetype" in names:
            dst.writestr("mimetype", src.read("mimetype"), compress_type=zipfile.ZIP_STORED)
        for name in names:
            if name == "mimetype" or name.startswith("Preview/"):
                continue  # 미리보기(원 서식 캐시)는 제외 — 한글이 다시 만든다
            if name in sections:
                data = etree.tostring(sections[name], xml_declaration=True, encoding="UTF-8", standalone=True)
            elif name == "Contents/header.xml" and header_root is not None:
                data = etree.tostring(header_root, xml_declaration=True, encoding="UTF-8", standalone=True)
            else:
                data = src.read(name)
            dst.writestr(name, data)
    out.write_bytes(buf.getvalue())
    return {"hwpx": str(out), "filled": filled, "todo": todo}


# ───────────────────────── HWPX → DOCX (동일 변환) ─────────────────────────
def _hu_twips(v) -> int:  # HWPUNIT(1/7200in) → twips(1/1440in)
    return int(round(int(v) / 5))


def _hu_emu(v) -> int:
    return int(v) * 127


class _Header:
    def __init__(self, data: bytes):
        h = etree.fromstring(data)
        self.fonts = {}
        for ff in h.iter("{%s}fontface" % HH):
            self.fonts[ff.get("lang")] = {f.get("id"): f.get("face") for f in ff.findall("hh:font", NS)}
        self.char = {}
        for cp in h.iter("{%s}charPr" % HH):
            fr = cp.find("hh:fontRef", NS)
            ul = cp.find("hh:underline", NS)
            self.char[cp.get("id")] = {
                "size": int(cp.get("height", "1000")) / 100.0, "color": cp.get("textColor", "#000000"),
                "hangul": self.fonts.get("HANGUL", {}).get(fr.get("hangul")) if fr is not None else None,
                "latin": self.fonts.get("LATIN", {}).get(fr.get("latin")) if fr is not None else None,
                "bold": cp.find("hh:bold", NS) is not None, "italic": cp.find("hh:italic", NS) is not None,
                "underline": ul is not None and ul.get("type", "NONE") != "NONE",
                "spacing": int((cp.find("hh:spacing", NS).get("hangul", 0)) if cp.find("hh:spacing", NS) is not None else 0),
                "ratio": int((cp.find("hh:ratio", NS).get("hangul", 100)) if cp.find("hh:ratio", NS) is not None else 100),
            }
        self.para = {}
        for pp in h.iter("{%s}paraPr" % HH):
            al = pp.find("hh:align", NS)
            blk = pp.find("hp:switch/hp:case", NS)
            if blk is None:
                blk = pp.find("hp:switch/hp:default", NS)
            mg = blk.find("hh:margin", NS) if blk is not None else pp.find("hh:margin", NS)
            ls = blk.find("hh:lineSpacing", NS) if blk is not None else pp.find("hh:lineSpacing", NS)
            g = lambda k: int(mg.find("hc:" + k, NS).get("value", 0)) if mg is not None and mg.find("hc:" + k, NS) is not None else 0
            self.para[pp.get("id")] = {"align": al.get("horizontal", "JUSTIFY") if al is not None else "JUSTIFY",
                                       "left": g("left"), "right": g("right"), "intent": g("intent"),
                                       "prev": g("prev"), "next": g("next"),
                                       "ls_type": ls.get("type") if ls is not None else "PERCENT",
                                       "ls": int(ls.get("value", 160)) if ls is not None else 160}
        self.border = {}
        for bf in h.iter("{%s}borderFill" % HH):
            sides = {}
            for k, dk in (("leftBorder", "left"), ("rightBorder", "right"), ("topBorder", "top"), ("bottomBorder", "bottom")):
                e = bf.find("hh:" + k, NS)
                if e is not None:
                    sides[dk] = (e.get("type", "NONE"), e.get("width", "0.12 mm"), e.get("color", "#000000"))
            wb = bf.find(".//hc:winBrush", NS)
            self.border[bf.get("id")] = {"sides": sides, "fill": wb.get("faceColor") if wb is not None else None}


def _border_sz(width: str) -> int:
    m = re.match(r"([\d.]+)\s*mm", width or "")
    mm = float(m.group(1)) if m else 0.12
    return max(2, int(round(mm / 25.4 * 72 * 8)))  # 1/8 pt


def hwpx_to_docx(hwpx: Path, out: Path) -> dict:
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Emu, Pt, RGBColor, Twips

    z = zipfile.ZipFile(hwpx)
    H = _Header(z.read("Contents/header.xml"))
    doc = Document()
    # 기본 스타일 여백 제거(한글 문단은 자체 여백 사용)
    st = doc.styles["Normal"]
    st.paragraph_format.space_after = Pt(0)
    st.paragraph_format.space_before = Pt(0)
    st.font.size = Pt(10)
    ALIGN = {"JUSTIFY": WD_ALIGN_PARAGRAPH.JUSTIFY, "CENTER": WD_ALIGN_PARAGRAPH.CENTER, "LEFT": WD_ALIGN_PARAGRAPH.LEFT,
             "RIGHT": WD_ALIGN_PARAGRAPH.RIGHT, "DISTRIBUTE": WD_ALIGN_PARAGRAPH.DISTRIBUTE}
    stats = {"paragraphs": 0, "tables": 0}
    first_section = True

    def _max_size(p) -> float:
        sizes = [H.char.get(r.get("charPrIDRef", "0"), {}).get("size", 10.0) for r in p.findall("hp:run", NS)]
        return max(sizes) if sizes else 10.0

    def apply_run(run, cp_id: str):
        c = H.char.get(cp_id) or {}
        run.font.size = Pt(c.get("size", 10))
        if c.get("bold"):
            run.font.bold = True
        if c.get("italic"):
            run.font.italic = True
        if c.get("underline"):
            run.font.underline = True
        col = (c.get("color") or "#000000").lstrip("#")
        if re.fullmatch(r"[0-9A-Fa-f]{6}", col):
            run.font.color.rgb = RGBColor.from_string(col.upper())
        latin, hangul = c.get("latin") or c.get("hangul"), c.get("hangul") or c.get("latin")
        if latin:
            run.font.name = latin
        rpr = run._element.get_or_add_rPr()
        rf = rpr.find(qn("w:rFonts"))
        if rf is None:
            rf = OxmlElement("w:rFonts"); rpr.insert(0, rf)
        if hangul:
            rf.set(qn("w:eastAsia"), hangul)
        if latin:
            rf.set(qn("w:ascii"), latin); rf.set(qn("w:hAnsi"), latin)
        # 자간(%)·장평(%) — HWPX 와 같은 모양으로(2026-10-15). OOXML rPr 순서: … color → spacing → w → … → sz
        sp_pct, ratio = int(c.get("spacing") or 0), int(c.get("ratio") or 100)
        anchor = rpr.find(qn("w:sz"))
        for tag, on, val in (("w:spacing", sp_pct != 0, str(round(sp_pct / 100 * c.get("size", 10) * 20))),
                             ("w:w", ratio != 100, str(ratio))):
            if not on or rpr.find(qn(tag)) is not None:
                continue
            el = OxmlElement(tag); el.set(qn("w:val"), val)
            (anchor.addprevious(el) if anchor is not None else rpr.append(el))

    def apply_para(dp, pp_id: str, max_size: float = 10.0):
        s = H.para.get(pp_id) or {}
        pf = dp.paragraph_format
        ppr = dp._p.get_or_add_pPr()
        for tag in ("w:autoSpaceDE", "w:autoSpaceDN"):  # 한글처럼 한/영·한/숫자 사이 자동 간격 없음
            e = OxmlElement(tag); e.set(qn("w:val"), "0"); ppr.append(e)
        pf.alignment = ALIGN.get(s.get("align", "JUSTIFY"), WD_ALIGN_PARAGRAPH.JUSTIFY)
        left, intent = s.get("left", 0), s.get("intent", 0)
        # 한글: 들여쓰기(intent) 음수 = 내어쓰기. Word: left_indent + first_line_indent
        if intent < 0:
            pf.left_indent = Twips(_hu_twips(left - intent))
            pf.first_line_indent = Twips(_hu_twips(intent))
        else:
            pf.left_indent = Twips(_hu_twips(left))
            pf.first_line_indent = Twips(_hu_twips(intent))
        if s.get("right"):
            pf.right_indent = Twips(_hu_twips(s["right"]))
        pf.space_before = Twips(_hu_twips(s.get("prev", 0)))
        pf.space_after = Twips(_hu_twips(s.get("next", 0)))
        if s.get("ls_type") == "PERCENT":
            pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY
            pf.line_spacing = Pt(max(6.0, max_size * s.get("ls", 160) / 100.0))
        elif s.get("ls_type") in ("FIXED", "BETWEEN_LINES"):
            pf.line_spacing_rule = WD_LINE_SPACING.EXACTLY if s["ls_type"] == "FIXED" else WD_LINE_SPACING.AT_LEAST
            pf.line_spacing = Pt(max(6, s.get("ls", 1600) / 100.0))

    def set_cell_borders(cell, bf_id: str):
        b = H.border.get(bf_id) or {}
        tcPr = cell._element.get_or_add_tcPr()
        borders = OxmlElement("w:tcBorders")
        for side in ("top", "left", "bottom", "right"):
            typ, width, color = b.get("sides", {}).get(side, ("NONE", "0.12 mm", "#000000"))
            e = OxmlElement(f"w:{side}")
            if typ == "NONE":
                e.set(qn("w:val"), "nil")
            else:
                e.set(qn("w:val"), {"SOLID": "single", "DOUBLE_SLIM": "double", "DASH": "dashed", "DOT": "dotted",
                                    "THICK": "single", "DOUBLE": "double"}.get(typ, "single"))
                e.set(qn("w:sz"), str(_border_sz(width) * (2 if typ == "THICK" else 1)))
                e.set(qn("w:space"), "0")
                e.set(qn("w:color"), (color or "#000000").lstrip("#"))
            borders.append(e)
        tcPr.append(borders)
        fill = b.get("fill")
        if fill and fill.lower() not in ("none", "#ffffff"):
            shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), fill.lstrip("#")); tcPr.append(shd)

    def emit_paragraph(container, p, in_cell=False):
        """hp:p → docx paragraph(s); 문단 안 표는 문단 뒤에 이어서 출력."""
        nonlocal first_section
        pending_tables = []
        dp = container.add_paragraph()
        apply_para(dp, p.get("paraPrIDRef", "0"), _max_size(p))
        has_text = False
        for run in p.findall("hp:run", NS):
            cp = run.get("charPrIDRef", "0")
            for el in run:
                tag = etree.QName(el).localname
                if tag == "t":
                    txt = el.text or ""
                    if txt:
                        r = dp.add_run(txt); apply_run(r, cp); has_text = True
                    for ch in el:
                        ctag = etree.QName(ch).localname
                        if ctag == "lineBreak":
                            r = dp.add_run(); r.add_break(); apply_run(r, cp)
                        elif ctag == "tab":
                            r = dp.add_run("\t"); apply_run(r, cp)
                        elif ctag in ("fwSpace", "nbSpace"):
                            r = dp.add_run(" "); apply_run(r, cp)
                        if ch.tail:
                            r = dp.add_run(ch.tail); apply_run(r, cp); has_text = True
                elif tag == "tbl":
                    pending_tables.append(el)
                elif tag == "ctrl" and el.find("hp:pageNum", NS) is not None and not stats.get("pagenum"):
                    stats["pagenum"] = True
                    pn = el.find("hp:pageNum", NS)
                    fp = doc.sections[0].footer.paragraphs[0]
                    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER if "CENTER" in (pn.get("pos") or "") else WD_ALIGN_PARAGRAPH.RIGHT
                    side = pn.get("sideChar") or ""
                    r0 = fp.add_run(f"{side} " if side else ""); r0.font.size = Pt(9)
                    for typ, txt in (("begin", None), (None, "PAGE"), ("end", None)):
                        r = fp.add_run(); r.font.size = Pt(9)
                        if typ:
                            fc = OxmlElement("w:fldChar"); fc.set(qn("w:fldCharType"), typ); r._element.append(fc)
                        else:
                            it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = " PAGE "; r._element.append(it)
                    r1 = fp.add_run(f" {side}" if side else ""); r1.font.size = Pt(9)
                elif tag == "secPr" and first_section:
                    first_section = False
                    pg = el.find(".//hp:pagePr", NS)
                    if pg is not None:
                        sec = doc.sections[0]
                        sec.page_width = Emu(_hu_emu(pg.get("width", 59528)))
                        sec.page_height = Emu(_hu_emu(pg.get("height", 84188)))
                        mg = pg.find("hp:margin", NS)
                        if mg is not None:
                            hd, ft = int(mg.get("header", 0)), int(mg.get("footer", 0))
                            sec.top_margin = Emu(_hu_emu(int(mg.get("top", 0)) + hd))
                            sec.bottom_margin = Emu(_hu_emu(int(mg.get("bottom", 0)) + ft))
                            sec.left_margin = Emu(_hu_emu(int(mg.get("left", 0)) + int(mg.get("gutter", 0))))
                            sec.right_margin = Emu(_hu_emu(mg.get("right", 0)))
                            sec.header_distance = Emu(_hu_emu(mg.get("top", 0)))
                            sec.footer_distance = Emu(_hu_emu(mg.get("bottom", 0)))
        if not has_text:
            # 빈 문단도 줄 높이는 서식 글자 크기를 따르도록 빈 run 에 크기 부여
            runs = p.findall("hp:run", NS)
            if runs:
                r = dp.add_run(""); apply_run(r, runs[0].get("charPrIDRef", "0"))
        stats["paragraphs"] += 1
        for tbl in pending_tables:
            emit_table(container, tbl, in_cell)

    def emit_table(container, tbl, in_cell=False):
        rows, cols = int(tbl.get("rowCnt", 1)), int(tbl.get("colCnt", 1))
        cells = []
        for tc in tbl.findall("hp:tr/hp:tc", NS):
            a, sp, sz = tc.find("hp:cellAddr", NS), tc.find("hp:cellSpan", NS), tc.find("hp:cellSz", NS)
            cells.append({"el": tc, "c": int(a.get("colAddr")), "r": int(a.get("rowAddr")),
                          "cs": int(sp.get("colSpan", 1)) if sp is not None else 1, "rs": int(sp.get("rowSpan", 1)) if sp is not None else 1,
                          "w": int(sz.get("width", 0)) if sz is not None else 0, "h": int(sz.get("height", 0)) if sz is not None else 0})
        # 열 폭: 단일 열 셀 우선, 나머지는 병합 셀 폭을 균등 분배
        colw = [0] * cols
        for c in cells:
            if c["cs"] == 1 and c["w"]:
                colw[c["c"]] = max(colw[c["c"]], c["w"])
        for c in sorted(cells, key=lambda x: x["cs"]):
            if c["cs"] > 1:
                span_cols = range(c["c"], c["c"] + c["cs"])
                known = sum(colw[i] for i in span_cols if colw[i])
                unknown = [i for i in span_cols if not colw[i]]
                if unknown:
                    each = max(1, (c["w"] - known) // len(unknown))
                    for i in unknown:
                        colw[i] = each
        total = sum(colw) or int(tbl.find("hp:sz", NS).get("width", 47000))
        t = container.add_table(rows=rows, cols=cols)
        t.autofit = False
        t.alignment = WD_TABLE_ALIGNMENT.LEFT
        tblPr = t._tbl.tblPr
        lay = OxmlElement("w:tblLayout"); lay.set(qn("w:type"), "fixed"); tblPr.append(lay)
        tw = tblPr.find(qn("w:tblW"))
        if tw is None:
            tw = OxmlElement("w:tblW"); tblPr.append(tw)
        tw.set(qn("w:w"), str(_hu_twips(total))); tw.set(qn("w:type"), "dxa")
        # 표 안쪽 여백(셀 기본 여백)
        im = tbl.find("hp:inMargin", NS)
        if im is not None:
            cm = OxmlElement("w:tblCellMar")
            for side in ("top", "left", "bottom", "right"):
                e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(_hu_twips(im.get(side, 0)))); e.set(qn("w:type"), "dxa"); cm.append(e)
            tblPr.append(cm)
        # 표 밖 여백(위/아래) → 앞 문단 간격 대신 표 뒤 빈 문단 없이 tblpPr 미사용; 단순화
        for i, w in enumerate(colw):
            for r in range(rows):
                t.cell(r, i).width = Twips(_hu_twips(w))
        rowh = [0] * rows
        for c in cells:
            if c["rs"] == 1 and c["h"]:
                rowh[c["r"]] = max(rowh[c["r"]], c["h"])
        for r in range(rows):
            if rowh[r]:
                t.rows[r].height = Twips(_hu_twips(rowh[r]))
        for c in cells:
            cell = t.cell(c["r"], c["c"])
            if c["cs"] > 1 or c["rs"] > 1:
                cell = cell.merge(t.cell(c["r"] + c["rs"] - 1, c["c"] + c["cs"] - 1))
            set_cell_borders(cell, c["el"].get("borderFillIDRef", "0"))
            sub = c["el"].find("hp:subList", NS)
            va = (sub.get("vertAlign", "TOP") if sub is not None else "TOP")
            from docx.enum.table import WD_ALIGN_VERTICAL
            cell.vertical_alignment = {"CENTER": WD_ALIGN_VERTICAL.CENTER, "BOTTOM": WD_ALIGN_VERTICAL.BOTTOM}.get(va, WD_ALIGN_VERTICAL.TOP)
            # 셀 기본 빈 문단 제거 후 서식 문단 출력
            first = True
            for p in (sub.findall("hp:p", NS) if sub is not None else []):
                if first:
                    dp = cell.paragraphs[0]
                    for r_ in list(dp.runs):
                        r_._element.getparent().remove(r_._element)
                    # emit into existing paragraph: 재사용을 위해 임시 컨테이너 대신 직접 처리
                    _emit_into(dp, p, cell)
                    first = False
                else:
                    emit_paragraph(cell, p, in_cell=True)
        stats["tables"] += 1

    def _emit_into(dp, p, cell):
        """셀의 첫 문단(이미 존재)에 hp:p 내용을 채운다."""
        apply_para(dp, p.get("paraPrIDRef", "0"), _max_size(p))
        has_text = False
        tables = []
        for run in p.findall("hp:run", NS):
            cp = run.get("charPrIDRef", "0")
            for el in run:
                tag = etree.QName(el).localname
                if tag == "t":
                    if el.text:
                        r = dp.add_run(el.text); apply_run(r, cp); has_text = True
                    for ch in el:
                        ctag = etree.QName(ch).localname
                        if ctag == "lineBreak":
                            r = dp.add_run(); r.add_break(); apply_run(r, cp)
                        elif ctag in ("fwSpace", "nbSpace", "tab"):
                            r = dp.add_run("\t" if ctag == "tab" else " "); apply_run(r, cp)
                        if ch.tail:
                            r = dp.add_run(ch.tail); apply_run(r, cp); has_text = True
                elif tag == "tbl":
                    tables.append(el)
        if not has_text:
            runs = p.findall("hp:run", NS)
            if runs:
                r = dp.add_run(""); apply_run(r, runs[0].get("charPrIDRef", "0"))
        stats["paragraphs"] += 1
        for tbl in tables:
            emit_table(cell, tbl, True)

    for name in sorted(n for n in z.namelist() if re.match(r"Contents/section\d+\.xml", n)):
        root = etree.fromstring(z.read(name))
        for p in root.findall("hp:p", NS):
            emit_paragraph(doc, p)
    # 문서 기본 문단(첫 빈 문단) 제거
    body = doc.element.body
    first_p = body.find(qn("w:p"))
    if first_p is not None and not first_p.findall(".//" + qn("w:t")) and len(doc.paragraphs) > 1:
        body.remove(first_p)
    doc.save(str(out))
    stats["docx"] = str(out)
    return stats


# ───────────────────────── 진입점 ─────────────────────────
# 19차(현장: 'A 사용자가 넣은 보고서 기본 정보가 모든 판정 리포트에 똑같이 들어간다'): 기본 정보가 report_profile.json 한 벌뿐이라
# 누가 어느 분석으로 만들어도 같은 값이 들어갔다. → 저장 자리를 셋으로 나눈다.
#   이 분석(profiles/inc-<분석 ID>.json)  >  내 기본값(profiles/u-<계정 해시>.json)  >  없음(빈칸 → [기재] 표시)
# 로그인 없는 PC 단독은 '내 기본값' = 예전 report_profile.json(한 사람이 쓰는 PC — 예전 동작 그대로).
# 계정 서버에서 예전 파일은 '공용 값(이전 판)' — 자동으로 넣지 않고 [불러오기]로만 가져온다.
_PROFILE_OVERRIDE: contextvars.ContextVar = contextvars.ContextVar("lt_profile_override", default=None)
PROFILE_DIR = "profiles"
_INC_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,95}")


def _legacy_profile(tdir: Path) -> dict:
    p = tdir / "report_profile.json"
    try:
        v = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}


def load_profile(tdir: Path) -> dict:
    """보고서를 채울 기본 정보. 화면 요청(계정·분석)에 맞춰 고른 값이 use_profile 로 걸려 있으면 그것, 아니면 예전 파일
    (자동화·명령줄 보고서는 예전 동작 그대로)."""
    ov = _PROFILE_OVERRIDE.get()
    if ov is not None:
        return dict(ov)
    return _legacy_profile(tdir)


class use_profile:
    """with use_profile(값): 이 안에서 만드는 보고서는 이 기본 정보를 쓴다(요청별 — 다른 사람 요청과 섞이지 않는다)."""

    def __init__(self, values: dict | None):
        self.values = dict(values or {})
        self.tok = None

    def __enter__(self):
        self.tok = _PROFILE_OVERRIDE.set(self.values)
        return self.values

    def __exit__(self, *exc):
        _PROFILE_OVERRIDE.reset(self.tok)
        return False


def clean_profile(profile: dict) -> dict:
    keys = {k for k, _ in PROFILE_FIELDS}
    return {k: norm(str(v))[:200] for k, v in (profile or {}).items() if k in keys and isinstance(v, (str, int, float))}


def _atomic_json(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(p)


def save_profile(tdir: Path, profile: dict) -> dict:
    """예전 한 벌 저장(PC 단독의 '내 기본값'·명령줄)."""
    clean = clean_profile(profile)
    _atomic_json(tdir / "report_profile.json", clean)
    return clean


def _user_key(login: str) -> str:
    import hashlib
    return "u-" + hashlib.sha256(("lt-profile:" + str(login).strip().lower()).encode("utf-8")).hexdigest()[:24]


def _profile_path(tdir: Path, scope: str, key: str) -> Path:
    if scope == "inc":
        if not _INC_ID_RE.fullmatch(str(key or "")):
            raise ValueError("분석 ID 형식이 맞지 않습니다")
        return tdir / PROFILE_DIR / f"inc-{key}.json"
    if scope == "user":
        if not str(key or "").strip():
            raise ValueError("계정이 없습니다")
        return tdir / PROFILE_DIR / f"{_user_key(key)}.json"
    raise ValueError("저장 자리는 inc / user 중 하나")


def profile_read(tdir: Path, scope: str, key: str) -> dict | None:
    """{'values','by','by_name','at'} 또는 None. 로그인 없는 '내 기본값'은 예전 파일."""
    if scope == "user" and not str(key or "").strip():
        v = _legacy_profile(tdir)
        return {"values": v, "by": "", "by_name": "", "at": None} if (tdir / "report_profile.json").exists() else None
    p = _profile_path(tdir, scope, key)
    try:
        d = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except Exception:
        return None
    if not isinstance(d, dict) or not isinstance(d.get("values"), dict):
        return None
    d["values"] = clean_profile(d["values"])
    return d


def profile_write(tdir: Path, scope: str, key: str, values: dict, by: str = "", by_name: str = "") -> dict:
    import time as _t
    clean = clean_profile(values)
    if scope == "user" and not str(key or "").strip():
        return {"values": save_profile(tdir, clean), "by": "", "by_name": "", "at": _t.time()}
    rec = {"values": clean, "by": str(by or "")[:120], "by_name": str(by_name or "")[:80], "at": _t.time()}
    if scope == "inc":
        rec["incident"] = key
    _atomic_json(_profile_path(tdir, scope, key), rec)
    return rec


def resolve_profile(tdir: Path, login: str, incident_id: str = "") -> tuple[dict, str, dict]:
    """보고서에 쓸 기본 정보 → (값, 출처, 메타). 출처: incident(이 분석) / mine(내 기본값) / none(없음 — 빈칸 표시)."""
    if incident_id and _INC_ID_RE.fullmatch(incident_id):
        d = profile_read(tdir, "inc", incident_id)
        if d is not None:
            return d["values"], "incident", {"by_name": d.get("by_name", ""), "by": d.get("by", ""), "at": d.get("at")}
    d = profile_read(tdir, "user", login)
    if d is not None:
        return d["values"], "mine", {"at": d.get("at")}
    return {}, "none", {}


def profile_delete(tdir: Path, incident_id: str) -> bool:
    """분석을 지울 때 그 분석에 저장한 기본 정보(담당자 연락처 등 개인정보)도 함께 지운다(GPT 119 P1-03)."""
    try:
        p = _profile_path(tdir, "inc", incident_id)
    except ValueError:
        return False
    if p.exists():
        p.unlink()
        return True
    return False


def profile_incidents(tdir: Path) -> list[dict]:
    """분석별로 저장된 기본 정보 목록(값 없이 누가·언제) — 화면 [불러오기] 후보. 서버가 볼 수 있는 분석만 거른다."""
    out = []
    d = tdir / PROFILE_DIR
    if not d.is_dir():
        return out
    for p in d.glob("inc-*.json"):
        iid = p.stem[4:]
        if not _INC_ID_RE.fullmatch(iid):
            continue
        r = profile_read(tdir, "inc", iid)
        if r is None:
            continue
        out.append({"id": iid, "by": r.get("by", ""), "by_name": r.get("by_name", ""), "at": r.get("at"),
                    "n": sum(1 for v in r["values"].values() if str(v).strip())})
    out.sort(key=lambda x: -(x["at"] or 0))
    return out[:200]


def style_info(tdir: Path) -> dict:
    """서식 학습 프로필 요약(문서 수·학습일·항목 수) — 내용 없음."""
    return StyleProfile.load(tdir).info()


_TODO_ORDER = ("복구 시각", "소요", "이용자", "수행 여부", "원인 확정", "이관 여부")


def summarize_todo(todo: list[dict]) -> list[dict]:
    """같은 기재 항목을 묶는다 — 한 번 정한 값(예: 복구 시각)을 여러 서식·칸에 넣으면 되게(2026-10-15 아이디어 4).
    여러 곳에 나오는 것, 그다음 장애 보고에서 늘 묻는 항목(복구 시각·소요·이용자 불편·수행 여부…) 순."""
    groups: dict[str, dict] = {}
    for t in todo:
        key = re.split(r"\s*[—(]", t.get("item", ""), maxsplit=1)[0].strip() or t.get("item", "")
        g = groups.setdefault(key, {"item": key, "count": 0, "forms": [], "wheres": [], "_spots": [], "each": False})
        g["count"] += 1
        if t.get("form") and t["form"] not in g["forms"]:
            g["forms"].append(t["form"])
        w = t.get("where", "")
        if w and w not in g["wheres"]:
            g["wheres"].append(w)
        spot = (t.get("form", ""), w)
        if spot in g["_spots"]:
            g["each"] = True   # 같은 서식·같은 항목 안에 여러 번 = 줄마다 다른 값(조치 시각·수행 여부 등) — 한 값으로 묶지 않는다(GPT 27차)
        g["_spots"].append(spot)
    for g in groups.values():
        g.pop("_spots")
    rank = lambda g: (-(g["count"] > 1 and not g["each"]), g["each"], next((i for i, k in enumerate(_TODO_ORDER) if k in g["item"]), 99), -g["count"], g["item"])
    return sorted(groups.values(), key=rank)


def write_todo(path: Path, inc_id: str, todo: list[dict], fitted: list | None = None) -> Path:
    """담당자 확인 목록 텍스트(서식 라벨·표시 문구만). 한글에서 '[기재' 검색으로 같은 자리를 찾는다.
    맨 위에 '한 번에 채울 항목'(같은 항목 묶음) 요약 — 아이디어 4."""
    lines = [f"LogTriage 보고서 확인 목록 — 분석 {inc_id} ({datetime.now():%Y-%m-%d %H:%M})",
             "한글에서 Ctrl+F → '[기재' 로 파란 표시를 찾아 채우거나 지운 뒤 제출하십시오.", ""]
    summ = summarize_todo(todo)
    if summ:
        lines.append(f"■ 같은 이름으로 묶은 항목 {len(summ)}가지 — 같은 값이면 한 번 정해 함께 넣고, '줄마다'는 줄마다 다른 값입니다")
        for g in summ:
            lines.append(f"  {g['item']} — {g['count']}곳" + (" · 줄마다 다른 값" if g["each"] else "")
                         + (f" ({'·'.join(g['forms'])})" if len(g["forms"]) > 1 else ""))
        lines.append("")
    cur = None
    for t in todo:
        if t["form"] != cur:
            cur = t["form"]
            lines.append(f"[{cur}]")
        lines.append(f"  · {t['where']} — {t['item']}")
    lines.append("")
    lines.append(f"총 {len(todo)}곳")
    if fitted:   # 3차 아이디어 12: 자동으로 바꾼 줄을 숨기지 않는다(항목과 끝 몇 글자만)
        lines += ["", f"■ 자동으로 다듬은 줄 {len(fitted)}개 — 실보고서 문장 끝에 맞춰 높임 끝맺음만 바꿨습니다",
                  "  원래대로 두려면 [보고서 기본 정보]의 '문장 끝 자동 다듬기'에 '끔'을 넣고 다시 만드십시오."]
        lines += [f"  · {x['label']}: {x['before']} → {x['after']}" for x in fitted]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def generate_forms(tdir: Path, inc: dict, out_dir: Path, values: dict | None = None) -> dict:
    tok = _VALUES.set(clean_values(values) or None)
    try:
        r = _generate_forms(tdir, inc, out_dir)
        r["values_used"] = sorted((_VALUES.get() or {}).keys())
        return r
    finally:
        _VALUES.reset(tok)


def _generate_forms(tdir: Path, inc: dict, out_dir: Path) -> dict:
    """서식 2종 HWPX 생성(DOCX 는 사용자 결정으로 제외 — 한글에서 열어 보완).
    반환: {files:[{form,title,hwpx,filled,todo_count}], todo:[...], todo_file, style:{...}, missing:[...]}"""
    profile = load_profile(tdir)
    sp = StyleProfile.load(tdir)
    sp.fit_on = option_on(profile, "fit_endings", True)
    out_dir.mkdir(parents=True, exist_ok=True)
    res: dict = {"files": [], "missing": [], "todo": [], "style": sp.info(), "fitted": sp.log}
    inc_id = inc.get("id", "INC")
    for f in FORMS:
        src = tdir / f["file"]
        if not src.exists():
            res["missing"].append(f["file"])
            continue
        hw = out_dir / f"{f['title']}_{inc_id}.hwpx"
        r = fill_hwpx(src, inc, profile, f["key"], hw, sp)
        res["files"].append({"form": f["key"], "title": f["title"], "hwpx": str(hw), "filled": r["filled"],
                             "todo_count": len(r["todo"])})
        res["todo"] += r["todo"]
    # 담당자가 등록한 사용자 서식 (report-template/custom/)
    try:
        from .report_custom import generate_custom
        for c in generate_custom(tdir, inc, profile, out_dir):
            if c.get("error"):
                res.setdefault("custom_errors", []).append(f"{c['title']}: {c['error']}")
            else:
                res["files"].append(c)
                res["todo"] += c.get("todo", [])
                res["fitted"] += c.get("fitted", [])
    except Exception as e:
        res.setdefault("custom_errors", []).append(str(e))
    if res["files"]:
        res["todo_file"] = str(write_todo(out_dir / f"확인목록_{inc_id}.txt", inc_id, res["todo"], res["fitted"]))
    return res
