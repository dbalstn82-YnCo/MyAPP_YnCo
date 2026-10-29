# -*- coding: utf-8 -*-
"""실제 작성된 장애 보고서(HWP/HWPX/DOCX)에서 '서식 통계'만 학습해 style_profile.json 을 만든다.

보안 원칙 (운영자 요구 — 위반 시 작업 중단):
  · 모든 처리는 이 PC 안에서만. 네트워크 사용 없음.
  · 문서의 제목·본문·파일명은 화면(stdout)에 절대 출력하지 않는다. 출력은 건수·통계·경로뿐이다.
  · 저장하는 것은 서식 통계뿐이다: 글꼴 이름·크기·굵기·색·정렬·줄간격·여백, 항목별 줄 수·글자 수·글머리 기호 종류,
    날짜/시간 표기 '형식' 분류, 항목별 기입률. 문장·단어·인명·기관명은 어떤 형태로도 저장하지 않는다.
  · 항목 키는 공식 서식(report-template/form_*.hwpx — 기관명 없는 배포 허용 서식)의 라벨만 쓴다.

사용:  python tools/report_style.py <보고서.zip 또는 폴더> [report-template 폴더] [출력 json]
      (GUI: 판정 리포트 → 보고서 기본 정보 → 서식 학습)
기본 출력: report-template/style_profile.json
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import statistics
import struct
import sys
import zipfile
import zlib
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

from lxml import etree

try:
    import olefile
except ImportError:  # pragma: no cover
    olefile = None

HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"
HH = "http://www.hancom.co.kr/hwpml/2011/head"
HC = "http://www.hancom.co.kr/hwpml/2011/core"
NS = {"hp": HP, "hh": HH, "hc": HC}
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_WS = re.compile(r"\s+")
# 표 구분자 — 예전엔 id(요소)를 써서 파이썬이 메모리를 재사용하면 다른 표가 한 표로 섞여 표 통계가 실행마다 달랐다(2026-10-15)
_TID = __import__("itertools").count(1)
_BULLET_H1 = "□■◆◇▣"
_BULLET_H2 = "○●◎◦"
_BULLET_NOTE = "※"
_BULLET_DASH = "-–—‐"
_BULLET_DOT = "·ㆍ•‧∙"
_BULLET_ARROW = "▶▷▸▹→➜"
_NUM = re.compile(r"^\s*(\d{1,2}[.)]|[①-⑳]|\(\d{1,2}\)|[가-힣][.)])\s")
_LABEL_CUT = re.compile(r"[:：(（#]")

# 날짜·시간 '형식' 분류 (값 자체는 저장하지 않는다)
DATE_PATTERNS = [
    ("’YY.M.D.(요일)", re.compile(r"[’'‘]\d{2}\.\s?\d{1,2}\.\s?\d{1,2}\.?\s?\([월화수목금토일]\)")),
    ("’YY.M.D.", re.compile(r"[’'‘]\d{2}\.\s?\d{1,2}\.\s?\d{1,2}\.?")),
    ("YYYY.M.D.(요일)", re.compile(r"\d{4}\.\s?\d{1,2}\.\s?\d{1,2}\.?\s?\([월화수목금토일]\)")),
    ("YYYY.M.D.", re.compile(r"\d{4}\.\s?\d{1,2}\.\s?\d{1,2}\.?")),
    ("YYYY-MM-DD", re.compile(r"\d{4}-\d{2}-\d{2}")),
    ("YY.M.D.", re.compile(r"(?<![\d.])\d{2}\.\s?\d{1,2}\.\s?\d{1,2}\.?")),
    ("M월 D일", re.compile(r"\d{1,2}\s?월\s?\d{1,2}\s?일")),
    ("M/D", re.compile(r"(?<!\d)\d{1,2}/\d{1,2}(?!\d)")),
]
TIME_PATTERNS = [
    ("HH:MM~HH:MM", re.compile(r"\d{1,2}:\d{2}\s?[~∼～-]\s?\d{1,2}:\d{2}")),
    ("HH:MM", re.compile(r"\d{1,2}:\d{2}")),
    ("HH시MM분", re.compile(r"\d{1,2}\s?시\s?\d{1,2}\s?분")),
    ("HH시", re.compile(r"\d{1,2}\s?시(?!\S*분)")),
]
DUR_PATTERN = re.compile(r"\(\s?(약\s?)?\d+\s?(분|시간|일)")


def norm(s: str) -> str:
    return _WS.sub(" ", s or "").strip()


def label_key(text: str) -> str:
    """'○ 장애시간 : …' → '장애시간' (라벨 골격만). 값 부분은 버린다."""
    t = norm(text)
    t = t.lstrip("".join(_BULLET_H1 + _BULLET_H2 + _BULLET_NOTE + _BULLET_DASH + _BULLET_DOT + _BULLET_ARROW) + " ")
    t = _LABEL_CUT.split(t, 1)[0]
    return norm(t)[:40]


def bullet_class(text: str) -> str:
    t = (text or "").lstrip()
    if not t:
        return "empty"
    c = t[0]
    if c in _BULLET_H1:
        return "h1"
    if c in _BULLET_H2:
        return "h2"
    if c in _BULLET_NOTE:
        return "note"
    if c in _BULLET_DASH:
        return "dash"
    if c in _BULLET_DOT:
        return "dot"
    if c in _BULLET_ARROW:
        return "arrow"
    if _NUM.match(t):
        return "number"
    return "none"


# ───────────────────────── 문서 모델 (메모리 안에서만) ─────────────────────────
# 문장 끝 유형(아이디어 10) — 통계는 유형 이름과 건수뿐(문장 없음)
_EUM = set("함됨음임짐림킴봄옴줌움냄씀춤핌")
_TAIL_PAREN = re.compile(r"\s*[(（][^()（）]*[)）]$")


def ending_class(text: str) -> str:
    """da = 서술형(…다) / eum = 명사형 어미(…함·…됨·…음) / noun = 명사로 끝(개조식, …완료·…조치) / other = 숫자·기호로 끝.
    '' = 셀 수 없음(빈 줄·담당자 기재 자리)."""
    t = norm(text).rstrip(" .。")
    for _ in range(4):   # 끝의 '(최초 이상) (2회, ~14:02)' 같은 덧붙임 괄호는 문장 끝이 아니다
        t2 = _TAIL_PAREN.sub("", t).rstrip(" .。")
        if t2 == t or not t2:
            break
        t = t2
    if not t or t.endswith("○") or t.endswith("]"):
        return ""
    ch = t[-1]
    if ch == "다":
        return "da"
    if ch in _EUM:
        return "eum"
    if "가" <= ch <= "힣":
        return "noun"
    return "other"


class Para:
    __slots__ = ("text", "runs", "para", "in_table", "table", "cell", "level")

    def __init__(self, text, runs, para, in_table=False, table=None, cell=None, level=0):
        self.text, self.runs, self.para = text, runs, para          # runs: [(text, charstyle dict)]
        self.in_table, self.table, self.cell, self.level = in_table, table, cell, level


def char_style(face=None, size=None, bold=False, italic=False, color="#000000", underline=False, spacing=0, ratio=100) -> dict:
    """spacing = 자간(%, 한글 기준 · 음수면 좁게), ratio = 장평(%) — 2026-10-15 마스터 요구 '폰트 간격' 학습."""
    return {"face": face, "size": size, "bold": bool(bold), "italic": bool(italic),
            "color": (color or "#000000").lower(), "underline": bool(underline),
            "spacing": int(spacing or 0), "ratio": int(ratio or 100)}


def para_style(align="JUSTIFY", left=0, intent=0, prev=0, nxt=0, ls_type="PERCENT", ls=160) -> dict:
    return {"align": align, "left": left, "intent": intent, "prev": prev, "next": nxt, "ls_type": ls_type, "ls": ls}


# ───────────────────────── HWPX ─────────────────────────
def _hwpx_header(data: bytes):
    h = etree.fromstring(data)
    fonts = {}
    for ff in h.iter("{%s}fontface" % HH):
        fonts[ff.get("lang")] = {f.get("id"): f.get("face") for f in ff.findall("hh:font", NS)}
    chars = {}
    for cp in h.iter("{%s}charPr" % HH):
        fr = cp.find("hh:fontRef", NS)
        ul = cp.find("hh:underline", NS)
        spc, rat = cp.find("hh:spacing", NS), cp.find("hh:ratio", NS)
        chars[cp.get("id")] = char_style(
            spacing=int(spc.get("hangul", 0)) if spc is not None else 0, ratio=int(rat.get("hangul", 100)) if rat is not None else 100,
            face=fonts.get("HANGUL", {}).get(fr.get("hangul")) if fr is not None else None,
            size=int(cp.get("height", "1000")) / 100.0, bold=cp.find("hh:bold", NS) is not None,
            italic=cp.find("hh:italic", NS) is not None, color=cp.get("textColor", "#000000"),
            underline=ul is not None and ul.get("type", "NONE") != "NONE")
    paras = {}
    for pp in h.iter("{%s}paraPr" % HH):
        al = pp.find("hh:align", NS)
        blk = pp.find("hp:switch/hp:case", NS)
        if blk is None:
            blk = pp.find("hp:switch/hp:default", NS)
        mg = blk.find("hh:margin", NS) if blk is not None else pp.find("hh:margin", NS)
        ls = blk.find("hh:lineSpacing", NS) if blk is not None else pp.find("hh:lineSpacing", NS)
        g = lambda k: int(mg.find("hc:" + k, NS).get("value", 0)) if mg is not None and mg.find("hc:" + k, NS) is not None else 0
        paras[pp.get("id")] = para_style(al.get("horizontal", "JUSTIFY") if al is not None else "JUSTIFY",
                                         g("left"), g("intent"), g("prev"), g("next"),
                                         ls.get("type") if ls is not None else "PERCENT",
                                         int(ls.get("value", 160)) if ls is not None else 160)
    return chars, paras


def _hwpx_paras(root, chars, paras, out: list, level=0, table=None, cell=None):
    for p in root.findall("hp:p", NS):
        runs = []
        for r in p.findall("hp:run", NS):
            cs = chars.get(r.get("charPrIDRef", "0"), char_style())
            txt = "".join("".join(t.itertext()) for t in r.findall("hp:t", NS))
            if txt:
                runs.append((txt, cs))
        text = norm("".join(t for t, _ in runs))
        out.append(Para(text, runs, paras.get(p.get("paraPrIDRef", "0"), para_style()), table is not None, table, cell, level))
        for r in p.findall("hp:run", NS):
            for ti, tbl in enumerate(r.findall("hp:tbl", NS)):
                tinfo = {"rows": int(tbl.get("rowCnt", 1)), "cols": int(tbl.get("colCnt", 1)), "id": next(_TID)}
                for tc in tbl.findall("hp:tr/hp:tc", NS):
                    a = tc.find("hp:cellAddr", NS)
                    sub = tc.find("hp:subList", NS)
                    cinfo = {"col": int(a.get("colAddr", 0)), "row": int(a.get("rowAddr", 0)), "bf": tc.get("borderFillIDRef")}
                    if sub is not None:
                        _hwpx_paras(sub, chars, paras, out, level + 1, tinfo, cinfo)


def parse_hwpx(data: bytes) -> list[Para] | None:
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    if "Contents/header.xml" not in names:
        return None
    chars, paras = _hwpx_header(z.read("Contents/header.xml"))
    out: list[Para] = []
    for n in sorted(x for x in names if re.match(r"Contents/section\d+\.xml", x)):
        _hwpx_paras(etree.fromstring(z.read(n)), chars, paras, out)
    return out


# ───────────────────────── HWP 5.0 (바이너리) ─────────────────────────
_TAG = 0x10
T_ID_MAPPINGS, T_FACE_NAME, T_CHAR_SHAPE, T_PARA_SHAPE = _TAG + 1, _TAG + 3, _TAG + 5, _TAG + 9
T_PARA_HEADER, T_PARA_TEXT, T_PARA_CHAR_SHAPE, T_CTRL_HEADER, T_LIST_HEADER, T_TABLE = _TAG + 50, _TAG + 51, _TAG + 52, _TAG + 55, _TAG + 56, _TAG + 61
_ALIGN = {0: "JUSTIFY", 1: "LEFT", 2: "RIGHT", 3: "CENTER", 4: "DISTRIBUTE", 5: "DISTRIBUTE_SPACE"}
_LS_TYPE = {0: "PERCENT", 1: "FIXED", 2: "BETWEEN_LINES", 3: "AT_LEAST"}
# 문단 텍스트 제어 문자: 1글자(2바이트) / 인라인·확장(8글자=16바이트)
_CTRL_ONE = {0, 10, 13, 24, 25, 26, 27, 28, 29, 30, 31}
_CTRL_EXT = {1, 2, 3, 11, 12, 14, 15, 16, 17, 18, 21, 22, 23}
_CTRL_INLINE = {4, 5, 6, 7, 8, 9, 19, 20}


def _records(buf: bytes):
    i, n = 0, len(buf)
    while i + 4 <= n:
        (h,) = struct.unpack_from("<I", buf, i)
        tag, level, size = h & 0x3FF, (h >> 10) & 0x3FF, (h >> 20) & 0xFFF
        i += 4
        if size == 0xFFF:
            (size,) = struct.unpack_from("<I", buf, i)
            i += 4
        yield tag, level, buf[i:i + size]
        i += size


def _stream(ole, name: str, compressed: bool) -> bytes:
    raw = ole.openstream(name).read()
    if not compressed:
        return raw
    try:
        return zlib.decompress(raw, -15)
    except zlib.error:
        return zlib.decompressobj(-15).decompress(raw)


def _colorref(v: int) -> str:
    return "#%02x%02x%02x" % (v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF)


def _hwp_text(raw: bytes) -> str:
    out = []
    i, n = 0, len(raw)
    while i + 2 <= n:
        (c,) = struct.unpack_from("<H", raw, i)
        if c < 32:
            if c in _CTRL_EXT or c in _CTRL_INLINE:
                out.append("\t" if c == 9 else "")
                i += 16
                continue
            out.append(" " if c in (10, 13) else "")
            i += 2
            continue
        out.append(chr(c))
        i += 2
    return "".join(out)


def parse_hwp(data: bytes) -> list[Para] | None | str:
    """반환: Para 목록 / None(파싱 불가) / 'encrypted'·'distribution'(암호·배포용 문서 — 건너뜀)"""
    if olefile is None:
        return None
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return None
    if not ole.exists("FileHeader") or not ole.exists("DocInfo"):
        return None
    fh = ole.openstream("FileHeader").read()
    flags = struct.unpack_from("<I", fh, 36)[0]
    compressed = bool(flags & 1)
    if flags & 2:
        return "encrypted"
    if flags & 4:
        return "distribution"
    # DocInfo: 글꼴·글자모양·문단모양
    faces_by_lang: list[list[str]] = []
    counts = None
    faces: list[str] = []
    chars: dict[int, dict] = {}
    paras: dict[int, dict] = {}
    for tag, level, body in _records(_stream(ole, "DocInfo", compressed)):
        if tag == T_ID_MAPPINGS:
            counts = list(struct.unpack_from("<" + "i" * (len(body) // 4), body))
        elif tag == T_FACE_NAME:
            attr = body[0]
            (ln,) = struct.unpack_from("<H", body, 1)
            faces.append(body[3:3 + ln * 2].decode("utf-16-le", errors="ignore"))
        elif tag == T_CHAR_SHAPE:
            fids = struct.unpack_from("<7H", body, 0)
            (base,) = struct.unpack_from("<i", body, 42)
            (attr,) = struct.unpack_from("<I", body, 46)
            (color,) = struct.unpack_from("<I", body, 52)
            # 5.0 CharShape: 글꼴 id WORD[7] · 장평 UINT8[7](14) · 자간 INT8[7](21) · 상대크기 · 위치 · 기준크기(42) · 속성(46) — 한글(첫 언어) 값
            ratio = body[14] if len(body) > 14 else 100
            (spacing,) = struct.unpack_from("<b", body, 21) if len(body) > 21 else (0,)
            chars[len(chars)] = {"fid": fids[0], "size": base / 100.0, "bold": bool(attr & 2), "italic": bool(attr & 1),
                                 "underline": ((attr >> 2) & 0xF) != 0, "color": _colorref(color),
                                 "spacing": int(spacing), "ratio": int(ratio) or 100}
        elif tag == T_PARA_SHAPE:
            (a1, left, right, intent, prev, nxt, ls_old) = struct.unpack_from("<Iiiiiii", body, 0)
            align = _ALIGN.get((a1 >> 2) & 7, "JUSTIFY")
            ls_type, ls = _LS_TYPE.get(a1 & 3, "PERCENT"), ls_old
            if len(body) >= 54:  # attr2(4) + attr3(4) + 줄간격(4) — 5.0.2.5 이상
                (a3,) = struct.unpack_from("<I", body, 46)
                (ls5,) = struct.unpack_from("<I", body, 50)
                ls_type, ls = _LS_TYPE.get(a3 & 0x1F, "PERCENT"), ls5
            # HWP 바이너리 여백은 HWPUNIT 의 2배 단위로 저장(관례) → HWPX 와 맞춘다
            paras[len(paras)] = para_style(align, left // 2, intent // 2, prev // 2, nxt // 2, ls_type, ls)
    # 글꼴 id → 이름: ID_MAPPINGS 의 언어별 글꼴 수(한글이 첫 번째 언어)
    n_hangul = counts[3] if counts and len(counts) > 3 else len(faces)  # [binData, hangul, latin, hanja, ...] 순서상 hangul=1
    # ID_MAPPINGS 순서: 바이너리데이터, 한글글꼴, 영어글꼴, 한자, 일어, 기타, 기호, 사용자, 테두리, 글자모양, 탭, 번호, 글머리, 문단모양, 스타일
    if counts and len(counts) > 1:
        n_hangul = counts[1]
    hangul_faces = faces[:n_hangul] if n_hangul else faces
    for c in chars.values():
        c["face"] = hangul_faces[c["fid"]] if c["fid"] < len(hangul_faces) else None
        c.pop("fid", None)
        c["color"] = c["color"].lower()
    # BodyText
    out: list[Para] = []
    sections = sorted(n for n in ("/".join(x) for x in ole.listdir()) if n.startswith("BodyText/Section"))
    for sec in sections:
        buf = _stream(ole, sec, compressed)
        pending = None      # (para_shape, char shape count)
        cur_runs: list = []
        cur_text = ""
        cur_para = None
        cur_level = 0
        cur_cs = []
        table_stack: list[dict] = []   # {level, info}
        cell_stack: list[dict] = []
        para_level = 0

        def flush():
            nonlocal cur_para
            if cur_para is None:
                return
            tbl = table_stack[-1]["info"] if table_stack else None
            cell = cell_stack[-1]["info"] if cell_stack else None
            # 글자모양 구간 → run 나누기
            runs = []
            if cur_cs:
                bounds = sorted(cur_cs) + [(len(cur_text), None)]
                for k in range(len(bounds) - 1):
                    s, cid = bounds[k]
                    e = bounds[k + 1][0]
                    seg = cur_text[s:e]
                    if seg:
                        runs.append((seg, chars.get(cid, char_style())))
            elif cur_text:
                runs.append((cur_text, char_style()))
            out.append(Para(norm(cur_text), runs, cur_para, tbl is not None, tbl, cell, para_level))
            cur_para = None

        for tag, level, body in _records(buf):
            # 표/셀 범위 종료 판단
            while table_stack and level <= table_stack[-1]["level"] and tag != T_TABLE and tag != T_LIST_HEADER:
                if tag == T_PARA_HEADER and level > table_stack[-1]["level"]:
                    break
                table_stack.pop()
                cell_stack = [c for c in cell_stack if table_stack and c["level"] > table_stack[-1]["level"]] if table_stack else []
            if tag == T_PARA_HEADER:
                flush()
                (ps_id,) = struct.unpack_from("<H", body, 8)
                (n_cs,) = struct.unpack_from("<H", body, 10)
                cur_para = paras.get(ps_id, para_style())
                cur_text, cur_cs, para_level = "", [], level
            elif tag == T_PARA_TEXT and cur_para is not None:
                cur_text = _hwp_text(body)
            elif tag == T_PARA_CHAR_SHAPE and cur_para is not None:
                cur_cs = [(struct.unpack_from("<I", body, k)[0], struct.unpack_from("<I", body, k + 4)[0]) for k in range(0, len(body) - 7, 8)]
                # 위치는 '글자 수' 기준(제어문자 포함) — 제어문자를 제거한 텍스트와 어긋날 수 있어 첫 run 스타일 위주로 쓴다
                cur_cs = [(min(pos, len(cur_text)), cid) for pos, cid in cur_cs]
            elif tag == T_CTRL_HEADER:
                if body[:4][::-1] == b"tbl ":
                    table_stack.append({"level": level, "info": {"rows": 0, "cols": 0, "id": len(out)}})
            elif tag == T_TABLE and table_stack:
                rows, cols = struct.unpack_from("<HH", body, 4)
                table_stack[-1]["info"].update(rows=rows, cols=cols)
            elif tag == T_LIST_HEADER and table_stack and len(body) >= 22:
                col, row, cs, rs = struct.unpack_from("<HHHH", body, 6)
                cell_stack = [c for c in cell_stack if c["level"] < level]
                bf = struct.unpack_from("<H", body, 30)[0] if len(body) >= 32 else None
                cell_stack.append({"level": level, "info": {"col": col, "row": row, "bf": bf}})
        flush()
    return out


# ───────────────────────── DOCX ─────────────────────────
def parse_docx(data: bytes) -> list[Para] | None:
    z = zipfile.ZipFile(io.BytesIO(data))
    if "word/document.xml" not in z.namelist():
        return None
    root = etree.fromstring(z.read("word/document.xml"))
    q = lambda t: "{%s}%s" % (W, t)
    out: list[Para] = []

    def walk(container, level=0, table=None, cell=None):
        for el in container:
            if el.tag == q("p"):
                runs = []
                for r in el.findall(q("r")):
                    rpr = r.find(q("rPr"))
                    sz = rpr.find(q("sz")) if rpr is not None else None
                    rf = rpr.find(q("rFonts")) if rpr is not None else None
                    col = rpr.find(q("color")) if rpr is not None else None
                    spc = rpr.find(q("spacing")) if rpr is not None else None     # 1/20pt — 글자 크기 대비 % 로
                    ww = rpr.find(q("w")) if rpr is not None else None            # 장평 %
                    txt = "".join(t.text or "" for t in r.findall(q("t")))
                    size_pt = int(sz.get(q("val"))) / 2 if sz is not None and sz.get(q("val")) else None
                    if txt:
                        runs.append((txt, char_style(
                            spacing=round(int(spc.get(q("val"))) / 20 / size_pt * 100) if spc is not None and size_pt and re.fullmatch(r"-?\d+", spc.get(q("val"), "")) else 0,
                            ratio=int(ww.get(q("val"))) if ww is not None and (ww.get(q("val")) or "").isdigit() else 100,
                            face=rf.get(q("eastAsia")) if rf is not None else None,
                            size=int(sz.get(q("val"))) / 2 if sz is not None and sz.get(q("val")) else None,
                            bold=rpr is not None and rpr.find(q("b")) is not None,
                            italic=rpr is not None and rpr.find(q("i")) is not None,
                            color="#" + col.get(q("val")) if col is not None and re.fullmatch(r"[0-9A-Fa-f]{6}", col.get(q("val"), "")) else "#000000",
                            underline=rpr is not None and rpr.find(q("u")) is not None)))
                ppr = el.find(q("pPr"))
                jc = ppr.find(q("jc")) if ppr is not None else None
                ps = para_style({"both": "JUSTIFY", "center": "CENTER", "right": "RIGHT", "left": "LEFT", "distribute": "DISTRIBUTE"}.get(
                    jc.get(q("val")) if jc is not None else "both", "JUSTIFY"))
                out.append(Para(norm("".join(t for t, _ in runs)), runs, ps, table is not None, table, cell, level))
            elif el.tag == q("tbl"):
                trs = el.findall(q("tr"))
                tinfo = {"rows": len(trs), "cols": max((len(tr.findall(q("tc"))) for tr in trs), default=0), "id": next(_TID)}
                for ri, tr in enumerate(trs):
                    for ci, tc in enumerate(tr.findall(q("tc"))):
                        walk(tc, level + 1, tinfo, {"col": ci, "row": ri, "bf": None})
            elif el.tag in (q("sdt"), q("sdtContent"), q("body")):
                walk(el, level, table, cell)
    walk(root.find(q("body")))
    return out


# ───────────────────────── 서식(공식) 라벨 ─────────────────────────
def form_labels(tdir: Path) -> dict:
    """공식 서식 2종에서 라벨 골격(본문 항목·표 라벨 칸)만 추출. 반환 {form_key: {"h1":[..], "h2":[..], "cells":[..], "title":..}}"""
    res = {}
    for key, fn in (("status", "form_status.hwpx"), ("postmortem", "form_postmortem.hwpx")):
        p = tdir / fn
        if not p.exists():
            continue
        paras = parse_hwpx(p.read_bytes()) or []
        h1, h2, cells = [], [], []
        for pa in paras:
            if not pa.text:
                continue
            bc = bullet_class(pa.text)
            if pa.in_table:
                k = label_key(pa.text)
                if k and len(k) <= 20 and bc in ("none",) and not re.search(r"\d{2}:\d{2}", pa.text):
                    cells.append(k)
            elif bc == "h1":
                h1.append(label_key(pa.text))
            elif bc == "h2":
                h2.append(label_key(pa.text))
        res[key] = {"h1": h1, "h2": h2, "cells": sorted(set(cells)), "n": len(paras)}
    return res


def classify(paras: list[Para], labels: dict) -> tuple[str, float]:
    texts = [norm(p.text) for p in paras if p.text]
    best, score = "other", 0.0
    for key, lb in labels.items():
        keys = [k for k in lb["h1"] + lb["h2"] if len(k) >= 2]
        if not keys:
            continue
        hit = sum(1 for k in keys if any(t.lstrip("".join(_BULLET_H1 + _BULLET_H2) + " ").startswith(k[:6]) for t in texts))
        s = hit / len(keys)
        if s > score:
            best, score = key, s
    return (best if score >= 0.35 else "other"), round(score, 2)


# ───────────────────────── 통계 누적 ─────────────────────────
class Agg:
    def __init__(self):
        self.style = defaultdict(Counter)     # role → Counter of style tuples
        self.pstyle = defaultdict(Counter)    # role → Counter of para style tuples
        self.field_lines = defaultdict(list)  # field → [line count per doc]
        self.field_chars = defaultdict(list)  # field → [chars per line]
        self.field_bullets = defaultdict(Counter)
        self.field_sub_bullets = defaultdict(Counter)
        self.field_style = defaultdict(Counter)
        self.field_filled = defaultdict(list)   # field → [0/1 per doc]
        self.field_dates = defaultdict(Counter)
        self.field_times = defaultdict(Counter)
        self.field_dur = defaultdict(list)
        self.field_endings = defaultdict(Counter)
        self.cell_endings = defaultdict(Counter)
        self.cell_lines = defaultdict(list)
        self.cell_chars = defaultdict(list)
        self.cell_style = defaultdict(Counter)
        self.cell_filled = defaultdict(list)
        self.table_rows = defaultdict(Counter)
        self.docs = Counter()
        self.skipped = Counter()
        self.sizes = Counter()

    @staticmethod
    def key(cs: dict) -> tuple:
        return (cs.get("face") or "?", cs.get("size") or 0, bool(cs.get("bold")), bool(cs.get("italic")), cs.get("color") or "#000000",
                int(cs.get("spacing") or 0), int(cs.get("ratio") or 100))

    @staticmethod
    def pkey(ps: dict) -> tuple:
        return (ps.get("align"), ps.get("ls_type"), ps.get("ls"), ps.get("left"), ps.get("intent"), ps.get("prev"), ps.get("next"))


def _first_style(pa: Para, skip_label=False) -> dict | None:
    runs = [r for r in pa.runs if norm(r[0])]
    if not runs:
        return None
    if skip_label and len(runs) >= 2:
        # '라벨 : 값' — 라벨 run 뒤의 값 run 스타일
        for k, (t, cs) in enumerate(runs):
            if ":" in t or "：" in t:
                after = t.split(":", 1)[-1].split("：", 1)[-1]
                if norm(after):
                    return cs
                return runs[k + 1][1] if k + 1 < len(runs) else cs
        return runs[1][1]
    return runs[0][1]


def _value_after_label(text: str) -> str:
    m = re.split(r"[:：]", text, maxsplit=1)
    return norm(m[1]) if len(m) > 1 else ""


def learn_doc(paras: list[Para], form: str, labels: dict, agg: Agg):
    lb = labels.get(form)
    if lb is None:  # 서식 판별이 안 된 문서 — 두 서식 라벨을 합쳐 항목 통계에만 참여
        lb = {"h1": sum((v["h1"] for v in labels.values()), []), "h2": sum((v["h2"] for v in labels.values()), []),
              "cells": sorted(set(sum((v["cells"] for v in labels.values()), [])))}
    h2keys = [k for k in lb["h2"] if k]
    cellkeys = set(lb["cells"])
    body = [p for p in paras if not p.in_table or p.cell is None]
    # 본문: 역할 분류 + 항목 연결
    cur_field = None
    field_lines: dict[str, list] = defaultdict(list)
    seen_fields: dict[str, bool] = {}   # 항목 → 값(인라인 또는 줄) 있음
    seen_title = False
    for pa in body:
        if not pa.text:
            continue
        bc = bullet_class(pa.text)
        cs = _first_style(pa)
        if bc == "h1":
            role, cur_field = "h1", None
        elif bc == "h2":
            role = "h2"
            k = label_key(pa.text)
            # 가장 길게 맞는 칸 이름 — 예전엔 앞 6글자만 보고 처음 맞는 것을 골라 '장애 근본원인 조치 여부' 줄이
            # '장애 근본원인' 에 합쳐 세어졌다(2026-10-15 적합도 실증에서 발견)
            cands = [f for f in h2keys if k.startswith(f[:6]) or f.startswith(k[:6])] if k else []
            exact = [f for f in cands if k == f or k.startswith(f) or f.startswith(k)]
            cur_field = max(exact or cands, key=lambda f: (k.startswith(f) or f.startswith(k), len(f) if k.startswith(f) else -len(f)), default=None)
            if cur_field:
                v = _value_after_label(pa.text)
                seen_fields[cur_field] = seen_fields.get(cur_field, False) or bool(v)
                if v:
                    vcs = _first_style(pa, skip_label=True)
                    if vcs:
                        agg.field_style[cur_field][agg.key(vcs)] += 1
                    agg.field_chars[cur_field].append(len(v))
                    e = ending_class(v)
                    if e:
                        agg.field_endings[cur_field][e] += 1
                    for name, rx in DATE_PATTERNS:
                        if rx.search(v):
                            agg.field_dates[cur_field][name] += 1
                            break
                    for name, rx in TIME_PATTERNS:
                        if rx.search(v):
                            agg.field_times[cur_field][name] += 1
                            break
                    if DUR_PATTERN.search(v):
                        agg.field_dur[cur_field].append(1)
        elif bc == "note":
            role = "note"
        elif bc in ("dash", "dot", "arrow", "number"):
            role = "bullet_" + bc
            if cur_field:
                line = pa.text.lstrip("".join(_BULLET_DASH + _BULLET_DOT + _BULLET_ARROW) + " ")
                if line and line not in ("", "-"):
                    field_lines[cur_field].append((bc, len(line), cs, pa.para))
                    e = ending_class(line)
                    if e:
                        agg.field_endings[cur_field][e] += 1
                    for name, rx in DATE_PATTERNS:
                        if rx.search(line):
                            agg.field_dates[cur_field][name] += 1
                            break
                    for name, rx in TIME_PATTERNS:
                        if rx.search(line):
                            agg.field_times[cur_field][name] += 1
                            break
        else:
            if not seen_title and "보고서" in pa.text and cs and (cs.get("size") or 0) >= 14:
                role, seen_title = "title", True
            else:
                role = "body"
                if cur_field:
                    field_lines[cur_field].append(("none", len(pa.text), cs, pa.para))
                    e = ending_class(pa.text)
                    if e:
                        agg.field_endings[cur_field][e] += 1
        if cs:
            agg.style[role][agg.key(cs)] += 1
        agg.pstyle[role][agg.pkey(pa.para)] += 1
    for f, lines in field_lines.items():
        agg.field_lines[f].append(len(lines))
        seen_fields[f] = True
        top = [l for l in lines if l[0] in ("dash", "number", "none")]
        sub = [l for l in lines if l[0] in ("dot", "arrow")]
        for bc, n, cs, ps in lines:
            agg.field_chars[f].append(n)
            if cs:
                agg.field_style[f][agg.key(cs)] += 1
        for bc, *_ in top:
            agg.field_bullets[f][bc] += 1
        for bc, *_ in sub:
            agg.field_sub_bullets[f][bc] += 1
    for f, ok in seen_fields.items():
        agg.field_filled[f].append(1 if ok else 0)
    # 표: 라벨 칸 ↔ 값 칸
    tables: dict = defaultdict(list)
    for pa in paras:
        if pa.in_table and pa.table is not None and pa.cell is not None:
            tables[pa.table["id"]].append(pa)
    for tid, tps in tables.items():
        t = tps[0].table
        cells: dict = defaultdict(list)
        for pa in tps:
            cells[(pa.cell["row"], pa.cell["col"])].append(pa)
        agg.table_rows[f"{t['cols']}col"][t["rows"]] += 1
        label_at = {}
        for (r, c), ps in cells.items():
            txt = norm(" ".join(p.text for p in ps))
            k = label_key(txt)
            if k in cellkeys:
                label_at[(r, c)] = k
                cs = _first_style(ps[0])
                if cs:
                    agg.style["cell_label"][agg.key(cs)] += 1
                    agg.pstyle["cell_label"][agg.pkey(ps[0].para)] += 1
        for (r, c), ps in cells.items():
            if (r, c) in label_at:
                continue
            # 같은 행 왼쪽의 가장 가까운 라벨, 없으면 같은 열 위쪽 라벨
            key = None
            for cc in range(c - 1, -1, -1):
                if (r, cc) in label_at:
                    key = label_at[(r, cc)]
                    break
            if key is None:
                for rr in range(r - 1, -1, -1):
                    if (rr, c) in label_at:
                        key = label_at[(rr, c)]
                        break
            if key is None:
                continue
            lines = [p for p in ps if p.text and p.text != "-"]
            agg.cell_filled[key].append(1 if lines else 0)
            if lines:
                agg.cell_lines[key].append(len(lines))
                for p in lines:
                    agg.cell_chars[key].append(len(p.text))
                    e = ending_class(p.text)
                    if e:
                        agg.cell_endings[key][e] += 1
                    cs = _first_style(p)
                    if cs:
                        agg.cell_style[key][agg.key(cs)] += 1
                        agg.style["cell_value"][agg.key(cs)] += 1
                        agg.pstyle["cell_value"][agg.pkey(p.para)] += 1
                    for name, rx in DATE_PATTERNS:
                        if rx.search(p.text):
                            agg.field_dates[key][name] += 1
                            break
                    for name, rx in TIME_PATTERNS:
                        if rx.search(p.text):
                            agg.field_times[key][name] += 1
                            break


# ───────────────────────── 요약 ─────────────────────────
def _style_summary(cnt: Counter) -> dict | None:
    if not cnt:
        return None
    total = sum(cnt.values())
    # 최빈 모양·비율은 예전처럼 (글꼴·크기·굵기·기울임·색)으로 정한다 — 자간·장평까지 열쇠에 넣으면 비율이 쪼개져
    # '40% 이상일 때만 적용' 기준에서 예전에 적용되던 글꼴·크기까지 빠진다. 자간·장평은 그 최빈 모양 안에서 따로 고른다.
    main = Counter()
    for key, k in cnt.items():
        main[key[:5]] += k
    (face, size, bold, italic, color), n = main.most_common(1)[0]
    inner = Counter()
    faces, sizes, spacings, ratios = Counter(), Counter(), Counter(), Counter()
    for key, k in cnt.items():
        f, s, b, i, c = key[:5]
        sp, ra = (key[5], key[6]) if len(key) >= 7 else (0, 100)
        faces[f] += k
        sizes[s] += k
        spacings[sp] += k
        ratios[ra] += k
        if key[:5] == (face, size, bold, italic, color):
            inner[(sp, ra)] += k
    spacing, ratio = inner.most_common(1)[0][0] if inner else (0, 100)
    # 자간·장평이 얼마나 한결같은가 — 적용 기준(GPT 21차: 표본 5+, 최빈 60%+, 2위와 20%p+)에 쓴다
    top2 = [k for _, k in inner.most_common(2)] + [0, 0]
    sr_share = round(top2[0] / n, 2) if n else 0
    sr_margin = round((top2[0] - top2[1]) / n, 2) if n else 0
    return {"face": face, "size": size, "bold": bold, "italic": italic, "color": color, "spacing": spacing, "ratio": ratio,
            "sr_share": sr_share, "sr_margin": sr_margin,
            "share": round(n / total, 2), "n": total,
            "faces": dict(faces.most_common(4)), "sizes": {str(k): v for k, v in sizes.most_common(5)},
            "spacings": {str(k): v for k, v in spacings.most_common(4)}, "ratios": {str(k): v for k, v in ratios.most_common(4)}}


def _pstyle_summary(cnt: Counter) -> dict | None:
    if not cnt:
        return None
    (align, ls_type, ls, left, intent, prev, nxt), n = cnt.most_common(1)[0]
    return {"align": align, "ls_type": ls_type, "ls": ls, "left": left, "intent": intent, "prev": prev, "next": nxt,
            "share": round(n / sum(cnt.values()), 2)}


def _num_summary(vals: list) -> dict | None:
    if not vals:
        return None
    v = sorted(vals)
    q = lambda p: v[min(len(v) - 1, int(round((len(v) - 1) * p)))]
    return {"n": len(v), "min": v[0], "p25": q(0.25), "median": statistics.median(v), "p75": q(0.75), "max": v[-1]}


def summarize(agg: Agg, labels: dict) -> dict:
    prof = {"generated": date.today().isoformat(), "docs": dict(agg.docs), "skipped": dict(agg.skipped),
            "roles": {}, "fields": {}, "cells": {}, "tables": {}}
    for role in sorted(set(agg.style) | set(agg.pstyle)):
        prof["roles"][role] = {"char": _style_summary(agg.style.get(role, Counter())), "para": _pstyle_summary(agg.pstyle.get(role, Counter()))}
    fields = set(agg.field_lines) | set(agg.field_filled) | set(agg.field_style) | set(agg.field_endings)
    for f in sorted(fields):
        filled = agg.field_filled.get(f, [])
        prof["fields"][f] = {
            "fill_rate": round(sum(filled) / len(filled), 2) if filled else None,
            "lines": _num_summary(agg.field_lines.get(f, [])),
            "chars": _num_summary(agg.field_chars.get(f, [])),
            "bullet": dict(agg.field_bullets.get(f, Counter()).most_common()),
            "sub_bullet": dict(agg.field_sub_bullets.get(f, Counter()).most_common()),
            "char": _style_summary(agg.field_style.get(f, Counter())),
            "date": dict(agg.field_dates.get(f, Counter()).most_common(3)),
            "time": dict(agg.field_times.get(f, Counter()).most_common(3)),
            "duration_paren": len(agg.field_dur.get(f, [])),
            "ending": dict(agg.field_endings.get(f, Counter()).most_common()),
        }
    for k in sorted(set(agg.cell_lines) | set(agg.cell_filled)):
        filled = agg.cell_filled.get(k, [])
        prof["cells"][k] = {
            "fill_rate": round(sum(filled) / len(filled), 2) if filled else None,
            "lines": _num_summary(agg.cell_lines.get(k, [])),
            "chars": _num_summary(agg.cell_chars.get(k, [])),
            "char": _style_summary(agg.cell_style.get(k, Counter())),
            "date": dict(agg.field_dates.get(k, Counter()).most_common(3)),
            "time": dict(agg.field_times.get(k, Counter()).most_common(3)),
            "ending": dict(agg.cell_endings.get(k, Counter()).most_common()),
        }
    for k, cnt in agg.table_rows.items():
        prof["tables"][k] = {str(r): n for r, n in sorted(cnt.items())}
    prof["form_labels"] = {k: {"h1": v["h1"], "h2": v["h2"], "cells": v["cells"]} for k, v in labels.items()}
    return prof


def _forbidden_check(prof: dict, labels: dict) -> list[str]:
    """프로필에 서식 라벨·글꼴 이름 외의 긴 한글 문자열이 들어갔는지 검사(문장 유출 방지)."""
    allowed = {n for n, _ in DATE_PATTERNS} | {n for n, _ in TIME_PATTERNS}
    for v in labels.values():
        allowed.update(v["h1"] + v["h2"] + v["cells"])
    bad = []

    def walk(o, path=""):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(k, str) and re.search(r"[가-힣]", k) and len(k) > 12 and k not in allowed:
                    bad.append(f"{path}/<키 {len(k)}자>")   # 내용은 출력하지 않는다
                walk(v, path + "/" + (str(k) if not (isinstance(k, str) and re.search(r"[가-힣]", k) and k not in allowed) else "<키>"))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str) and re.search(r"[가-힣]", o) and len(o) > 12 and o not in allowed:
            bad.append(f"{path}/<값 {len(o)}자>")
    walk(prof)
    return bad


# ───────────────────────── 입력 순회 ─────────────────────────
def iter_docs(src: Path):
    """zip(중첩 zip 포함) 또는 폴더 → (확장자, bytes). 파일명은 반환하지 않는다."""
    def from_zip(data: bytes, depth=0):
        try:
            z = zipfile.ZipFile(io.BytesIO(data))
        except Exception:
            return
        for i in z.infolist():
            if i.is_dir():
                continue
            ext = Path(i.filename).suffix.lower()
            if ext == ".zip" and depth < 2:
                yield from from_zip(z.read(i), depth + 1)
            elif ext in (".hwp", ".hwpx", ".docx"):
                yield ext, z.read(i)
    if src.is_dir():
        for p in sorted(src.rglob("*")):
            if p.suffix.lower() in (".hwp", ".hwpx", ".docx"):
                yield p.suffix.lower(), p.read_bytes()
            elif p.suffix.lower() == ".zip":
                yield from from_zip(p.read_bytes())
    else:
        yield from from_zip(src.read_bytes())


BY_FORM_MIN_DOCS = 5
CEIL_MIN_DOCS = 10   # 이보다 적으면 상한을 재지 않는다(반으로 나누면 비교가 무의미)


# ───────────────────────── 적합도 비교(생성·실보고서 공통) ─────────────────────────
def ok_style(gen: dict, ref: dict) -> tuple:
    g, r = (gen or {}).get("char") or {}, (ref or {}).get("char") or {}
    if not r or r.get("n", 0) < 3 or r.get("share", 0) < 0.4 or not g:
        return None, "-"
    same = (g.get("face"), g.get("size"), bool(g.get("bold"))) == (r.get("face"), r.get("size"), bool(r.get("bold")))
    sr = (g.get("spacing", 0), g.get("ratio", 100)) == (r.get("spacing", 0), r.get("ratio", 100))
    return same and sr, f"생성 {g.get('face')}/{g.get('size')}/{'굵게' if g.get('bold') else '보통'}/자간{g.get('spacing')}/장평{g.get('ratio')}" \
                        f" · 실보고서 {r.get('face')}/{r.get('size')}/{'굵게' if r.get('bold') else '보통'}/자간{r.get('spacing')}/장평{r.get('ratio')}"


def ok_range(gen: dict, ref: dict, key: str) -> tuple:
    g, r = (gen or {}).get(key) or {}, (ref or {}).get(key) or {}
    if not r or not g or r.get("n", 0) < 3:
        return None, "-"
    gm = g.get("median")
    return r["min"] <= gm <= r["max"], f"생성 {gm} · 실보고서 {r['min']}~{r['max']}(중앙 {r['median']})"


def ok_top(gen: dict, ref: dict, key: str) -> tuple:
    g, r = (gen or {}).get(key) or {}, (ref or {}).get(key) or {}
    g = {k: v for k, v in g.items() if k != "none"}
    r = {k: v for k, v in r.items() if k != "none"}
    if not r or not g:
        return None, "-"
    gt, rt = max(g, key=g.get), max(r, key=r.get)
    return gt == rt, f"생성 {gt} · 실보고서 {rt}"


CHECKS_KO = ("모양", "줄 수", "줄당 글자", "날짜 형식", "문장 끝", "글머리")


def compare(gen_prof: dict, sp, ref_prof: dict):
    """생성(또는 나눔 한쪽) 통계 ↔ 기준 통계 — (검사 이름, 칸, 맞음 여부, 설명) 를 낸다. sp = StyleProfile(서식별 기준 포함)."""
    for sec in ("fields", "cells"):
        for k, gv in (gen_prof.get(sec) or {}).items():
            if k not in (ref_prof.get(sec) or {}):
                continue
            r = sp.field(k) if sec == "fields" else sp.cell(k)
            checks = [("모양", ok_style(gv, r)), ("줄 수", ok_range(gv, r, "lines")), ("줄당 글자", ok_range(gv, r, "chars")),
                      ("날짜 형식", ok_top(gv, r, "date")), ("문장 끝", ok_top(gv, r, "ending"))]
            if sec == "fields":
                checks.append(("글머리", ok_top(gv, r, "bullet")))
            for name, (ok, why) in checks:
                if ok is not None:
                    yield name, k, ok, why


_MARK_FILL = re.compile(r"\[기재:[^\]]*\]")


def conform(hwpx_paths: list, tdir: Path) -> dict | None:
    """3차 아이디어 7: 생성 보고서(공식 서식) 적합도 — 학습 상한과 같은 검사로 잰 비율. [기재] 자리는 담당자가 채울 값이라 5글자로 바꿔 잰다.
    프로필이 없으면 None. 돌려주는 것은 검사 이름·비율·건수와 '상한보다 크게 낮은' 칸 이름(서식 라벨)뿐."""
    from .report_forms import StyleProfile
    p = Path(tdir) / "style_profile.json"
    if not p.exists():
        return None
    prof = json.loads(p.read_text(encoding="utf-8"))
    labels = form_labels(Path(tdir))
    tot, low = Counter(), Counter()
    for h in hwpx_paths:
        try:
            paras = parse_hwpx(Path(h).read_bytes()) or []
        except Exception:   # noqa: BLE001
            continue
        for pa in paras:
            pa.text = _MARK_FILL.sub("○○○○○", pa.text)
            pa.runs = [(_MARK_FILL.sub("○○○○○", t), cs) for t, cs in pa.runs]
        form, _ = classify(paras, labels)
        a = Agg()
        learn_doc(paras, form, labels, a)
        for name, k, ok, _w in compare(summarize(a, labels), StyleProfile(prof).for_form(form), prof):
            tot[(name, ok)] += 1
            if not ok:
                low[k] += 1
    checks = {}
    for name in CHECKS_KO:
        y, no = tot[(name, True)], tot[(name, False)]
        if y + no:
            checks[name] = {"ratio": round(y / (y + no), 2), "n": y + no}
    ceil = (prof.get("ceiling") or {}).get("checks") or {}
    gaps = [{"check": n, "gen": v["ratio"], "ceiling": ceil[n]["ratio"]} for n, v in checks.items()
            if n in ceil and ceil[n]["ratio"] - v["ratio"] >= 0.15]      # 상한보다 15%p 이상 낮은 검사만 '개선 후보'
    allok, alln = sum(v for (n, ok), v in tot.items() if ok), sum(tot.values())
    return {"overall": round(allok / alln, 2) if alln else None, "checks": checks, "gaps": gaps,
            "ceiling_overall": (prof.get("ceiling") or {}).get("overall"), "weak_fields": [k for k, _ in low.most_common(5)]}


def _shingles(paras) -> set:
    t = "".join("".join(p.text.split()) for p in paras if p.text)
    return {t[i:i + 5] for i in range(0, max(0, len(t) - 4))}


def similar_groups(docs_paras: list) -> list:
    """글 5글자 조각 겹침(Jaccard) 0.5 이상끼리 한 묶음 — 같은 장애의 종료·사후 보고처럼 닮은 문서를 나눔 양쪽에 갈라 넣지 않게(GPT 27차)."""
    sh = [_shingles(p) for p in docs_paras]
    par = list(range(len(sh)))

    def f(x):
        while par[x] != x:
            par[x] = par[par[x]]
            x = par[x]
        return x
    for i in range(len(sh)):
        for j in range(i + 1, len(sh)):
            a, b = sh[i], sh[j]
            if a and b and len(a & b) / len(a | b) >= 0.5:
                par[f(i)] = f(j)
    out: dict = {}
    for i in range(len(sh)):
        out.setdefault(f(i), []).append(i)
    return list(out.values())


def ceiling(docs: list, labels: dict) -> dict | None:
    """나눔 검증 상한(아이디어 7): 비슷한 문서 묶음 단위로 반씩 나눠 한쪽으로 배우고 다른 쪽 실보고서를 잰다(두 번 교차).
    '실보고서끼리도 이만큼만 같다' — 생성 보고서 적합도를 읽는 기준. docs = [(form, paras, sha)]. 비율만 돌려준다."""
    from .report_forms import StyleProfile
    if len(docs) < CEIL_MIN_DOCS:
        return None
    groups = similar_groups([d[1] for d in docs])
    side, n = [0] * len(docs), [0, 0]
    for g in sorted(groups, key=lambda g: (-len(g), min(docs[i][2] for i in g))):
        k = 0 if n[0] <= n[1] else 1
        for i in g:
            side[i] = k
        n[k] += len(g)
    tot = Counter()
    for train in (0, 1):
        agg, per = Agg(), {k: Agg() for k in labels}
        for i, (form, paras, _) in enumerate(docs):
            if side[i] == train:
                agg.docs[form] += 1
                learn_doc(paras, form, labels, agg)
                if form in per:
                    per[form].docs[form] += 1
                    learn_doc(paras, form, labels, per[form])
        prof = summarize(agg, labels)
        prof["by_form"] = {k: summarize(a, labels) for k, a in per.items() if sum(a.docs.values()) >= BY_FORM_MIN_DOCS}
        for i, (form, paras, _) in enumerate(docs):
            if side[i] == train:
                continue
            a = Agg()
            learn_doc(paras, form, labels, a)
            for name, _k, ok, _w in compare(summarize(a, labels), StyleProfile(prof).for_form(form), prof):
                tot[(name, ok)] += 1
    out = {}
    for name in CHECKS_KO:
        y, no = tot[(name, True)], tot[(name, False)]
        if y + no:
            out[name] = {"ratio": round(y / (y + no), 2), "n": y + no}
    allok, alln = sum(v for (nm, ok), v in tot.items() if ok), sum(tot.values())
    return {"overall": round(allok / alln, 2) if alln else None, "checks": out, "docs": len(docs), "groups": len(groups)}


def learn(src: Path, tdir: Path, out: Path | None = None) -> dict:
    """실 보고서(zip/폴더) → 서식 통계 프로필 저장. 반환은 건수·경로만(문서 내용 없음)."""
    src, tdir = Path(src), Path(tdir)
    out = Path(out) if out else tdir / "style_profile.json"
    if not src.exists():
        raise FileNotFoundError(f"입력이 없습니다: {src}")
    labels = form_labels(tdir)
    if not labels:
        raise FileNotFoundError(f"공식 서식(form_status.hwpx/form_postmortem.hwpx)이 없습니다: {tdir}")
    agg = Agg()
    kept = []                           # 아이디어 7: 나눔 상한 계산용(메모리 안에서만 — 저장하지 않는다)
    per = {k: Agg() for k in labels}   # 아이디어 2: 서식별 통계 — 상황관리 보고서와 사후관리 보고서의 글자 모양·줄 수가 다르면 따로 쓴다
    n = 0
    for ext, data in iter_docs(src):
        n += 1
        try:
            if ext == ".hwpx":
                paras = parse_hwpx(data)
            elif ext == ".hwp":
                paras = parse_hwp(data)
            else:
                paras = parse_docx(data)
        except Exception:
            paras = None
        if isinstance(paras, str):
            agg.skipped[f"{ext}:{paras}"] += 1
            continue
        if not paras:
            agg.skipped[f"{ext}:parse_fail"] += 1
            continue
        form, score = classify(paras, labels)
        kept.append((form, paras, hashlib.sha256(data).hexdigest()))
        agg.docs[form] += 1
        agg.sizes[ext] += 1
        learn_doc(paras, form, labels, agg)
        if form in per:
            per[form].docs[form] += 1
            learn_doc(paras, form, labels, per[form])
    if n == 0:
        raise ValueError("HWP/HWPX/DOCX 문서를 찾지 못했습니다")
    prof = summarize(agg, labels)
    prof["input_files"] = n
    prof["by_ext"] = dict(agg.sizes)
    prof["by_form"] = {}
    for k, a in per.items():
        if sum(a.docs.values()) >= BY_FORM_MIN_DOCS:   # 문서가 적으면 서식별로 나누지 않는다(전체 통계로 충분)
            sub = summarize(a, labels)
            prof["by_form"][k] = {x: sub[x] for x in ("docs", "roles", "fields", "cells", "tables")}
    try:
        prof["ceiling"] = ceiling(kept, labels)   # 비율·건수만
    except Exception:
        prof["ceiling"] = None
    kept.clear()
    bad = _forbidden_check(prof, labels)
    if bad:
        raise ValueError(f"프로필에 서식 라벨 외 문자열이 섞여 저장하지 않았습니다({len(bad)}곳)")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(prof, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"input_files": n, "docs": dict(agg.docs), "skipped": dict(agg.skipped), "roles": len(prof["roles"]),
            "fields": len(prof["fields"]), "cells": len(prof["cells"]), "profile": str(out), "generated": prof["generated"],
            "by_form": {k: sum(v["docs"].values()) for k, v in prof["by_form"].items()},
            "ceiling": prof.get("ceiling")}


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1])
    tdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(__file__).resolve().parents[1] / "report-template"
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else tdir / "style_profile.json"
    try:
        r = learn(src, tdir, out)
    except Exception as e:
        print("중단:", e)
        return 1
    print(f"입력 문서 {r['input_files']}건 · 분류 {r['docs']} · 건너뜀 {r['skipped']}")
    print(f"역할 {r['roles']}종 · 항목 {r['fields']}개 · 표 칸 {r['cells']}개 · 서식별 {r['by_form']} → {r['profile']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
