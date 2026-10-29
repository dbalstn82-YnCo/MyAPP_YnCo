"""운영 보고서·정기 상태 점검 결과 출력기(r4) — 하나의 자료 모델을 HTML · PDF · HWPX(한글) 로 만든다.

자료 모델(doc)
  {"title": "정기 운영 보고서", "subtitle": "2026-09-18 00:00 ~ 2026-09-18 17:00", "site": "본사",
   "meta": [("생성", "2026-09-18 17:00"), ...],
   "kpis": [("분석", "12건", "ok|warn|crit|mute"), ...],
   "sections": [{"title": "장비 상태", "note": "…", "cols": [("장비", 3, "L"), ("상태", 1, "C")],
                 "rows": [["web01", "정상"], ...], "tones": ["", "crit", ...], "empty": "없음"}],
   "footer": "…"}

· PDF: 표준 라이브러리만으로 만든다. 한글은 PDF 표준 한국어 CID 글꼴(HYGoThic-Medium, UniKS-UCS2-H)을 참조만 하고 파일에
  넣지 않는다 — 한글 글꼴이 있는 PC(Windows 맑은 고딕 등)의 PDF 보기 프로그램이 대체 글꼴로 그린다. 파일이 작고 외부 연결 없이도 만들 수 있다.
· HWPX: 제품에 들어 있는 보고서 양식(report-template/form_status.hwpx)의 쪽 설정·글꼴 표를 바탕으로 제목·요약·표를 새로 쓴다.
  한글 2014 이상(HWPX)에서 바로 열어 편집·제출할 수 있다. lxml 이 없으면 HWPX 는 건너뛴다.
"""
from __future__ import annotations

import copy
import html
import io
import re
import time
import zipfile
import zlib
from pathlib import Path

FORMATS = ("html", "pdf", "hwpx")
# 라틴 글자 폭(Helvetica 기준, 1/1000 em) — 대체 글꼴로 그려도 자간이 자연스럽도록 CID 폭 표(W)와 줄바꿈 계산에 함께 쓴다
_LATIN_W = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + [
    278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
    611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833,
    556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
TONE_RGB = {"crit": (0.776, 0.157, 0.157), "warn": (0.698, 0.416, 0.0), "ok": (0.118, 0.490, 0.294), "mute": (0.357, 0.420, 0.478), "": (0.1, 0.145, 0.19)}
TONE_HEX = {"crit": "#C62828", "warn": "#B26A00", "ok": "#1E7D4B", "mute": "#5B6B7A", "": "#1A2530"}


def _s(v) -> str:
    return "" if v is None else str(v)


# ── HTML ─────────────────────────────────────────────────────────────────
_CSS = """
*{box-sizing:border-box}body{margin:0;background:#F4F7F9;color:#1A2530;font:14px/1.6 "Malgun Gothic","Segoe UI",sans-serif}
.wrap{max-width:1120px;margin:0 auto;padding:28px 24px 40px}
.head{background:linear-gradient(135deg,#0B6E8A 0%,#0E7490 45%,#4F46E5 100%);color:#fff;border-radius:16px;padding:24px 28px;box-shadow:0 14px 34px rgba(14,116,144,.22)}
.head small{opacity:.85;letter-spacing:.08em;font-size:11.5px}.head h1{margin:4px 0 2px;font-size:24px}.head .sub{opacity:.92}
.meta{display:flex;flex-wrap:wrap;gap:8px 18px;margin-top:12px;font-size:12.5px;opacity:.95}.meta b{font-weight:700;margin-right:4px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.kpi{background:#fff;border:1px solid #DFE6EB;border-radius:12px;padding:12px 14px;position:relative;overflow:hidden}
.kpi::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--t,#0E7490)}
.kpi span{display:block;font-size:11.5px;color:#5B6B7A}.kpi b{font-size:20px;font-variant-numeric:tabular-nums}
.kpi.crit{--t:#C62828}.kpi.warn{--t:#B26A00}.kpi.ok{--t:#1E7D4B}.kpi.mute{--t:#9AA9B5}
.sec{background:#fff;border:1px solid #DFE6EB;border-radius:12px;margin:0 0 16px;overflow:hidden}
.sec h2{margin:0;padding:12px 16px;font-size:15px;border-bottom:1px solid #DFE6EB;display:flex;gap:10px;align-items:center}
.sec h2::before{content:"";width:4px;height:16px;border-radius:2px;background:#0E7490}
.sec .note{padding:10px 16px 0;color:#5B6B7A;font-size:12.5px}
table{width:100%;border-collapse:collapse;font-size:12.5px}th{background:#EEF5F8;color:#3E5566;text-align:left;font-weight:700;padding:8px 10px;border-bottom:1px solid #DFE6EB;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid #EEF1F4;vertical-align:top}tr:nth-child(even) td{background:#FAFCFD}
td.C,th.C{text-align:center}td.R,th.R{text-align:right;font-variant-numeric:tabular-nums}
tr.crit td{color:#B42318}tr.warn td{color:#8A5300}tr.ok td{color:#1E7D4B}
.empty{padding:16px;color:#5B6B7A}.foot{margin-top:18px;color:#5B6B7A;font-size:11.5px;text-align:center}
@media print{body{background:#fff}.wrap{padding:0}.head{box-shadow:none}.sec,.kpi{break-inside:avoid}}
"""


def render_html(doc: dict) -> str:
    e = html.escape
    out = [f'<!doctype html><html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           f'<title>{e(doc["title"])}</title><style>{_CSS}</style></head><body><div class="wrap">',
           f'<div class="head"><small>LOGTRIAGE · {e(_s(doc.get("site")))}</small><h1>{e(doc["title"])}</h1><div class="sub">{e(_s(doc.get("subtitle")))}</div>',
           '<div class="meta">' + "".join(f"<span><b>{e(k)}</b>{e(_s(v))}</span>" for k, v in doc.get("meta", [])) + "</div></div>"]
    if doc.get("kpis"):
        out.append('<div class="kpis">' + "".join(f'<div class="kpi {e(t)}"><span>{e(k)}</span><b>{e(_s(v))}</b></div>' for k, v, t in doc["kpis"]) + "</div>")
    for sec in doc.get("sections", []):
        out.append(f'<div class="sec"><h2>{e(sec["title"])}</h2>')
        if sec.get("note"):
            out.append(f'<div class="note">{e(sec["note"])}</div>')
        rows = sec.get("rows") or []
        if not rows:
            out.append(f'<div class="empty">{e(sec.get("empty") or "해당 없음")}</div></div>')
            continue
        cols = sec["cols"]
        tones = sec.get("tones") or [""] * len(rows)
        out.append('<div style="overflow-x:auto"><table><thead><tr>' + "".join(f'<th class="{a}">{e(c)}</th>' for c, _, a in cols) + "</tr></thead><tbody>")
        for r, t in zip(rows, tones):
            out.append(f'<tr class="{e(t or "")}">' + "".join(f'<td class="{cols[i][2]}">{e(_s(v))}</td>' for i, v in enumerate(r)) + "</tr>")
        out.append("</tbody></table></div></div>")
    out.append(f'<div class="foot">{e(_s(doc.get("footer")))}</div></div></body></html>')
    return "".join(out)


# ── PDF(표준 라이브러리, 한국어 CID 글꼴 참조) ───────────────────────────────
class _Pdf:
    W, H, M = 595.28, 841.89, 40.0

    def __init__(self, title: str):
        self.title = title
        self.pages: list[list[str]] = []
        self.y = 0.0
        self.new_page()

    @staticmethod
    def width(s: str, size: float) -> float:
        return sum((_LATIN_W[ord(c) - 32] / 1000 if 32 <= ord(c) < 127 else (0.5 if ord(c) < 0x80 else 1.0)) for c in s) * size

    def new_page(self):
        self.ops = []
        self.pages.append(self.ops)
        self.y = self.H - self.M

    def ensure(self, h: float) -> bool:
        if self.y - h < self.M + 24:
            self.new_page()
            return True
        return False

    def text(self, x, y, s, size, rgb=(0.1, 0.145, 0.19), bold=False):
        s = s.replace("·", "ㆍ").replace("•", "ㆍ")   # U+00B7 은 한국어 CID 표(UniKS-UCS2)에 없어 빠진다
        hx = "".join(f"{ord(c):04X}" for c in s if 0x20 <= ord(c) < 0x10000 and not 0xD800 <= ord(c) < 0xE000)
        if not hx:
            return
        r, g, b = rgb
        mode = f"2 Tr {size * 0.035:.2f} w {r:.3f} {g:.3f} {b:.3f} RG " if bold else "0 Tr "
        self.ops.append(f"BT /F1 {size:.1f} Tf {mode}{r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} Td <{hx}> Tj ET")

    def rect(self, x, y, w, h, fill=None, stroke=None, lw=0.6):
        s = ""
        if fill:
            s += f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg "
        if stroke:
            s += f"{lw:.2f} w {stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG "
        op = "B" if fill and stroke else ("f" if fill else "S")
        self.ops.append(f"{s}{x:.2f} {y:.2f} {w:.2f} {h:.2f} re {op}")

    def line(self, x1, y1, x2, y2, rgb=(0.79, 0.84, 0.87), lw=0.5):
        self.ops.append(f"{lw:.2f} w {rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} RG {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def wrap(self, s: str, size: float, maxw: float, max_lines: int = 8) -> list[str]:
        lines = []
        for para in _s(s).replace("\r", "").split("\n"):
            cur, cw = "", 0.0
            for word in re.split(r"(\s+)", para):
                ww = self.width(word, size)
                if cw + ww <= maxw:
                    cur += word; cw += ww
                    continue
                if cur.strip():
                    lines.append(cur.rstrip())
                cur, cw = "", 0.0
                word = word.lstrip()
                for ch in word:   # 긴 낱말(경로·해시)은 글자 단위로 끊는다
                    w = self.width(ch, size)
                    if cw + w > maxw and cur:
                        lines.append(cur); cur, cw = "", 0.0
                    cur += ch; cw += w
            lines.append(cur.rstrip())
        lines = [x for x in lines] or [""]
        if len(lines) > max_lines:
            lines = lines[:max_lines]; lines[-1] = lines[-1][:max(0, len(lines[-1]) - 2)] + "…"
        return lines

    def save(self) -> bytes:
        n = len(self.pages)
        for i, ops in enumerate(self.pages, 1):   # 쪽 번호
            ops.append("")
            self.ops = ops
            self.line(self.M, self.M - 2, self.W - self.M, self.M - 2)
            self.text(self.M, self.M - 14, f"LogTriage · {self.title}", 7.5, TONE_RGB["mute"])
            t = f"{i} / {n}"
            self.text(self.W - self.M - self.width(t, 7.5), self.M - 14, t, 7.5, TONE_RGB["mute"])
        objs: list[bytes] = []

        def add(b: bytes) -> int:
            objs.append(b); return len(objs)
        font_desc = add(b"<< /Type /FontDescriptor /FontName /HYGoThic-Medium /Flags 6 /FontBBox [-6 -145 1003 880] /ItalicAngle 0 "
                        b"/Ascent 880 /Descent -120 /CapHeight 880 /StemV 59 >>")
        widths = " ".join(str(w) for w in _LATIN_W)
        cid = add(("<< /Type /Font /Subtype /CIDFontType0 /BaseFont /HYGoThic-Medium /CIDSystemInfo << /Registry (Adobe) /Ordering (Korea1) "
                   f"/Supplement 1 >> /FontDescriptor {font_desc} 0 R /DW 1000 /W [1 [{widths}]] >>").encode())
        font = add(f"<< /Type /Font /Subtype /Type0 /BaseFont /HYGoThic-Medium /Encoding /UniKS-UCS2-H /DescendantFonts [{cid} 0 R] >>".encode())
        pages_id = len(objs) + 1 + 2 * n   # 예약: 각 쪽 내용·쪽 객체 뒤
        page_ids = []
        for ops in self.pages:
            data = zlib.compress("\n".join(ops).encode("latin-1"))
            c = add(f"<< /Length {len(data)} /Filter /FlateDecode >>\nstream\n".encode() + data + b"\nendstream")
            page_ids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.W:.2f} {self.H:.2f}] "
                                f"/Resources << /Font << /F1 {font} 0 R >> >> /Contents {c} 0 R >>".encode()))
        assert add(("<< /Type /Pages /Kids [" + " ".join(f"{p} 0 R" for p in page_ids) + f"] /Count {n} >>").encode()) == pages_id
        info = add(b"<< /Producer (LogTriage) /Title <FEFF" + "".join(f"{ord(c):04X}" for c in self.title if ord(c) < 0x10000).encode() + b"> >>")
        cat = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())
        out = io.BytesIO()
        out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offs = []
        for i, b in enumerate(objs, 1):
            offs.append(out.tell())
            out.write(f"{i} 0 obj\n".encode() + b + b"\nendobj\n")
        x = out.tell()
        out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
        for o in offs:
            out.write(f"{o:010d} 00000 n \n".encode())
        out.write(f"trailer\n<< /Size {len(objs) + 1} /Root {cat} 0 R /Info {info} 0 R >>\nstartxref\n{x}\n%%EOF\n".encode())
        return out.getvalue()


def render_pdf(doc: dict) -> bytes:
    p = _Pdf(doc["title"])
    M, W = p.M, p.W - 2 * p.M
    teal, ink, mute = (0.055, 0.455, 0.565), TONE_RGB[""], TONE_RGB["mute"]
    # 머리 띠
    a, b = (0.043, 0.431, 0.541), (0.31, 0.275, 0.898)   # 청록 → 인디고 그라데이션(띠 60개)
    for i in range(60):
        t = i / 59
        p.rect(M + W * i / 60, p.y - 74, W / 60 + 0.6, 74, fill=tuple(a[k] + (b[k] - a[k]) * t ** 1.6 for k in range(3)))
    p.text(M + 16, p.y - 18, f"LOGTRIAGE · {_s(doc.get('site'))}", 8, (0.85, 0.95, 0.97))
    p.text(M + 16, p.y - 40, doc["title"], 18, (1, 1, 1), bold=True)
    p.text(M + 16, p.y - 58, _s(doc.get("subtitle")), 9.5, (0.92, 0.97, 0.98))
    p.y -= 86
    meta = "   ".join(f"{k} {_s(v)}" for k, v in doc.get("meta", []))
    for ln in p.wrap(meta, 8.5, W):
        p.text(M, p.y, ln, 8.5, mute); p.y -= 12
    p.y -= 4
    kp = doc.get("kpis") or []
    if kp:
        per = len(kp) if len(kp) <= 5 else 4; bw = (W - (per - 1) * 8) / per
        for i in range(0, len(kp), per):
            p.ensure(46)
            for j, (k, v, t) in enumerate(kp[i:i + per]):
                x = M + j * (bw + 8)
                p.rect(x, p.y - 40, bw, 40, fill=(1, 1, 1), stroke=(0.87, 0.9, 0.92))
                p.rect(x, p.y - 40, 3, 40, fill=TONE_RGB.get(t, teal) if t else teal)
                p.text(x + 10, p.y - 14, k, 8, mute)
                p.text(x + 10, p.y - 32, _s(v), 13, ink, bold=True)
            p.y -= 50
    for sec in doc.get("sections", []):
        p.ensure(60)
        p.y -= 6
        p.rect(M, p.y - 13, 3, 14, fill=teal)
        p.text(M + 9, p.y - 11, sec["title"], 11.5, ink, bold=True)
        p.y -= 22
        if sec.get("note"):
            for ln in p.wrap(sec["note"], 8.5, W):
                p.ensure(12); p.text(M, p.y, ln, 8.5, mute); p.y -= 12
            p.y -= 2
        rows = sec.get("rows") or []
        if not rows:
            p.ensure(16); p.text(M + 4, p.y - 8, sec.get("empty") or "해당 없음", 9, mute); p.y -= 20
            continue
        cols = sec["cols"]
        tot = sum(c[1] for c in cols)
        cw = [W * c[1] / tot for c in cols]
        fs, pad, lh = 8.2, 4.0, 10.5

        def header():
            h = 18
            p.rect(M, p.y - h, W, h, fill=(0.933, 0.961, 0.973))
            x = M
            for (name, _, al), w in zip(cols, cw):
                tw = p.width(name, 8)
                tx = x + pad if al == "L" else (x + w - pad - tw if al == "R" else x + (w - tw) / 2)
                p.text(tx, p.y - 12.5, name, 8, (0.243, 0.333, 0.4), bold=True)
                x += w
            p.line(M, p.y - h, M + W, p.y - h, (0.8, 0.85, 0.88), 0.7)
            p.y -= h
        header()
        tones = sec.get("tones") or [""] * len(rows)
        for ri, (r, t) in enumerate(zip(rows, tones)):
            cells = [p.wrap(_s(v), fs, w - 2 * pad, 6) for v, w in zip(r, cw)]
            h = max(len(c) for c in cells) * lh + 2 * pad - 1
            if p.ensure(h + 2):
                header()
            if ri % 2:
                p.rect(M, p.y - h, W, h, fill=(0.98, 0.988, 0.992))
            x = M
            for (name, _, al), w, lines in zip(cols, cw, cells):
                for li, ln in enumerate(lines):
                    tw = p.width(ln, fs)
                    tx = x + pad if al == "L" else (x + w - pad - tw if al == "R" else x + (w - tw) / 2)
                    p.text(tx, p.y - pad - fs - li * lh + 1, ln, fs, TONE_RGB.get(t or "", ink))
                x += w
            p.y -= h
            p.line(M, p.y, M + W, p.y, (0.9, 0.92, 0.94), 0.4)
        p.y -= 10
    if doc.get("footer"):
        p.y -= 8
        for ln in p.wrap(doc["footer"], 8, W):
            p.ensure(12); p.text(M, p.y, ln, 8, mute); p.y -= 11
    return p.save()


# ── HWPX(한글) ───────────────────────────────────────────────────────────
def render_hwpx(doc: dict, template: Path) -> bytes:
    from lxml import etree
    from .report_forms import HP, NS, HeaderCtx
    HHn = NS["hh"]
    zin = zipfile.ZipFile(template)
    header = etree.fromstring(zin.read("Contents/header.xml"))
    sec = etree.fromstring(zin.read("Contents/section0.xml"))
    ctx = HeaderCtx(header)
    face = "맑은 고딕"
    cp = lambda size, bold=False, color="#1A2530": ctx.styled("0", face, size, bold, color, False)

    # 표 테두리: 얇은 실선(본문) · 머리 칸 채움
    bfs = header.find(".//hh:borderFills", NS)
    base_bf = next(b for b in bfs.findall("hh:borderFill", NS) if b.get("id") == "8")

    def add_bf(fill: str | None) -> str:
        nb = copy.deepcopy(base_bf)
        for side in ("leftBorder", "rightBorder", "topBorder", "bottomBorder"):
            el = nb.find(f"hh:{side}", NS)
            el.set("type", "SOLID"); el.set("width", "0.12 mm"); el.set("color", "#9FB3C0")
        for fb in nb.findall("{%s}fillBrush" % NS["hc"]):
            nb.remove(fb)
        if fill:
            fb = etree.SubElement(nb, "{%s}fillBrush" % NS["hc"])
            etree.SubElement(fb, "{%s}winBrush" % NS["hc"], faceColor=fill, hatchColor=fill, alpha="0")
        nid = str(max(int(b.get("id")) for b in bfs.findall("hh:borderFill", NS)) + 1)
        nb.set("id", nid)
        bfs.append(nb)
        bfs.set("itemCnt", str(len(bfs.findall("hh:borderFill", NS))))
        return nid
    bf_cell, bf_head, bf_kpi = add_bf(None), add_bf("#E6F2F6"), add_bf("#F3F7FA")
    bf_band = add_bf("#0E7490")
    band = next(b for b in bfs.findall("hh:borderFill", NS) if b.get("id") == bf_band)
    for side in ("leftBorder", "rightBorder", "topBorder", "bottomBorder"):
        el = band.find(f"hh:{side}", NS); el.set("type", "NONE"); el.set("width", "0.1 mm")

    # 문단 모양: 양식의 기본 문단(20: 왼쪽·줄 간격 100%)을 복제해 가운데·오른쪽 정렬을 만든다 — 한 표 안에서 줄 높이가 같아야 칸이 가지런하다
    pps = header.find(".//hh:paraProperties", NS)
    base_pp = next(x for x in pps.findall("hh:paraPr", NS) if x.get("id") == "20")

    def add_pp(align: str, prev: int = 0, nxt: int = 0, spacing: int = 100) -> str:
        np_ = copy.deepcopy(base_pp)
        np_.find("hh:align", NS).set("horizontal", align)
        for m in np_.iter("{%s}prev" % NS["hc"]):
            m.set("value", str(prev))
        for m in np_.iter("{%s}next" % NS["hc"]):
            m.set("value", str(nxt))
        for ls in np_.iter("{%s}lineSpacing" % HHn):
            ls.set("value", str(spacing))
        nid = str(max(int(x.get("id")) for x in pps.findall("hh:paraPr", NS)) + 1)
        np_.set("id", nid)
        pps.append(np_)
        pps.set("itemCnt", str(len(pps.findall("hh:paraPr", NS))))
        return nid
    PP_L, PP_C, PP_R = add_pp("LEFT", 0, 0, 115), add_pp("CENTER", 0, 0, 115), add_pp("RIGHT", 0, 0, 115)
    PP_H = add_pp("LEFT", 900, 200, 130)     # 절 제목
    PP_N = add_pp("LEFT", 0, 100, 130)       # 설명 문장

    first = sec.find("hp:p", NS)
    for p in sec.findall("hp:p", NS)[1:]:
        sec.remove(p)
    runs = first.findall("hp:run", NS)
    for r in runs[1:]:
        first.remove(r)
    for ch in list(runs[0]):
        if etree.QName(ch).localname not in ("secPr", "ctrl"):
            runs[0].remove(ch)
    for ls in first.findall("hp:linesegarray", NS):
        first.remove(ls)
    pid = [3000000000]

    def para(parts, pp="20"):
        pid[0] += 1
        p = etree.SubElement(sec, f"{{{HP}}}p", id=str(pid[0]), paraPrIDRef=pp, styleIDRef="0", pageBreak="0", columnBreak="0", merged="0")
        for text, cid in parts:
            r = etree.SubElement(p, f"{{{HP}}}run", charPrIDRef=cid)
            t = etree.SubElement(r, f"{{{HP}}}t"); t.text = text
        return p

    def cell_para(parent, text, cid, pp):
        pid[0] += 1
        p = etree.SubElement(parent, f"{{{HP}}}p", id=str(pid[0]), paraPrIDRef=pp, styleIDRef="0", pageBreak="0", columnBreak="0", merged="0")
        r = etree.SubElement(p, f"{{{HP}}}run", charPrIDRef=cid)
        t = etree.SubElement(r, f"{{{HP}}}t"); t.text = text

    def table(cols, rows, tones, head=True, bf_body=None, size=9.5):
        TW = 47600
        tot = sum(c[1] for c in cols)
        widths = [int(TW * c[1] / tot) for c in cols]
        widths[-1] += TW - sum(widths)
        p = para([], "20")
        run = etree.SubElement(p, f"{{{HP}}}run", charPrIDRef=cp(size))
        all_rows = ([[c[0] for c in cols]] if head else []) + rows
        rh = 1700
        pid[0] += 1
        tbl = etree.SubElement(run, f"{{{HP}}}tbl", id=str(pid[0]), zOrder="0", numberingType="TABLE", textWrap="TOP_AND_BOTTOM", textFlow="BOTH_SIDES",
                               lock="0", dropcapstyle="None", pageBreak="CELL", repeatHeader="1" if head else "0", rowCnt=str(len(all_rows)),
                               colCnt=str(len(cols)), cellSpacing="0", borderFillIDRef=bf_cell, noAdjust="0")
        etree.SubElement(tbl, f"{{{HP}}}sz", width=str(TW), widthRelTo="ABSOLUTE", height=str(rh * len(all_rows)), heightRelTo="ABSOLUTE", protect="0")
        etree.SubElement(tbl, f"{{{HP}}}pos", treatAsChar="1", affectLSpacing="0", flowWithText="1", allowOverlap="0", holdAnchorAndSO="0",
                         vertRelTo="PARA", horzRelTo="PARA", vertAlign="TOP", horzAlign="LEFT", vertOffset="0", horzOffset="0")
        etree.SubElement(tbl, f"{{{HP}}}outMargin", left="0", right="0", top="140", bottom="140")
        etree.SubElement(tbl, f"{{{HP}}}inMargin", left="400", right="400", top="120", bottom="120")
        tones = tones or [""] * len(rows)
        for ri, row in enumerate(all_rows):
            tr = etree.SubElement(tbl, f"{{{HP}}}tr")
            is_head = head and ri == 0
            tone = "" if is_head else tones[ri - (1 if head else 0)]
            for ci, (val, w) in enumerate(zip(row, widths)):
                tc = etree.SubElement(tr, f"{{{HP}}}tc", name="", header="1" if is_head else "0", hasMargin="0", protect="0", editable="0", dirty="0",
                                      borderFillIDRef=bf_head if is_head else (bf_body or bf_cell))
                sl = etree.SubElement(tc, f"{{{HP}}}subList", id="", textDirection="HORIZONTAL", lineWrap="BREAK", vertAlign="CENTER", linkListIDRef="0",
                                      linkListNextIDRef="0", textWidth="0", textHeight="0", hasTextRef="0", hasNumRef="0")
                al = cols[ci][2]
                pp = PP_C if (is_head or al == "C") else (PP_R if al == "R" else PP_L)
                cid = cp(size, True, "#3E5566") if is_head else cp(size, False, TONE_HEX.get(tone or "", "#1A2530"))
                for line in (_s(val).split("\n") or [""]):
                    cell_para(sl, line, cid, pp)
                etree.SubElement(tc, f"{{{HP}}}cellAddr", colAddr=str(ci), rowAddr=str(ri))
                etree.SubElement(tc, f"{{{HP}}}cellSpan", colSpan="1", rowSpan="1")
                etree.SubElement(tc, f"{{{HP}}}cellSz", width=str(w), height=str(rh))
                etree.SubElement(tc, f"{{{HP}}}cellMargin", left="400", right="400", top="120", bottom="120")
        t = etree.SubElement(run, f"{{{HP}}}t")
        return p

    # 머리 띠: 색 채운 1칸 표(표 안 문단은 한글이 줄 높이를 다시 계산하므로 제목·부제목이 겹치지 않는다)
    hp_ = para([], PP_L)
    hrun = etree.SubElement(hp_, f"{{{HP}}}run", charPrIDRef=cp(10))
    pid[0] += 1
    htbl = etree.SubElement(hrun, f"{{{HP}}}tbl", id=str(pid[0]), zOrder="0", numberingType="TABLE", textWrap="TOP_AND_BOTTOM", textFlow="BOTH_SIDES",
                            lock="0", dropcapstyle="None", pageBreak="CELL", repeatHeader="0", rowCnt="1", colCnt="1", cellSpacing="0", borderFillIDRef=bf_band, noAdjust="0")
    etree.SubElement(htbl, f"{{{HP}}}sz", width="47600", widthRelTo="ABSOLUTE", height="7000", heightRelTo="ABSOLUTE", protect="0")
    etree.SubElement(htbl, f"{{{HP}}}pos", treatAsChar="1", affectLSpacing="0", flowWithText="1", allowOverlap="0", holdAnchorAndSO="0",
                     vertRelTo="PARA", horzRelTo="PARA", vertAlign="TOP", horzAlign="LEFT", vertOffset="0", horzOffset="0")
    etree.SubElement(htbl, f"{{{HP}}}outMargin", left="0", right="0", top="0", bottom="200")
    etree.SubElement(htbl, f"{{{HP}}}inMargin", left="1100", right="1100", top="700", bottom="700")
    tr = etree.SubElement(htbl, f"{{{HP}}}tr")
    tc = etree.SubElement(tr, f"{{{HP}}}tc", name="", header="0", hasMargin="1", protect="0", editable="0", dirty="0", borderFillIDRef=bf_band)
    sl = etree.SubElement(tc, f"{{{HP}}}subList", id="", textDirection="HORIZONTAL", lineWrap="BREAK", vertAlign="CENTER", linkListIDRef="0",
                          linkListNextIDRef="0", textWidth="0", textHeight="0", hasTextRef="0", hasNumRef="0")
    cell_para(sl, f"LOGTRIAGE · {_s(doc.get('site'))}", cp(8.5, False, "#CDEEF4"), PP_L)
    cell_para(sl, doc["title"], cp(19, True, "#FFFFFF"), add_pp("LEFT", 200, 200, 120))
    cell_para(sl, _s(doc.get("subtitle")), cp(10.5, False, "#E4F4F8"), PP_L)
    etree.SubElement(tc, f"{{{HP}}}cellAddr", colAddr="0", rowAddr="0")
    etree.SubElement(tc, f"{{{HP}}}cellSpan", colSpan="1", rowSpan="1")
    etree.SubElement(tc, f"{{{HP}}}cellSz", width="47600", height="7000")
    etree.SubElement(tc, f"{{{HP}}}cellMargin", left="1100", right="1100", top="700", bottom="700")
    etree.SubElement(hrun, f"{{{HP}}}t")
    para([("   ".join(f"{k} {_s(v)}" for k, v in doc.get("meta", [])), cp(9, False, "#5B6B7A"))], PP_N)
    kp = doc.get("kpis") or []
    if kp:
        per = len(kp) if len(kp) <= 5 else 4
        cols = [("", 1, "C")] * per
        rows = []
        for i in range(0, len(kp), per):
            chunk = kp[i:i + per] + [("", "", "")] * (per - len(kp[i:i + per]))
            rows.append([f"{k}\n{_s(v)}" if k else "" for k, v, _ in chunk])
        table(cols, rows, None, head=False, bf_body=bf_kpi, size=10.5)
    for s in doc.get("sections", []):
        para([("■ " + s["title"], cp(13, True, "#0E7490"))], PP_H)
        if s.get("note"):
            para([(s["note"], cp(9, False, "#5B6B7A"))], PP_N)
        if not s.get("rows"):
            para([(s.get("empty") or "해당 없음", cp(10, False, "#5B6B7A"))], PP_N)
            continue
        table(s["cols"], [[_s(v) for v in r] for r in s["rows"]], s.get("tones"))
    if doc.get("footer"):
        para([(doc["footer"], cp(8.5, False, "#5B6B7A"))], add_pp("LEFT", 600, 0, 130))

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "Contents/header.xml":
                data = etree.tostring(header, xml_declaration=True, encoding="UTF-8", standalone=True)
            elif info.filename == "Contents/section0.xml":
                data = etree.tostring(sec, xml_declaration=True, encoding="UTF-8", standalone=True)
            elif info.filename == "Preview/PrvText.txt":
                data = (doc["title"] + "\r\n" + _s(doc.get("subtitle"))).encode("utf-16-le") if data[:2] in (b"\xff\xfe",) else (doc["title"] + "\r\n" + _s(doc.get("subtitle"))).encode("utf-8")
            ct = zipfile.ZIP_STORED if info.filename == "mimetype" else zipfile.ZIP_DEFLATED
            zo.writestr(zipfile.ZipInfo(info.filename, date_time=time.localtime()[:6]), data, compress_type=ct)
    return out.getvalue()


def write_outputs(doc: dict, dest: Path, stem: str, formats, template: Path | None = None) -> tuple[list[Path], list[str]]:
    """형식별 파일을 임시 이름으로 쓴 뒤 바꿔 넣는다. (만든 파일, 실패 메시지) — 한 형식이 실패해도 나머지는 만든다."""
    dest.mkdir(parents=True, exist_ok=True)
    made, errors = [], []
    for fmt in [f for f in FORMATS if f in (formats or ["html"])]:
        try:
            if fmt == "html":
                data = render_html(doc).encode("utf-8")
            elif fmt == "pdf":
                data = render_pdf(doc)
            else:
                if not template or not template.exists():
                    raise FileNotFoundError("HWPX 양식(report-template/form_status.hwpx)이 없습니다")
                data = render_hwpx(doc, template)
            f = dest / f"{stem}.{fmt}"
            tmp = dest / f".{stem}.{fmt}.partial"
            tmp.write_bytes(data)
            tmp.replace(f)
            made.append(f)
        except Exception as e:   # noqa: BLE001 — 형식별 실패는 알림으로 남기고 계속
            errors.append(f"{fmt.upper()}: {type(e).__name__}: {e}")
    return made, errors
