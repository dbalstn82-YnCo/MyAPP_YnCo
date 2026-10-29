# -*- coding: utf-8 -*-
"""간단 Markdown → DOCX 변환 (제목·표·코드블록·목록·문단). 사용: python md2docx.py in.md out.docx"""
import re, sys
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

src, dst = sys.argv[1], sys.argv[2]
lines = open(src, encoding="utf-8").read().split("\n")
doc = Document()
for s in doc.sections:
    s.left_margin = s.right_margin = Cm(2); s.top_margin = s.bottom_margin = Cm(2)
st = doc.styles["Normal"]; st.font.name = "Malgun Gothic"; st.font.size = Pt(10)
st.element.rPr.rFonts.set(qn("w:eastAsia"), "Malgun Gothic")
for name in ("Heading 1", "Heading 2", "Heading 3", "Title"):
    h = doc.styles[name]; h.font.name = "Malgun Gothic"; h.element.rPr.rFonts.set(qn("w:eastAsia"), "Malgun Gothic")
    h.font.color.rgb = RGBColor(0x0B, 0x5C, 0x73)

def shade(cell, color):
    tcPr = cell._tc.get_or_add_tcPr(); shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), color); tcPr.append(shd)

def add_inline(par, text):
    # **bold**, `code`
    pos = 0
    for m in re.finditer(r"(\*\*.+?\*\*|`[^`]+`)", text):
        if m.start() > pos: par.add_run(text[pos:m.start()])
        tok = m.group(0)
        if tok.startswith("**"):
            r = par.add_run(tok[2:-2]); r.bold = True
        else:
            r = par.add_run(tok[1:-1]); r.font.name = "Consolas"; r.font.size = Pt(9)
            r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        pos = m.end()
    if pos < len(text): par.add_run(text[pos:])

i = 0; first = True
while i < len(lines):
    ln = lines[i]
    if ln.startswith("```"):
        buf = []; i += 1
        while i < len(lines) and not lines[i].startswith("```"): buf.append(lines[i]); i += 1
        i += 1
        p = doc.add_paragraph(); p.paragraph_format.left_indent = Cm(0.4)
        r = p.add_run("\n".join(buf)); r.font.name = "Consolas"; r.font.size = Pt(8.5)
        r._element.rPr.rFonts.set(qn("w:eastAsia"), "Consolas")
        pPr = p._p.get_or_add_pPr(); shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:fill"), "F4F7F9"); pPr.append(shd)
        continue
    if ln.startswith("|") and i + 1 < len(lines) and re.match(r"^\|[\s:|-]+\|$", lines[i + 1]):
        rows = []
        while i < len(lines) and lines[i].startswith("|"):
            if not re.match(r"^\|[\s:|-]+\|$", lines[i]):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
            i += 1
        ncol = max(len(r) for r in rows)
        t = doc.add_table(rows=len(rows), cols=ncol); t.style = "Table Grid"
        for ri, row in enumerate(rows):
            for ci in range(ncol):
                cell = t.cell(ri, ci); cell.text = ""
                par = cell.paragraphs[0]; add_inline(par, row[ci] if ci < len(row) else "")
                for r in par.runs: r.font.size = Pt(8.5)
                if ri == 0:
                    shade(cell, "E1F0F4")
                    for r in par.runs: r.bold = True
        doc.add_paragraph()
        continue
    if ln.startswith("# "):
        if first:
            doc.add_heading(ln[2:], 0); first = False
        else:
            doc.add_heading(ln[2:], 1)
    elif ln.startswith("## "): doc.add_heading(ln[3:], 1)
    elif ln.startswith("### "): doc.add_heading(ln[4:], 2)
    elif ln.strip() == "---": pass
    elif ln.startswith("> "):
        p = doc.add_paragraph(); p.paragraph_format.left_indent = Cm(0.6); add_inline(p, ln[2:])
        for r in p.runs: r.italic = True
    elif re.match(r"^\s*[-*] ", ln):
        p = doc.add_paragraph(style="List Bullet"); add_inline(p, re.sub(r"^\s*[-*] ", "", ln))
    elif re.match(r"^\s*\d+\. ", ln):
        p = doc.add_paragraph(style="List Number"); add_inline(p, re.sub(r"^\s*\d+\. ", "", ln))
    elif ln.strip():
        p = doc.add_paragraph(); add_inline(p, ln)
    i += 1
doc.save(dst); print("saved", dst)
