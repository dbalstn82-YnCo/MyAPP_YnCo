"""제조사 회신 반입(2026-10-16 7차 아이디어 8 · GPT 60차) — 제조사 자료 요청서(md·docx)의 '회신' 칸을 읽어 목록만 만든다.

  · 미검증 해제 후보: 회신이 '맞음'이고 근거(문서 제목·번호·판)가 적힌 것 — 그래도 사람이 원문을 확인하고 승인해야 한다
  · 수정 대상: 회신이 '틀림'이고 근거가 적힌 것
  · 보류: 근거 없음·형식이 다름·빈칸
지식 파일은 고치지 않는다. 회신 '맞음'은 공식 검증 완료가 아니다(문서 원본·판·주장·근거 위치를 확인한 뒤 따로 승인).
방어: 파일 2MB 이하·md/docx 만·칸 2,000자 자르기·HTML 태그 제거·'=' 로 시작하는 칸(수식)은 글로만 다룸·주소를 열지 않음.

사용: python tools/build/import_vendor_replies.py <회신 파일 또는 폴더> [--out deploy/local/제조사자료요청/회신정리.md]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
MAX_BYTES = 2 * 1024 * 1024
YES = re.compile(r"^\s*(맞음|맞다|맞습니다|correct|yes)\b", re.I)
NO = re.compile(r"^\s*(틀림|틀리다|틀립니다|incorrect|wrong|no)\b", re.I)
SRC = re.compile(r"(근거|문서|매뉴얼|manual|guide|KB|번호|doc|ref)\s*[:：]?\s*\S", re.I)


def _clean(t: str) -> str:
    t = re.sub(r"<[^>]{0,200}>", "", str(t or ""))[:2000].strip()
    return ("'" + t) if t.startswith(("=", "+", "@")) else t   # 수식처럼 보이는 칸은 글로 고정


def rows_md(p: Path):
    vendor = p.stem
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("|") or set(line.replace("|", "").strip()) <= set("-: "):
            continue
        cells = [_clean(c) for c in line.strip().strip("|").split("|")]
        if len(cells) >= 4 and cells[0].isdigit():
            yield vendor, cells[1], cells[2], cells[3]


def rows_docx(p: Path):
    from docx import Document   # 매크로를 실행하지 않는 읽기 전용 구문 분석
    vendor = p.stem
    for t in Document(str(p)).tables:
        for r in t.rows:
            cells = [_clean(c.text) for c in r.cells]
            if len(cells) >= 4 and cells[0].strip().isdigit():
                yield vendor, cells[1], cells[2], cells[3]


def classify(reply: str) -> str:
    if not reply.strip():
        return "보류(빈칸)"
    if YES.search(reply):
        return "해제 후보" if SRC.search(reply) else "보류(근거 없음)"
    if NO.search(reply):
        return "수정 대상" if SRC.search(reply) else "보류(근거 없음)"
    return "보류(형식 다름)"


def collect(paths: list[Path]) -> list[dict]:
    out = []
    for p in paths:
        if p.suffix.lower() not in (".md", ".docx") or p.name.startswith("_"):
            continue
        if p.stat().st_size > MAX_BYTES:
            out.append({"vendor": p.stem, "where": "", "claim": "", "reply": "", "class": "보류(파일이 너무 큼 — 2MB 초과)"})
            continue
        gen = rows_md(p) if p.suffix.lower() == ".md" else rows_docx(p)
        for vendor, where, claim, reply in gen:
            out.append({"vendor": vendor, "where": where, "claim": claim, "reply": reply, "class": classify(reply)})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("--out", default=str(ENGINE / "deploy" / "local" / "제조사자료요청" / "회신정리.md"))
    a = ap.parse_args(argv)
    src = Path(a.src)
    paths = sorted(src.glob("*")) if src.is_dir() else [src]
    items = collect(paths)
    groups = {}
    for x in items:
        groups.setdefault(x["class"], []).append(x)
    md = ["# 제조사 회신 정리\n", "지식은 자동으로 고치지 않습니다. '해제 후보'도 원문(제목·판·근거 위치)을 확인한 뒤 사람이 승인해야 합니다.\n"]
    for k in ("해제 후보", "수정 대상", "보류(근거 없음)", "보류(형식 다름)", "보류(빈칸)", "보류(파일이 너무 큼 — 2MB 초과)"):
        xs = groups.get(k, [])
        md += [f"## {k} — {len(xs)}건\n", "| 제조사 | 위치 | 주장 | 회신 |", "|---|---|---|---|"]
        md += [f"| {x['vendor']} | {x['where'].replace('|', '/')} | {x['claim'][:200].replace('|', '/')} | {x['reply'][:300].replace('|', '/')} |" for x in xs]
        md.append("")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text("\n".join(md), encoding="utf-8")
    print(" · ".join(f"{k} {len(v)}" for k, v in groups.items()) or "회신 없음", "→", a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
