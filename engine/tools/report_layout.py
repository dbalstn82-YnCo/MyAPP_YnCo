"""기존 HWPX 보고서들로부터 '마스터 양식' 을 선정하고 값 칸 지도를 만든다 (완전 로컬).

원리: 같은 양식으로 작성된 문서들은 표 구조가 같다. 같은 위치의 칸 텍스트가
문서마다 동일하면 양식 라벨(예: 항목명)이고, 문서마다 다르면 값 칸이다.
→ 마스터 문서(.hwpx)를 그대로 복제하고 값 칸만 분석 결과로 채우면 양식이 100% 보존된다.

보안 원칙: 네트워크 미사용. stdout 에는 통계만 출력(문서 내용·파일명 미출력).
산출물(로컬): report-template/master.hwpx, report-template/layout.json

사용: python tools/report_layout.py <보고서.zip> <출력폴더>
"""
from __future__ import annotations

import io
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

from lxml import etree

NS = {"hp": "http://www.hancom.co.kr/hwpml/2011/paragraph",
      "hs": "http://www.hancom.co.kr/hwpml/2011/section"}
_WS = re.compile(r"\s+")

# 라벨 키워드 → 분석기 필드 (report_template.py 와 동일 규칙)
FIELD_RULES = [
    (("작성일", "보고일", "일자", "날짜"), "report_date"),
    (("복구 시각", "복구시각", "복구 완료", "종료 시각", "종료시각", "소요"), "manual"),
    (("발생 일시", "발생일시", "일시", "발생시각", "발생 시각", "발생일", "인지", "탐지", "발견", "시간"), "incident_time"),
    (("경위", "타임라인", "진행", "이력", "상세", "근거", "로그"), "timeline"),
    (("원인",), "cause"),
    (("사건명", "장애명", "건명", "제목", "서비스명", "업무명"), "service"),
    (("현상", "증상", "내용", "개요", "요약", "설명"), "summary"),
    (("복구", "긴급", "즉시", "응급"), "immediate"),
    (("조치", "대응", "처리"), "actions"),
    (("재발", "대책", "개선", "예방", "후속"), "prevention"),
    (("영향", "범위", "피해", "고객", "손실"), "manual"),
    (("담당", "작성자", "보고자", "승인", "결재", "부서", "연락", "확인자", "검토"), "manual"),
    (("장비", "시스템", "서버", "대상", "호스트", "IP", "장치"), "hosts"),
    (("계층", "구분", "유형", "등급", "분류", "레벨", "심각", "종류"), "category"),
]


def norm(s: str) -> str:
    return _WS.sub(" ", s or "").strip()


def own_text(p) -> str:
    """문단 자체 텍스트 — 문단 안에 삽입된 표(hp:tbl) 내부 텍스트는 제외."""
    out = []
    for t in p.iter("{%s}t" % NS["hp"]):
        anc = t.getparent()
        inside_tbl = False
        while anc is not None and anc is not p:
            if anc.tag == "{%s}tbl" % NS["hp"]:
                inside_tbl = True
                break
            anc = anc.getparent()
        if not inside_tbl:
            out.append("".join(t.itertext()))
    return "".join(out)


def cell_text(tc) -> str:
    return norm(" ".join("".join(t.itertext()) for t in tc.iter("{%s}t" % NS["hp"])))


def doc_structure(data: bytes):
    """HWPX → (표 목록[(rows, cols, {(r,c): text})], 본문 문단 텍스트 목록)"""
    z = zipfile.ZipFile(io.BytesIO(data))
    tables, paras = [], []
    for name in sorted(n for n in z.namelist() if re.match(r"Contents/section\d+\.xml", n)):
        root = etree.fromstring(z.read(name))
        for tbl in root.iter("{%s}tbl" % NS["hp"]):
            cells, spans = {}, {}
            rows = cols = 0
            for tc in tbl.iter("{%s}tc" % NS["hp"]):
                addr = tc.find("hp:cellAddr", NS)
                if addr is None:
                    continue
                r, c = int(addr.get("rowAddr", 0)), int(addr.get("colAddr", 0))
                sp = tc.find("hp:cellSpan", NS)
                rs = int(sp.get("rowSpan", 1)) if sp is not None else 1
                cs = int(sp.get("colSpan", 1)) if sp is not None else 1
                rows, cols = max(rows, r + rs), max(cols, c + cs)
                cells[(r, c)] = cell_text(tc)
                spans[(r, c)] = (rs, cs)
            tables.append((rows, cols, cells, spans))
        # 표 밖 문단 (표 내부 문단 제외, 문단이 품은 표의 텍스트도 제외)
        for p in root.iter("{%s}p" % NS["hp"]):
            if any(a.tag == "{%s}tc" % NS["hp"] for a in p.iterancestors()):
                continue
            t = norm(own_text(p))
            if t:
                paras.append(t)
    return tables, paras


def map_field(label: str) -> str:
    for keys, field in FIELD_RULES:
        if any(k in label for k in keys):
            return field
    return "manual"


def main() -> int:
    if len(sys.argv) < 3:
        print("사용: report_layout.py <보고서.zip> <출력폴더>")
        return 2
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    docs = []  # (name, data, tables, paras)
    z = zipfile.ZipFile(src)

    def collect(name, data):
        if name.lower().endswith(".zip"):
            try:
                zz = zipfile.ZipFile(io.BytesIO(data))
                for n2 in zz.namelist():
                    if not n2.endswith("/"):
                        collect(n2, zz.read(n2))
            except Exception:
                pass
            return
        if name.lower().endswith(".hwpx"):
            try:
                tables, paras = doc_structure(data)
                if tables:
                    docs.append((name, data, tables, paras))
            except Exception:
                pass

    for n in z.namelist():
        if not n.endswith("/"):
            collect(n, z.read(n))
    if not docs:
        print("HWPX 문서에서 표 구조를 찾지 못했습니다.")
        return 1

    # 표 구조 시그니처로 그룹화 → 상위 3개 그룹 각각 양식 후보로 산출
    sig = lambda tables: tuple((t[0], t[1]) for t in tables)
    groups = defaultdict(list)
    for d in docs:
        groups[sig(d[2])].append(d)
    ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))[:3]
    for rank, (best_sig, group) in enumerate(ranked, 1):
        _emit(best_sig, group, out_dir, rank, len(docs), len(groups))
    return 0


def _emit(best_sig, group, out_dir: Path, rank: int, total_docs: int, total_groups: int):
    n = len(group)

    # 칸별 텍스트 일치도 → 라벨/값 판별 (실존 셀 기준)
    labels, values = {}, []
    master_cells = group[0][2]
    for ti, (rows, cols) in enumerate(best_sig):
        for (r, c) in master_cells[ti][2].keys():
            texts = [d[2][ti][2].get((r, c), "") for d in group]
            common, cnt = Counter(texts).most_common(1)[0]
            if common and cnt >= max(2, int(n * 0.6)):
                labels[(ti, r, c)] = common
            else:
                values.append((ti, r, c))

    # 병합 셀 커버리지: 라벨이 차지하는 모든 (행,열) 위치에 라벨을 전파
    cover: dict[tuple, str] = {}
    for (ti, r, c), lab in labels.items():
        rs, cs = master_cells[ti][3].get((r, c), (1, 1))
        for rr in range(r, r + rs):
            for cc in range(c, c + cs):
                cover[(ti, rr, cc)] = lab

    # 값 칸 → 라벨 문맥: 같은 행 왼쪽 → 같은 열 위쪽 → 왼쪽 위 대각 → 필드
    layout_cells = []
    for ti, r, c in values:
        label = ""
        for cc in range(c - 1, -1, -1):
            if (ti, r, cc) in cover:
                label = cover[(ti, r, cc)]
                break
        if not label:
            for rr in range(r - 1, -1, -1):
                if (ti, rr, c) in cover:
                    label = cover[(ti, rr, c)]
                    break
        if not label:
            for dist in range(1, 6):
                for rr in range(r, max(-1, r - dist - 1), -1):
                    for cc in range(c - 1, max(-1, c - dist - 1), -1):
                        if (ti, rr, cc) in cover:
                            label = cover[(ti, rr, cc)]
                            break
                    if label:
                        break
                if label:
                    break
        layout_cells.append({"table": ti, "row": r, "col": c,
                             "field": map_field(label) if label else "manual",
                             "label": label})

    # 본문 문단: 그룹 내 60% 이상에 동일 등장 → 고정(제목/안내), 그 외 → 값 문단
    para_counter = Counter(t for d in group for t in set(d[3]))
    fixed_paras = {t for t, k in para_counter.items() if k >= max(2, int(n * 0.6))}

    # 마스터 = 라벨 일치도가 가장 높은(가장 전형적인) 문서
    def typicality(d):
        return sum(1 for (ti, r, c), lab in labels.items() if d[2][ti][2].get((r, c)) == lab)

    # 라벨이 있는데 필드 미매핑된 라벨 종류 수(내용 미출력, 개수만)
    unmapped_labels = {x["label"] for x in layout_cells if x["label"] and x["field"] == "manual"}
    no_label = sum(1 for x in layout_cells if not x["label"])
    master = max(group, key=typicality)
    suffix = "" if rank == 1 else f"_{rank}"
    (out_dir / f"master{suffix}.hwpx").write_bytes(master[1])
    layout = {
        "rank": rank, "group_docs": n, "tables": [list(s) for s in best_sig],
        "cells": layout_cells, "fixed_paragraphs": sorted(fixed_paras),
        "note": "값 칸 위치·라벨 문맥만 기록. 과거 보고서의 값 내용은 저장하지 않음",
    }
    (out_dir / f"layout{suffix}.json").write_text(
        json.dumps(layout, ensure_ascii=False, indent=1), encoding="utf-8")
    fields = Counter(x["field"] for x in layout_cells)
    print(f"[양식 후보 {rank}] 동일 양식 문서 {n}건 (HWPX 전체 {total_docs}건, 그룹 {total_groups}개) · 표 {len(best_sig)}개")
    print(f"  라벨 칸 {len(labels)} · 값 칸 {len(values)} → 필드 매핑 {dict(fields)}")
    print(f"  라벨 없는 값 칸 {no_label} · 키워드 미매핑 라벨 종류 {len(unmapped_labels)} · 고정 본문 문단 {len(fixed_paras)}")
    print(f"  저장: master{suffix}.hwpx / layout{suffix}.json")


if __name__ == "__main__":
    sys.exit(main())
