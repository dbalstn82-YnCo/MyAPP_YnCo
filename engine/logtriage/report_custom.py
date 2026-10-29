"""사용자 서식(HWPX) 등록·항목 매핑·채우기 — 고정 서식 2종 외에 담당자가 올린 임의의 보고서 서식을 같은 방식으로 채운다.

흐름
  analyze_form(hwpx)      서식 구조를 읽어 '값을 넣을 수 있는 자리'(표 값 칸, '라벨 : 값' 문단, 항목 아래 '-' 줄)를 후보로 뽑고
                          라벨 키워드로 분석기 값을 1차 추천한다.
  save_template(...)      서식 파일 + 매핑(mapping.json)을 report-template/custom/<id>/ 에 저장(이 PC/서버에만, 반출물 제외).
  fill_template(...)      서식 원본을 복제해 매핑된 자리만 채운다(report_forms 의 치환 도우미 재사용 → 문단·글자 모양 보존).

값 종류(FIELDS): 보고서 기본 정보(profile) + 분석 판정 값. 분석기가 모르는 항목은 '비움' 으로 두고 담당자가 채운다(임의 추정 없음).
"""
from __future__ import annotations

import json
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

from lxml import etree

from .report_forms import (HP, NS, Facts, HeaderCtx, PROFILE_FIELDS, StyleProfile, body_paragraphs, cell_run_ref, collect_todo,
                           find_cell, fmt_date, mark, norm, own_runs, para_text, replace_following, set_cell_lines, set_para,
                           set_para_value, top_tables)

# ── 넣을 수 있는 값 목록 (키, 라벨, 그룹) ─────────────────────────────────────
FIELDS: list[tuple[str, str, str]] = [("blank", "비움 (담당자 기재)", "기본")]
FIELDS += [(k, l, "보고서 기본 정보") for k, l in PROFILE_FIELDS if k not in ("fit_endings", "evidence_index")]   # 선택 항목은 값이 아니다
FIELDS += [
    ("incident_period", "장애시간 (발생 시각 ~ 복구 시각 기재)", "분석 결과"),
    ("incident_date", "장애 발생일자", "분석 결과"),
    ("incident_time", "발생 시각 (HH:MM ~ 복구 시각 기재)", "분석 결과"),
    ("report_date", "작성일 (오늘)", "분석 결과"),
    ("summary", "대표 판정 한 줄 (유형 — 판정)", "분석 결과"),
    ("content", "장애내용 (유형·판정·최초 이상·이용자 영향)", "분석 결과"),
    ("cause", "장애원인 (1차 판정·제조사 문서 원인)", "분석 결과"),
    ("root_cause", "근본원인 (1차 판정)", "분석 결과"),
    ("timeline", "시간대별 조치 (로그 근거 + 1차 조치)", "분석 결과"),
    ("actions", "1차 조치 목록", "분석 결과"),
    ("escalation", "이관 기준 (2차·3차)", "분석 결과"),
    ("category", "장애 유형 / 계층", "분석 결과"),
    ("vendors", "제조사 (감지 제품 기준)", "분석 결과"),
    ("model", "모델/사양 (감지 제품)", "분석 결과"),
    ("files", "분석 로그 파일", "분석 결과"),
    ("analysis_id", "분석 ID", "분석 결과"),
    # 2026-10-15 사용자 서식 ↔ 내장 채우기 동등화(같은 서식을 사용자 서식으로 올려도 같은 결과가 나오게)
    ("person_phone", "담당자 (연락처)", "보고서 기본 정보"),
    ("server_note", "※ 서버위치 / 관리주체 (안내 문구 자리)", "보고서 기본 정보"),
    ("obs_cert", "로그 관측 — 인증서·라이선스", "분석 결과"),
    ("obs_eos", "로그 관측 — 노후화·기술지원 중단", "분석 결과"),
    ("obs_threshold", "로그 관측 — 임계치(자원·풀·스레드)", "분석 결과"),
    ("obs_change", "로그 관측 — 변경작업", "분석 결과"),
    ("obs_batch", "로그 관측 — 백업·배치", "분석 결과"),
]
FIELD_KEYS = {k for k, _, _ in FIELDS}

# 라벨 키워드 → 값 키 (앞에서부터 먼저 맞는 것)
SUGGEST_RULES: list[tuple[tuple[str, ...], str]] = [
    (("지연 사유", "지연시", "지연"), "blank"),          # 지연 사유·제출자료 등은 분석기가 모르는 항목
    (("제출자료", "첨부자료"), "blank"),
    # 로그로 관측할 수 있는 관리 현황 — 관측이 없으면 서식 예시 줄을 그대로 둔다(내장 사후관리 채우기와 같게)
    (("인증서", "라이선스", "사용권한"), "obs_cert"),
    (("노후화", "기술지원 중단"), "obs_eos"),
    (("임계치",), "obs_threshold"),
    (("변경작업",), "obs_change"),
    (("백업", "배치"), "obs_batch"),
    (("실시간 전환", "예방점검", "사용자 증가", "관제", "대국민", "민원", "언론", "결재", "승인", "검토"), "blank"),
    (("담당자(연락처)", "담당자 (연락처)", "담당자(전화)"), "person_phone"),
    (("조치 여부", "조치여부"), "actions"),
    (("상위기관", "상위 기관"), "parent_org"),
    (("기관명", "기관"), "org"),
    (("시스템명", "정보시스템명", "시스템 명"), "system"),
    (("서비스명", "서비스 명", "업무명"), "service"),
    (("등급",), "grade"),
    (("설치 위치", "설치위치", "서버위치", "서버 위치", "위치"), "location"),
    (("관리주체", "운영주체", "운영 주체"), "operator"),
    (("소관 부서", "소관부서", "운영부서", "운영 부서", "부서", "소속"), "dept"),
    (("연락처", "전화", "휴대폰"), "phone"),
    (("직위", "직급"), "rank"),
    (("담당자", "작성자", "보고자", "성명", "이름"), "person"),
    (("제조사", "벤더", "업체"), "vendors"),      # 기본 정보에 있으면 그것, 없으면 로그로 감지한 제품의 제조사
    (("모델", "사양", "기종"), "model"),
    (("도입", "내용연수", "도입년도"), "intro_year"),
    (("이중화",), "ha"),
    (("장애시간", "장애 시간", "발생시간", "발생 시간", "장애일시", "발생일시", "발생 일시"), "incident_period"),
    (("발생일자", "발생 일자", "장애일자", "발생일", "일자"), "incident_date"),
    (("복구 시간", "복구시간", "발생/복구"), "incident_time"),
    (("작성일", "보고일", "날짜"), "report_date"),
    (("근본원인", "근본 원인"), "root_cause"),
    (("원인",), "cause"),
    (("시간대별", "타임라인", "경위", "조치 세부", "조치내용", "조치 내용", "처리 내용", "대응 과정"), "timeline"),
    (("조치", "대응", "처리"), "actions"),
    (("이관", "에스컬레이션", "협조"), "escalation"),
    (("장애내용", "장애 내용", "현상", "증상", "개요", "내용"), "content"),
    (("유형", "분류", "계층", "구분"), "category"),
    (("로그", "파일", "첨부"), "files"),
    (("판정", "요약", "결과"), "summary"),
]
_BULLET = re.compile(r"^[\s○●◦•□■◇◆▶▷▪‣※]*")
_LABEL_VALUE = re.compile(r"^\s*([○●◦•□■◇◆▶▷▪‣※]?\s*[^:：]{1,24}?)\s*[:：]\s*(.*)$")
_DASH = re.compile(r"^\s*[-–—ㆍ·]\s*")
_HEADER_WORDS = {"항목", "내용", "비고", "구분", "값", "세부내용", "내역", "확인", "결과"}
# '※ 서버위치, 관리주체, … 기재(…)' — 담당자에게 무엇을 쓰라는 안내 문단. 기본 정보로 채울 수 있으면 채우고, 없으면 지운다(내장과 같게)
_NOTE = re.compile(r"^\s*※.*(서버\s?위치|설치\s?위치|관리\s?주체|운영\s?주체).*기재")
# '□ 장애 개요 #한장을 초과해도 …' — 제목 뒤 작성 안내
_HEAD_GUIDE = re.compile(r"^(\s*[□■◆◇▣]\s*[^#]*?\S)\s+#.+$")


_AMBIGUOUS = {"내용", "비고", "기타", "구분", "결과", "값", "세부내용", "내역", "항목", "참고", "특이사항"}


_LEAD = "○●◦•□■◇◆▶▷▸▹▪‣※-–—·ㆍ "


def _is_ambiguous(label: str) -> bool:
    return norm(label).lstrip(_LEAD).replace(" ", "") in _AMBIGUOUS   # '▹비고' 처럼 글머리가 붙어도 같은 이름


def suggest(label: str) -> str:
    t = norm(label)
    # 한 낱말짜리 일반 이름은 무엇을 넣을지 모른다 — 자동 확정하지 않고 '비움(담당자 기재)'(GPT 21차: 잘못 넣어도 자연스러워 보이는 오입력이 가장 위험)
    if _is_ambiguous(t):
        return "blank"
    for keys, key in SUGGEST_RULES:
        if any(k in t for k in keys):
            return key
    return "blank"


def basis(label: str, field: str) -> str:
    """auto = 분석 결과로 채움 / ambiguous = 이름이 너무 일반적이라 일부러 비움 / confirm = 분석기가 모르는 항목(담당자 기재)."""
    if field and field != "blank":
        return "auto"
    return "ambiguous" if _is_ambiguous(label) else "confirm"


# ── 값 생성 ─────────────────────────────────────────────────────────────────
_OBS = {   # 내장 사후관리 채우기(report_forms._fill_postmortem)와 같은 관측 기준
    "obs_cert": (("SSL", "CERT", "LICENSE", "LIC-"), ()),
    "obs_eos": (("EOS", "EOL"), ("eos",)),
    "obs_threshold": (("POOL", "THREAD", "MEM", "DISK", "CPU", "OOM", "HEAP"), ("resource", "performance")),
    "obs_change": (("DEPLOY", "CHANGE"), ("deploy",)),
    "obs_batch": (("BATCH", "BACKUP"), ()),
}


def value_lines(F: Facts, key: str, label: str = "") -> list[str]:
    """값 키 → 넣을 줄. 내장 서식 채우기(report_forms)와 같은 값·같은 '[기재: …]' 표시 — 같은 서식을 사용자 서식으로
    올려도 결과가 같아야 담당자 수정이 최소가 된다(2026-10-15 실증: 내장 대비 다른 곳 14 → 0 목표)."""
    f = F.first
    pf = F.p
    if key in ("vendor", "vendors"):
        return [F.vendors()]                       # 기본 정보 → 없으면 로그로 감지한 제품의 제조사 → 없으면 [기재]
    if key == "model":
        return [F.model()]
    if key == "person_phone":
        v = " ".join(x for x in (pf("person"), f"({pf('phone')})" if pf("phone") else "") if x)
        return [v or mark(label or "담당자(연락처)")]
    if key == "server_note":
        parts = [x for x in (("서버위치: " + pf("location")) if pf("location") else "",
                             ("관리주체: " + pf("operator")) if pf("operator") else "") if x]
        return [" / ".join(parts)] if parts else []
    if key in {k for k, _ in PROFILE_FIELDS}:
        # 비어 있으면 [기재: 라벨] — 확인 목록에 오른다. 칸 이름이 짧으면 무엇을 쓸지 알려 주는 표시(내장과 같게)
        hint = {"시스템명": "시스템명(IRM 등록 명칭)", "서비스명": "서비스명(제공 기능 설명)"}.get(norm(label).replace(" ", ""), label)
        if key == "service" and not F.p("service"):
            return [F.service() or mark(hint or "서비스명(제공 기능 설명)")]
        return [F.pm(key, hint or None)]
    if key in _OBS:
        return F.related(*_OBS[key])
    if key == "incident_period":
        return [F.period()]
    if key == "incident_date":
        return [fmt_date(F.t, F.sp.date_style(label) or "YYYY.M.D.(요일)")] if F.t else [mark(label or "장애 발생일자")]
    if key == "incident_time":
        return [f"{F.time_k} ~ {F.recovery_mark(short=True)}"] if F.t else [f"{mark('발생 시각')} ~ {mark('복구 시각')}"]
    if key == "report_date":
        return [fmt_date(datetime.now().strftime("%Y-%m-%d %H:%M"), F.sp.date_style(label) or "YYYY.M.D.")]
    if key == "summary":
        return [f"{f.get('category_ko', '')} — {f.get('verdict', '')}".strip(" —")] if f else ["알려진 장애 패턴 미검출 — 담당자 기재"]
    if key == "content":
        return F.content_lines()
    if key == "cause":
        return F.cause_lines()
    if key == "root_cause":
        return F.cause_lines(root=True)
    if key == "timeline":
        lab = label or "조치내용"
        acts = F.action_lines(3)
        lines = F.timeline_lines(lab, max(3, F.sp.lines_limit(lab, 8) - len(acts))) + acts
        return lines + [f"{F.recovery_mark()} : 서비스 정상화 확인"]
    if key == "actions":
        # 예전엔 옛 표시 '(시각 기재) : ' 를 지우려다 표시 형식이 바뀌어 '[기재: 시각] :' 가 남았다
        return F.fix_lines(label or "장애 근본원인 조치 여부")
    if key == "escalation":
        return F.escalation_lines()
    if key == "category":
        return [f"{f.get('layer_ko', '')} / {f.get('category_ko', '')}".strip(" /")] if f else []
    if key == "vendors":
        v = F.vendors()
        return [v] if v else []
    if key == "model":
        m = F.model()
        return [m] if m else []
    if key == "files":
        return [", ".join(sorted({x.get("name", "") for x in F.inc.get("files", [])}))] if F.inc.get("files") else []
    if key == "analysis_id":
        return [F.inc.get("id", "")]
    return []


# ── 서식 구조 분석 ───────────────────────────────────────────────────────────
def _cell_text(tc) -> str:
    return norm(" ".join("".join(t.itertext()) for t in tc.iter("{%s}t" % HP)))


def _cells(tbl):
    out = {}
    for tc in tbl.findall("hp:tr/hp:tc", NS):
        a, sp = tc.find("hp:cellAddr", NS), tc.find("hp:cellSpan", NS)
        if a is None:
            continue
        c, r = int(a.get("colAddr")), int(a.get("rowAddr"))
        out[(c, r)] = {"el": tc, "c": c, "r": r, "cs": int(sp.get("colSpan", 1)) if sp is not None else 1,
                       "rs": int(sp.get("rowSpan", 1)) if sp is not None else 1, "text": _cell_text(tc)}
    return out


def analyze_form(hwpx: Path) -> dict:
    """서식 → 값 자리 후보 목록. 반환 {"fields": [...], "tables": n, "paragraphs": n}"""
    z = zipfile.ZipFile(hwpx)
    names = [n for n in z.namelist() if re.match(r"Contents/section\d+\.xml", n)]
    if not names:
        raise ValueError("HWPX 본문(section)을 찾지 못했습니다 — 한글에서 HWPX 로 저장한 파일인지 확인")
    root = etree.fromstring(z.read(sorted(names)[0]))
    fields: list[dict] = []
    seen_cells: set = set()
    # 1) 표: 라벨 칸 → 오른쪽 빈 칸(우선) / 아래 빈 칸
    tables = top_tables(root)
    for ti, tbl in enumerate(tables):
        cells = _cells(tbl)
        # '항 목 | 내 용 | 비 고' 같은 머리줄은 칸 이름이 아니다 — 예전엔 '내 용' 아래 칸을 '장애내용' 자리로 잡아 정보시스템명이 비었다
        row0 = [x["text"].replace(" ", "") for (c, r), x in cells.items() if r == 0 and x["text"]]
        header_row0 = len(row0) >= 2 and all(t in _HEADER_WORDS for t in row0)
        for (c, r), cell in sorted(cells.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            label = cell["text"]
            if not label or len(label) > 24 or (header_row0 and r == 0):
                continue
            right = cells.get((c + cell["cs"], r))
            below = cells.get((c, r + cell["rs"]))
            target = None
            if right is not None and not right["text"]:
                target = right
            elif below is not None and not below["text"] and (right is None or right["text"]):
                target = below
            if target is None or (ti, target["c"], target["r"]) in seen_cells:
                continue
            seen_cells.add((ti, target["c"], target["r"]))
            fields.append({"id": f"t{ti}c{target['c']}r{target['r']}", "kind": "cell", "table": ti,
                           "col": target["c"], "row": target["r"], "label": label, "lc": c, "lr": r,   # 칸 이름이 있는 칸(글자 모양 기준)
                           "where": f"표{ti + 1} {target['r'] + 1}행 {target['c'] + 1}열", "field": suggest(label)})
        # 표 안 문단의 '라벨: (값)' 형태 (예: 제목 표의 '(기관명: )')
        for tc in tbl.iter("{%s}tc" % HP):
            for p in tc.findall(".//hp:p", NS):
                t = para_text(p)
                m = _LABEL_VALUE.match(t)
                if m and len(m.group(1)) <= 16 and not m.group(2).strip(") ").strip():
                    key = f"tp{ti}_{len(fields)}"
                    fields.append({"id": key, "kind": "para_value", "anchor": t, "nth": 0, "in_table": ti,
                                   "label": norm(_BULLET.sub("", m.group(1))).strip("("), "where": f"표{ti + 1} 안 문단",
                                   "field": suggest(m.group(1))})
    # 2) 본문 문단: '라벨 : 값' / 항목 + '-' 줄
    paras = body_paragraphs(root)
    texts = [para_text(p) for p in paras]
    counts: dict[str, int] = {}
    i = 0
    while i < len(texts):
        t = texts[i]
        if not t:
            i += 1
            continue
        nth = counts.get(t, 0)
        counts[t] = nth + 1
        if _NOTE.match(t):
            fields.append({"id": f"pn{i}", "kind": "para_note", "anchor": t, "nth": nth, "label": "※ 서버위치 / 관리주체",
                           "where": f"문단 {i + 1} (작성 안내)", "field": "server_note"})
            i += 1
            continue
        m = _LABEL_VALUE.match(t)
        bare = _BULLET.sub("", t).strip()
        is_dash = bool(_DASH.match(t))
        if m and not is_dash and len(_BULLET.sub("", m.group(1)).strip()) <= 20:
            label = norm(_BULLET.sub("", m.group(1)))
            fields.append({"id": f"pv{i}", "kind": "para_value", "anchor": t, "nth": nth, "label": label,
                           "where": f"문단 {i + 1}", "example": m.group(2)[:40], "field": suggest(label)})
            i += 1
            continue
        if not is_dash and bare and len(bare) <= 40 and i + 1 < len(texts) and _DASH.match(texts[i + 1] or ""):
            cnt = 0
            j = i + 1
            while j < len(texts) and _DASH.match(texts[j] or ""):
                cnt += 1
                j += 1
            fields.append({"id": f"pl{i}", "kind": "para_lines", "anchor": t, "nth": nth, "count": cnt, "label": bare,
                           "where": f"문단 {i + 1} 아래 '-' {cnt}줄", "example": _DASH.sub("", texts[i + 1])[:40],
                           "field": suggest(bare)})
            i = j
            continue
        i += 1
    for f in fields:   # 아이디어 1: 자동 판단의 근거 — 화면이 '자동 N · 담당자 확인 M · 모호해서 비움 K' 를 보인다
        f["auto"] = f["field"]
        f["basis"] = basis(f.get("label", ""), f["field"])
    return {"fields": fields, "tables": len(tables), "paragraphs": len(paras),
            "fit": {k: sum(1 for f in fields if f["basis"] == k) for k in ("auto", "confirm", "ambiguous")}}


# ── 채우기 ───────────────────────────────────────────────────────────────────
def _find_para(paras, anchor: str, nth: int):
    k = 0
    for p in paras:
        if para_text(p) == anchor:
            if k == nth:
                return p
            k += 1
    return None


def fill_template(form: Path, mapping: list[dict], inc: dict, profile: dict, out: Path) -> dict:
    src = zipfile.ZipFile(form)
    names = src.namelist()
    header_root = etree.fromstring(src.read("Contents/header.xml")) if "Contents/header.xml" in names else None
    ctx = HeaderCtx(header_root) if header_root is not None else None
    tdir = form.parent.parent.parent if form.parent.name != "report-template" else form.parent
    sp = StyleProfile.load(tdir)
    from .report_forms import option_on
    sp.fit_on = option_on(profile, "fit_endings", True)
    if sp.d.get("by_form"):   # 아이디어 2: 사용자 서식도 어느 공식 서식에 가까운지 보고 그 서식의 통계를 먼저 쓴다
        from . import report_style as rs
        try:
            kind, _ = rs.classify(rs.parse_hwpx(Path(form).read_bytes()) or [], rs.form_labels(tdir))
        except Exception:
            kind = ""
        sp = sp.for_form(kind)
    F = Facts(inc, profile, ctx, sp)
    sections = {}
    filled = skipped = 0
    todo: list[dict] = []
    for name in names:
        if not re.match(r"Contents/section\d+\.xml", name):
            continue
        root = etree.fromstring(src.read(name))
        tables = top_tables(root)
        table_styles = {}
        for ti in {m.get("table") for m in mapping if m.get("kind") == "cell" and (m.get("field") or "blank") != "blank"}:
            table_styles[ti] = sp.table_style([m.get("label", "") for m in mapping if m.get("kind") == "cell" and m.get("table") == ti])
        # 표 값 칸
        for m in mapping:
            key = m.get("field") or "blank"
            if key == "blank" or key not in FIELD_KEYS:
                continue
            lines = value_lines(F, key, m.get("label", ""))
            if m.get("kind") == "para_note":
                p = _find_para(body_paragraphs(root), m["anchor"], int(m.get("nth", 0)))
                if p is None:
                    skipped += 1
                    continue
                if lines:
                    runs = [r for r in own_runs(p) if r.find("hp:t", NS) is not None]
                    set_para(p, "※ " + lines[0], black_ref=ctx.black(runs[0].get("charPrIDRef", "0")) if ctx and runs else None, ctx=ctx)
                else:
                    p.getparent().remove(p)          # 채울 값이 없으면 안내 문단을 남기지 않는다(내장 채우기와 같게)
                filled += 1
                continue
            if m.get("kind") == "para_lines" and not lines and key in _OBS:
                continue                             # 로그 관측 없음 → 서식 예시 줄 그대로(담당자 기재)
            if m.get("kind") == "cell":
                if m["table"] < len(tables):
                    tc = find_cell(tables[m["table"]], int(m["col"]), int(m["row"]))
                    if tc is not None:
                        cp = None
                        if ctx is not None:
                            tb = tables[m["table"]]
                            if "lc" in m:      # 칸 이름이 있는 칸이 기준(위에 이름이 있는 담당자 표에서 옆 값 칸을 기준으로 잡던 것)
                                base = cell_run_ref(find_cell(tb, int(m["lc"]), int(m["lr"]))) or "0"
                            else:              # 예전에 저장한 대응(lc 없음)
                                base = cell_run_ref(find_cell(tb, int(m["col"]) - 1, int(m["row"]))) or \
                                    cell_run_ref(find_cell(tb, int(m["col"]), int(m["row"]) - 1)) or "0"
                            # 한 표의 값 칸은 같은 모양(학습 최빈 글꼴·크기, 굵기 없음) — 칸마다 따로면 한 표 안에서 크기·굵기가 섞인다(내장과 같게)
                            cp = ctx.value_ref(base, table_styles.get(m["table"]) or {"bold": False})
                        set_cell_lines(tc, lines or [""], ctx=ctx, cp=cp); filled += 1
                        continue
                skipped += 1
            elif m.get("kind") == "para_value":
                if "in_table" in m and m["in_table"] < len(tables):
                    pool = tables[m["in_table"]].findall(".//hp:p", NS)
                else:
                    pool = body_paragraphs(root)
                p = _find_para(pool, m["anchor"], int(m.get("nth", 0)))
                if p is None:
                    skipped += 1
                    continue
                val = " / ".join(lines) if lines else ""
                if m.get("in_table") is not None and m["anchor"].startswith("(") and m["anchor"].rstrip().endswith(")"):
                    # '(기관명: )' 처럼 괄호로 닫힌 형태 → 괄호 유지
                    label = m["anchor"].split(":")[0].split("：")[0]
                    from .report_forms import set_para
                    set_para(p, f"{label}: {val})", ctx=ctx)
                else:
                    runs = [r for r in own_runs(p) if r.find("hp:t", NS) is not None]
                    cp = ctx.value_ref(runs[0].get("charPrIDRef", "0"), sp.field_style(m.get("label", ""))) if ctx and runs else None
                    set_para_value(p, val, sep=" ", ctx=ctx, cp=cp)
                filled += 1
            elif m.get("kind") == "para_lines":
                paras = body_paragraphs(root)
                p = _find_para(paras, m["anchor"], int(m.get("nth", 0)))
                if p is None:
                    skipped += 1
                    continue
                idx = paras.index(p)
                label = m.get("label", "")
                cp = None
                if ctx is not None and idx + 1 < len(paras):
                    runs = [r for r in own_runs(paras[idx + 1]) if r.find("hp:t", NS) is not None]
                    cp = ctx.value_ref(runs[0].get("charPrIDRef", "0") if runs else "0", sp.field_style(label))
                replace_following(paras, idx, int(m.get("count", 1)) or 1, sp.fit_endings(label, lines, kind="timeline" if m.get("field") == "timeline" else "") or ["-"], prefix=sp.bullet(label), ctx=ctx, cp=cp,
                                  sub_prefix=sp.sub_bullet(label))
                filled += 1
        # 제목 뒤 작성 안내('□ 장애 개요 #한장을 초과해도 …')는 지운다 — 서식 사용법이지 보고 내용이 아니다(내장 채우기와 같게)
        for p in body_paragraphs(root):
            g = _HEAD_GUIDE.match(para_text(p))
            if g:
                set_para(p, g.group(1).strip(), ctx=ctx)
        todo += collect_todo(root, form.stem)
        sections[name] = root
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        if "mimetype" in names:
            dst.writestr("mimetype", src.read("mimetype"), compress_type=zipfile.ZIP_STORED)
        for name in names:
            if name == "mimetype" or name.startswith("Preview/"):
                continue
            if name in sections:
                data = etree.tostring(sections[name], xml_declaration=True, encoding="UTF-8", standalone=True)
            elif name == "Contents/header.xml" and header_root is not None:
                data = etree.tostring(header_root, xml_declaration=True, encoding="UTF-8", standalone=True)
            else:
                data = src.read(name)
            dst.writestr(name, data)
    out.write_bytes(buf.getvalue())
    return {"hwpx": str(out), "filled": filled, "skipped": skipped, "todo": todo, "fitted": sp.log}


# ── 등록 저장소 (report-template/custom/<id>/form.hwpx + mapping.json) ─────────
def custom_dir(tdir: Path) -> Path:
    return tdir / "custom"


def list_templates(tdir: Path) -> list[dict]:
    out = []
    d = custom_dir(tdir)
    if not d.exists():
        return out
    for sub in sorted(d.iterdir()):
        mp = sub / "mapping.json"
        if sub.is_dir() and mp.exists() and (sub / "form.hwpx").exists():
            try:
                m = json.loads(mp.read_text(encoding="utf-8"))
            except Exception:
                continue
            fields = m.get("fields", [])
            out.append({"id": sub.name, "name": m.get("name", sub.name), "file_name": m.get("file_name", ""),
                        "created": m.get("created", ""), "fields": len(fields),
                        "mapped": sum(1 for f in fields if (f.get("field") or "blank") != "blank"),
                        "form_state": form_state({**m, "form": str(sub / "form.hwpx")})})
    return out


def same_form(tdir: Path, form_path: Path, exclude_id: str | None = None) -> str | None:
    """이미 있는 서식과 바이트가 같으면 그 이름 — 같은 서식을 두 번 등록하면 보고서를 만들 때마다 같은 문서가 두 벌 나온다."""
    import hashlib
    try:
        h = hashlib.sha256(Path(form_path).read_bytes()).hexdigest()
    except OSError:
        return None
    from .report_forms import FORMS
    for f in FORMS:
        p = Path(tdir) / f["file"]
        if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == h:
            return f"기본 서식 '{f['title']}'"
    for t in list_templates(tdir):
        if t["id"] == exclude_id:
            continue
        p = custom_dir(tdir) / t["id"] / "form.hwpx"
        if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest() == h:
            return f"등록된 사용자 서식 '{t['name']}'"
    return None


def save_template(tdir: Path, form_path: Path, name: str, fields: list[dict], tpl_id: str | None = None) -> dict:
    if not tpl_id:
        dup = same_form(tdir, Path(form_path))
        if dup:
            raise ValueError(f"이미 {dup}(으)로 등록돼 있는 서식과 같은 파일입니다 — 다시 등록하지 않아도 보고서를 만들 때 함께 만들어집니다")
    name = norm(name)[:60] or form_path.stem
    tpl_id = tpl_id or f"tpl_{datetime.now():%Y%m%d-%H%M%S}"
    if not re.fullmatch(r"tpl_[\w\-]+", tpl_id):
        raise ValueError("잘못된 서식 ID")
    d = custom_dir(tdir) / tpl_id
    d.mkdir(parents=True, exist_ok=True)
    if Path(form_path).resolve() != (d / "form.hwpx").resolve():
        shutil.copyfile(form_path, d / "form.hwpx")
    clean = []
    for f in fields:
        if not isinstance(f, dict) or f.get("kind") not in ("cell", "para_value", "para_lines", "para_note"):   # para_note: 예전엔 저장하면서 버려졌다
            continue
        key = f.get("field") or "blank"
        f = dict(f)
        f["field"] = key if key in FIELD_KEYS else "blank"
        clean.append(f)
    m = {"name": name, "file_name": Path(form_path).name, "created": datetime.now().strftime("%Y-%m-%d %H:%M"), "fields": clean,
         "form_sha256": _sha(d / "form.hwpx")}   # 아이디어 7: 등록 때의 원본 지문 — 나중에 파일이 바뀌면 자리가 어긋나므로 채우지 않는다
    (d / "mapping.json").write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"id": tpl_id, "name": name, "fields": len(clean), "mapped": sum(1 for f in clean if f["field"] != "blank")}


def _sha(p: Path) -> str:
    import hashlib
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


FORM_CHANGED = "등록한 뒤 서식 파일이 바뀌었습니다(원본 지문 불일치) — 값 자리가 어긋날 수 있어 채우지 않았습니다. [보고서 양식]에서 이 서식을 다시 분석·저장하십시오"
FORM_NO_PRINT = "원본 지문이 없는 예전 등록입니다 — 바뀌었는지 알 수 없어 채우지 않았습니다. 등록한 원본 서식 파일을 한글로 열어 확인한 뒤 [보고서 양식]에서 [지문 등록]을 누르거나 [매핑 편집]에서 다시 저장하십시오"


def form_block(m: dict) -> str:
    """채우기 전에 막을 이유 — 바뀐 서식·지문 없는 예전 등록(GPT 27차: 기준값 없이 채우면 바뀐 것을 못 가린다)."""
    return {"changed": FORM_CHANGED, "none": FORM_NO_PRINT}.get(m.get("form_state", ""), "")


def pin_form(tdir: Path, tpl_id: str) -> dict:
    """지문 없는 예전 등록에 지금 파일의 지문을 기준값으로 남긴다 — 담당자가 원본을 확인한 뒤에만(화면이 확인을 받는다).
    이미 지문이 있으면 하지 않는다(바뀐 서식은 매핑 편집에서 다시 분석·저장 — 자리부터 다시 맞춰야 한다)."""
    if not re.fullmatch(r"tpl_[\w\-]+", tpl_id or ""):
        raise ValueError("잘못된 서식 ID")
    d = custom_dir(tdir) / tpl_id
    mp = d / "mapping.json"
    m = json.loads(mp.read_text(encoding="utf-8"))
    if m.get("form_sha256"):
        raise ValueError("이미 원본 지문이 있습니다 — 서식이 바뀌었으면 [매핑 편집]에서 다시 저장하십시오")
    m["form_sha256"] = _sha(d / "form.hwpx")
    m["pinned"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    mp.write_text(json.dumps(m, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"ok": True, "id": tpl_id}


def form_state(m: dict) -> str:
    """ok = 등록 때와 같은 파일 / changed = 바뀜 / none = 지문 없이 등록된 예전 서식(다시 저장하면 지문이 생긴다)"""
    want = m.get("form_sha256")
    if not want:
        return "none"
    try:
        return "ok" if _sha(Path(m["form"])) == want else "changed"
    except OSError:
        return "changed"


def load_template(tdir: Path, tpl_id: str) -> dict:
    d = custom_dir(tdir) / tpl_id
    m = json.loads((d / "mapping.json").read_text(encoding="utf-8"))
    m["id"] = tpl_id
    m["form"] = str(d / "form.hwpx")
    m["form_state"] = form_state(m)
    return m


def delete_template(tdir: Path, tpl_id: str) -> bool:
    if not re.fullmatch(r"tpl_[\w\-]+", tpl_id):
        return False
    d = custom_dir(tdir) / tpl_id
    if d.is_dir():
        shutil.rmtree(d)
        return True
    return False


LEDGER_KIND = "logtriage-form-ledger"
LEDGER_MAX = 512 * 1024


def ledger_export(tdir: Path) -> dict:
    """서식 원장(아이디어 6) — 이 PC(서버)의 기본·등록 서식 이름·지문(sha256)·값 자리 수만. 서식 파일·매핑 내용은 넣지 않는다.
    본사가 여러 사이트 원장을 모아 '같은 회사 양식을 쓰는가'를 대조한다."""
    from .report_forms import FORMS
    forms = []
    for f in FORMS:
        p = Path(tdir) / f["file"]
        if p.exists():
            forms.append({"kind": "builtin", "name": f["title"], "sha256": _sha(p)})
    for t in list_templates(tdir):
        m = load_template(tdir, t["id"])
        forms.append({"kind": "custom", "name": t["name"], "sha256": m.get("form_sha256") or _sha(Path(m["form"])),
                      "fields": t["fields"], "mapped": t["mapped"], "state": t.get("form_state", "")})
    return {"kind": LEDGER_KIND, "version": 1, "made": datetime.now().strftime("%Y-%m-%d %H:%M"), "forms": forms}


def ledger_check(tdir: Path, text: str) -> dict:
    """다른 곳(본사)의 서식 원장과 이 PC 의 서식을 지문으로 대조 — same(같은 파일) / changed(이름은 같은데 파일이 다름)
    / missing(원장에만 있음) / local_only(이 PC 에만 있음). 원장 글은 바깥에서 온 것이라 형식·크기를 엄격히 본다."""
    if not isinstance(text, str) or len(text.encode("utf-8")) > LEDGER_MAX:
        raise ValueError("서식 원장 파일이 너무 크거나 형식이 아닙니다")
    try:
        d = json.loads(text)
    except ValueError:
        raise ValueError("서식 원장 파일이 JSON 이 아닙니다")
    if not isinstance(d, dict) or d.get("kind") != LEDGER_KIND or not isinstance(d.get("forms"), list) or len(d["forms"]) > 500:
        raise ValueError("LogTriage 서식 원장 파일이 아닙니다")
    theirs, invalid = [], 0
    for x in d["forms"]:
        sha = str(x.get("sha256", "")).lower() if isinstance(x, dict) else ""
        name = norm(str(x.get("name", "")))[:60] if isinstance(x, dict) else ""
        if re.fullmatch(r"[0-9a-f]{64}", sha) and name:
            theirs.append({"name": name, "sha256": sha, "kind": "builtin" if x.get("kind") == "builtin" else "custom"})
        else:
            invalid += 1   # 버리되 센다 — 버린 줄이 있으면 '모두 같음'으로 보지 않는다(GPT 33차)
    mine = ledger_export(tdir)["forms"]
    my_sha = {f["sha256"] for f in mine}
    my_name = {norm(f["name"]): f for f in mine}
    out = []
    for t in theirs:
        if t["sha256"] in my_sha:
            st = "same"
        elif t["name"] in my_name:
            st = "changed"
        else:
            st = "missing"
        out.append({"name": t["name"], "kind": t["kind"], "state": st})
    their_sha, their_name = {t["sha256"] for t in theirs}, {t["name"] for t in theirs}
    for f in mine:
        if f["sha256"] not in their_sha and norm(f["name"]) not in their_name:
            out.append({"name": f["name"], "kind": f["kind"], "state": "local_only"})
    counts = {k: sum(1 for x in out if x["state"] == k) for k in ("same", "changed", "missing", "local_only")}
    return {"made": str(d.get("made", ""))[:20], "items": out, "counts": counts, "invalid": invalid,
            "complete": invalid == 0 and counts["changed"] == counts["missing"] == counts["local_only"] == 0}


def generate_custom(tdir: Path, inc: dict, profile: dict, out_dir: Path) -> list[dict]:
    """등록된 사용자 서식 전부 채우기 → [{form:'custom', id, title, hwpx, filled}]"""
    out = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for t in list_templates(tdir):
        try:
            m = load_template(tdir, t["id"])
            if form_block(m):
                raise ValueError(form_block(m))
            safe_name = re.sub(r'[\\/:*?"<>|]+', '_', m['name'])  # Python 3.11 호환
            hw = out_dir / f"{safe_name}_{inc.get('id', 'INC')}.hwpx"
            r = fill_template(Path(m["form"]), m.get("fields", []), inc, profile, hw)
            out.append({"form": "custom", "id": t["id"], "title": m["name"], "hwpx": r["hwpx"], "filled": r["filled"],
                        "todo": r.get("todo", []), "todo_count": len(r.get("todo", [])), "fitted": r.get("fitted", [])})
        except Exception as e:
            out.append({"form": "custom", "id": t["id"], "title": t["name"], "error": str(e)})
    return out


def sample_values(inc: dict, profile: dict) -> dict:
    """매핑 화면용 예시 값 — 각 값 키의 첫 줄"""
    F = Facts(inc or {}, profile or {})
    out = {}
    for k, _, _ in FIELDS:
        if k == "blank":
            continue
        try:
            v = value_lines(F, k)
        except Exception:
            v = []
        out[k] = (v[0][:60] + ("…" if len(v) > 1 or len(v[0]) > 60 else "")) if v else ""
    return out
