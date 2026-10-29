"""분석기 판정 결과 + 사내 양식 템플릿 → 장애 보고서 초안(DOCX·HTML) 로컬 생성.

보안 원칙: 네트워크 사용 없음. stdout 에는 통계·저장 경로만 출력(보고서 내용 미출력).

사용: python tools/report_gen.py <template.yaml> <incidents.json> <출력폴더> [분석ID]
      분석ID 생략 시 가장 최근 분석.
"""
from __future__ import annotations

import html
import json
import sys
from datetime import datetime
from pathlib import Path

import yaml

TIER_LABEL = {"immediate": "즉시 조치", "short": "단기 조치",
              "mid": "중기 조치", "long": "장기 조치"}


def _lines(inc: dict, field: str) -> list[str]:
    """템플릿 필드 → 분석 결과 문장 목록 (판정 데이터만 사용, 임의 추정 없음)."""
    f = inc.get("first") or {}
    if field == "incident_time":
        t = inc.get("incident_time") or "-"
        how = "로그 자동 탐지" if inc.get("auto_detected") else "담당자 입력"
        return [f"장애 발생(추정) 시각: {t} ({how})",
                f"분석 수행 시각: {inc.get('analyzed_at', '-')}",
                f"분석 범위: {inc.get('window', '-')}"]
    if field == "summary":
        if not f:
            return ["분석 결과 알려진 장애 패턴이 검출되지 않음(전 계층 CLEAR) — 로그 외 원인 검토 필요"]
        return [f"장애 유형: {f.get('category_ko', '')} — {f.get('verdict', '')}",
                f"최초 이상 계층(추정): {f.get('layer_ko', '')} · 최초 발생 {f.get('ts', '')}",
                f"판정 근거: 룰/코드 {f.get('rule_id', '')} · 총 매칭 {inc.get('match_count', 0)}건 "
                f"(이벤트 {inc.get('events_window', 0):,}건 분석)"]
    if field == "timeline":
        out = []
        key = inc.get("timeline_key") or []
        if key:  # 요점: 판정별 최초 발생·횟수·구간
            for t in key[:15]:
                cnt = f" ×{int(t.get('count', 1)):,} ({t.get('ts')}~{t.get('last', '')})" if int(t.get("count", 1) or 1) > 1 else ""
                mark = f"[{'/'.join(t.get('marks', []))}] " if t.get("marks") else ""
                out.append(f"{t.get('ts')} {mark}[{t.get('layer_ko')}] {t.get('severity', '').upper()} "
                           f"{t.get('verdict')}{cnt} — {t.get('message', '')[:90]}")
            return out
        for t in inc.get("timeline", [])[:15]:
            out.append(f"{t.get('ts')} [{t.get('layer_ko')}] {t.get('severity', '').upper()} "
                       f"{t.get('verdict')} — {t.get('message', '')[:90]}")
        return out or ["타임라인 근거 없음"]
    if field == "cause":
        if not f:
            return ["시그니처·벤더 코드 사전 기준 원인 미검출"]
        out = [f"1차 판정 원인: {f.get('verdict', '')} ({f.get('category_ko', '')})",
               f"발생 계층: {f.get('layer_ko', '')} / 근거 로그 위치는 타임라인 참조"]
        for c in inc.get("checklist", []):
            if c.get("vendor_cause"):
                from .codes import cause_label
                out.append(f"{cause_label(c.get('vendor_url', ''))} [{c.get('rule_id')}]: {c['vendor_cause']}")
                break
        layers = inc.get("layers", {})
        if layers:
            out.append("계층별 매칭: " + ", ".join(
                f"{v.get('layer_ko')} {v.get('rules')}건(critical {v.get('critical')})"
                for v in layers.values()))
        return out
    if field in ("immediate", "actions", "prevention"):
        keys = {"immediate": ["immediate"], "actions": ["short", "mid"],
                "prevention": ["long"]}[field]
        out = []
        for c in inc.get("checklist", []):
            for k in keys:
                for a in c.get(k, []):
                    out.append(f"[{TIER_LABEL[k]}] ({c.get('verdict', '')}) {a}")
        return out or ["해당 없음"]
    plan = inc.get("plan") or {}
    if field == "analysis" and plan:
        a = plan.get("analysis", {})
        out = list(a.get("summary", []))
        out += [f"{c['code']} ({c['severity']}) {c['count']}회 {c['first_ts']}~{c['last_ts']} — {c['verdict']}"
                for c in a.get("codes", [])[:12]]
        out += list(a.get("observations", []))
        for v in a.get("vendor", [])[:10]:
            out.append(f"[{'제조사 문서' if v.get('url') else '분석기 지식'}] {v['code']} 원인: {v.get('cause') or '-'} / 조치: {v.get('action') or '-'}"
                       + (f" / {v['url']}" if v.get("url") else ""))
        return out or ["해당 없음"]
    if field == "tier1" and plan:
        t = plan.get("tier1", {})
        out = [f"담당: {t.get('role', '유지보수(관리) 담당자')}"]
        out += [f"상황: {x}" for x in t.get("situation", [])]
        for st in t.get("steps", []):
            if isinstance(st, dict):
                out.append(f"{st['n']}) {st['do']} — 방법: {st['how']} — 확인: {st['check']}")
            else:
                out.append(str(st))
        out += [f"1차 대응 금지 사항: {x}" for x in t.get("dont", [])]
        if t.get("note"):
            out.append(f"주의: {t['note']}")
        out += [f"세부 조치: {x}" for x in t.get("detail", [])]
        out += [f"1차 제외(2차 수행·승인 필요): {x}" for x in t.get("deferred", [])]
        esc = t.get("escalate", {})
        if esc:
            out.append("2차로 넘기는 기준: " + " / ".join(esc.get("when", [])))
            out.append("넘길 때 전달: " + " / ".join(esc.get("hand", [])))
        out += [f"[{c['product']}] {c['title']}: {c['body']}" for c in t.get("commands", [])]
        return out or ["해당 없음"]
    if field == "tier2" and plan:
        t = plan.get("tier2", {})
        out = ["▶ 확인 내용"] + [f"- {x}" for x in t.get("checks", [])]
        out += ["▶ 전달 내용"] + [f"- {x}" for x in t.get("handover", [])]
        caps = t.get("captures", [])
        if caps:
            out.append("▶ 로그 캡처 (>> 표시 = 판정 근거 라인)")
            for c in caps:
                out.append(f"[{c['code']}] {c['verdict']} — {c['file']}:{c['range']} ({c['ts']})")
                out += [f"  {'>>' if ln['hit'] else '  '} {ln['n']:>6} | {ln['text'][:160]}"
                        for ln in c.get("lines", [])]
        return out
    if field == "tier3" and plan:
        t = plan.get("tier3", {})
        out = ["▶ 의뢰 정리"] + [f"- {x}" for x in t.get("summary", [])]
        out += ["▶ 수집·첨부 자료"] + [f"- {x}" for x in t.get("collect", [])]
        out += ["▶ 중·장기 과제"] + [f"- {x}" for x in t.get("mid_long", [])]
        if t.get("contact"):
            out.append(f"▶ 문의: {t['contact']}")
        return out
    return []


def build(template: dict, inc: dict) -> list[dict]:
    """섹션 목록 → [{heading, auto:bool, lines:[...], guide}]"""
    out = []
    for s in template.get("sections", []):
        field = s.get("field", "manual")
        if field == "manual":
            out.append({"heading": s["heading"], "auto": False, "lines": [],
                        "guide": s.get("guide", "담당자 작성")})
        else:
            out.append({"heading": s["heading"], "auto": True,
                        "lines": _lines(inc, field), "guide": s.get("guide", "")})
    return out


def write_docx(path: Path, title: str, inc: dict, sections: list[dict]):
    from docx import Document
    from docx.shared import Pt, RGBColor
    doc = Document()
    doc.add_heading(title, level=0)
    meta = doc.add_paragraph()
    meta.add_run(f"분석 ID {inc.get('id', '-')} · 분석 이름 {inc.get('name', '-')} · "
                 f"작성일 {datetime.now():%Y-%m-%d}").font.size = Pt(9)
    doc.add_paragraph("※ 본 문서는 LogTriage 분석 결과를 사내 양식에 자동 기입한 초안입니다. "
                      "[담당자 작성] 표시 항목은 반드시 검토·보완 후 제출하십시오.").runs[0].font.size = Pt(9)
    for i, s in enumerate(sections, 1):
        doc.add_heading(f"{i}. {s['heading']}", level=1)
        if s["auto"]:
            for line in s["lines"]:
                doc.add_paragraph(line, style="List Bullet")
        else:
            p = doc.add_paragraph()
            r = p.add_run(f"[담당자 작성] {s['guide']}")
            r.font.color.rgb = RGBColor(0xC6, 0x28, 0x28)
            doc.add_paragraph("")
    doc.save(str(path))


def write_html(path: Path, title: str, inc: dict, sections: list[dict]):
    h = html.escape
    body = [f"<h1>{h(title)}</h1>",
            f"<p class='meta'>분석 ID {h(inc.get('id', '-'))} · {h(inc.get('name', '-'))} · "
            f"작성일 {datetime.now():%Y-%m-%d}</p>",
            "<p class='note'>※ LogTriage 분석 결과를 사내 양식에 자동 기입한 초안. "
            "[담당자 작성] 항목은 검토·보완 후 제출.</p>"]
    for i, s in enumerate(sections, 1):
        body.append(f"<h2>{i}. {h(s['heading'])}</h2>")
        if s["auto"]:
            body.append("<ul>" + "".join(f"<li>{h(x)}</li>" for x in s["lines"]) + "</ul>")
        else:
            body.append(f"<p class='manual'>[담당자 작성] {h(s['guide'])}</p>")
    css = ("body{font:11pt/1.7 'Malgun Gothic',sans-serif;max-width:800px;margin:30px auto;color:#1A2530}"
           "h1{font-size:20pt;border-bottom:3px solid #14212B;padding-bottom:6px}"
           "h2{font-size:13pt;color:#0B5C73;margin-top:22px}.meta,.note{color:#5B6B7A;font-size:9.5pt}"
           ".manual{color:#C62828;border:1px dashed #C62828;padding:8px 12px;border-radius:6px}"
           "li{margin-bottom:3px}@page{size:A4;margin:18mm}")
    path.write_text(f"<!DOCTYPE html><html lang='ko'><head><meta charset='utf-8'>"
                    f"<title>{h(title)}</title><style>{css}</style></head><body>"
                    + "\n".join(body) + "</body></html>", encoding="utf-8")


_HEADING_RULES = [
    (("작성일", "보고일", "일자", "날짜"), "report_date"),
    (("복구 시각", "복구시각", "복구 완료", "종료 시각", "종료시각", "소요"), "manual"),
    (("발생 일시", "발생일시", "일시", "발생시각", "발생 시각", "발생일", "인지", "탐지", "발견", "시간"), "incident_time"),
    (("경위", "타임라인", "진행", "이력", "상세", "근거", "로그"), "timeline"),
    (("원인",), "cause"),
    (("사건명", "장애명", "건명", "제목", "서비스명", "업무명"), "service"),
    (("현상", "증상", "내용", "개요", "요약", "설명"), "summary"),
    (("제조사", "벤더", "3차", "기술지원"), "tier3"),
    (("유지보수", "엔지니어", "2차", "전달", "인계"), "tier2"),
    (("1차", "긴급", "응급", "초동"), "tier1"),
    (("분석",), "analysis"),
    (("복구", "즉시"), "immediate"),
    (("조치", "대응", "처리"), "actions"),
    (("재발", "대책", "개선", "예방", "후속"), "prevention"),
    (("영향", "범위", "피해", "고객", "손실"), "manual"),
    (("담당", "작성자", "보고자", "승인", "결재", "부서", "연락", "확인자", "검토"), "manual"),
    (("장비", "시스템", "서버", "대상", "호스트", "IP", "장치"), "hosts"),
    (("계층", "구분", "유형", "등급", "분류", "레벨", "심각", "종류"), "category"),
]


def _map_heading(text: str) -> str | None:
    for keys, field in _HEADING_RULES:
        if any(k in text for k in keys):
            return field
    return None


def _field_text(inc: dict, field: str) -> list[str]:
    """HWPX 값 칸용 텍스트 (필드별) — 판정 데이터만, 임의 추정 없음."""
    f = inc.get("first") or {}
    if field == "hosts":
        return [", ".join(sorted({x.get("name", "") for x in inc.get("files", [])})) or "-"]
    if field == "category":
        return [f"{f.get('layer_ko', '')} / {f.get('category_ko', '')}".strip(" /") or "-"]
    if field == "service":
        return [inc.get("name") or "-"]
    if field == "report_date":
        return [datetime.now().strftime("%Y-%m-%d")]
    if field == "incident_time":
        return [inc.get("incident_time") or "-"]  # 칸에는 시각만 간결히
    return _lines(inc, field)


def generate_hwpx(master: Path, layout_path: Path, inc: dict, out: Path) -> dict:
    """마스터 HWPX 를 복제해 값 칸만 채운다 — 양식(표·글꼴·배치) 100% 보존."""
    import io
    import json
    import zipfile
    from lxml import etree

    NS_P = "http://www.hancom.co.kr/hwpml/2011/paragraph"
    layout = json.loads(layout_path.read_text(encoding="utf-8"))
    cell_map = {(c["table"], c["row"], c["col"]): c for c in layout["cells"]}
    fixed = set(layout.get("fixed_paragraphs", []))

    def set_cell(tc, lines: list[str]):
        ps = tc.findall(".//{%s}p" % NS_P)
        if not ps:
            return
        proto = ps[0]
        for p in ps[1:]:
            p.getparent().remove(p)
        parent = proto.getparent()
        idx = list(parent).index(proto)
        for k, line in enumerate(lines or [""]):
            p = proto if k == 0 else etree.fromstring(etree.tostring(proto))
            ts = p.findall(".//{%s}t" % NS_P)
            if ts:
                for t in ts[1:]:
                    t.getparent().remove(t)
                ts[0].clear()
                ts[0].text = line
            else:
                run = p.find("{%s}run" % NS_P)
                if run is not None:
                    t = etree.SubElement(run, "{%s}t" % NS_P)
                    t.text = line
            if k > 0:
                parent.insert(idx + k, p)

    src = zipfile.ZipFile(master)
    buf = io.BytesIO()
    filled = blanked = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        # HWPX(OWPML) 규격: mimetype 항목은 무압축으로 첫 번째에 위치해야 한글이 정상 인식
        if "mimetype" in src.namelist():
            dst.writestr("mimetype", src.read("mimetype"), compress_type=zipfile.ZIP_STORED)
        ti = 0
        for name in src.namelist():
            if name == "mimetype":
                continue
            data = src.read(name)
            if name.startswith("Contents/section") and name.endswith(".xml"):
                root = etree.fromstring(data)
                for tbl in root.iter("{%s}tbl" % NS_P):
                    for tc in tbl.iter("{%s}tc" % NS_P):
                        addr = tc.find("{%s}cellAddr" % NS_P)
                        if addr is None:
                            continue
                        key = (ti, int(addr.get("rowAddr", 0)), int(addr.get("colAddr", 0)))
                        spec = cell_map.get(key)
                        if not spec:
                            continue  # 라벨 칸 — 그대로 보존
                        if spec["field"] == "manual":
                            set_cell(tc, [""]); blanked += 1
                        else:
                            set_cell(tc, _field_text(inc, spec["field"])); filled += 1
                    ti += 1
                # 표 밖 문단: 고정 문단(제목·안내)은 보존, 그 아래 값 문단에는
                # 제목→필드 매핑 내용을 채우고, 매핑 없으면 비운다 (문단 안의 표는 건드리지 않음)
                body = [p for p in root.iter("{%s}p" % NS_P)
                        if not any(a.tag == "{%s}tc" % NS_P for a in p.iterancestors())]
                heading_field = None
                pending: list = []

                def own_ts(p):
                    out = []
                    for t in p.iter("{%s}t" % NS_P):
                        anc, inside = t.getparent(), False
                        while anc is not None and anc is not p:
                            if anc.tag == "{%s}tbl" % NS_P:
                                inside = True
                                break
                            anc = anc.getparent()
                        if not inside:
                            out.append(t)
                    return out

                def flush_pending():
                    nonlocal pending, blanked, filled
                    if not pending:
                        return
                    lines = _field_text(inc, heading_field) if heading_field and heading_field != "manual" else []
                    first = pending[0]
                    ts = own_ts(first)
                    if lines and ts:
                        for t in ts[1:]:
                            t.getparent().remove(t)
                        ts[0].clear(); ts[0].text = lines[0]
                        parent = first.getparent(); idx = list(parent).index(first)
                        for k, line in enumerate(lines[1:], 1):
                            clone = etree.fromstring(etree.tostring(first))
                            cts = own_ts(clone)
                            if cts:
                                cts[0].clear(); cts[0].text = line
                            parent.insert(idx + k, clone)
                        filled += 1
                        rest = pending[1:]
                    else:
                        rest = pending
                        if ts:
                            for t in ts:
                                t.clear()
                            blanked += 1
                            rest = pending[1:]
                    for p in rest:  # 나머지 과거 값 문단: 텍스트만 비움 (표·개체 보존)
                        for t in own_ts(p):
                            t.clear()
                        blanked += 1
                    pending = []

                for p in body:
                    text = "".join("".join(t.itertext()) for t in own_ts(p)).strip()
                    if not text:
                        continue
                    if text in fixed:
                        flush_pending()
                        heading_field = _map_heading(text)
                    else:
                        pending.append(p)
                flush_pending()
                data = etree.tostring(root, xml_declaration=True, encoding="UTF-8", standalone=True)
            dst.writestr(name, data)
    out.write_bytes(buf.getvalue())
    return {"hwpx": str(out), "filled_cells": filled, "blanked": blanked}


def generate(template_path: Path, inc: dict, out_dir: Path, values: dict | None = None) -> dict:
    """GUI/CLI 공용 — 공식 서식 2종(HWPX)과 분석 요약 HTML 생성, 경로·통계 반환 (네트워크 미사용).
    서식: report-template/form_status.hwpx(상황관리 종료 보고서), form_postmortem.hwpx(사후관리 보고서)."""
    from .report_forms import generate_forms
    tdir = template_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    res: dict = {"files": [], "hwpx_all": [], "filled_cells": 0}
    try:
        fr = generate_forms(tdir, inc, out_dir, values)
        res["files"] = fr["files"]
        res["hwpx_all"] = [f["hwpx"] for f in fr["files"]]
        res["filled_cells"] = sum(f["filled"] for f in fr["files"])
        res["todo"] = fr.get("todo", [])
        res["fitted"] = fr.get("fitted", [])
        res["values_used"] = fr.get("values_used", [])
        try:   # 3차 아이디어 7: 생성 보고서 적합도 ↔ 실보고서끼리 상한(통계만)
            from .report_style import conform
            res["conform"] = conform([f["hwpx"] for f in fr["files"] if f.get("form") != "custom"], tdir)
        except Exception:   # noqa: BLE001 — 적합도 측정 실패가 보고서 만들기를 막지 않는다
            res["conform"] = None   # 3차 아이디어 12: 자동으로 다듬은 줄(항목·끝 몇 글자)
        res["todo_count"] = len(res["todo"])
        if fr.get("todo_file"):
            res["todo_file"] = fr["todo_file"]
        res["style"] = fr.get("style", {})
        if fr["missing"]:
            res["missing_forms"] = fr["missing"]
        if fr.get("custom_errors"):
            res["custom_errors"] = fr["custom_errors"]   # 사용자 서식 실패(예: 등록 뒤 서식 파일이 바뀜)를 화면에 알린다 — 예전엔 조용히 빠졌다
    except Exception as e:
        res["forms_error"] = str(e)
    if res["hwpx_all"]:
        res["hwpx"] = res["hwpx_all"][0]
    # 분석 요약(HTML) — 서식과 별개로 판정 근거 전체를 담는 참고용
    base = out_dir / f"분석요약_{inc.get('id', 'INC')}"
    tpl = (yaml.safe_load(template_path.read_text(encoding="utf-8")) or {}) if template_path.exists() else {}
    sections = build(tpl, inc) if tpl else []
    # 아이디어 4: 맨 앞에 '제출 전 확인 목록' — 같은 기재 항목을 묶어 한 번 정한 값을 여러 곳에 넣게
    from .report_forms import summarize_todo
    summ = summarize_todo(res.get("todo") or [])
    res["todo_summary"] = [{k: g[k] for k in ("item", "count", "forms", "each")} for g in summ]   # 화면도 같은 묶음을 쓴다
    if summ:
        sections.insert(0, {"heading": f"제출 전 확인 목록 — 같은 이름으로 묶은 항목 {len(summ)}가지(총 {len(res.get('todo') or [])}곳, 한글 Ctrl+F '[기재')",
                            "auto": True, "guide": "같은 값이면 한 번 정해 함께 넣고, '줄마다'는 줄마다 다른 값입니다",
                            "lines": [f"{g['item']} — {g['count']}곳" + (" · 줄마다 다른 값" if g["each"] else "")
                                      + (f" ({'·'.join(g['forms'])})" if len(g["forms"]) > 1 else "") for g in summ]})
    # 판정 근거 전체 — 서식 보고서가 줄 수를 맞추느라 '그 밖의 관측 N건 … 분석요약(첨부)' 로 넘긴 판정이 여기 빠짐없이 있어야 한다
    # (GPT 22차: 예전 분석요약에는 25건 중 1건만 있었다 — 가리키는 곳에 내용이 없으면 그것도 누락)
    key = inc.get("timeline_key") or []
    if key:
        sections.append({"heading": f"판정 근거 전체 — 판정별 요점 {len(key)}건", "auto": True, "guide": "",
                         "lines": [(f"{t['eid']} · " if t.get("eid") else "") + f"{str(t.get('ts', ''))[-8:-3] or t.get('ts', '')} [{t.get('layer_ko', '')}] {t.get('verdict', '')}"
                                   + (f" ({int(t.get('count', 1)):,}회, ~{str(t.get('last', ''))[-8:-3]})" if int(t.get('count', 1) or 1) > 1 else "")
                                   + (f" — {str(t.get('message', ''))[:200]}" if t.get("message") else "") for t in key]})
    chk = [c for c in (inc.get("checklist") or []) if c.get("eid")]
    if chk:   # 아이디어 4: 조치 방안마다 그 조치를 권하는 근거 줄 — 아래 '근거 줄' 절에서 같은 ID 로 찾는다
        sections.append({"heading": f"조치 방안별 근거 — {len(chk)}건", "auto": True, "guide": "",
                         "lines": [f"{c['eid']} · [{c.get('rule_id', '')}] {c.get('verdict', '')} — 즉시 조치 {len(c.get('immediate') or [])}개"
                                   for c in chk]})
    tl = inc.get("timeline") or []
    if tl:
        total = max(int(inc.get("timeline_total", len(tl)) or len(tl)), len(tl))
        shown = len(tl)   # 저장 상한 3,000 + 판정 요점이 가리키는 상한 밖 근거(service)
        # '판정 요점 전체'(위 절)와 '로그 근거 일부'(이 절)를 구분한다 — 생략분은 건수와 조회 경로를 적는다(GPT 23차)
        sections.append({"heading": f"판정 근거 — 근거 줄 {shown:,}건" + (f" (전체 {total:,}건 중 일부 · 생략 {total - shown:,}건은 프로그램 [로그 검색]에서 분석 ID {inc.get('id', '')}로 조회)" if total > shown else " (전체)"),
                         "auto": True, "guide": "",
                         "lines": [(f"{t['eid']} · " if t.get("eid") else "") + f"{t.get('ts', '')} [{t.get('layer_ko', '')}] {t.get('verdict', '')} ({t.get('rule_id', '')}) {t.get('raw_ref', '')} — {str(t.get('message', ''))[:200]}"
                                   for t in tl]})
    write_html(base.with_suffix(".html"), "장애 분석 요약", inc, sections)    # 골격이 없어도 만든다 — 보고서가 이 파일을 가리킨다
    res["html"] = str(base.with_suffix(".html"))
    if not res["hwpx_all"] and not res.get("html"):
        return {"error": "보고서 서식이 없습니다 (report-template/form_status.hwpx, form_postmortem.hwpx). "
                         + res.get("forms_error", "")}
    return res


def main() -> int:
    if len(sys.argv) < 4:
        print("사용: report_gen.py <template.yaml> <incidents.json> <출력폴더> [분석ID]")
        return 2
    tpl = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
    hist = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    out_dir = Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    inc_id = sys.argv[4] if len(sys.argv) > 4 else None
    inc = next((h for h in hist if h.get("id") == inc_id), None) if inc_id else (hist[0] if hist else None)
    if not inc:
        print("오류: 분석 이력이 없습니다.")
        return 1
    sections = build(tpl, inc)
    title = "장애 보고서"
    base = out_dir / f"장애보고서_초안_{inc.get('id', 'INC')}"
    write_docx(base.with_suffix(".docx"), title, inc, sections)
    write_html(base.with_suffix(".html"), title, inc, sections)
    auto = sum(1 for s in sections if s["auto"])
    filled = sum(len(s["lines"]) for s in sections)
    print(f"분석 {inc.get('id')} 기준 초안 생성 — 섹션 {len(sections)}개 "
          f"(자동 {auto} · 담당자 작성 {len(sections) - auto}) · 자동 기입 {filled}줄")
    print(f"저장: {base.with_suffix('.docx')}")
    print(f"저장: {base.with_suffix('.html')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
