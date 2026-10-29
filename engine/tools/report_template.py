"""기존 장애·사후조치 보고서(HWP/HWPX/DOCX)에서 '양식 골격'만 추출해 템플릿을 만든다.

보안 원칙 (운영자 요구):
  - 모든 처리는 이 PC 안에서만 수행. 네트워크 사용 없음.
  - 화면(stdout)에는 건수·통계만 출력하고 문서의 제목·본문·파일명은 절대 출력하지 않는다.
  - 문장(서술 내용)은 저장하지 않는다. 저장 대상은 섹션 제목 골격뿐이며,
    템플릿 파일은 로컬(보고서템플릿/template.yaml)에만 기록된다.

사용: python tools/report_template.py <보고서.zip> <출력폴더>
"""
from __future__ import annotations

import io
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

import yaml

try:
    import olefile
except ImportError:  # pragma: no cover
    olefile = None

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"[ \t ]+")


# ── 텍스트 추출 (모두 로컬) ────────────────────────────────────
def _text_hwp(data: bytes) -> str:
    """HWP5(OLE)의 PrvText 스트림(미리보기 텍스트) 추출 — 본문 골격 파악용."""
    if olefile is None:
        return ""
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
        if ole.exists("PrvText"):
            return ole.openstream("PrvText").read().decode("utf-16-le", errors="ignore")
    except Exception:
        return ""
    return ""


def _text_zip_xml(data: bytes, patterns: tuple[str, ...]) -> str:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return ""
    parts = []
    for n in sorted(z.namelist()):
        if any(re.match(p, n) for p in patterns):
            try:
                xml = z.read(n).decode("utf-8", errors="ignore")
            except Exception:
                continue
            # 문단 경계 유지: 문단 종료 태그를 줄바꿈으로
            xml = re.sub(r"</(hp:p|w:p|p)>", "\n", xml)
            parts.append(_TAG.sub("", xml))
    return "\n".join(parts)


def extract_text(name: str, data: bytes) -> str:
    low = name.lower()
    if low.endswith(".hwp"):
        return _text_hwp(data)
    if low.endswith(".hwpx"):
        return _text_zip_xml(data, (r"Contents/section\d+\.xml",))
    if low.endswith(".docx"):
        return _text_zip_xml(data, (r"word/document\.xml",))
    return ""


# ── 골격(섹션 제목) 추출 ───────────────────────────────────────
_HEAD = re.compile(
    r"^\s*(?:(?:\d{1,2}|[IVXivx]{1,4}|[가-힣]|[①-⑳]|[A-Z])[.)\]]|[■□◆◇●○▶►▪\-]|\[)\s*(.{1,40})$")
_KEYWORDS = ["개요", "일시", "발생", "현상", "경위", "원인", "분석", "조치", "복구", "대책",
             "재발", "영향", "범위", "담당", "결과", "요약", "내역", "일정", "사후", "점검",
             "개선", "후속", "장애", "장비", "시스템", "대상", "구분", "내용", "비고"]

# 섹션 제목 키워드 → 분석기 필드 매핑 (자동 채움 가능 여부)
_FIELD_RULES = [
    (("일시", "발생시각", "발생 시각", "발생일", "시간"), "incident_time", "장애 시간(자동 탐지) 자동 기입"),
    (("경위", "타임라인", "진행", "이력"), "timeline", "인과 타임라인 자동 기입"),
    (("원인",), "cause", "장애 유형·판정 근거 자동 기입"),
    (("현상", "증상", "내용", "개요", "요약"), "summary", "장애 유형·계층·요약 자동 기입"),
    (("복구", "긴급", "즉시", "응급"), "immediate", "즉시 조치 방안 자동 기입"),
    (("조치", "대응", "처리"), "actions", "단기·중기 조치 자동 기입"),
    (("재발", "대책", "개선", "예방", "후속"), "prevention", "장기 조치(구조 개선) 자동 기입"),
    (("영향", "범위", "피해"), "manual", "서비스 영향 범위 — 담당자 작성"),
    (("담당", "작성", "보고자", "승인", "결재"), "manual", "담당자·결재 — 담당자 작성"),
]


def _norm(s: str) -> str:
    s = _WS.sub(" ", s).strip(" :：.·")
    return s


def headings_of(text: str) -> list[str]:
    out, seen = [], set()
    for raw in text.splitlines():
        line = _norm(raw)
        if not line or len(line) > 40:
            continue
        m = _HEAD.match(line)
        cand = _norm(m.group(1)) if m else (line if any(k in line for k in _KEYWORDS) and len(line) <= 14 else "")
        if not cand or len(cand) < 2:
            continue
        # 키워드가 하나도 없는 번호 항목은 목차가 아닐 가능성 → 제외
        if not any(k in cand for k in _KEYWORDS):
            continue
        key = re.sub(r"\s", "", cand)
        if key in seen:
            continue
        seen.add(key)
        out.append(cand)
    return out


def map_field(heading: str) -> tuple[str, str]:
    for keys, field, guide in _FIELD_RULES:
        if any(k in heading for k in keys):
            return field, guide
    return "manual", "담당자 작성 항목"


def main() -> int:
    if len(sys.argv) < 3:
        print("사용: report_template.py <보고서.zip> <출력폴더>")
        return 2
    src, out_dir = Path(sys.argv[1]), Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)

    docs = 0
    extracted = 0
    heading_pos: dict[str, list[float]] = defaultdict(list)
    heading_cnt: Counter = Counter()
    types: Counter = Counter()

    def handle(name: str, data: bytes):
        nonlocal docs, extracted
        low = name.lower()
        if low.endswith(".zip"):  # 중첩 zip 1단계
            try:
                for n2 in zipfile.ZipFile(io.BytesIO(data)).namelist():
                    if not n2.endswith("/"):
                        handle(n2, zipfile.ZipFile(io.BytesIO(data)).read(n2))
            except Exception:
                pass
            return
        if not low.endswith((".hwp", ".hwpx", ".docx")):
            return
        docs += 1
        types[low.rsplit(".", 1)[-1]] += 1
        text = extract_text(name, data)
        if not text.strip():
            return
        hs = headings_of(text)
        if not hs:
            return
        extracted += 1
        for i, h in enumerate(hs):
            key = re.sub(r"\s", "", h)
            heading_cnt[key] += 1
            heading_pos[key].append(i / max(1, len(hs) - 1))
            heading_pos.setdefault("__label__" + key, [0]).append(0)
            _labels[key] = h

    _labels: dict[str, str] = {}
    z = zipfile.ZipFile(src)
    for n in z.namelist():
        if not n.endswith("/"):
            handle(n, z.read(n))

    # 공통 골격: 2건 이상(또는 문서 수의 20% 이상)에 등장한 제목을 평균 위치순으로
    threshold = max(2, int(extracted * 0.2))
    common = [(k, sum(heading_pos[k]) / len(heading_pos[k]), heading_cnt[k])
              for k in heading_cnt if heading_cnt[k] >= threshold]
    common.sort(key=lambda x: x[1])

    sections = []
    auto = manual = 0
    for key, _pos, cnt in common[:18]:
        label = _labels[key]
        field, guide = map_field(label)
        if field == "manual":
            manual += 1
        else:
            auto += 1
        sections.append({"heading": label, "field": field, "guide": guide,
                         "seen_in": cnt})
    template = {
        "name": "사내 장애 보고서 양식 (기존 보고서 골격 자동 추출)",
        "source_docs": extracted,
        "sections": sections,
        "note": "섹션 제목만 추출됨 — 과거 보고서의 본문·문장은 저장하지 않음",
    }
    (out_dir / "template.yaml").write_text(
        yaml.safe_dump(template, allow_unicode=True, sort_keys=False), encoding="utf-8")

    # 화면에는 통계만
    print(f"문서 {docs}건 (형식별 {dict(types)}) · 골격 추출 성공 {extracted}건")
    print(f"공통 섹션 {len(sections)}개 (기준: {threshold}건 이상 등장) · "
          f"자동 채움 {auto} · 담당자 작성 {manual}")
    print(f"템플릿 저장: {out_dir / 'template.yaml'}  ← 내용은 로컬에서만 확인")
    return 0


if __name__ == "__main__":
    sys.exit(main())
