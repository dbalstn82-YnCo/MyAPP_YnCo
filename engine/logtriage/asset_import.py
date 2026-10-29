# -*- coding: utf-8 -*-
"""남이 준 파일을 읽어 우리 기준 항목을 채운다 (2026-09-29)

사용자 지시: "우리가 기준이 되어야 하고, 사용자가 엑셀이든 한글이든 첨부했을 때
우리 포털에서 파싱해서 정보를 채울 수 있는 기능도 구현."

그래서 여기서는 **양식을 강요하지 않는다.** 아무 표나 받아서
  ① 어느 줄이 머리글인지 찾고
  ② 머리글을 우리 항목(asset_spec)에 맞추고 — 확실 / 추정 / 모름을 그대로 말하고
  ③ 몇 줄을 실제로 채워 보여 준 뒤
  ④ 빠진 필수 항목을 '왜 필요한지' 와 함께 알린다.

지키는 것 — 민감 열(비밀번호·키·뜻이 섞인 자격 정보)에 대한 약속
  엑셀·CSV·한글을 읽는 순간 그 칸도 파이썬 값이 된다. 그것까지 막으려면 형식마다 스트리밍
  파서를 새로 써야 하고, 그 과정에서 더 많은 결함이 생긴다. 그래서 지킬 수 있는 약속으로 쓴다.
  · **머리글을 가린 직후 민감 열을 격자에서 지운다.** 그 뒤로는 미리보기·기록·오류 메시지·
    저장 어디에도 그 값이 닿지 않는다(시험으로 고정).
  · 읽기 전에 압축 폭탄·경로 조작·매크로·외부 엔터티를 막는다(엑셀은 이미 굳은 로더를 그대로 쓴다).
  · 한 칸이 이상해도(수식·오류 값) 파일 전체를 버리지 않는다 — 그 칸만 비우고 세어 둔다.
"""
from __future__ import annotations

import csv
import io
import re
import threading
import zipfile
from pathlib import Path

from . import asset_spec

# 한 번에 받아들일 한계 — 넘으면 '왜' 를 말하고 멈춘다
MAX_BYTES = 10 * 1024 * 1024      # 파일 10 MB (엑셀 로더와 같은 값)
MAX_ROWS = 10_000                 # 시트당 데이터 행
MAX_COLS = 200                    # 시트당 열
MAX_CELL = 4_000                  # 칸당 글자
MAX_SHEETS = 20
HEAD_SCAN = 15                    # 머리글을 찾느라 훑는 첫 줄 수
SAMPLE = 5                        # 미리보기로 채워 보여 줄 줄 수

# 한글 문서는 ZIP 검사를 통과한 뒤 '파싱에서' 터질 수 있다 — 따로 막는다(GPT 교차 검토)
MAX_XML_TOTAL = 64 * 1024 * 1024  # 읽어 들이는 본문 XML 합계
MAX_XML_ONE = 32 * 1024 * 1024    # 본문 XML 하나
MAX_TABLES = 50                   # 논리적인 표 개수(section 개수와 다르다)
MAX_TC = 200_000                  # 원본 칸(hp:tc) 개수
MAX_GRID_CELLS = 500_000          # span 을 편 뒤의 논리 격자 칸 수

# 머리글이라고 확정하는 최소 조건 — 못 미치면 '사람이 골라 달라' 고 한다
HEAD_MIN_SURE = 2
HEAD_MIN_ANY = 3

SUPPORTED = (".xlsx", ".csv", ".txt", ".tsv", ".hwpx")

# csv.field_size_limit 는 프로세스 전역이다 — 스레드 서버에서 서로 밟지 않게 잠근다(GPT 교차 검토)
_CSV_LOCK = threading.Lock()

# 칸 안에 비밀이 섞여 들어오는 현실적인 표기 — 이런 칸은 통째로 버린다(아이디만 잘라 살리지 않는다)
# ① 이름 = 값 꼴. 구분자를 : = 만 보지 않는다 — 'pw 1234'·'비번은 1234' 도 현실의 표기다.
#    보안 우선 지시에 따라 오탐(정상 값을 버리는 일)을 감수한다.
#    낱말은 asset_spec.LEXICON 한 곳에서 가져온다 — 두 곳에 적어 두면 한쪽만 늘어난다(GPT 11차).
def _lex_re():
    import re as _re
    latin, hangul = [], []
    for w in asset_spec.LEXICON:
        esc = _re.escape(w).replace(r"\ ", r"[\s_\-]*")     # 'api key' 와 'api_key' 를 함께
        (hangul if any("\uac00" <= c <= "\ud7a3" for c in w) else latin).append(esc)
    # 영문은 낱말 경계로, 한글은 경계 표시가 없으므로 그대로
    return _re.compile(r"(?i)\b(?:" + "|".join(sorted(latin, key=len, reverse=True)) + r")\b"
                       r"\s*(?:[:=]|is\s|\s)\s*\S"
                       r"|(?:" + "|".join(sorted(hangul, key=len, reverse=True)) + r")"
                       r"\s*(?:[:=]|은|는)?\s*\S")


_SECRET_LABELLED = _lex_re()

# ② 주소 안에 자격 정보가 박힌 꼴 — scheme://사용자:비밀번호@호스트
_SECRET_URI = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://[^\s/:@]{1,64}:[^\s/@]{1,128}@")

# ③ 인증 헤더 — 그 값 자체가 열쇠다
_SECRET_AUTH = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9+/=._\-]{12,}"
                          r"|authorization\s*[:=]")

# ④ 개인키 원문 덩이
_SECRET_PEM = re.compile(r"(?i)-----\s*BEGIN[^-]{0,40}(PRIVATE KEY|CERTIFICATE REQUEST)")

# ⑤ JWT 꼴(세 토막 base64url) — 자격증명이다
_SECRET_JWT = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")

_SECRET_LAYERS = (("labelled", _SECRET_LABELLED), ("uri", _SECRET_URI), ("auth", _SECRET_AUTH),
                  ("pem", _SECRET_PEM), ("jwt", _SECRET_JWT))


class _CellGuard:
    """칸 하나가 비밀을 품고 있는지 — 여러 겹으로 본다.

    엔트로피로 판정하지 않는다. UUID·일련번호·인증서 지문이 비밀번호와 똑같이 생겨서
    정상 값을 대량으로 버리게 된다(GPT 교차 판단).
    """

    @staticmethod
    def search(text):
        t = str(text or "")
        if not t.strip():
            return None
        for name, rx in _SECRET_LAYERS:
            if rx.search(t):
                return name
        return None


_SECRET_IN_CELL = _CellGuard


# ── 파일 종류별 읽기 ────────────────────────────────────────────────────────
def _trim(line: list) -> list:
    """줄 끝의 빈 칸을 버린다 — 엑셀은 쓰지도 않은 열까지 채워 주므로 그대로 두면
    '모름 191개' 같은 헛소리가 나오고, 사람이 확인할 목록이 쓰레기로 덮인다."""
    while line and not str(line[-1] or "").strip():
        line.pop()
    return line


def _cap(v):
    """칸 값 다듬기 — 너무 길면 자르고, 빈 것은 빈 문자열로."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "예" if v else "아니오"
    s = str(v).strip()
    return s[:MAX_CELL]


def _from_xlsx(raw: bytes) -> list[dict]:
    from .inventory import workbook          # 압축 폭탄·매크로·DTD 를 이미 막는 로더
    wb = workbook(raw)
    out, odd, hidden = [], 0, []
    for name in wb.sheetnames[:MAX_SHEETS]:
        ws = wb[name]
        # 숨김 시트는 자동으로 읽지 않는다 — 보조표뿐 아니라 접속 정보·임시 계정표가 거기 있다
        if getattr(ws, "sheet_state", "visible") != "visible":
            hidden.append(name)
            continue
        rows = []
        for r in ws.iter_rows(max_row=MAX_ROWS + HEAD_SCAN, max_col=MAX_COLS):
            line = []
            for c in r:
                try:
                    if getattr(c, "data_type", "") in ("f", "e"):   # 수식·오류 값은 비운다
                        odd += 1
                        line.append("")
                        continue
                    line.append(_cap(c.value))
                except Exception:
                    odd += 1
                    line.append("")
            rows.append(_trim(line))
        while rows and not any(str(c or "").strip() for c in rows[-1]):
            rows.pop()
        out.append({"sheet": name, "rows": rows, "odd_cells": odd, "hidden_sheets": []})
    if out:
        out[0]["hidden_sheets"] = hidden
    elif hidden:
        raise ValueError(f"읽을 수 있는 시트가 없습니다 — 숨김 시트 {len(hidden)}개는"
                         " 자동으로 읽지 않습니다(접속 정보가 들어 있는 일이 있습니다)")
    return out


def _decode(raw: bytes) -> str:
    for enc in ("utf-8-sig", "cp949", "utf-8"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace")


def _from_csv(raw: bytes, filename: str) -> list[dict]:
    text = _decode(raw)
    fallback = "\t" if filename.lower().endswith(".tsv") else ","
    # 표본은 줄 수만이 아니라 글자 수로도 자른다 — 한 줄이 몇 MB 일 수 있다
    sample = "\n".join(text.splitlines()[:20])[:65536]
    try:
        delim = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except Exception:
        delim = fallback
    if delim not in ",;\t|":          # 추정 결과도 믿지 않는다
        delim = fallback

    def _read(d):
        rows = []
        for i, line in enumerate(csv.reader(io.StringIO(text), delimiter=d)):
            if i >= MAX_ROWS + HEAD_SCAN:
                break
            rows.append(_trim([_cap(v) for v in line[:MAX_COLS]]))
        return rows

    with _CSV_LOCK:                           # 전역 설정을 만지는 동안은 한 번에 하나만
        old_limit = csv.field_size_limit()
        try:
            csv.field_size_limit(MAX_CELL * 16)   # 거대한 한 칸은 파서 단계에서 막는다
            rows = _read(delim)
            # 추정이 틀리면 한 줄이 통째로 한 칸이 된다 — 그럴 때는 물러선다
            if delim != fallback and rows and max((len(r) for r in rows[:20]), default=0) <= 1:
                rows = _read(fallback)
        except Exception:
            rows = _read(fallback)
        finally:
            csv.field_size_limit(old_limit)
    return [{"sheet": Path(filename).stem or "표", "rows": rows, "odd_cells": 0}]


def _from_hwpx(raw: bytes) -> list[dict]:
    """한글 문서의 표를 격자로. 표가 여럿이면 각각 한 장(sheet)으로 본다."""
    if len(raw) > MAX_BYTES:
        raise ValueError(f"한글 파일 크기 제한: {MAX_BYTES // 1024 // 1024} MB")
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except Exception as exc:
        raise ValueError("읽을 수 없는 HWPX 파일입니다") from exc
    with z:
        infos = z.infolist()
        if len(infos) > 10_000 or sum(i.file_size for i in infos) > 200 * 1024 * 1024:
            raise ValueError("압축 해제 크기 제한: 200 MB / 10,000개 항목")
        for i in infos:
            if i.filename.startswith(("/", "\\")) or ".." in i.filename.split("/"):
                raise ValueError("비정상 경로가 포함된 파일은 지원하지 않습니다")
        names = sorted(n for n in z.namelist() if re.match(r"Contents/section\d+\.xml", n))
        if not names:
            raise ValueError("HWPX 본문(section)을 찾지 못했습니다 —"
                             " 한글에서 'HWPX' 로 저장한 파일인지 확인하십시오")
        blobs, total = [], 0
        for n in names[:MAX_SHEETS]:
            b = z.read(n)
            if len(b) > MAX_XML_ONE:
                raise ValueError(f"본문 하나가 너무 큽니다({MAX_XML_ONE // 1024 // 1024} MB 제한)")
            total += len(b)
            if total > MAX_XML_TOTAL:
                raise ValueError(f"본문 합계가 너무 큽니다({MAX_XML_TOTAL // 1024 // 1024} MB 제한)")
            up = b.replace(b"\x00", b"").upper()
            if b"<!DOCTYPE" in up or b"<!ENTITY" in up:
                raise ValueError("외부 엔터티/DTD가 포함된 파일은 지원하지 않습니다")
            blobs.append(b)

    from lxml import etree
    from .report_custom import _cells
    from .report_forms import NS

    # 바이트 검사(위)에 더해 파서에도 뜻을 남긴다 — 다음 사람이 기본값을 바꿔도 의도가 코드에 있다
    parser = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True,
                             huge_tree=False, recover=False)
    out, tables, tcs, gridcells = [], 0, 0, 0
    for si, blob in enumerate(blobs):
        try:
            root = etree.fromstring(blob, parser=parser)
        except Exception as exc:
            raise ValueError("HWPX 본문을 읽을 수 없습니다") from exc
        for ti, tbl in enumerate(root.iter("{%s}tbl" % NS["hp"])):
            tables += 1
            if tables > MAX_TABLES:
                raise ValueError(f"표가 너무 많습니다 — {MAX_TABLES}개까지 읽습니다")
            tcs += len(tbl.findall("hp:tr/hp:tc", NS))
            if tcs > MAX_TC:
                raise ValueError(f"칸이 너무 많습니다 — {MAX_TC:,}칸까지 읽습니다")
            cells = _cells(tbl)
            if not cells:
                continue
            # span 을 편 뒤의 격자가 진짜 위험한 곳이다 — 원본 칸 20개로도 수백만 칸이 될 수 있다
            w = min(max(c for c, _ in cells) + 1, MAX_COLS)
            h = min(max(r for _, r in cells) + 1, MAX_ROWS + HEAD_SCAN)
            gridcells += w * h
            if gridcells > MAX_GRID_CELLS:
                raise ValueError(f"표가 너무 큽니다 — 합쳐서 {MAX_GRID_CELLS:,}칸까지 읽습니다")
            grid = [["" for _ in range(w)] for _ in range(h)]
            for (c, r), cell in cells.items():
                if c < w and r < h:
                    grid[r][c] = _cap(cell.get("text"))
            out.append({"sheet": f"표 {si + 1}-{ti + 1}", "rows": grid, "odd_cells": 0})
    if not out:
        raise ValueError("한글 문서에서 표를 찾지 못했습니다 — 자산 목록이 표로 되어 있어야 읽을 수 있습니다")
    return out


def read_tables(raw: bytes, filename: str) -> list[dict]:
    """파일 → 격자 목록. 종류를 모르면 '무엇을 올려야 하는지' 를 말한다."""
    if not raw:
        raise ValueError("빈 파일입니다")
    if len(raw) > MAX_BYTES:
        raise ValueError(f"파일 크기 제한: {MAX_BYTES // 1024 // 1024} MB")
    ext = Path(filename or "").suffix.lower()
    if ext == ".xlsx":
        return _from_xlsx(raw)
    if ext in (".csv", ".txt", ".tsv"):
        return _from_csv(raw, filename)
    if ext == ".hwpx":
        return _from_hwpx(raw)
    if ext in (".xls", ".hwp"):
        raise ValueError(f"{ext} 는 옛 형식이라 읽을 수 없습니다 —"
                         " 엑셀은 .xlsx 로, 한글은 .hwpx 로 다시 저장해 올려 주십시오")
    raise ValueError("엑셀(.xlsx) · CSV · 한글(.hwpx) 파일을 올려 주십시오"
                     f" — 받은 것: {ext or '확장자 없음'}")


# ── 고르는 항목의 값 맞추기 ────────────────────────────────────────────────
def _choice_maps(asset_type: str) -> dict:
    """{항목id: {보이는 말 → 우리 값}} — '상' 을 'high' 로. 한 번 만들어 두고 쓴다."""
    maps = {}
    for f in asset_spec.fields(asset_type):
        if f.get("kind") != "choice":
            continue
        m = {}
        for key, ko in (f.get("choice_ko") or {}).items():
            m[asset_spec._norm(key)] = key
            m[asset_spec._norm(ko)] = key
        for word, key in (("높음", "high"), ("중간", "mid"), ("낮음", "low"),
                          ("상급", "high"), ("하급", "low"),
                          ("critical", "high"), ("normal", "mid"),
                          ("서버", "server"), ("데이터베이스", "dbms"), ("db", "dbms"),
                          ("네트워크장비", "network"), ("솔루션", "sw"),
                          # 운영 환경 — 현장이 쓰는 말
                          ("production", "prod"), ("실운영", "prod"), ("상용", "prod"),
                          ("운영계", "prod"), ("real", "prod"),
                          ("staging", "stage"), ("스테이징", "stage"), ("검증계", "stage"),
                          ("development", "dev"), ("개발계", "dev"),
                          ("테스트", "test"), ("시험계", "test"),
                          # 운영 상태 — 죽어 있어야 정상인 것을 장애로 잡지 않게
                          ("운영중", "active"), ("사용중", "active"), ("정상", "active"),
                          ("가동중", "active"), ("running", "active"), ("사용", "active"),
                          ("예비", "standby"), ("이중화대기", "standby"), ("standby기", "standby"),
                          ("점검", "maintenance"), ("정비중", "maintenance"),
                          ("불용", "retired"), ("반납", "retired"), ("폐기예정", "retired"),
                          ("미사용", "retired"), ("철거", "retired"),
                          # 정보 출처
                          ("수기", "manual"), ("직접", "manual"), ("엑셀", "file"),
                          ("연동", "api"), ("자동", "discovered"), ("탐지", "discovered")):
            if key in (f.get("choice_ko") or {}):
                m.setdefault(asset_spec._norm(word), key)
        maps[f["id"]] = m
    return maps


# ── 값이 그 종류의 모양인가 ────────────────────────────────────────────────
# 모양을 못 맞추면 버리지 않고 <항목>_raw 로 옮긴다. raw 는 필수를 충족하지 않으므로,
# 뜻을 모르는 값으로 자산이 '완성' 되는 일이 없다.
_SHAPE_DATE = re.compile(r"^\d{4}[-./]\d{1,2}[-./]\d{1,2}")
_SHAPE_CODE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._/\-]{0,39}$")
SHAPES = {"date": _SHAPE_DATE, "code": _SHAPE_CODE}


def _is_ip(value: str) -> bool:
    """IPv4 든 IPv6 든 — 직접 만든 정규식으로 보면 현장의 IPv6 를 통째로 '확인 필요' 로 떨어뜨린다.

    fe80::1%eth0 처럼 구역 표시가 붙는 것도 현장에 있으므로 떼어 보고 판단한다(GPT 11차).
    """
    import ipaddress
    t = (value or "").strip()
    if not t:
        return False
    try:
        ipaddress.ip_address(t.split("%", 1)[0] if t.count("%") == 1 else t)
        return True
    except ValueError:
        return False


def _fits(kind: str, value: str) -> bool:
    kind = kind or ""
    if kind == "ip":
        return _is_ip(value)
    if kind == "code":
        t = (value or "").strip()
        # 'a/../../x' 같은 글자를 담아 두면, 나중에 누가 이 값을 경로 조각으로 쓰는 순간
        # 취약점이 된다. 지금은 DB 값일 뿐이지만 그 씨앗을 두지 않는다(GPT 11차).
        if ".." in t:
            return False
        return bool(_SHAPE_CODE.match(t))
    rx = SHAPES.get(kind)
    return True if rx is None else bool(rx.match((value or "").strip()))


def _put(rec: dict, fid: str, raw: str, maps: dict, kinds: dict = None) -> None:
    """칸 하나를 기록에 담는다.

    · 계정 칸에 'pw=...' 처럼 비밀이 섞여 있으면 **칸째 버린다** — 아이디만 잘라 살리려는
      순간 비밀번호를 읽게 된다(GPT 교차 검토).
    · 고르는 항목(유형·중요도)은 **아는 말일 때만** 우리 값을 넣는다. 모르는 말을 그 자리에
      그대로 넣으면 뒤에서 'high 인가?' 로 비교하는 코드가 조용히 어긋난다.
      모르는 말은 버리지 않고 `<항목>_raw` 에 남겨 사람이 고르게 한다.
    """
    m = maps.get(fid)
    # 어느 항목이든 마찬가지다 — 칸 안에 'pw=' 같은 표지가 있으면 통째로 버린다.
    # 현장이 만든 항목도 예외가 아니다('메모' 칸에 비밀번호를 적어 오는 일이 있다).
    hit = _SECRET_IN_CELL.search(raw)
    if hit:
        # 무엇이 걸렸는지만 남긴다 — **값은 절대 남기지 않는다**(GPT 9차: 진단 편의가 곧 우회 출구다)
        rec.setdefault("_dropped_cells", []).append(fid)
        rec.setdefault("_dropped_why", {})[fid] = hit
        return
    if not m:
        kind = (kinds or {}).get(fid)
        if kind and not _fits(kind, raw):
            # 모양이 아니면 그 자리에 넣지 않는다 — 넣으면 뒤에서 IP·날짜라고 믿고 쓴다
            rec[fid + "_raw"] = raw
            return
        rec[fid] = raw
        return
    known = m.get(asset_spec._norm(raw))
    if known:
        rec[fid] = known
    else:
        rec[fid + "_raw"] = raw


# ── 어느 줄이 머리글인가 ────────────────────────────────────────────────────
def find_header(rows, asset_type: str = "", extra=None, levels=None) -> dict:
    """머리글 줄을 고른다 — {"row": n, "confidence": "확실|추정", "why": ...}. 못 고르면 row=-1.

    양식마다 제목·부제가 몇 줄씩 붙는다. '우리 항목에 가장 많이 맞는 줄' 을 머리글로 본다 —
    칸이 많은 줄이 아니라. 제목 줄이 병합돼 칸이 많아 보이는 일이 흔하기 때문이다.

    비밀번호 열은 점수에 넣지 않는다(GPT 교차 검토): 자격증명 관리표(ID|PW|계정)가
    '좋은 자산 머리글' 로 뽑히는 역설이 생긴다. 민감 열 판정은 보안 신호일 뿐,
    여기가 머리글인지와는 다른 이야기다.
    """
    scored = []
    for i, row in enumerate(rows[:HEAD_SCAN]):
        filled = [c for c in row if str(c or "").strip()]
        if len(filled) < 2:
            continue
        m = asset_spec.map_headers([str(c or "") for c in row], asset_type, None, extra, levels)
        c = m["counts"]
        score = c["sure"] * 3 + c["guess"]
        scored.append((score, i, c))
    if not scored:
        return {"row": -1, "confidence": "", "why": "항목 이름이 한 줄에 나란히 있는 줄을 찾지 못했습니다"}
    scored.sort(key=lambda x: (-x[0], x[1]))
    score, i, c = scored[0]
    if c["sure"] < HEAD_MIN_SURE and (c["sure"] + c["guess"]) < HEAD_MIN_ANY:
        return {"row": -1, "confidence": "",
                "why": "우리 항목과 맞는 이름이 너무 적어 머리글을 확정하지 못했습니다 —"
                       " 어느 줄이 머리글인지 골라 주십시오"}
    conf = "확실"
    if len(scored) > 1 and scored[1][0] >= score - 1:
        conf = "추정"          # 1·2등이 근소하면 확정하지 않는다
    return {"row": i, "confidence": conf,
            "why": "" if conf == "확실" else "비슷한 줄이 더 있어 확정하지 못했습니다 — 맞는지 확인해 주십시오"}


def scrub(rows, header_row: int) -> dict:
    """민감 열을 **격자에서 지운다**. 이 뒤로는 어떤 경로로도 그 값에 닿을 수 없다.

    읽는 순간 그 칸도 파이썬 값이 되는 것은 막을 수 없다(openpyxl·csv·lxml 이 그렇게 동작한다).
    막을 수 있는 것은 '그 값이 여기서 한 발짝도 더 나가지 못하게' 하는 것이고, 그것을 여기서 한다.
    미리보기·기록·오류 메시지·저장 어디에도 닿지 않는다.
    """
    if header_row < 0 or header_row >= len(rows):
        return {"dropped": {}, "count": 0}
    headers = [str(c or "") for c in rows[header_row]]
    hit = {}
    for i, h in enumerate(headers):
        key = asset_spec.is_dropped(h)
        if key:
            hit[str(i)] = key
    if hit:
        idx = {int(i) for i in hit}
        for n, r in enumerate(rows):
            if n == header_row:
                continue          # 이름은 남긴다 — 어느 열을 왜 지웠는지 말해 줘야 한다
            for i in idx:
                if i < len(r):
                    r[i] = ""
    return {"dropped": hit, "count": len(hit)}


def for_spreadsheet(value: str) -> str:
    """표 계산기로 **내보낼 때** 수식으로 실행되지 않게 한다(GPT 교차 검토).

    들여올 때는 원문을 그대로 둔다 — 고객 자료를 우리가 훼손하면 안 된다.
    위험은 우리가 그것을 다시 .xlsx/.csv 로 내보내 누가 열 때 생기므로, 그 경계에서 막는다.
    """
    t = "" if value is None else str(value)
    probe = t.lstrip(chr(9) + chr(10) + chr(13))      # 앞의 제어문자로 검사를 비켜 가지 못하게
    return ("'" + t) if probe[:1] in ("=", "+", "-", "@") else t


# ── 미리보기 ────────────────────────────────────────────────────────────────
def preview(raw: bytes, filename: str, asset_type: str = "", extra=None, levels=None) -> dict:
    """올린 파일을 읽어 '무엇을 어떻게 채울 것인지' 를 먼저 보여 준다.

    아직 저장하지 않는다 — 추정·모름을 사람이 고친 뒤에 저장한다.
    """
    tables = read_tables(raw, filename)
    sheets = []
    for t in tables:
        rows = t["rows"]
        head = find_header(rows, asset_type, extra, levels)
        hi = head["row"]
        if hi < 0:
            sheets.append({"sheet": t["sheet"], "header_row": -1, "rows": 0,
                           "note": head["why"]})
            continue
        gone = scrub(rows, hi)          # 여기서 민감 열을 지운다 — 아래로는 값이 내려가지 않는다
        headers = [str(c or "").strip() for c in rows[hi]]
        body = [r for r in rows[hi + 1:] if any(str(c or "").strip() for c in r)]
        samples = {}
        for ci in range(len(headers)):
            samples[ci] = [r[ci] for r in body[:20] if ci < len(r) and str(r[ci] or "").strip()][:5]
        m = asset_spec.map_headers(headers, asset_type, samples, extra, levels)
        drop_idx = {int(k) for k in m["dropped"]}
        take = [(c["index"], c["field"]) for c in m["columns"]
                if c["field"] and c["index"] not in drop_idx]
        maps = _choice_maps(asset_type)
        kinds = {f["id"]: f.get("kind")
                 for f in asset_spec.fields(asset_type, extra, levels)}
        preview_rows = []
        for r in body[:SAMPLE]:
            rec = {}
            for ci, fid in take:
                if ci < len(r):
                    v = str(r[ci] or "").strip()
                    if v:
                        _put(rec, fid, v[:MAX_CELL], maps, kinds)
            preview_rows.append(rec)
        sheets.append({
            "sheet": t["sheet"], "header_row": hi, "headers": headers,
            "header_confidence": head["confidence"], "header_note": head["why"],
            "rows": len(body), "mapping": m, "samples": preview_rows,
            "odd_cells": t.get("odd_cells", 0), "dropped": gone["dropped"],
            # 칸 안에 자격 정보로 보이는 값이 있어 가져오지 않은 칸의 **개수**만 — 값은 담지 않는다
            "dropped_cells": sum(len(r.get("_dropped_cells") or []) for r in preview_rows),
            "checked": asset_spec.check(preview_rows[0] if preview_rows else {},
                                        asset_type, extra, levels),
        })
    dropped = sum(s.get("dropped") and len(s["dropped"]) or 0 for s in sheets)
    return {"file": Path(filename or "").name, "type": asset_type or "",
            "scope": "type" if asset_type else "common",
            "type_requirements_checked": bool(asset_type),
            "sheets": sheets, "dropped_columns": dropped,
            "note": ("민감한 열 %d개는 지웠습니다 — 비밀번호·키·자격 정보는 미리보기에도"
                     " 저장에도 남지 않습니다." % dropped) if dropped else ""}


def records(raw: bytes, filename: str, asset_type: str = "", mapping: dict = None,
            extra=None, levels=None) -> dict:
    """확인이 끝난 매핑으로 전 줄을 우리 항목에 담는다.

    mapping: {"<시트>": {"<열 번호>": "<항목 id>"}} — 사람이 고친 결과. 없으면 자동 매핑 그대로.
    """
    tables = read_tables(raw, filename)
    out, skipped = [], 0
    for t in tables:
        rows = t["rows"]
        head = find_header(rows, asset_type, extra, levels)
        hi = head["row"]
        if hi < 0:
            continue
        gone = scrub(rows, hi)          # 지우고 시작한다 — 사람이 매핑을 고쳐도 되살아나지 않는다
        headers = [str(c or "").strip() for c in rows[hi]]
        auto = asset_spec.map_headers(headers, asset_type, None, extra, levels)
        drop_idx = {int(k) for k in auto["dropped"]} | {int(k) for k in gone["dropped"]}
        chosen = (mapping or {}).get(t["sheet"])
        if chosen:
            take = [(int(k), v) for k, v in chosen.items() if v and int(k) not in drop_idx]
        else:
            take = [(c["index"], c["field"]) for c in auto["columns"]
                    if c["field"] and c["index"] not in drop_idx]
        maps = _choice_maps(asset_type)
        kinds = {f["id"]: f.get("kind")
                 for f in asset_spec.fields(asset_type, extra, levels)}
        for r in rows[hi + 1:]:
            if not any(str(c or "").strip() for c in r):
                continue
            rec = {}
            for ci, fid in take:
                if ci < len(r):
                    v = str(r[ci] or "").strip()
                    if v:
                        _put(rec, fid, v[:MAX_CELL], maps, kinds)
            if not rec:
                skipped += 1
                continue
            rec["_sheet"] = t["sheet"]
            out.append(rec)
            if len(out) >= MAX_ROWS:
                break
    done = [dict(r, _check=asset_spec.check(r, asset_type, extra, levels)) for r in out]
    incomplete = sum(1 for r in done if not r["_check"]["complete"])
    return {"records": done, "count": len(done), "skipped": skipped,
            "incomplete": incomplete,
            "note": f"{incomplete}건은 필수 항목이 비어 [미완성] 입니다." if incomplete else ""}
