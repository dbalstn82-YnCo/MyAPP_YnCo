"""자산 관리 v3 — 업로드한 엑셀 문서 자체가 기준.
어떤 양식이든 시트·행·열을 그대로 읽어(병합 셀은 범위 전체에 값을 채우고 병합 정보도 보존) 저장하고,
큰 화면에서 시트별로 보고 검색하며, 원본 그대로 또는 현재 표를 XLSX 로 다시 내려받는다.
저장: data/inventory/resources.sqlite3 의 docs 테이블(원본 파일 + 파싱 JSON). 이전 양식 기반 표(resource_items)는 그대로 둔다.
GPT 교차 검토(collect/verify/resp_inventory_docs_2026-09-14.txt) 반영: 보이는 행 기준 병합 블록, 숨김 행·열 보존, 가로 병합만 제목 판정,
숫자형만 제목 제외, 원본 열 너비·표시 형식 보존, 문자열 셀 강제, 파일명 정제.
"""
from __future__ import annotations
import hashlib
import io
import json
import re
import time
import zlib
from datetime import date, datetime
from pathlib import Path
from .inventory import _load_workbook, workbook as _check_workbook
from .nms import Store

MAX_SHEETS = 30
MAX_ROWS_TOTAL = 20000
MAX_COLS = 120
MAX_CELL = 4000
HEADER_SCAN = 12
MAX_EDIT_OPS = 500       # 한 번의 편집 요청에 담을 수 있는 작업 수
MAX_ROW_BATCH = 200      # 한 번에 추가/삭제할 수 있는 행 수
UNDO_KEEP = 20           # 되돌리기용 시트 스냅샷 보관 수(문서별)
EDIT_LOG_KEEP = 500      # 변경 이력 보관 수(문서별)


class EditConflict(ValueError):
    """다른 사용자가 먼저 수정(rev 불일치) — HTTP 409"""


def _cell_value(c):
    """저장값: 문자열은 그대로(선행 0 보존), 숫자는 숫자, 날짜는 ISO 문자열(원본 형식은 fmt 에 별도 저장), 수식은 '(수식) =...' 표시만."""
    v = c.value
    if v is None:
        return None
    if isinstance(v, (datetime, date)):
        return v.isoformat(sep=' ') if isinstance(v, datetime) else v.isoformat()
    if isinstance(v, bool):
        return '예' if v else '아니오'
    if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
        return int(v)
    if isinstance(v, (int, float)):
        return v
    s = str(v)
    if s.startswith('='):  # 수식은 값이 아니라 식 — 표시만 하고 계산하지 않음(원본은 BLOB 에 보존)
        s = '(수식) ' + s
    return s[:MAX_CELL]


def _looks_like_header(vals) -> bool:
    """열 이름 행 판정: 값 3개 이상, 숫자형 셀 없음(문자열 안의 숫자는 허용), 모두 60자 이하."""
    cells = [v for v in vals if v is not None and v != '']
    if len(cells) < 3:
        return False
    for v in cells:
        if isinstance(v, (int, float)):
            return False
        if len(str(v)) > 60:
            return False
    return True


_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _cell_shape(v):
    """칸 모양 — 숫자 포함·한글·영문·IP 꼴. 빈 칸은 None."""
    if v is None or v == '':
        return None
    if isinstance(v, (int, float)):
        return 'num'
    t = str(v).strip()
    return (bool(re.search(r'\d', t)), bool(re.search(r'[가-힣]', t)), bool(re.search(r'[A-Za-z]', t)), bool(_IP_RE.match(t)))


def _same_shape(a, b) -> bool:
    """두 행의 칸 모양이 60% 이상 같으면 같은 종류(데이터) 행."""
    pairs = [(_cell_shape(x), _cell_shape(y)) for x, y in zip(a, b)]
    used = [(x, y) for x, y in pairs if x is not None or y is not None]
    if not used:
        return False
    return sum(1 for x, y in used if x == y) >= 0.6 * len(used)


def safe_filename(name: str, default: str = 'workbook.xlsx') -> str:
    name = re.sub(r'[\x00-\x1f\x7f/\\:*?"<>|]+', '_', str(name or '')).strip().strip('.')
    return name[:150] or default


def parse_workbook(raw: bytes, name: str = '') -> dict:
    """→ {'name','sheets':[{'name','nrows','ncols','header_rows','merges':[[r1,c1,r2,c2]...],'rows':[[row_no,[cells...]],...],
         'hidden_rows':[...],'hidden_cols':[...],'widths':{col:width},'fmt':{'r:c':number_format}}], 'total_rows'}
    rows 는 값이 하나라도 있는 행만(원본 행 번호 유지, 순서 그대로). 병합 셀은 범위 전체에 왼쪽 위 값을 채운다."""
    _check_workbook(raw)  # 크기·zip 폭탄·DTD·매크로·경로 검사 (read_only 로 한 번 열어 봄)
    load_workbook = _load_workbook()
    wb = load_workbook(io.BytesIO(raw), read_only=False, data_only=False, keep_links=False, keep_vba=False)
    try:
        if len(wb.sheetnames) > MAX_SHEETS:
            raise ValueError(f'시트는 최대 {MAX_SHEETS}개')
        sheets = []; total = 0
        for ws in wb.worksheets:
            ncols = ws.max_column or 1
            nrows = ws.max_row or 1
            if ncols > MAX_COLS:
                raise ValueError(f"시트 '{ws.title}' 의 열이 {ncols}개 — 최대 {MAX_COLS}열")
            merges = []
            for rng in ws.merged_cells.ranges:
                merges.append([rng.min_row, rng.min_col, rng.max_row, rng.max_col])
            merge_val = {}  # (r,c) → 왼쪽 위 값
            for (r1, c1, r2, c2) in merges:
                v = _cell_value(ws.cell(r1, c1))
                if v is None:
                    continue
                for r in range(r1, r2 + 1):
                    for c in range(c1, c2 + 1):
                        merge_val[(r, c)] = v
            rows = []; fmt = {}
            for r_idx, row in enumerate(ws.iter_rows(min_row=1, max_row=nrows, max_col=ncols), start=1):
                vals = []
                any_val = False
                for c_idx, cell in enumerate(row, start=1):
                    v = _cell_value(cell)
                    if v is None:
                        v = merge_val.get((r_idx, c_idx))
                    else:
                        nf = cell.number_format
                        if nf and nf != 'General' and isinstance(cell.value, (int, float, datetime, date)):
                            fmt[f'{r_idx}:{c_idx}'] = nf[:40]
                    vals.append(v)
                    if v is not None and v != '':
                        any_val = True
                if any_val:
                    rows.append([r_idx, vals])
                    total += 1
                    if total > MAX_ROWS_TOTAL:
                        raise ValueError(f'전체 {MAX_ROWS_TOTAL:,}행 제한을 넘었습니다')
            # 제목 행 추정: 상단 12행 안의 가로 병합(그룹 제목)만 기준. 세로 병합(데이터 묶음)은 제외
            h = 0
            for (r1, c1, r2, c2) in merges:
                if r1 <= HEADER_SCAN and c2 > c1:
                    h = max(h, r2)
            hdr_rows = sum(1 for r in rows if r[0] <= h)
            if hdr_rows == 0 and rows:
                hdr_rows = 1 if _looks_like_header(rows[0][1]) or len(rows) == 1 else 0
                if hdr_rows == 0:
                    hdr_rows = 1  # 최소 1행은 제목으로 두고 사용자가 조정
            extra = 0
            # 추가 제목 행: 숫자형 셀이 없고, 채워진 칸 수가 바로 위 제목 행의 60% 이상일 때만(첫 데이터 행이 글자만이어도 삼키지 않음)
            def _filled(v): return sum(1 for x in v if x is not None and x != '')
            # (모든 칸이 글자인 장비 대장에서 데이터 행을 삼키지 않도록: 바로 아래 행과 모양이 같으면 데이터)
            while hdr_rows < len(rows) - 1 and extra < 2 and _looks_like_header(rows[hdr_rows][1])                     and (hdr_rows == 0 or _filled(rows[hdr_rows][1]) >= 0.6 * _filled(rows[hdr_rows - 1][1]))                     and not any(_same_shape(rows[hdr_rows][1], rows[k][1]) for k in range(hdr_rows + 1, min(len(rows), hdr_rows + 4))):
                hdr_rows += 1; extra += 1
            hidden_rows = sorted(r for r, d in ws.row_dimensions.items() if d.hidden and r <= nrows)
            hidden_cols = sorted({idx for k, d in ws.column_dimensions.items() if d.hidden
                                  for idx in range(d.min or 0, (d.max or 0) + 1) if 1 <= idx <= ncols})
            widths = {}
            for k, d in ws.column_dimensions.items():
                if d.width and d.min and d.max:
                    for idx in range(d.min, min(d.max, ncols) + 1):
                        widths[str(idx)] = round(float(d.width), 1)
            sheets.append({'name': ws.title[:80], 'nrows': len(rows), 'ncols': ncols, 'header_rows': hdr_rows,
                           'header_auto': hdr_rows, 'header_auto_extra': extra,   # 자동으로 더 붙인 제목 행 수 — 보기 화면이 '확인' 안내
                           'merges': merges, 'rows': rows, 'hidden_rows': hidden_rows, 'hidden_cols': hidden_cols,
                           'widths': widths, 'fmt': fmt})
        return {'name': safe_filename(Path(name).name), 'sheets': sheets, 'total_rows': total}
    finally:
        wb.close()


def merge_blocks(merges, visible_rows):
    """보이는 행(원본 행 번호, 순서대로) 기준으로 병합 범위를 연속 블록으로 나눈다 → [(첫 행 번호, c1, 행 수, 열 수, 첫 행 index)]
    검색으로 일부 행만 남거나 제목/데이터 경계를 넘는 경우에도 원본 구조를 덮지 않는다."""
    idx = {rno: i for i, rno in enumerate(visible_rows)}
    out = []
    for (r1, c1, r2, c2) in merges:
        rows_in = [idx[r] for r in range(r1, r2 + 1) if r in idx]
        if not rows_in:
            continue
        rows_in.sort()
        run = [rows_in[0]]
        for i in rows_in[1:]:
            if i == run[-1] + 1:
                run.append(i)
            else:
                out.append((visible_rows[run[0]], c1, len(run), c2 - c1 + 1, run[0])); run = [i]
        out.append((visible_rows[run[0]], c1, len(run), c2 - c1 + 1, run[0]))
    return [b for b in out if b[2] > 1 or b[3] > 1]


def edit_value(v):
    """화면에서 입력한 값 → 저장값. 빈 문자열은 None, 정수/소수 형태(선행 0 없는)는 숫자, 수식('=' 시작)은 표시용 문자열."""
    if v is None:
        return None
    if isinstance(v, bool):
        return '예' if v else '아니오'
    if isinstance(v, (int, float)):
        if isinstance(v, float) and v.is_integer() and abs(v) < 1e15:
            return int(v)
        return v
    s = str(v).rstrip('\r\n')
    if len(s) > MAX_CELL:
        raise ValueError(f'셀 값은 {MAX_CELL:,}자까지')
    if s.strip() == '':
        return None
    st = s.strip()
    if re.fullmatch(r'-?\d{1,15}', st) and not re.match(r'-?0\d', st):
        return int(st)
    if re.fullmatch(r'-?\d{1,15}\.\d{1,10}', st) and not re.match(r'-?0\d', st) and len(st.replace('-', '').replace('.', '').lstrip('0')) <= 15:
        return float(st)   # 유효 숫자 15자리 초과(자산번호·고정밀 값)는 float 변환 시 손실 → 문자열 유지
    if st.startswith('=') and not s.startswith('(수식)'):
        s = '(수식) ' + st   # 수식은 계산하지 않음 — 표시용 문자열로만 저장
    return s


def _col_letter(c: int) -> str:
    out = ''
    while c > 0:
        c, r = divmod(c - 1, 26); out = chr(65 + r) + out
    return out


def _as_int(v, name, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f'{name} 은 정수여야 합니다')
    if not lo <= v <= hi:
        raise ValueError(f'{name} 범위 오류 ({lo}~{hi})')
    return v


def _shift_cols(s: dict, at: int, count: int):
    """열 삽입(at 열 앞에 count개): 행 값·병합·숨김 열·너비·표시 형식을 함께 이동. 병합 범위 안에 삽입하면 범위를 넓힌다(Excel 과 동일)."""
    for row in s['rows']:
        vals = row[1]
        while len(vals) < s['ncols']:
            vals.append(None)
        vals[at - 1:at - 1] = [None] * count
    nm = []
    for (r1, c1, r2, c2) in s['merges']:
        if c1 >= at:
            c1 += count; c2 += count
        elif c2 >= at:
            c2 += count
        nm.append([r1, c1, r2, c2])
    s['merges'] = nm
    s['hidden_cols'] = sorted(c + count if c >= at else c for c in s.get('hidden_cols', []))
    s['widths'] = {(str(int(k) + count) if int(k) >= at else k): v for k, v in s.get('widths', {}).items()}
    fmt = {}
    for k, v in s.get('fmt', {}).items():
        r, c = k.split(':'); c = int(c)
        fmt[f'{r}:{c + count if c >= at else c}'] = v
    s['fmt'] = fmt
    s['ncols'] += count


def _drop_cols(s: dict, cols: set):
    """열 삭제: 병합 범위는 남는 열 기준으로 줄이고(모두 삭제되면 제거), 숨김 열·너비·표시 형식도 다시 번호 매김."""
    def newc(c): return c - sum(1 for d in cols if d < c)
    for row in s['rows']:
        row[1] = [v for i, v in enumerate(row[1], start=1) if i not in cols]
    nm = []
    for (r1, c1, r2, c2) in s['merges']:
        kept = [c for c in range(c1, c2 + 1) if c not in cols]
        if not kept:
            continue
        a, b = newc(kept[0]), newc(kept[-1])
        if r1 == r2 and a == b:
            continue
        nm.append([r1, a, r2, b])
    s['merges'] = nm
    s['hidden_cols'] = sorted(newc(c) for c in s.get('hidden_cols', []) if c not in cols)
    s['widths'] = {str(newc(int(k))): v for k, v in s.get('widths', {}).items() if int(k) not in cols}
    s['fmt'] = {f"{k.split(':')[0]}:{newc(int(k.split(':')[1]))}": v for k, v in s.get('fmt', {}).items() if int(k.split(':')[1]) not in cols}
    s['ncols'] -= len(cols)


def apply_edit_op(s: dict, op: dict, total_rows: int) -> tuple[str, int]:
    """시트 dict 에 편집 작업 하나를 적용 → (요약, 전체 행 수 증감).
    set: {r,c,v}  insert_rows: {at,count,copy_from?}  delete_rows: {rows:[...]}  insert_cols: {at,count}  delete_cols: {cols:[...]}
    r 은 rows 목록의 0 기반 index(원본 행 번호가 아님), c/at/cols 는 1 기반 열 번호."""
    if not isinstance(op, dict):
        raise ValueError('작업 형식 오류')
    kind = op.get('op'); rows = s['rows']; ncols = s['ncols']; hdr = s['header_rows']
    if kind == 'set':
        r = _as_int(op.get('r'), '행', 0, len(rows) - 1); c = _as_int(op.get('c'), '열', 1, ncols)
        v = edit_value(op.get('v')); rno = rows[r][0]
        targets = [(r, c)]
        if rno is not None:  # 병합 셀이면 범위 전체(원본 행 번호가 있는 행)에 같은 값 — '병합 범위 값 채움' 규칙 유지
            for (r1, c1, r2, c2) in s['merges']:
                if r1 <= rno <= r2 and c1 <= c <= c2:
                    pos = {row[0]: i for i, row in enumerate(rows) if row[0] is not None}
                    targets = [(pos[rr], cc) for rr in range(r1, r2 + 1) if rr in pos for cc in range(c1, c2 + 1)]
                    break
        for (ri, ci) in targets:
            vals = rows[ri][1]
            while len(vals) < ncols:
                vals.append(None)
            old = vals[ci - 1]; vals[ci - 1] = v
            if isinstance(v, str) or v is None or isinstance(old, str):
                s.get('fmt', {}).pop(f'{rows[ri][0]}:{ci}', None)   # 문자열이 되거나(날짜 ISO 문자열→숫자 포함) 비면 숫자·날짜 표시 형식 해제
        return f'{_col_letter(c)}{rno if rno is not None else "(신규)"} 수정', 0
    if kind == 'insert_rows':
        at = _as_int(op.get('at'), '위치', 0, len(rows)); count = _as_int(op.get('count', 1), '개수', 1, MAX_ROW_BATCH)
        if total_rows + count > MAX_ROWS_TOTAL:
            raise ValueError(f'전체 {MAX_ROWS_TOTAL:,}행 제한을 넘습니다')
        src = op.get('copy_from')
        base = list(rows[_as_int(src, '복제 원본', 0, len(rows) - 1)][1]) if src is not None else [None] * ncols
        rows[at:at] = [[None, list(base)] for _ in range(count)]
        if at < hdr:
            s['header_rows'] = hdr + count
        return f'행 {count}개 {"복제" if src is not None else "추가"}(위치 {at + 1})', count
    if kind == 'delete_rows':
        idx = op.get('rows')
        if not isinstance(idx, list) or not 0 < len(idx) <= MAX_ROW_BATCH:
            raise ValueError(f'삭제할 행은 1~{MAX_ROW_BATCH}개')
        idx = sorted({_as_int(i, '행', 0, len(rows) - 1) for i in idx})
        hdr_del = [i for i in idx if i < hdr]
        if any(rows[i][0] is not None for i in hdr_del):   # 원본 제목 행은 보호, 편집으로 추가한 행(row_no 없음)은 제목 영역이어도 삭제 가능
            raise ValueError('제목 행은 삭제할 수 없습니다 — 먼저 제목 행 수를 줄이십시오')
        gone = {rows[i][0] for i in idx if rows[i][0] is not None}
        s['rows'] = [row for i, row in enumerate(rows) if i not in set(idx)]
        s['header_rows'] = hdr - len(hdr_del)
        s['hidden_rows'] = [r for r in s.get('hidden_rows', []) if r not in gone]
        s['fmt'] = {k: v for k, v in s.get('fmt', {}).items() if int(k.split(':')[0]) not in gone} if gone else s.get('fmt', {})
        if gone:  # 생존 행이 하나도 없는 병합은 정리(stale merge 방지)
            alive = {row[0] for row in s['rows'] if row[0] is not None}
            s['merges'] = [m for m in s['merges'] if any(r in alive for r in range(m[0], m[2] + 1))]
        return f'행 {len(idx)}개 삭제', -len(idx)
    if kind == 'insert_cols':
        at = _as_int(op.get('at'), '위치', 1, ncols + 1); count = _as_int(op.get('count', 1), '개수', 1, 20)
        if ncols + count > MAX_COLS:
            raise ValueError(f'열은 최대 {MAX_COLS}개')
        _shift_cols(s, at, count)
        return f'열 {count}개 추가({_col_letter(at)} 앞)', 0
    if kind == 'delete_cols':
        cols = op.get('cols')
        if not isinstance(cols, list) or not 0 < len(cols) <= 50:
            raise ValueError('삭제할 열은 1~50개')
        cols = {_as_int(c, '열', 1, ncols) for c in cols}
        if len(cols) >= ncols:
            raise ValueError('열은 최소 1개 남아야 합니다')
        _drop_cols(s, cols)
        return f'열 {len(cols)}개 삭제({", ".join(_col_letter(c) for c in sorted(cols))})', 0
    raise ValueError(f'알 수 없는 작업: {kind!r}')


class DocStore(Store):
    """업로드 문서 저장소 — nms.Store 의 db() 만 재사용."""

    def __init__(self, path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript('''PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY,name TEXT,at REAL,sha256 TEXT,size INTEGER,
              sheets INTEGER,rows INTEGER,original BLOB,data TEXT,header_json TEXT DEFAULT '{}');
            CREATE TABLE IF NOT EXISTS doc_edits(id INTEGER PRIMARY KEY,doc_id INTEGER,at REAL,sheet TEXT,summary TEXT,rev INTEGER,snap BLOB,
              undone INTEGER DEFAULT 0,actor TEXT);
            CREATE INDEX IF NOT EXISTS doc_edits_doc ON doc_edits(doc_id,id);
            ''')
            cols = {r[1] for r in db.execute('PRAGMA table_info(docs)')}
            for name, ddl in (('rev', 'INTEGER DEFAULT 0'), ('edits', 'INTEGER DEFAULT 0'), ('edited_at', 'REAL')):
                if name not in cols:
                    db.execute(f'ALTER TABLE docs ADD COLUMN {name} {ddl}')
            cols = {r[1] for r in db.execute('PRAGMA table_info(doc_edits)')}
            for name, ddl in (('undone', 'INTEGER DEFAULT 0'), ('actor', 'TEXT')):
                if name not in cols:
                    db.execute(f'ALTER TABLE doc_edits ADD COLUMN {name} {ddl}')

    def add(self, raw: bytes, name: str) -> dict:
        parsed = parse_workbook(raw, name)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT count(*) FROM docs').fetchone()[0] >= 200:
                raise ValueError('문서는 최대 200개 — 오래된 문서를 삭제하십시오')
            cur = db.execute('INSERT INTO docs(name,at,sha256,size,sheets,rows,original,data) VALUES(?,?,?,?,?,?,?,?)',
                             (parsed['name'], time.time(), hashlib.sha256(raw).hexdigest(), len(raw), len(parsed['sheets']), parsed['total_rows'],
                              raw, json.dumps(parsed, ensure_ascii=False)))
            doc_id = cur.lastrowid
        return {'id': doc_id, 'name': parsed['name'], 'sheets': [(s['name'], s['nrows'], s['ncols']) for s in parsed['sheets']], 'rows': parsed['total_rows']}

    def list(self) -> list:
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT id,name,at,sha256,size,sheets,rows,rev,edits,edited_at FROM docs ORDER BY at DESC')]

    def sheet_names(self, doc_id: int) -> list:
        with self.db() as db:
            r = db.execute('SELECT data FROM docs WHERE id=?', (doc_id,)).fetchone()
        return [s['name'] for s in json.loads(r['data'])['sheets']] if r else []

    def get(self, doc_id: int) -> dict:
        with self.db() as db:
            r = db.execute('SELECT id,name,at,sha256,size,data,header_json,rev,edits,edited_at FROM docs WHERE id=?', (doc_id,)).fetchone()
        if not r:
            raise ValueError('문서가 없습니다')
        data = json.loads(r['data']); over = json.loads(r['header_json'] or '{}')
        for s in data['sheets']:
            if s['name'] in over:
                s['header_rows'] = max(0, min(int(over[s['name']]), s['nrows']))
                s['header_set'] = True   # 사람이 정한 제목 행 수 — 자동 추정 안내를 끈다
        data.update({'id': r['id'], 'at': r['at'], 'sha256': r['sha256'], 'size': r['size'], 'rev': r['rev'] or 0, 'edits': r['edits'] or 0, 'edited_at': r['edited_at']})
        return data

    def original(self, doc_id: int):
        with self.db() as db:
            r = db.execute('SELECT name,original FROM docs WHERE id=?', (doc_id,)).fetchone()
        if not r:
            raise ValueError('문서가 없습니다')
        return safe_filename(r['name']), bytes(r['original'])

    def set_header(self, doc_id: int, sheet: str, header_rows: int):
        if not isinstance(header_rows, int) or not 0 <= header_rows <= 50:
            raise ValueError('제목 행 수는 0~50')
        with self.db() as db:
            r = db.execute('SELECT header_json FROM docs WHERE id=?', (doc_id,)).fetchone()
            if not r:
                raise ValueError('문서가 없습니다')
            over = json.loads(r['header_json'] or '{}'); over[sheet] = header_rows
            db.execute('UPDATE docs SET header_json=? WHERE id=?', (json.dumps(over, ensure_ascii=False), doc_id))
        return {'ok': True}

    def delete(self, doc_id: int):
        with self.db() as db:
            if not db.execute('DELETE FROM docs WHERE id=?', (doc_id,)).rowcount:
                raise ValueError('문서가 없습니다')
            db.execute('DELETE FROM doc_edits WHERE doc_id=?', (doc_id,))
        return {'ok': True}

    # ── 편집: 셀 수정·행/열 추가·삭제·되돌리기 (문서 rev 로 동시 수정 충돌 검사, 시트 스냅샷으로 되돌리기) ──
    def _load_for_edit(self, db, doc_id: int, rev):
        r = db.execute('SELECT id,name,data,header_json,rev,edits FROM docs WHERE id=?', (doc_id,)).fetchone()
        if not r:
            raise ValueError('문서가 없습니다')
        if rev is not None and int(rev) != (r['rev'] or 0):
            raise EditConflict('다른 사용자가 먼저 수정했습니다 — 화면을 새로 고친 뒤 다시 시도하십시오')
        data = json.loads(r['data']); over = json.loads(r['header_json'] or '{}')
        for s in data['sheets']:
            if s['name'] in over:
                s['header_rows'] = max(0, min(int(over[s['name']]), len(s['rows'])))
        return r, data, over

    def _save_edit(self, db, r, data, over, sheet: dict, summary: str, snap, at: float, actor=None):
        sheet['nrows'] = len(sheet['rows']); over[sheet['name']] = sheet['header_rows']
        data['total_rows'] = sum(len(s['rows']) for s in data['sheets'])
        new_rev = (r['rev'] or 0) + 1
        edits = max(0, (r['edits'] or 0) + (1 if snap is not None else -1))
        db.execute('UPDATE docs SET data=?,header_json=?,rev=?,edits=?,edited_at=?,rows=? WHERE id=?',
                   (json.dumps(data, ensure_ascii=False), json.dumps(over, ensure_ascii=False), new_rev, edits, at, data['total_rows'], r['id']))
        db.execute('INSERT INTO doc_edits(doc_id,at,sheet,summary,rev,snap,actor) VALUES(?,?,?,?,?,?,?)', (r['id'], at, sheet['name'], summary, new_rev, snap, (actor or '')[:64]))
        db.execute('UPDATE doc_edits SET snap=NULL WHERE doc_id=? AND snap IS NOT NULL AND id NOT IN (SELECT id FROM doc_edits WHERE doc_id=? AND snap IS NOT NULL ORDER BY id DESC LIMIT ?)',
                   (r['id'], r['id'], UNDO_KEEP))
        db.execute('DELETE FROM doc_edits WHERE doc_id=? AND id NOT IN (SELECT id FROM doc_edits WHERE doc_id=? ORDER BY id DESC LIMIT ?)', (r['id'], r['id'], EDIT_LOG_KEEP))
        return {'ok': True, 'rev': new_rev, 'edits': edits, 'edited_at': at, 'total_rows': data['total_rows'], 'sheet': sheet, 'summary': summary}

    def edit(self, doc_id: int, sheet: str, rev, ops: list, actor=None) -> dict:
        """편집 작업 목록을 한 트랜잭션으로 적용. 적용 전 시트 스냅샷(zlib)을 남겨 되돌리기 가능. → {rev, sheet(갱신된 시트), summary}"""
        if not isinstance(ops, list) or not 0 < len(ops) <= MAX_EDIT_OPS:
            raise ValueError(f'작업은 1~{MAX_EDIT_OPS}개')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            r, data, over = self._load_for_edit(db, doc_id, rev)
            s = next((x for x in data['sheets'] if x['name'] == sheet), None)
            if s is None:
                raise ValueError('시트가 없습니다')
            snap = zlib.compress(json.dumps(s, ensure_ascii=False).encode('utf-8'))
            total = data['total_rows']; parts = []
            for op in ops:
                msg, d = apply_edit_op(s, op, total); total += d; parts.append(msg)
            summary = parts[0] if len(parts) == 1 else f'{parts[0]} 외 {len(parts) - 1}건'
            return self._save_edit(db, r, data, over, s, summary[:200], snap, time.time(), actor)

    def undo(self, doc_id: int, rev, sheet: str = '', actor=None) -> dict:
        """가장 최근 편집(스냅샷이 남아 있고 아직 되돌리지 않은)을 되돌린다 — 그 시트 전체를 편집 직전 상태로.
        sheet 를 주면 그 시트의 최근 변경만 대상(다른 시트 편집을 건드리지 않음). 원래 이력은 지우지 않고 undone 표시(감사용)."""
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            r, data, over = self._load_for_edit(db, doc_id, rev)
            q = 'SELECT id,sheet,summary,snap FROM doc_edits WHERE doc_id=? AND snap IS NOT NULL AND undone=0'
            args = [doc_id]
            if sheet:
                q += ' AND sheet=?'; args.append(sheet)
            e = db.execute(q + ' ORDER BY id DESC LIMIT 1', args).fetchone()
            if not e:
                raise ValueError('되돌릴 변경이 없습니다' + (f" (시트 '{sheet}')" if sheet else ''))
            prev = json.loads(zlib.decompress(e['snap']).decode('utf-8'))
            for i, s in enumerate(data['sheets']):
                if s['name'] == e['sheet']:
                    data['sheets'][i] = prev; break
            else:
                raise ValueError('되돌릴 시트가 없습니다')
            db.execute('UPDATE doc_edits SET undone=1, snap=NULL WHERE id=?', (e['id'],))   # 이력은 남기고 스냅샷만 해제
            return self._save_edit(db, r, data, over, prev, f'되돌림: {e["summary"]}', None, time.time(), actor)

    def edits(self, doc_id: int, limit: int = 100) -> list:
        with self.db() as db:
            return [dict(x) for x in db.execute('SELECT id,at,sheet,summary,rev,actor,undone,(snap IS NOT NULL AND undone=0) AS undoable FROM doc_edits WHERE doc_id=? ORDER BY id DESC LIMIT ?', (doc_id, limit))]

    def export_xlsx(self, doc_id: int, sheet: str = '', query: str = '', show_hidden: bool = False) -> tuple[str, bytes]:
        """현재 표(검색 필터 적용, 제목 행은 항상 포함, 원본 행 순서 유지)를 병합·열 너비·표시 형식과 함께 XLSX 로 생성(파생본)."""
        _load_workbook()
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
        data = self.get(doc_id)
        terms = [t.casefold() for t in (query or '').split() if t.strip()]
        out = Workbook(); out.remove(out.active)
        for s in data['sheets']:
            if sheet and s['name'] != sheet:
                continue
            ws = out.create_sheet(re.sub(r'[\\/*?:\[\]]', '_', s['name'])[:31] or 'Sheet')
            hdr = s['header_rows']; hidden_rows = set(s.get('hidden_rows', [])); hidden_cols = set(s.get('hidden_cols', []))
            keep = []
            for i, (rno, vals) in enumerate(s['rows']):
                if not show_hidden and rno in hidden_rows and i >= hdr:
                    continue
                text = ' '.join(str(v) for v in vals if v is not None).casefold()
                if i < hdr or not terms or all(t in text for t in terms):
                    keep.append((rno, vals))
            fmt = s.get('fmt', {})
            for new_r, (rno, vals) in enumerate(keep, start=1):
                for c, v in enumerate(vals, start=1):
                    if v is None:
                        continue
                    cell = ws.cell(new_r, c)
                    if isinstance(v, str):
                        cell.value = v; cell.data_type = 's'   # 문자열은 수식으로 해석되지 않게 강제
                        if re.fullmatch(r'\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?', v) and f'{rno}:{c}' in fmt:
                            try:
                                cell.value = datetime.fromisoformat(v); cell.number_format = fmt[f'{rno}:{c}']
                            except ValueError:
                                pass
                    else:
                        cell.value = v
                        if f'{rno}:{c}' in fmt:
                            cell.number_format = fmt[f'{rno}:{c}']
                if new_r <= hdr:
                    for c in range(1, len(vals) + 1):
                        cell = ws.cell(new_r, c); cell.font = Font(bold=True); cell.fill = PatternFill('solid', fgColor='E1F0F4')
                        cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            visible = [rno for rno, _ in keep]
            for (first_rno, c1, nr, nc, first_idx) in merge_blocks(s['merges'], visible):
                ws.merge_cells(start_row=first_idx + 1, start_column=c1, end_row=first_idx + nr, end_column=c1 + nc - 1)
            widths = s.get('widths', {})
            for c in range(1, s['ncols'] + 1):
                ws.column_dimensions[get_column_letter(c)].width = widths.get(str(c), 16)
                if not show_hidden and c in hidden_cols:
                    ws.column_dimensions[get_column_letter(c)].hidden = True
            if hdr:
                ws.freeze_panes = ws.cell(hdr + 1, 1)
        if not out.worksheets:
            raise ValueError('내보낼 시트가 없습니다')
        buf = io.BytesIO(); out.save(buf)
        base = re.sub(r'\.xlsx$', '', data['name'], flags=re.I)
        return safe_filename(f"{base}{'-' + sheet if sheet else ''}{'-검색' if terms else ''}-현재표.xlsx"), buf.getvalue()
