"""XLSX 자원 가져오기 공통(파일 검증·셀 값 정규화·범용 단일 시트 가져오기). 반영은 전부-아니면-전무, 파일에 없는 기존 행은 삭제하지 않는다."""
from __future__ import annotations
import hashlib
import io
import json
import sys
import time
import zipfile
from datetime import date, datetime
from pathlib import Path
from .nms import Store


def _load_workbook():
    """openpyxl: 시스템 설치본 우선, 없으면 동봉 순수 Python 패키지(logtriage/_vendor)."""
    vend = str(Path(__file__).with_name("_vendor"))
    try:
        import defusedxml  # noqa: F401 — openpyxl 이 import 시점에 감지해 XML 폭탄(billion laughs 등) 방어에 사용
    except ImportError:
        if vend not in sys.path:
            sys.path.append(vend)
        import defusedxml  # noqa: F401
    try:
        from openpyxl import load_workbook
    except ImportError:
        if vend not in sys.path:
            sys.path.append(vend)
        from openpyxl import load_workbook
    return load_workbook


def workbook(raw):
    load_workbook = _load_workbook()
    if not raw or len(raw)>10*1024*1024:
        raise ValueError('엑셀 파일 크기 제한: 10 MB')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            if len(z.infolist())>10000 or sum(i.file_size for i in z.infolist())>200*1024*1024:  # 서식 많은 7,600행 양식도 통과(10MB 파일 기준 20:1)
                raise ValueError('압축 해제 크기 제한: 200 MB / 10,000개 항목')
            if any('vbaProject' in n for n in z.namelist()):
                raise ValueError('매크로 파일은 지원하지 않습니다')
            for n in z.namelist():  # 비정상 경로(../, 절대 경로)·단일 멤버 크기 상한
                if n.startswith(('/', '\\')) or '..' in n.split('/'):
                    raise ValueError('비정상 경로가 포함된 파일은 지원하지 않습니다')
            if any(i.file_size > 150*1024*1024 for i in z.infolist()):
                raise ValueError('압축 해제 크기 제한: 단일 항목 150 MB')
            # Reject XML DTDs even when optional defusedxml is absent.
            for item in z.infolist():
                if item.filename.endswith(('.xml','.rels')):
                    text=z.read(item).replace(b'\x00',b'').upper()
                    if b'<!DOCTYPE' in text or b'<!ENTITY' in text:
                        raise ValueError('외부 엔터티/DTD가 포함된 파일은 지원하지 않습니다')
        return load_workbook(io.BytesIO(raw),read_only=True,data_only=False,keep_links=False,keep_vba=False)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError('읽을 수 없는 XLSX 파일입니다') from exc


def scalar(cell):
    if cell.data_type=='f':
        raise ValueError(f'{cell.coordinate}: 수식은 값으로 붙여넣은 후 업로드하십시오')
    if cell.data_type=='e':
        raise ValueError(f'{cell.coordinate}: Excel 오류 값이 있습니다')
    value=cell.value
    if isinstance(value,(datetime,date)):
        return value.isoformat()
    if isinstance(value,str):
        if len(value)>4000:
            raise ValueError(f'{cell.coordinate}: 셀당 4,000자 제한')
        return value.strip()
    if value is None or isinstance(value,(int,float,bool)):
        return value
    return str(value)


def inspect(raw):
    wb=workbook(raw)
    try:
        if len(wb.sheetnames)>30:
            raise ValueError('최대 30개 시트')
        result=[]
        for ws in wb.worksheets:
            result.append({'sheet':ws.title,'preview':[
                [str(c.value or '')[:100] for c in row]
                for row in ws.iter_rows(max_row=10,max_col=min(ws.max_column or 1,40))]})
        return {'sheets':result}
    finally:
        wb.close()


def parse(raw,layout):
    sheet=layout.get('sheet')
    header=layout.get('header_row')
    key=layout.get('key_column')
    if not isinstance(sheet,str) or type(header) is not int or not 1<=header<=50 or not isinstance(key,str):
        raise ValueError('시트명, 제목 행(1~50), 고유 식별 열 이름이 필요합니다')
    wb=workbook(raw)
    try:
        if sheet not in wb.sheetnames:
            raise ValueError('등록된 시트가 없습니다: '+sheet)
        ws=wb[sheet]
        if (ws.max_column or 0)>100 or (ws.max_row or 0)>10050:
            raise ValueError('최대 100열 / 데이터 10,000행')
        cells=list(ws.iter_rows(min_row=header,max_row=header))[0]
        headers=[str(scalar(c) or '').strip() for c in cells]
        while headers and not headers[-1]:headers.pop()
        if not headers or any(not x for x in headers) or len(set(headers))!=len(headers):
            raise ValueError('제목 행에 빈 열 또는 중복 제목이 있습니다. 병합 제목은 단일 제목 행으로 정리하십시오')
        if any(len(x)>100 for x in headers) or key not in headers:
            raise ValueError('고유 식별 열을 확인하십시오 (열 제목 최대 100자)')
        if layout.get('columns') and headers!=layout['columns']:
            raise ValueError('등록 양식과 열 이름 또는 순서가 다릅니다')
        records={}
        for row in ws.iter_rows(min_row=header+1,max_col=len(headers)):
            values=[scalar(c) for c in row]
            if all(v is None or v=='' for v in values):continue
            value=dict(zip(headers,values))
            identity=value[key]
            if identity is None or identity=='' or isinstance(identity,bool):
                raise ValueError(f'{row[0].row}행: 고유 식별 값 누락')
            identity=str(identity)
            if len(identity)>200 or identity in records:
                raise ValueError(f'{row[0].row}행: 식별 값 중복 또는 길이 초과')
            records[identity]=value
            if len(records)>10000:raise ValueError('데이터 10,000행 제한')
        if not records:raise ValueError('등록할 데이터가 없습니다')
        return {'sheet':sheet,'header_row':header,'key_column':key,'columns':headers},records
    finally:
        wb.close()


class Inventory(Store):
    def __init__(self,path):
        # Reuse only the database context helper, not NMS tables.
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.executescript('''PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS layout(id INTEGER PRIMARY KEY CHECK(id=1),config TEXT,original BLOB);
            CREATE TABLE IF NOT EXISTS resources(identity TEXT PRIMARY KEY,content TEXT,updated REAL);
            CREATE TABLE IF NOT EXISTS imports(id INTEGER PRIMARY KEY,at REAL,name TEXT,sha256 TEXT,inserted INTEGER,updated INTEGER,unchanged INTEGER);
            CREATE TABLE IF NOT EXISTS revisions(id INTEGER PRIMARY KEY,identity TEXT,at REAL,previous TEXT,reason TEXT);
            ''')

    def template(self):
        with self.db() as db:
            row=db.execute('SELECT config FROM layout WHERE id=1').fetchone()
            return json.loads(row[0]) if row else None

    def apply(self,raw,name,layout=None):
        old=self.template()
        selected,records=parse(raw,old or layout or {})
        inserted=updated=unchanged=0
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT config FROM layout WHERE id=1').fetchone()
            if (json.loads(current[0]) if current else None)!=old:
                raise ValueError('양식이 변경되었습니다. 다시 업로드하십시오')
            if not old:
                db.execute('INSERT INTO layout VALUES(1,?,?)',(json.dumps(selected,ensure_ascii=False),raw))
            for identity,content in records.items():
                encoded=json.dumps(content,ensure_ascii=False,sort_keys=True)
                previous=db.execute('SELECT content FROM resources WHERE identity=?',(identity,)).fetchone()
                if previous and previous[0]==encoded:
                    unchanged+=1;continue
                if previous:
                    updated+=1
                    db.execute('INSERT INTO revisions(identity,at,previous,reason) VALUES(?,?,?,?)',(identity,time.time(),previous[0],'excel import'))
                else:inserted+=1
                db.execute('INSERT INTO resources VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET content=excluded.content,updated=excluded.updated',(identity,encoded,time.time()))
            db.execute('INSERT INTO imports(at,name,sha256,inserted,updated,unchanged) VALUES(?,?,?,?,?,?)',
                       (time.time(),Path(name).name[:200],hashlib.sha256(raw).hexdigest(),inserted,updated,unchanged))
        return {'inserted':inserted,'updated':updated,'unchanged':unchanged,'total_in_file':len(records)}

    def list(self):
        with self.db() as db:
            rows=[{'identity':r['identity'],'values':json.loads(r['content']),'updated':r['updated']}
                  for r in db.execute('SELECT * FROM resources ORDER BY identity LIMIT 10000')]
            imports=[dict(r) for r in db.execute('SELECT * FROM imports ORDER BY id DESC LIMIT 30')]
        return {'layout':self.template(),'rows':rows,'imports':imports}

    def save_resource(self,data):
        layout=self.template()
        if not layout:raise ValueError('엑셀 양식을 먼저 등록하십시오')
        identity=data.get('identity')
        values=data.get('values')
        if not isinstance(identity,str) or not identity or len(identity)>200 or not isinstance(values,dict) or set(values)!=set(layout['columns']):
            raise ValueError('자원 식별자 또는 열 형식 오류')
        if str(values.get(layout['key_column']))!=identity:
            raise ValueError('기존 식별 값은 변경할 수 없습니다')
        for value in values.values():
            if value is not None and type(value) not in (str,int,float,bool):raise ValueError('잘못된 셀 값')
            if isinstance(value,str) and len(value)>4000:raise ValueError('셀당 4,000자 제한')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            previous=db.execute('SELECT content FROM resources WHERE identity=?',(identity,)).fetchone()
            if previous:db.execute('INSERT INTO revisions(identity,at,previous,reason) VALUES(?,?,?,?)',(identity,time.time(),previous[0],'manual edit'))
            db.execute('INSERT INTO resources VALUES(?,?,?) ON CONFLICT(identity) DO UPDATE SET content=excluded.content,updated=excluded.updated',
                       (identity,json.dumps(values,ensure_ascii=False,sort_keys=True),time.time()))
        return {'ok':True}
