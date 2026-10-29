"""Importer for the supplied six-sheet 자원정보.xlsx template."""
from __future__ import annotations
import hashlib
import json
import time
from pathlib import Path
from .inventory import workbook, scalar
from .nms import Store

SCHEMA=json.loads(Path(__file__).with_name('resource_schema.json').read_text(encoding='utf-8'))
SHEETS={s['sheet']:s for s in SCHEMA['sheets']}


def identity(sheet,values):
    spec=SHEETS[sheet]
    for key in spec['required']:
        if values.get(key) in (None,'') or isinstance(values.get(key),bool):
            label=next(f['label'] for f in spec['fields'] if f['id']==key)
            raise ValueError('식별 항목 누락: '+label)
    keys=[str(values.get(k) if values.get(k) is not None else '').strip() for k in spec['key_fields']]
    return hashlib.sha256(json.dumps([sheet,keys],ensure_ascii=False).encode()).hexdigest()


def parse_template(raw):
    wb=workbook(raw)
    records=[];counts={};ignored_passwords=0
    try:
        if set(wb.sheetnames)!=set(SHEETS):
            raise ValueError('자원정보 양식의 6개 시트 이름을 유지하십시오')
        for name,spec in SHEETS.items():
            ws=wb[name]
            if (ws.max_row or 0)>10050 or (ws.max_column or 0)>100:
                raise ValueError(name+': 최대 10,000 데이터 행 / 100열')
            for expected in spec['expected']:
                if str(ws[expected['cell']].value)!=expected['value']:
                    raise ValueError(name+' '+expected['cell']+': 양식 제목이 다릅니다')
            fields={f['id']:f for f in spec['fields']}
            seen=set();counts[name]=0
            for row in ws.iter_rows(min_row=spec['header_end']+1):
                if all(c.value is None or c.value=='' for c in row):continue
                values={f:None for f in fields}
                rownum=next(c.row for c in row if c.value is not None)
                try:
                    for cell in row:
                        if cell.value is None:continue
                        col=''.join(x for x in cell.coordinate if x.isalpha())
                        if col not in fields:
                            raise ValueError('제목 없는 열에 데이터가 있습니다: '+col)
                        if fields[col]['secret']:
                            ignored_passwords+=1
                        else:
                            values[col]=scalar(cell)
                    key=identity(name,values)
                    if key in seen:raise ValueError('동일한 식별 값이 두 번 나옵니다')
                    seen.add(key)
                except ValueError as exc:
                    raise ValueError(f'{name} {rownum}행: {exc}') from None
                records.append((key,name,values));counts[name]+=1
                if len(records)>20000:raise ValueError('파일 전체 자원 수 제한: 20,000개')
        return records,counts,ignored_passwords
    finally:wb.close()


class ResourceInventory(Store):
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.executescript('''PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS resource_items(id TEXT PRIMARY KEY,sheet TEXT,content TEXT,updated REAL);
            CREATE INDEX IF NOT EXISTS resource_sheet ON resource_items(sheet,id);
            CREATE TABLE IF NOT EXISTS resource_imports(id INTEGER PRIMARY KEY,at REAL,name TEXT,sha256 TEXT,result TEXT);
            CREATE TABLE IF NOT EXISTS resource_revisions(id INTEGER PRIMARY KEY,item_id TEXT,at REAL,previous TEXT,reason TEXT);
            ''')

    def apply(self,raw,name,layout=None):
        records,counts,ignored=parse_template(raw)
        result={'inserted':0,'updated':0,'unchanged':0,'total_in_file':len(records),
                'sheets':counts,'ignored_password_cells':ignored}
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            existing=db.execute('SELECT count(*) FROM resource_items').fetchone()[0]
            for key,sheet,values in records:
                encoded=json.dumps(values,sort_keys=True,ensure_ascii=False)
                old=db.execute('SELECT content FROM resource_items WHERE id=?',(key,)).fetchone()
                if old and old[0]==encoded:result['unchanged']+=1;continue
                if old:
                    result['updated']+=1
                    db.execute('INSERT INTO resource_revisions(item_id,at,previous,reason) VALUES(?,?,?,?)',(key,time.time(),old[0],'excel import'))
                else:
                    result['inserted']+=1
                    if existing+result['inserted']>20000:raise ValueError('저장 자원 수 제한: 20,000개')
                db.execute('INSERT INTO resource_items VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET content=excluded.content,updated=excluded.updated',(key,sheet,encoded,time.time()))
            db.execute('INSERT INTO resource_imports(at,name,sha256,result) VALUES(?,?,?,?)',
                       (time.time(),Path(name).name[:200],hashlib.sha256(raw).hexdigest(),json.dumps(result,ensure_ascii=False)))
        return result

    def list(self,sheet='서버',query='',page=1):
        if sheet not in SHEETS:raise ValueError('알 수 없는 자원 분류')
        page=max(1,min(int(page),1000));query=str(query).casefold()[:200]
        with self.db() as db:
            counts={s:0 for s in SHEETS}
            counts.update({r[0]:r[1] for r in db.execute('SELECT sheet,count(*) FROM resource_items GROUP BY sheet')})
            rows=[]
            for row in db.execute('SELECT * FROM resource_items WHERE sheet=? ORDER BY id',(sheet,)):
                values=json.loads(row['content'])
                if query and query not in ' '.join(str(v or '') for v in values.values()).casefold():continue
                rows.append({'identity':row['id'],'values':values,'updated':row['updated']})
            imports=[{**dict(r),'result':json.loads(r['result'])} for r in db.execute('SELECT * FROM resource_imports ORDER BY id DESC LIMIT 30')]
        return {'schema':SCHEMA,'sheet':sheet,'counts':counts,'rows':rows[(page-1)*100:page*100],
                'matched':len(rows),'page':page,'page_size':100,'imports':imports}

    def save_resource(self,data):
        sheet=data.get('sheet');values=data.get('values');old_id=data.get('identity')
        if sheet not in SHEETS or not isinstance(values,dict):raise ValueError('자원 분류/입력 형식 오류')
        fields=SHEETS[sheet]['fields']
        if set(values)!={f['id'] for f in fields}:raise ValueError('자원 열 형식 오류')
        for f in fields:
            value=values[f['id']]
            if f['secret']:values[f['id']]=None;continue
            if value is not None and type(value) not in (str,int,float,bool):raise ValueError('잘못된 셀 값')
            if isinstance(value,str) and len(value)>4000:raise ValueError('셀당 4,000자 제한')
        key=identity(sheet,values)
        if old_id and old_id!=key:raise ValueError('기존 자원의 식별 항목은 변경할 수 없습니다')
        encoded=json.dumps(values,sort_keys=True,ensure_ascii=False)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT content FROM resource_items WHERE id=?',(key,)).fetchone()
            if old_id and not old:raise ValueError('편집 대상 자원이 없습니다')
            if not old_id and old:raise ValueError('이미 등록된 식별 값입니다. 해당 자원을 편집하십시오')
            if old:db.execute('INSERT INTO resource_revisions(item_id,at,previous,reason) VALUES(?,?,?,?)',(key,time.time(),old[0],'manual edit'))
            elif db.execute('SELECT count(*) FROM resource_items').fetchone()[0]>=20000:raise ValueError('저장 자원 수 제한: 20,000개')
            db.execute('INSERT INTO resource_items VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET content=excluded.content,updated=excluded.updated',(key,sheet,encoded,time.time()))
        return {'ok':True}
