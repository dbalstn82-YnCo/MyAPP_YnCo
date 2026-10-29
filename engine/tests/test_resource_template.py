import sys
sys.dont_write_bytecode=True
import io,zipfile,tempfile,unittest,json
from pathlib import Path
from xml.etree import ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from logtriage.resource_inventory import ResourceInventory,SCHEMA,parse_template

TEMPLATE=Path(__file__).resolve().parents[1]/'logtriage/resource-template.xlsx'
NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'


def filled(changes):
    """In-memory test copies only; distributed source workbook remains unchanged."""
    buffer=io.BytesIO()
    with zipfile.ZipFile(TEMPLATE) as original,zipfile.ZipFile(buffer,'w',zipfile.ZIP_DEFLATED) as dest:
        for item in original.infolist():
            raw=original.read(item.filename)
            if item.filename in changes:
                root=ET.fromstring(raw);data=root.find('{'+NS+'}sheetData')
                for coord,value in changes[item.filename].items():
                    n=''.join(x for x in coord if x.isdigit())
                    row=next((r for r in data if r.attrib.get('r')==n),None)
                    if row is None:row=ET.SubElement(data,'{'+NS+'}row',r=n)
                    old=next((c for c in row if c.attrib.get('r')==coord),None)
                    if old is not None:row.remove(old)
                    cell=ET.SubElement(row,'{'+NS+'}c',r=coord,t='inlineStr')
                    ET.SubElement(ET.SubElement(cell,'{'+NS+'}is'),'{'+NS+'}t').text=value
                dimension=root.find('{'+NS+'}dimension')
                if dimension is not None:dimension.set('ref','A1:AV8000')
                raw=ET.tostring(root)
            dest.writestr(item,raw)
    return buffer.getvalue()


DATA={
 'xl/worksheets/sheet1.xml':{'D3':'SRV-001','E3':'시험 서버','F3':'test-server','I3':'synthetic-secret-do-not-store'},
 'xl/worksheets/sheet2.xml':{'E3':'NET-001','G3':'시험 방화벽','AH3':'HW 담당','AJ3':'SW 담당','AM3':'기타 담당'},
 'xl/worksheets/sheet3.xml':{'F3':'seoul-test','I3':'192.0.2.3'},
 'xl/worksheets/sheet4.xml':{'B7':'test-server','C7':'Test Software','D7':'1.0'},
 'xl/worksheets/sheet5.xml':{'B4':'SRV-001','Q4':'POL-001','R4':'/example'},
 'xl/worksheets/sheet6.xml':{'I3':'CIRCUIT-001','C3':'시험기관'},
}


class ResourceTemplateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=ResourceInventory(Path(self.tmp.name)/'resource.db')
    def tearDown(self):self.tmp.cleanup()
    def test_original_empty_template_all_sheets(self):
        result=self.store.apply(TEMPLATE.read_bytes(),'자원정보.xlsx')
        self.assertEqual(result['total_in_file'],0)
        self.assertEqual(len(result['sheets']),6)
        self.assertEqual([len(s['fields']) for s in SCHEMA['sheets']],[29,41,32,17,48,20])
    def test_first_and_repeat_import(self):
        raw=filled(DATA)
        result=self.store.apply(raw,'test.xlsx');self.assertEqual(result['inserted'],6)
        self.assertEqual(result['ignored_password_cells'],1)
        self.assertEqual(self.store.apply(raw,'test.xlsx')['unchanged'],6)
        all_rows=[self.store.list(s['sheet']) for s in SCHEMA['sheets']]
        self.assertNotIn('synthetic-secret',json.dumps(all_rows))
        row=self.store.list('서버 네트워크 보안')['rows'][0]['values']
        self.assertEqual((row['AH'],row['AJ'],row['AM']),('HW 담당','SW 담당','기타 담당'))
    def test_update_and_preserve_missing(self):
        self.store.apply(filled(DATA),'first.xlsx')
        result=self.store.apply(filled({'xl/worksheets/sheet1.xml':{'D3':'SRV-001','E3':'수정 서버'}}),'update.xlsx')
        self.assertEqual(result['updated'],1)
        self.assertEqual(sum(self.store.list()['counts'].values()),6)
    def test_cross_sheet_error_rolls_back(self):
        changes={'xl/worksheets/sheet1.xml':{'D3':'NEW-001'},'xl/worksheets/sheet6.xml':{'C3':'식별번호 누락'}}
        with self.assertRaises(ValueError):self.store.apply(filled(changes),'bad.xlsx')
        self.assertEqual(sum(self.store.list()['counts'].values()),0)
        self.assertEqual(self.store.list()['imports'],[])
    def test_duplicate_and_header_change(self):
        for changes in ({'xl/worksheets/sheet1.xml':{'D3':'DUP','D4':'DUP'}},{'xl/worksheets/sheet1.xml':{'D2':'wrong header'}}):
            with self.assertRaises(ValueError):self.store.apply(filled(changes),'bad.xlsx')
    def test_manual_edit_key_guard_and_search(self):
        self.store.apply(filled(DATA),'first.xlsx')
        row=self.store.list()['rows'][0];row['values']['E']='편집된 서버'
        self.store.save_resource({'sheet':'서버',**row})
        self.assertEqual(self.store.list(query='편집된')['matched'],1)
        row['values']['D']='changed-id'
        with self.assertRaises(ValueError):self.store.save_resource({'sheet':'서버',**row})

    def test_http_upload_and_download(self):
        import threading,urllib.request,urllib.parse
        from logtriage.server import make_server
        server,handler=make_server('127.0.0.1',0,Path(self.tmp.name)/'http',None)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        url='http://127.0.0.1:'+str(server.server_port)
        try:
            req=urllib.request.Request(url+'/api/inventory/apply?name=resources.xlsx',data=TEMPLATE.read_bytes(),headers={'X-NMS-Request':'1'})
            result=json.load(urllib.request.urlopen(req,timeout=15))
            self.assertEqual(result['total_in_file'],0)
            raw=filled(DATA)
            for expected in (6,0):
                req=urllib.request.Request(url+'/api/inventory/apply?name=test.xlsx',data=raw,headers={'X-NMS-Request':'1'})
                self.assertEqual(json.load(urllib.request.urlopen(req,timeout=15))['inserted'],expected)
            state=json.load(urllib.request.urlopen(url+'/api/inventory/list?'+urllib.parse.urlencode({'sheet':'서버 네트워크 보안'}),timeout=15))
            self.assertEqual(state['matched'],1)
            self.assertEqual(urllib.request.urlopen(url+'/api/inventory/template',timeout=15).read(),TEMPLATE.read_bytes())
        finally:server.shutdown();thread.join();server.server_close()

if __name__=='__main__':unittest.main(verbosity=2)
