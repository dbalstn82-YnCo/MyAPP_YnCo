import sys
sys.dont_write_bytecode=True
import io,json,tempfile,unittest,zipfile
from pathlib import Path
from xml.sax.saxutils import escape
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from logtriage.inventory import Inventory,inspect,parse


def fixture(rows,formula=False):
    """Small OOXML test fixture, never distributed as a user template."""
    buf=io.BytesIO()
    xml=[]
    for r,row in enumerate(rows,1):
        cells=[]
        for c,value in enumerate(row):
            ref=f'{chr(65+c)}{r}'
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>')
        xml.append(f'<row r="{r}">'+''.join(cells)+'</row>')
    sheet='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><dimension ref="A1:C'+str(len(rows))+'"/><sheetData>'+''.join(xml)+'</sheetData></worksheet>'
    if formula:sheet=sheet.replace('<c r="B2" t="inlineStr"><is><t>alpha</t></is></c>','<c r="B2"><f>1+1</f><v>2</v></c>')
    with zipfile.ZipFile(buf,'w') as z:
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>')
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml','<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Resources" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>')
        z.writestr('xl/worksheets/sheet1.xml',sheet)
    return buf.getvalue()


LAYOUT={'sheet':'Resources','header_row':1,'key_column':'ID'}
ROWS=[['ID','Name','IP'],['001','alpha','192.0.2.1'],['002','beta','192.0.2.2']]


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.store=Inventory(Path(self.tmp.name)/'inventory.db')
    def tearDown(self):self.tmp.cleanup()
    def test_inspect_and_initial_import(self):
        self.assertEqual(inspect(fixture(ROWS))['sheets'][0]['sheet'],'Resources')
        self.assertEqual(self.store.apply(fixture(ROWS),'test.xlsx',LAYOUT)['inserted'],2)
        self.assertEqual(self.store.list()['rows'][0]['identity'],'001')
    def test_idempotent_and_update_preserves_omitted(self):
        self.store.apply(fixture(ROWS),'test.xlsx',LAYOUT)
        self.assertEqual(self.store.apply(fixture(ROWS),'again.xlsx')['unchanged'],2)
        result=self.store.apply(fixture([ROWS[0],['001','changed','192.0.2.9']]),'change.xlsx')
        self.assertEqual(result['updated'],1);self.assertEqual(len(self.store.list()['rows']),2)
    def test_duplicate_atomic_no_partial(self):
        self.store.apply(fixture(ROWS),'test.xlsx',LAYOUT);before=self.store.list()
        with self.assertRaises(ValueError):self.store.apply(fixture([ROWS[0],['003','new','x'],['003','duplicate','y']]),'bad.xlsx')
        self.assertEqual(before,self.store.list())
    def test_wrong_header_atomic(self):
        self.store.apply(fixture(ROWS),'test.xlsx',LAYOUT)
        with self.assertRaises(ValueError):self.store.apply(fixture([['ID','Wrong','IP'],ROWS[1]]),'bad.xlsx')
        self.assertEqual(len(self.store.list()['imports']),1)
    def test_formulas_and_corrupt_files(self):
        with self.assertRaises(ValueError):parse(fixture(ROWS,formula=True),LAYOUT)
        with self.assertRaises(ValueError):inspect(b'not an xlsx')
        self.assertIsNone(self.store.template())
    def test_manual_edit_and_add(self):
        self.store.apply(fixture(ROWS),'test.xlsx',LAYOUT)
        self.store.save_resource({'identity':'001','values':{'ID':'001','Name':'manual','IP':'192.0.2.4'}})
        self.assertEqual(self.store.list()['rows'][0]['values']['Name'],'manual')
        with self.assertRaises(ValueError):self.store.save_resource({'identity':'001','values':{'ID':'bad','Name':'manual','IP':'x'}})
        self.store.save_resource({'identity':'003','values':{'ID':'003','Name':'new','IP':'192.0.2.3'}})
        self.assertEqual(len(self.store.list()['rows']),3)

if __name__=='__main__':unittest.main(verbosity=2)
