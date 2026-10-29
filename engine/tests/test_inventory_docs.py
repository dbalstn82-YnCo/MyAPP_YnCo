"""자원 문서(v3) 시험 — 병합 셀 채움·표시 정보, 행 순서(NO) 보존, 제목 행 추정, 원본/현재 표 XLSX 내보내기, HTTP 업로드"""
import sys
sys.dont_write_bytecode = True
import io, json, tempfile, unittest, threading, urllib.error, urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logtriage.inventory_docs import parse_workbook, DocStore, EditConflict, edit_value


def build(rows, merges=(), title=None):
    """openpyxl 로 시험용 워크북 생성(메모리)."""
    from logtriage.inventory import _load_workbook
    _load_workbook()
    from openpyxl import Workbook
    wb = Workbook(); ws = wb.active; ws.title = title or "장비"
    for r, row in enumerate(rows, start=1):
        for c, v in enumerate(row, start=1):
            if v is not None:
                ws.cell(r, c, v)
    for m in merges:
        ws.merge_cells(m)
    buf = io.BytesIO(); wb.save(buf); return buf.getvalue()


ROWS = [["기본항목", None, None, "담당"],
        ["NO", "기관명", "장비", "이름"],
        [1, "A기관", "web01", "홍"],
        [2, None, "web02", None],   # B3:B4 병합(기관명), D3:D4 병합(이름)
        [3, "B기관", "db01", "김"],
        [10, "C기관", "app01", "박"], [4, "D기관", "app02", "이"]]  # NO 는 시트 순서대로 보존(정렬하지 않음)
MERGES = ["A1:C1", "B3:B4", "D3:D4"]


class DocTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.store = DocStore(Path(self.tmp.name) / "r.sqlite3")
        self.raw = build(ROWS, MERGES)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_merge_fill_and_order(self):
        d = parse_workbook(self.raw, "장비.xlsx"); s = d["sheets"][0]
        self.assertEqual(s["header_rows"], 2)            # 병합 그룹 행 + 열 이름 행
        self.assertIn([3, 2, 4, 2], s["merges"])
        vals = {r[0]: r[1] for r in s["rows"]}
        self.assertEqual(vals[4][1], "A기관")               # 병합 범위에 값 채움
        self.assertEqual(vals[4][3], "홍")
        self.assertEqual([r[1][0] for r in s["rows"][2:]], [1, 2, 3, 10, 4])  # 시트 순서 그대로

    def test_all_text_inventory_keeps_data_rows(self):
        """모든 칸이 글자인 장비 대장(자산번호·IP·호스트명 문자열 — 흔한 형태)에서 첫 데이터 행을 제목으로 삼키지 않는다(2026-10-14 실측 결함)."""
        rows = [["자산번호", "장비명", "관리 IP", "종류", "책임조직"]] + [[f"NW-{i:03d}", f"sw{i:02d}", f"198.51.100.{i}", "L3 스위치", "네트워크팀"] for i in range(1, 6)]
        self.assertEqual(parse_workbook(build(rows), "a.xlsx")["sheets"][0]["header_rows"], 1)
        two = [["구분", "장비", "주소", "비고"], ["대분류", "이름", "IP", "설명"]] + [["서버", f"web{i}", f"192.0.2.{i}", "운영"] for i in range(1, 4)]
        self.assertEqual(parse_workbook(build(two), "b.xlsx")["sheets"][0]["header_rows"], 2)   # 진짜 2단 제목은 그대로
        # GPT 12차 반례 ① 숫자가 든 2단 제목('2026년 1분기')과 % 데이터 → 제목 2행 유지, 자동 추정 표시
        q = [["2026년 1분기", "2026년 1분기", "비고"], ["CPU 사용률", "메모리 사용률", "점검 결과"], ["75%", "82%", "정상"], ["68%", "79%", "정상"], ["71%", "80%", "정상"]]
        sq = parse_workbook(build(q), "c.xlsx")["sheets"][0]
        self.assertEqual((sq["header_rows"], sq["header_auto_extra"]), (2, 1))
        # 반례 ② 첫 두 데이터 행 모양이 다른 장비 대장 → 첫 데이터 행을 제목으로 삼키지 않는다(아래 3행까지 비교)
        mixed = [["자산번호", "호스트명", "IP", "비고"], ["SRV-001", "web01", "192.0.2.1", "본사"],
                 ["SRV-002", None, None, "이전"], ["SRV-003", "web03", "192.0.2.3", "본사"], ["SRV-004", "web04", "192.0.2.4", "운영"]]   # 2행은 빈칸 많음
        sm = parse_workbook(build(mixed), "d.xlsx")["sheets"][0]
        self.assertEqual((sm["header_rows"], sm["header_auto_extra"]), (1, 0))

    def test_store_export_roundtrip(self):
        doc = self.store.add(self.raw, "장비.xlsx")
        got = self.store.get(doc["id"]); self.assertEqual(got["total_rows"], 7)
        name, orig = self.store.original(doc["id"]); self.assertEqual(orig, self.raw)
        name, data = self.store.export_xlsx(doc["id"], "장비", "B기관")
        from openpyxl import load_workbook
        ws = load_workbook(io.BytesIO(data)).active
        self.assertEqual([c.value for c in ws[2]], ["NO", "기관명", "장비", "이름"])
        self.assertEqual(ws["B3"].value, "B기관"); self.assertEqual(ws.max_row, 3)   # 제목 2행 + 검색 1행
        self.assertIn("A1:C1", [str(m) for m in ws.merged_cells.ranges])
        self.store.set_header(doc["id"], "장비", 1)
        self.assertEqual(self.store.get(doc["id"])["sheets"][0]["header_rows"], 1)
        self.store.delete(doc["id"])
        with self.assertRaises(ValueError):
            self.store.get(doc["id"])

    def test_edit_value(self):
        self.assertEqual(edit_value("12"), 12); self.assertEqual(edit_value("1.5"), 1.5); self.assertEqual(edit_value("007"), "007")  # 선행 0 보존
        self.assertEqual(edit_value("1234567890123.4567"), "1234567890123.4567")   # 유효 숫자 15자리 초과 → 문자열(정밀도 보존)
        self.assertIsNone(edit_value("  ")); self.assertEqual(edit_value("=SUM(A1)"), "(수식) =SUM(A1)"); self.assertEqual(edit_value(3.0), 3)
        with self.assertRaises(ValueError):
            edit_value("x" * 5000)

    def test_edit_ops(self):
        doc = self.store.add(self.raw, "장비.xlsx"); i = doc["id"]
        r = self.store.edit(i, "장비", 0, [{"op": "set", "r": 2, "c": 2, "v": "신기관"}])
        self.assertEqual(r["rev"], 1); self.assertEqual([x[1][1] for x in r["sheet"]["rows"][2:4]], ["신기관", "신기관"])  # 병합 B3:B4 범위 전체
        r = self.store.edit(i, "장비", 1, [{"op": "insert_rows", "at": 3, "count": 1, "copy_from": 2}])
        self.assertIsNone(r["sheet"]["rows"][3][0]); self.assertEqual(r["sheet"]["rows"][3][1][2], "web01"); self.assertEqual(r["total_rows"], 8)
        r = self.store.edit(i, "장비", 2, [{"op": "set", "r": 3, "c": 1, "v": "007"}, {"op": "set", "r": 3, "c": 3, "v": "12"}])
        self.assertEqual(r["sheet"]["rows"][3][1][:3], ["007", "신기관", 12])
        r = self.store.edit(i, "장비", 3, [{"op": "insert_cols", "at": 2, "count": 1}])
        self.assertEqual(r["sheet"]["ncols"], 5); self.assertIn([1, 1, 1, 4], r["sheet"]["merges"]); self.assertIn([3, 3, 4, 3], r["sheet"]["merges"])  # 병합 범위 확장·이동
        self.assertEqual(r["sheet"]["rows"][2][1], [1, None, "신기관", "web01", "홍"])
        r = self.store.edit(i, "장비", 4, [{"op": "delete_cols", "cols": [2]}])
        self.assertEqual(r["sheet"]["ncols"], 4); self.assertIn([3, 2, 4, 2], r["sheet"]["merges"])
        with self.assertRaises(EditConflict):
            self.store.edit(i, "장비", 4, [{"op": "set", "r": 0, "c": 1, "v": "x"}])   # rev 불일치
        with self.assertRaises(ValueError):
            self.store.edit(i, "장비", 5, [{"op": "delete_rows", "rows": [0]}])         # 제목 행 보호
        with self.assertRaises(ValueError):
            self.store.edit(i, "장비", 5, [{"op": "delete_cols", "cols": [1, 2, 3, 4]}])  # 열은 최소 1개
        r = self.store.edit(i, "장비", 5, [{"op": "delete_rows", "rows": [3, 5]}])
        self.assertEqual([x[0] for x in r["sheet"]["rows"]], [1, 2, 3, 4, 6, 7]); self.assertEqual(r["total_rows"], 6)
        name, data = self.store.export_xlsx(i, "장비")
        from openpyxl import load_workbook
        ws = load_workbook(io.BytesIO(data)).active
        self.assertEqual(ws.max_row, 6); self.assertEqual(ws["B3"].value, "신기관"); self.assertIn("B3:B4", [str(m) for m in ws.merged_cells.ranges])
        self.assertEqual([e["summary"] for e in self.store.edits(i)][:2], ["행 2개 삭제", "열 1개 삭제(B)"])
        r = self.store.undo(i, 6); self.assertEqual(len(r["sheet"]["rows"]), 8); self.assertEqual(r["edits"], 5)
        r = self.store.undo(i, 7); self.assertEqual(r["sheet"]["ncols"], 5)
        g = self.store.get(i); self.assertEqual(g["rev"], 8); self.assertEqual(g["edits"], 4)
        r = self.store.edit(i, "장비", 8, [{"op": "insert_rows", "at": 1, "count": 1}])   # 제목 영역에 추가 → 제목 행 수 증가
        self.assertEqual(r["sheet"]["header_rows"], 3); self.assertEqual(self.store.get(i)["sheets"][0]["header_rows"], 3)
        self.assertEqual(self.store.list()[0]["edits"], 5)
        r = self.store.edit(i, "장비", 9, [{"op": "delete_rows", "rows": [1]}])   # 추가한 제목 영역 행은 삭제 가능 → 제목 행 수 복귀
        self.assertEqual(r["sheet"]["header_rows"], 2)
        hist = self.store.edits(i)
        self.assertTrue(any(e["undone"] for e in hist))                        # 되돌린 이력도 남음(감사)
        self.assertEqual([e["summary"] for e in hist if e["undone"]], ["행 2개 삭제", "열 1개 삭제(B)"])   # 최신순
        with self.assertRaises(ValueError):
            self.store.undo(i, 10, sheet="없는시트")                             # 시트 단위 되돌리기
        self.store.delete(i); self.assertEqual(self.store.edits(i), [])

    def test_rejects_bad_files(self):
        with self.assertRaises(ValueError):
            parse_workbook(b"not a workbook")
        big = build([[f"r{i}", "x"] for i in range(20001)], [])
        with self.assertRaises(ValueError):
            parse_workbook(big)

    def test_http_upload_view_export(self):
        from logtriage.server import make_server
        httpd, h = make_server("127.0.0.1", 0, Path(self.tmp.name) / "srv", None)
        t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
        url = f"http://127.0.0.1:{httpd.server_port}"
        try:
            req = urllib.request.Request(url + "/api/inventory/docs?name=%EC%9E%A5%EB%B9%84.xlsx", data=self.raw, headers={"X-NMS-Request": "1"})
            r = json.load(urllib.request.urlopen(req, timeout=15)); self.assertEqual(r["rows"], 7)
            lst = json.load(urllib.request.urlopen(url + "/api/inventory/docs", timeout=15))
            self.assertEqual(lst["docs"][0]["sheet_names"], ["장비"])
            page = urllib.request.urlopen(url + f"/resources/view?id={r['id']}", timeout=15).read().decode()
            self.assertIn("현재 표 엑셀", page)
            x = urllib.request.urlopen(url + f"/api/inventory/doc/export?id={r['id']}&sheet=%EC%9E%A5%EB%B9%84", timeout=15).read()
            self.assertTrue(x.startswith(b"PK"))
            o = urllib.request.urlopen(url + f"/api/inventory/doc/original?id={r['id']}", timeout=15).read()
            self.assertEqual(o, self.raw)
            def post(path, body, ok=True):
                req = urllib.request.Request(url + path, data=json.dumps(body).encode(), headers={"X-NMS-Request": "1", "Content-Type": "application/json"})
                try:
                    return json.load(urllib.request.urlopen(req, timeout=15)), 200
                except urllib.error.HTTPError as e:
                    return json.load(e), e.code
            e, code = post("/api/inventory/doc/edit", {"id": r["id"], "sheet": "장비", "rev": 0, "ops": [{"op": "set", "r": 2, "c": 3, "v": "web99"}]})
            self.assertEqual(code, 200); self.assertEqual(e["rev"], 1); self.assertEqual(e["sheet"]["rows"][2][1][2], "web99")
            e, code = post("/api/inventory/doc/edit", {"id": r["id"], "sheet": "장비", "rev": 0, "ops": [{"op": "set", "r": 2, "c": 3, "v": "x"}]})
            self.assertEqual(code, 409); self.assertTrue(e.get("conflict"))
            e, code = post("/api/inventory/doc/edit", {"id": r["id"], "sheet": "장비", "rev": 1, "ops": [{"op": "delete_rows", "rows": [0]}]})
            self.assertEqual(code, 400)
            h = json.load(urllib.request.urlopen(url + f"/api/inventory/doc/edits?id={r['id']}", timeout=15))
            self.assertEqual(h["edits"][0]["summary"], "C3 수정")
            e, code = post("/api/inventory/doc/undo", {"id": r["id"], "rev": 1})
            self.assertEqual(code, 200); self.assertEqual(e["sheet"]["rows"][2][1][2], "web01")
            page = urllib.request.urlopen(url + f"/resources/view?id={r['id']}", timeout=15).read().decode()
            self.assertIn('id="etb"', page)
        finally:
            httpd.shutdown(); t.join(); httpd.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
