# -*- coding: utf-8 -*-
"""남이 준 파일 읽기 — 엑셀·CSV·한글 (2026-09-29)

사용자 지시: "우리 기준에 맞게 사용자가 엑셀이던 한글파일이던 첨부를 했을 때
우리 포털에서 파싱해서 정보를 채울 수 있는 기능도 구현."

여기서 지키는 것
  · 양식을 강요하지 않는다 — 제목 줄이 몇 줄이든 머리글을 찾아낸다
  · **비밀번호 열은 값을 읽지 않는다** — 미리보기에도 결과에도 한 글자도 담기지 않는다
  · 확신을 지어내지 않는다 — 모르면 모른다고 한다
  · 칸 하나가 이상해도(수식·오류) 파일 전체를 버리지 않는다
  · 위험한 파일(압축 폭탄·경로 조작·외부 엔터티)은 읽기 전에 막는다
"""
import io
import sys
import json
import unittest
import zipfile
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage import asset_import as I  # noqa: E402

HP = "http://www.hancom.co.kr/hwpml/2011/paragraph"


def xlsx(rows, sheet="서버") -> bytes:
    from openpyxl import Workbook
    wb = Workbook()
    ws = wb.active
    ws.title = sheet
    for r in rows:
        ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def hwpx(table_rows, extra=None, doctype=False, compress=False) -> bytes:
    """표 하나짜리 최소 HWPX — 한글에서 저장한 것과 같은 자리에 같은 이름으로."""
    cells = []
    for r, row in enumerate(table_rows):
        for c, text in enumerate(row):
            cells.append(
                f'<hp:tc><hp:cellAddr colAddr="{c}" rowAddr="{r}"/>'
                f"<hp:subList><hp:p><hp:run><hp:t>{text}</hp:t></hp:run></hp:p></hp:subList></hp:tc>")
    doc = ('<?xml version="1.0" encoding="UTF-8"?>'
           + ('<!DOCTYPE section [<!ENTITY x "y">]>' if doctype else "")
           + f'<hp:sec xmlns:hp="{HP}"><hp:tbl><hp:tr>'
           + "".join(cells) + "</hp:tr></hp:tbl></hp:sec>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED) as z:
        z.writestr("Contents/section0.xml", doc)
        z.writestr("mimetype", "application/hwp+zip")
        for name, body in (extra or {}).items():
            z.writestr(name, body)
    return buf.getvalue()



def hwpx_many(n: int) -> bytes:
    """표가 아주 많은 한글 문서 — 표 개수 제한을 확인하려고."""
    one = ('<hp:tbl><hp:tr><hp:tc><hp:cellAddr colAddr="0" rowAddr="0"/>'
           "<hp:subList><hp:p><hp:run><hp:t>가</hp:t></hp:run></hp:p></hp:subList></hp:tc></hp:tr></hp:tbl>")
    doc = f'<?xml version="1.0"?><hp:sec xmlns:hp="{HP}">' + one * n + "</hp:sec>"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:   # 눌러 담아야 실제 공격과 같아진다
        z.writestr("Contents/section0.xml", doc)
    return buf.getvalue()

HEADERS = ["NO", "구성자원명", "Hostname", "IP 주소", "비밀번호", "운영체제",
           "제품/버전", "로그 위치", "담당자", "업무", "중요도"]
ROW1 = [1, "대외계 WAS 1호기", "was01", "10.10.1.21", "P@ssw0rd!", "RHEL 8.8",
        "JEUS 8", "/app/jeus/logs", "김운영", "인터넷뱅킹", "상"]
ROW2 = [2, "대외계 WAS 2호기", "was02", "10.10.1.22", "S3cret!!", "RHEL 8.8",
        "JEUS 8", "/app/jeus/logs", "김운영", "인터넷뱅킹", "상"]


class ExcelTests(unittest.TestCase):
    def setUp(self):
        self.raw = xlsx([["○○사 자산 현황표"], ["2026년 9월 기준"], HEADERS, ROW1, ROW2])
        self.p = I.preview(self.raw, "자산현황.xlsx", "was")
        self.s = self.p["sheets"][0]

    def test_it_finds_the_header_row_under_the_title_rows(self):
        """양식마다 제목·부제가 몇 줄씩 붙는다 — 그걸 머리글로 잡으면 전부 어긋난다."""
        self.assertEqual(self.s["header_row"], 2)
        self.assertEqual(self.s["rows"], 2)

    def test_it_matches_what_it_can_and_says_so(self):
        self.assertGreaterEqual(self.s["mapping"]["counts"]["sure"], 8)
        got = self.s["samples"][0]
        self.assertEqual(got["hostname"], "was01")
        self.assertEqual(got["mgmt_ip"], "10.10.1.21")
        self.assertEqual(got["log_path"], "/app/jeus/logs")

    def test_empty_columns_are_not_counted_as_unknown(self):
        """엑셀은 쓰지도 않은 열까지 채워 준다 — 그대로 두면 '모름 191개' 가 나온다(실제로 나왔다)."""
        self.assertEqual(self.s["mapping"]["counts"]["total"], len(HEADERS))

    def test_choice_values_become_ours(self):
        """'상' 을 그대로 두면 나중에 아무도 세지 못한다."""
        self.assertEqual(self.s["samples"][0]["criticality"], "high")

    def test_unreadable_choice_is_kept_but_not_in_the_typed_slot(self):
        """모르는 말을 'high' 자리에 그대로 넣으면, 뒤에서 그 자리를 enum 으로 믿는 코드가
        조용히 어긋난다(GPT 교차 검토). 버리지도 않는다 — 원문 자리에 남겨 사람이 고르게 한다."""
        raw = xlsx([HEADERS, ROW1[:10] + ["아주 중요"]])
        s = I.preview(raw, "x.xlsx", "was")["sheets"][0]
        got = s["samples"][0]
        self.assertNotIn("criticality", got, "모르는 말이 enum 자리에 들어갔습니다")
        self.assertEqual(got["criticality_raw"], "아주 중요", "원문까지 버렸습니다")

    def test_it_says_which_required_fields_the_file_lacks(self):
        missing = {m["id"] for m in self.s["mapping"]["missing_required"]}
        self.assertIn("asset_id", missing)
        self.assertIn("site", missing)
        self.assertNotIn("hostname", missing)

    def test_all_rows_come_through_for_the_real_import(self):
        r = I.records(self.raw, "자산현황.xlsx", "was")
        self.assertEqual(r["count"], 2)
        self.assertEqual(r["incomplete"], 2, "필수가 비었는데 완성이라고 합니다")
        self.assertIn("미완성", r["note"])

    def test_a_broken_cell_does_not_lose_the_file(self):
        from openpyxl import Workbook
        wb = Workbook(); ws = wb.active
        for row in (HEADERS, ROW1):
            ws.append(row)
        ws["C3"] = "=1/0"                     # 수식 — 값이 아니다
        buf = io.BytesIO(); wb.save(buf)
        s = I.preview(buf.getvalue(), "x.xlsx", "was")["sheets"][0]
        self.assertGreaterEqual(s["rows"], 1, "칸 하나 때문에 파일을 통째로 버렸습니다")


class PasswordTests(unittest.TestCase):
    """비밀번호는 읽지 않는다 — 대장 유출이 곧 전 장비 탈취가 되기 때문."""

    def setUp(self):
        self.raw = xlsx([HEADERS, ROW1, ROW2])

    def test_no_password_value_anywhere_in_the_preview(self):
        import json
        blob = json.dumps(I.preview(self.raw, "x.xlsx", "was"), ensure_ascii=False)
        self.assertNotIn("P@ssw0rd", blob)
        self.assertNotIn("S3cret", blob)

    def test_no_password_value_anywhere_in_the_records(self):
        import json
        blob = json.dumps(I.records(self.raw, "x.xlsx", "was"), ensure_ascii=False)
        self.assertNotIn("P@ssw0rd", blob)
        self.assertNotIn("S3cret", blob)

    def test_it_says_it_dropped_them(self):
        p = I.preview(self.raw, "x.xlsx", "was")
        self.assertEqual(p["dropped_columns"], 1)
        self.assertIn("지웠습니다", p["note"])
        # 약속을 지킬 수 있는 문장으로 고쳤다(GPT 교차 검토) — 읽는 것 자체는 막을 수 없고,
        # 막을 수 있는 것은 그 값이 여기서 한 발짝도 더 나가지 못하게 하는 것이다
        self.assertIn("저장에도 남지 않습니다", p["note"])

    def test_a_hand_made_mapping_cannot_smuggle_the_column_back(self):
        """사람이 매핑을 고칠 수 있다 — 그래도 비밀번호 열은 돌아오지 못한다."""
        r = I.records(self.raw, "x.xlsx", "was", mapping={"서버": {"4": "account"}})
        import json
        self.assertNotIn("P@ssw0rd", json.dumps(r, ensure_ascii=False))


class CsvTests(unittest.TestCase):
    def test_utf8_with_bom(self):
        raw = "자산ID,자산명,호스트명,IP,업무\nS-1,웹1,web01,10.1.1.1,포털\n".encode("utf-8-sig")
        s = I.preview(raw, "list.csv", "web")["sheets"][0]
        self.assertEqual(s["header_row"], 0)
        self.assertEqual(s["samples"][0]["asset_id"], "S-1")

    def test_cp949(self):
        raw = ("자산명,호스트명\n웹1,web01\n").encode("cp949")
        s = I.preview(raw, "list.csv", "web")["sheets"][0]
        self.assertEqual(s["samples"][0]["name"], "웹1")

    def test_tab_separated(self):
        raw = ("자산명\t호스트명\n웹1\tweb01\n").encode("utf-8")
        s = I.preview(raw, "list.tsv", "web")["sheets"][0]
        self.assertEqual(s["samples"][0]["hostname"], "web01")


class HwpxTests(unittest.TestCase):
    def test_a_table_in_a_hangul_document_is_read(self):
        raw = hwpx([["호스트명", "IP 주소", "업무"], ["was01", "10.1.1.1", "인터넷뱅킹"]])
        s = I.preview(raw, "자산.hwpx", "was")["sheets"][0]
        self.assertEqual(s["header_row"], 0)
        self.assertEqual(s["samples"][0]["hostname"], "was01")

    def test_a_document_without_tables_says_why(self):
        raw = hwpx([])
        with self.assertRaises(ValueError) as e:
            I.preview(raw, "글.hwpx", "")
        self.assertIn("표", str(e.exception))

    def test_external_entities_are_refused(self):
        raw = hwpx([["호스트명"], ["was01"]], doctype=True)
        with self.assertRaises(ValueError) as e:
            I.preview(raw, "나쁜.hwpx", "")
        self.assertIn("엔터티", str(e.exception))

    def test_path_traversal_is_refused(self):
        raw = hwpx([["호스트명"], ["was01"]], extra={"../evil.txt": "x"})
        with self.assertRaises(ValueError) as e:
            I.preview(raw, "나쁜.hwpx", "")
        self.assertIn("비정상 경로", str(e.exception))


class RefusalTests(unittest.TestCase):
    def test_old_formats_tell_the_user_what_to_do(self):
        for name in ("자산.xls", "자산.hwp"):
            with self.subTest(name=name), self.assertRaises(ValueError) as e:
                I.read_tables(b"x" * 100, name)
            self.assertIn("다시 저장", str(e.exception))

    def test_unknown_formats_say_what_we_take(self):
        with self.assertRaises(ValueError) as e:
            I.read_tables(b"x" * 100, "자산.pdf")
        self.assertIn(".xlsx", str(e.exception))

    def test_empty_file(self):
        with self.assertRaises(ValueError):
            I.read_tables(b"", "x.csv")

    def test_too_big(self):
        with self.assertRaises(ValueError) as e:
            I.read_tables(b"x" * (I.MAX_BYTES + 1), "x.csv")
        self.assertIn("크기 제한", str(e.exception))


if __name__ == "__main__":
    unittest.main()


class ReviewFixTests(unittest.TestCase):
    """GPT 교차 검토(7차)에서 잡힌 것들 — 다시 열리지 않게 시험으로 막는다."""

    def test_credential_table_is_not_taken_for_a_good_header(self):
        """자격증명 관리표(ID|PW|계정)가 비밀번호 열 덕분에 '좋은 자산 머리글' 로 뽑히던 역설.
        민감 열 판정은 보안 신호일 뿐, 여기가 머리글인지와는 다른 이야기다."""
        raw = xlsx([["ID", "PW", "root 계정 정보"], ["oper", "x", "y"]])
        h = I.find_header([["ID", "PW", "root 계정 정보"], ["oper", "x", "y"]], "")
        self.assertEqual(h["row"], -1, "자격증명 표를 자산 머리글로 확정했습니다")
        s = I.preview(raw, "x.xlsx", "")["sheets"][0]
        self.assertEqual(s["header_row"], -1)
        self.assertTrue(s["note"])

    def test_a_weak_header_is_not_confirmed(self):
        """우리 항목과 맞는 이름이 너무 적으면 확정하지 않고 사람에게 묻는다."""
        h = I.find_header([["가", "나", "다"], ["1", "2", "3"]], "")
        self.assertEqual(h["row"], -1)
        self.assertIn("골라", h["why"])

    def test_a_close_call_is_called_a_guess(self):
        """1·2등이 근소하면 '확실' 이라고 말하지 않는다."""
        rows = [["호스트명", "IP 주소", "업무"], ["호스트명", "IP 주소", "업무"], ["a", "b", "c"]]
        h = I.find_header(rows, "")
        self.assertEqual(h["confidence"], "추정")
        self.assertTrue(h["why"])

    def test_sensitive_columns_are_erased_from_the_grid(self):
        """미리보기에서 빼는 것으로는 부족하다 — 격자에서 지워 어떤 경로로도 못 닿게 한다."""
        rows = [["호스트명", "비밀번호"], ["was01", "P@ssw0rd!"]]
        got = I.scrub(rows, 0)
        self.assertEqual(got["count"], 1)
        self.assertEqual(rows[1][1], "", "값이 격자에 그대로 남아 있습니다")
        self.assertEqual(rows[1][0], "was01", "멀쩡한 열까지 지웠습니다")

    def test_the_column_name_survives_so_we_can_say_what_we_dropped(self):
        """이름까지 지우면 '지웠다' 와 '못 읽었다' 를 사람이 구분할 수 없다(실제로 그렇게 나왔다)."""
        rows = [["호스트명", "비밀번호"], ["was01", "P@ssw0rd!"]]
        I.scrub(rows, 0)
        self.assertEqual(rows[0][1], "비밀번호", "어느 열을 지웠는지 말할 수 없게 됐습니다")
        raw = xlsx([["호스트명", "IP 주소", "업무", "비밀번호"],
                    ["was01", "10.1.1.1", "인터넷뱅킹", "P@ssw0rd!"]])
        s = I.preview(raw, "x.xlsx", "")["sheets"][0]
        col = [c for c in s["mapping"]["columns"] if c.get("dropped")][0]
        self.assertEqual(col["dropped"], "password")
        self.assertIn("금고", col["why"])
        # 버린 열의 머리글은 **가린 꼴로만** 나간다 — 머리글 자리에 값이 들어와 있는 파일이 있다
        # ('password=P@ssw0rd'). 어느 열인지와 어느 계열인지로 사람은 알아본다(GPT 10차 중).
        self.assertEqual(col["header"], "비밀번***")
        self.assertEqual(col["category"], "password")

    def test_a_header_that_is_itself_a_secret_is_not_echoed(self):
        """머리글 자리에 값이 들어와 있으면, 막았다고 말하면서 같은 값을 화면·로그로 내보내게 된다."""
        raw = xlsx([["호스트명", "password=P@ssw0rd"], ["was01", "x"]])
        out = json.dumps(I.preview(raw, "x.xlsx", ""), ensure_ascii=False)
        self.assertNotIn("P@ssw0rd", out)

    def test_control_characters_in_a_header_do_not_get_through(self):
        """남의 파일 머리글로 로그 한 줄을 꾸며 내지 못하게 걷어낸다."""
        m = I.asset_spec.map_headers(["호스트명" + chr(10) + "조작된 줄", "IP 주소"], "was")
        self.assertNotIn(chr(10), m["columns"][0]["header"])

    def test_key_and_mixed_columns_are_dropped_too(self):
        for header in ("API Key", "SNMP Community", "root 계정 정보", "ID/PW"):
            with self.subTest(header=header):
                rows = [["호스트명", header], ["was01", "비밀값"]]
                self.assertEqual(I.scrub(rows, 0)["count"], 1, f"'{header}' 를 지우지 않았습니다")
                self.assertEqual(rows[1][1], "")

    def test_the_account_column_survives(self):
        """계정까지 지우면 누구로 붙는지 모른다 — 지울 것만 지운다."""
        rows = [["접속 계정", "계정"], ["oper", "admin"]]
        self.assertEqual(I.scrub(rows, 0)["count"], 0)
        self.assertEqual(rows[1], ["oper", "admin"])

    def test_formula_is_neutralised_only_on_the_way_out(self):
        """들여올 때는 원문을 지키고, 표 계산기로 내보낼 때 막는다.

        엑셀에서는 =cmd… 가 '수식 칸' 이라 읽는 단계에서 이미 비워진다(그건 그것대로 맞다).
        위험한 쪽은 CSV 다 — 거기서는 그냥 글자라 그대로 살아남는다."""
        raw = chr(10).join(["자산명,호스트명",
                            chr(34) + "=cmd|" + chr(39) + " /c calc" + chr(39)
                            + "!A1" + chr(34) + ",was01", ""]).encode("utf-8")
        rec = I.records(raw, "x.csv", "")["records"][0]
        self.assertTrue(rec["name"].startswith("="), "고객 자료를 우리가 훼손했습니다")
        self.assertEqual(I.for_spreadsheet(rec["name"])[:2], "'=")
        for v in ("+1", "-1", "@x", chr(9) + "=1", chr(13) + "+2", chr(10) + "@3"):
            self.assertTrue(I.for_spreadsheet(v).startswith("'"), v)
        # 앞의 제어문자만 있고 수식이 아니면 건드리지 않는다 — 멀쩡한 값을 훼손하지 않는다
        for v in ("was01", chr(9) + "was01", " - 장비 설명"):
            self.assertEqual(I.for_spreadsheet(v), v, v)

    def test_too_many_tables_is_refused(self):
        raw = hwpx_many(I.MAX_TABLES + 2)
        with self.assertRaises(ValueError) as e:
            I.read_tables(raw, "많은표.hwpx")
        self.assertIn("표가 너무 많습니다", str(e.exception))

    def test_a_single_huge_body_is_refused(self):
        big = ("<hp:p><hp:run><hp:t>" + "가" * 1000 + "</hp:t></hp:run></hp:p>") * 40000
        raw = hwpx([["호스트명"], ["was01"]], extra={"Contents/section1.xml":
                    f'<?xml version="1.0"?><hp:sec xmlns:hp="{HP}">{big}</hp:sec>'},
                   compress=True)
        with self.assertRaises(ValueError) as e:
            I.read_tables(raw, "큰.hwpx")
        self.assertIn("큽니다", str(e.exception))

    def test_a_weird_delimiter_guess_falls_back(self):
        """구분자를 잘못 짚으면 한 줄이 통째로 한 칸이 된다 — 그럴 때는 물러선다."""
        raw = "자산명,호스트명\n웹1,web01\n".encode("utf-8")
        s = I.preview(raw, "x.csv", "")["sheets"][0]
        self.assertEqual(s["samples"][0]["hostname"], "web01")


class CanaryTests(unittest.TestCase):
    """민감값이 **어느 출구로도** 나가지 않는지 표식을 심어 확인한다(GPT 교차 검토 제안).

    미리보기·기록·오류 문자열까지 한 번에 본다. 나중에 누가 오류 메시지에 원문 일부를
    넣는 코드를 더해도 이 시험이 잡는다."""

    CANARY = "LT_SECRET_CANARY_847291"

    def _scan(self, obj) -> bool:
        import json
        return self.CANARY in json.dumps(obj, ensure_ascii=False, default=str)

    def test_canary_never_leaves_through_any_door(self):
        raw = xlsx([["호스트명", "비밀번호", "API Key", "root 계정 정보", "업무"],
                    ["was01", self.CANARY, self.CANARY, self.CANARY, "인터넷뱅킹"]])
        p = I.preview(raw, "x.xlsx", "was")
        self.assertFalse(self._scan(p), "미리보기로 새 나갔습니다")
        r = I.records(raw, "x.xlsx", "was")
        self.assertFalse(self._scan(r), "기록으로 새 나갔습니다")
        r2 = I.records(raw, "x.xlsx", "was", mapping={"Sheet": {"1": "account", "2": "name"}})
        self.assertFalse(self._scan(r2), "사람이 고친 매핑으로 되살아났습니다")

    def test_canary_inside_an_account_cell_is_dropped_too(self):
        """계정 열은 받지만, 그 칸에 'pw=' 가 섞여 있으면 칸째 버린다."""
        raw = xlsx([["호스트명", "접속 계정"], ["was01", "oper pw=" + self.CANARY]])
        p = I.preview(raw, "x.xlsx", "")
        self.assertFalse(self._scan(p), "계정 칸에 섞인 비밀이 새 나갔습니다")
        self.assertIn("account", p["sheets"][0]["samples"][0].get("_dropped_cells", []))

    def test_a_clean_account_cell_still_comes_through(self):
        raw = xlsx([["호스트명", "접속 계정"], ["was01", "oper"]])
        p = I.preview(raw, "x.xlsx", "")
        self.assertEqual(p["sheets"][0]["samples"][0]["account"], "oper")


class HiddenSheetTests(unittest.TestCase):
    """숨김 시트는 자동으로 읽지 않는다 — 접속 정보·임시 계정표가 거기 있는 일이 흔하다."""

    def _book(self):
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "서버"
        ws.append(["호스트명", "업무"])
        ws.append(["was01", "인터넷뱅킹"])
        hid = wb.create_sheet("계정표")
        hid.append(["호스트명", "비밀번호"])
        hid.append(["was01", "Secret123!"])
        hid.sheet_state = "hidden"
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    def test_hidden_sheets_are_not_read(self):
        import json
        raw = self._book()
        t = I.read_tables(raw, "x.xlsx")
        self.assertEqual([x["sheet"] for x in t], ["서버"])
        self.assertEqual(t[0]["hidden_sheets"], ["계정표"])
        self.assertNotIn("Secret123", json.dumps(I.preview(raw, "x.xlsx", ""), ensure_ascii=False))


class UnconfirmedHeaderTests(unittest.TestCase):
    """머리글을 확정하지 못한 파일이 가장 위험하다 — 지울 열을 모르니 지우지도 못한다.
    그래서 그 경우에는 **표본을 아예 보여 주지 않는다**(GPT 교차 검토가 짚은 자리)."""

    CANARY = "LT_SECRET_CANARY_847291"

    def test_no_sample_data_when_the_header_is_not_confirmed(self):
        import json
        raw = xlsx([["ID", "PW", "root 계정 정보"], ["admin", CANARY_V := self.CANARY, self.CANARY]])
        p = I.preview(raw, "자격증명표.xlsx", "")
        s = p["sheets"][0]
        self.assertEqual(s["header_row"], -1)
        self.assertNotIn("samples", s, "머리글도 못 정했는데 표본을 보여 줍니다")
        self.assertNotIn(CANARY_V, json.dumps(p, ensure_ascii=False))
        self.assertTrue(s["note"], "왜 못 읽었는지 말하지 않습니다")

    def test_records_skips_that_sheet_entirely(self):
        import json
        raw = xlsx([["ID", "PW"], ["admin", self.CANARY]])
        r = I.records(raw, "x.xlsx", "")
        self.assertEqual(r["count"], 0)
        self.assertNotIn(self.CANARY, json.dumps(r, ensure_ascii=False))
