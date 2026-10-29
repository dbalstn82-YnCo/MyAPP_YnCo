# -*- coding: utf-8 -*-
"""자산 기준 항목 — 우리가 요구하는 것 (2026-09-29)

사용자 지시: "템플릿을 요청하는 게 아니라 반드시 필요한 항목과 정보를 요구해야 한다.
그렇기에 우리가 기준이 되어야 하고, 사용자가 엑셀이든 한글이든 첨부하면 파싱해서 채워야 한다."

여기서 지키는 것
  · 항목은 엑셀 칸 위치가 아니라 **뜻**으로 정의된다
  · 항목마다 '없으면 장애 때 무엇을 못 하는지' 가 붙어 있다 — 그 답이 없으면 요구하지 않는다
  · **비밀번호는 어떤 유형에도 칸이 없고, 남의 문서에서 들어와도 버린다**
  · 머리글을 맞출 때 확신을 지어내지 않는다(확실/추정/모름을 그대로 말한다)
"""
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENG))

from logtriage import asset_spec as A  # noqa: E402


class StandardTests(unittest.TestCase):
    def test_every_field_says_why_it_is_required(self):
        """이유를 못 대는 항목은 요구하지 않는다 — 그것이 '우리가 기준' 이라는 말의 내용이다."""
        for t in list(A.types()) + [""]:
            for f in A.fields(t):
                with self.subTest(type=t, field=f["id"]):
                    self.assertTrue(f.get("why", "").strip(), f"{f['id']}: 이유가 없습니다")
                    self.assertGreater(len(f["why"]), 15, f"{f['id']}: 이유가 너무 짧습니다")
                    self.assertIn(f["level"], A.LEVEL)
                    self.assertTrue(f.get("aliases"), f"{f['id']}: 남의 표를 맞출 사전이 없습니다")

    def test_fields_are_defined_by_meaning_not_by_column_position(self):
        """엑셀 칸 위치(A·B·C)로 정의하면 남의 양식은 영영 못 받는다."""
        for f in A.fields("was"):
            with self.subTest(field=f["id"]):
                self.assertFalse(len(f["id"]) == 1 and f["id"].isalpha(),
                                 f"{f['id']}: 칸 위치로 정의돼 있습니다")

    def test_the_essentials_are_required(self):
        """2판(2026-09-30) — GPT 교차 판단으로 필수 묶음을 다시 잡았다.

        빠져 있던 셋을 넣었다. 운영 환경(운영/검증/개발) 없이는 대응 강도를 잘못 잡고,
        운영 상태 없이는 죽어 있어야 정상인 대기·폐기 장비를 장애로 잡는다.
        책임은 사람이 아니라 조직에 묶는다 — 사람은 퇴사·이동으로 빨리 낡는다.
        """
        req = {f["id"] for f in A.fields("") if f["level"] == "required"}
        for must in ("asset_id", "name", "type", "site", "service", "criticality",
                     "env", "state", "owner_team"):
            with self.subTest(field=must):
                self.assertIn(must, req, f"{must} 가 필수가 아닙니다")

    def test_one_of_replaces_false_certainty(self):
        """'IP 필수' 로 못 박으면 NAT·VIP·DNS 환경에서 거짓 값을 채우게 된다.

        그래서 '이 중 하나는' 으로 요구한다. 빈칸을 막으려고 억지값을 넣는 순간 대장은 거짓이 된다.
        """
        by = {f["id"]: f for f in A.fields("")}
        for fid, grp in (("mgmt_ip", "reach"), ("fqdn", "reach"), ("console", "reach"),
                         ("hostname", "identify"),
                         ("log_path", "observe"), ("log_channel", "observe")):
            with self.subTest(field=fid):
                self.assertIn(fid, by, f"{fid} 항목이 없습니다")
                if by[fid]["level"] == "conditional":
                    self.assertEqual(by[fid].get("one_of"), grp)
        self.assertEqual(A.LEVEL["conditional"], "조건부 필수")

    def test_a_group_is_satisfied_by_any_one_member(self):
        base = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        self.assertFalse(A.check(base, "was")["complete"], "주소도 로그도 없는데 완성이라 합니다")
        self.assertTrue(A.check(dict(base, mgmt_ip="10.1.1.5", log_path="/l"), "was")["complete"])
        # 이름만 있어도, 이벤트 로그만 있어도 된다 — 파일 경로만이 로그가 아니다
        self.assertTrue(A.check(dict(base, fqdn="a.example.com",
                                     log_channel="Windows 이벤트 로그"), "was")["complete"])

    def test_the_group_reason_names_the_alternatives(self):
        """빠졌다고만 하면 무엇을 채워야 할지 모른다 — 고를 것을 같이 말한다."""
        base = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        miss = {m["id"]: m for m in A.check(base, "was")["missing"]}
        self.assertIn("one_of:reach", miss)
        self.assertIn("또는", miss["one_of:reach"]["why"])

    def test_a_type_raises_what_that_type_really_needs(self):
        """공통에서 'OS 필수' 를 못 박으면 맞지 않는 유형이 거짓 값을 채우고,
        공통에서 빼면 서버에서 놓친다 — 유형이 정해질 때 올려 받는다."""
        common = {f["id"]: f["level"] for f in A.fields("")}
        self.assertEqual(common["os"], "advised")
        self.assertEqual(common["product"], "advised")
        srv = {f["id"]: f["level"] for f in A.fields("server")}
        self.assertEqual(srv["os"], "required")
        self.assertEqual(srv["hostname"], "required")
        for t in ("dbms", "was", "web", "network", "sw"):
            with self.subTest(type=t):
                self.assertEqual({f["id"]: f["level"] for f in A.fields(t)}["product"], "required")

    def test_a_changed_standard_never_breaks_a_stored_asset(self):
        """기준이 올라가 필수가 늘어도 이미 등록된 자산을 막거나 지우지 않는다 —
        '확인 필요' 로만 표시한다(GPT 교차 판단)."""
        old = {"asset_id": "S-1", "name": "was01", "type": "was"}
        r = A.check(old, "was")
        self.assertFalse(r["complete"])
        self.assertEqual(r["state"], "needs_review")
        self.assertEqual(A.check({}, "was")["state"], "incomplete")

    def test_a_value_we_could_not_translate_does_not_satisfy_anything(self):
        """**뒤집은 규칙**(GPT 10차 상). 못 알아본 값(<항목>_raw)을 '채워짐' 으로 세면,
        `운영환경_raw="실서비스쯤?"` 인 자산을 '완성' 이라고 선언하게 된다 —
        뜻을 모르는 값을 가지고 완전하다고 말하는 것이다.

        버리지는 않는다. '확인 필요' 로만 말하고, 무엇을 못 알아봤는지 보여 준다.
        """
        base = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        base.update(mgmt_ip="10.1.1.5", log_path="/l")
        base["criticality"] = ""
        base["criticality_raw"] = "매우높음"
        r = A.check(base, "was")
        self.assertFalse(r["complete"])
        self.assertEqual(r["state"], "needs_review")
        self.assertEqual([u["id"] for u in r["unread"]], ["criticality"])
        self.assertIn("매우높음", r["unread"][0]["raw"])

    def test_a_raw_value_cannot_satisfy_a_conditional_group(self):
        """관리IP_raw='999.999.1.1' 로 '접속할 수 있는 주소가 있다' 고 세면 장애 때 닿지 못한다."""
        base = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        base["log_path"] = "/l"
        base["mgmt_ip_raw"] = "999.999.1.1"
        r = A.check(base, "was")
        self.assertFalse(r["complete"])
        self.assertIn("one_of:reach", [m["id"] for m in r["missing"]])

    def test_information_carries_its_own_age(self):
        """낡은 대장은 없는 것보다 위험하다 — 언제 확인했고 어디서 왔는지를 묶는다."""
        by = {f["id"]: f for f in A.fields("")}
        self.assertIn("verified_at", by)
        self.assertIn("source", by)

    def test_hostname_and_log_path_carry_their_real_reason(self):
        """이 둘은 우리 제품이 자산과 로그를 잇는 고리다 — 이유가 그렇게 적혀 있어야 한다."""
        by = {f["id"]: f for f in A.fields("")}
        self.assertIn("로그에 찍히는 이름", by["hostname"]["why"])
        self.assertIn("로그를 가져오는지", by["log_path"]["why"])

    def test_each_type_adds_what_only_that_type_needs(self):
        was = {f["id"] for f in A.fields("was")}
        dbms = {f["id"] for f in A.fields("dbms")}
        self.assertIn("heap", was)
        self.assertNotIn("heap", dbms)
        self.assertIn("archive_mode", dbms)
        self.assertNotIn("archive_mode", was)


class NoPasswordTests(unittest.TestCase):
    """계정은 받되 비밀번호는 받지 않는다(2026-09-29 사용자 확인).

    자산 대장은 여러 사람이 보고 내려받는 문서다. 거기에 평문 비밀번호를 모으면
    대장 유출이 곧 전 장비 탈취가 된다."""

    def test_no_password_field_exists_anywhere(self):
        for t in list(A.types()) + [""]:
            for f in A.fields(t):
                with self.subTest(type=t, field=f["id"]):
                    self.assertNotIn("password", f["id"])
                    self.assertNotIn("비밀번호", f["label"])
                    self.assertNotIn("암호", f["label"])

    def test_the_account_field_stays_and_says_so(self):
        by = {f["id"]: f for f in A.fields("")}
        self.assertIn("account", by, "계정까지 빼면 누구로 붙는지 모릅니다")
        self.assertIn("비밀번호는 받지 않습니다", by["account"].get("note", ""))

    def test_password_columns_from_other_documents_are_dropped(self):
        for h in ("비밀번호", "PASSWORD", "passwd", "pw", "관리자 암호", "Root PW", "패스워드"):
            with self.subTest(header=h):
                self.assertEqual(A.is_dropped(h), "password", f"'{h}' 를 걸러내지 못합니다")

    def test_ordinary_columns_are_not_mistaken_for_passwords(self):
        for h in ("호스트명", "제품/버전", "담당자", "포트", "계정"):
            with self.subTest(header=h):
                self.assertEqual(A.is_dropped(h), "", f"'{h}' 를 비밀번호로 잘못 봅니다")

    def test_the_spec_tells_the_screen_what_we_never_take(self):
        never = A.spec("")["never"]
        self.assertIn("password", never)
        self.assertIn("금고", never["password"]["why"])


class HeaderMappingTests(unittest.TestCase):
    """남이 준 표의 머리글을 우리 항목에 맞춘다 — 확신은 지어내지 않는다."""

    def test_exact_names_win_before_loose_ones(self):
        """'NO' 가 'node' 에 걸려 호스트명을 차지하면, 진짜 'Hostname' 열이 자리를 잃는다.
        (처음 만들었을 때 실제로 그렇게 나왔다)"""
        r = A.map_headers(["NO", "Hostname"], "")
        by = {c["header"]: c for c in r["columns"]}
        self.assertEqual(by["Hostname"]["field"], "hostname")
        self.assertEqual(by["Hostname"]["confidence"], A.SURE)
        self.assertEqual(by["NO"]["field"], "", "두 글자 머리글로 확신을 지어냈습니다")

    def test_synonyms_are_understood(self):
        r = A.map_headers(["구성자원명", "IP 주소", "운영체제", "로그 위치", "업무"], "")
        self.assertEqual(r["matched"].keys() >= {"name", "mgmt_ip", "os", "log_path", "service"},
                         True, f"맞춘 것: {r['matched']}")
        self.assertEqual(r["counts"]["sure"], 5)

    def test_unknown_columns_are_said_to_be_unknown(self):
        r = A.map_headers(["알 수 없는 열"], "")
        self.assertEqual(r["columns"][0]["confidence"], A.NONE)
        self.assertEqual(r["unknown"], [0])

    def test_two_columns_cannot_take_the_same_field(self):
        r = A.map_headers(["호스트명", "hostname"], "")
        fields = [c["field"] for c in r["columns"]]
        self.assertEqual(fields.count("hostname"), 1, "같은 항목에 두 열이 붙었습니다")

    def test_value_shape_is_a_guess_not_a_certainty(self):
        r = A.map_headers(["관리용 주소"], "", samples={0: ["10.1.1.1", "10.1.1.2"]})
        c = r["columns"][0]
        self.assertTrue(c["field"], "값 모양으로도 못 맞췄습니다")
        self.assertEqual(c["confidence"], A.GUESS, "넘겨짚은 것을 '확실' 이라고 말하면 안 됩니다")

    def test_password_columns_are_reported_as_dropped(self):
        r = A.map_headers(["호스트명", "비밀번호"], "")
        self.assertEqual(r["counts"]["dropped"], 1)
        self.assertEqual(r["columns"][1]["field"], "")
        self.assertIn("금고", r["columns"][1]["why"])

    def test_it_says_which_required_fields_the_file_does_not_have(self):
        r = A.map_headers(["호스트명"], "was")
        missing = {m["id"] for m in r["missing_required"]}
        self.assertIn("service", missing)
        self.assertIn("instance", missing)
        self.assertNotIn("hostname", missing)
        for m in r["missing_required"]:
            self.assertTrue(m["why"], "무엇이 없는지는 말하면서 왜 필요한지는 안 말합니다")


class CheckTests(unittest.TestCase):
    def test_missing_required_is_reported_with_the_reason(self):
        c = A.check({"asset_id": "S-1", "name": "가", "type": "server", "site": "본사"}, "server")
        self.assertFalse(c["complete"])
        ids = {m["id"] for m in c["missing"]}
        self.assertIn("service", ids)
        self.assertIn("hostname", ids)
        for m in c["missing"]:
            self.assertTrue(m["why"])

    def test_saving_is_not_blocked(self):
        """막으면 사람들이 아무 값이나 채워 넣는다 — 그러면 대장이 거짓이 된다."""
        self.assertIn("저장은 됩니다", A.check({}, "server")["note"])

    def test_a_complete_record_is_complete(self):
        vals = {f["id"]: "x" for f in A.fields("server") if f["level"] == "required"}
        # 조건부 묶음도 하나씩 채운다 — '이 중 하나는' 이 기준의 일부다
        vals.update(mgmt_ip="10.1.1.5", log_path="/var/log")
        self.assertTrue(A.check(vals, "server")["complete"])

    def test_blank_strings_count_as_empty(self):
        vals = {f["id"]: "x" for f in A.fields("server") if f["level"] == "required"}
        vals["hostname"] = "   "
        self.assertFalse(A.check(vals, "server")["complete"])


if __name__ == "__main__":
    unittest.main()
