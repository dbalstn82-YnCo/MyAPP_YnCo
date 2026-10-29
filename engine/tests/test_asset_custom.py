# -*- coding: utf-8 -*-
"""현장이 기준을 넓힐 수 있게 — 그리고 그 길이 옆문이 되지 않게 (2026-09-30)

사용자 지시: "사용자가 추가로 필요로 할 때 항목을 추가할 수 있는 기능도 구현이 필요하다."
그리고: "구현 시 보안정책 위배 또는 취약한 부분은 반드시 제거 또는 보완."

기능을 열면 규칙을 우회하는 길이 함께 열린다. 여기 있는 시험은 대부분 **막히는지**를 본다.
특히 '만들 때는 검사하고 이름 바꿀 때는 안 하는' 구멍이 실제로 있었다.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import asset_custom as C           # noqa: E402
from logtriage import asset_spec as A             # noqa: E402


def store():
    return C.Store(Path(tempfile.mkdtemp()) / "fields.sqlite3")


class AddTests(unittest.TestCase):
    def test_a_site_can_ask_for_more_than_we_do(self):
        st = store()
        r = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다", actor="kim")
        self.assertTrue(r["id"].startswith("x_"))
        self.assertIn("상면 위치", [f["label"] for f in st.fields()])
        self.assertIn("상면 위치", [f["label"] for f in A.fields("was", extra=st.fields())])

    def test_a_field_must_say_what_breaks_without_it(self):
        """까닭을 못 대는 항목은 요구하지 않는다 — 그것이 '우리가 기준' 이라는 말의 내용이다."""
        with self.assertRaises(ValueError):
            store().add_field("메모", why="필요", actor="kim")

    def test_the_same_label_at_two_sites_is_not_the_same_field(self):
        """전에는 id 를 이름에서 계산했다(sha1). 그러면 사이트 A 의 '운영주소' 와
        사이트 B 의 '운영주소' 가 같은 id 가 되어, 본사로 모을 때 **뜻이 다른 두 항목이
        조용히 하나로 합쳐진다**(GPT 10차 상). 이름은 겹치고 바뀌는 것이므로 id 의 근거가 못 된다.
        """
        a, b = store(), store()
        ia = a.add_field("운영주소", why="이 장비에 어느 주소로 붙는지 적습니다")["id"]
        ib = b.add_field("운영주소", why="이 장비에 어느 주소로 붙는지 적습니다")["id"]
        self.assertNotEqual(ia, ib)
        self.assertNotEqual(a.installation, b.installation)
        self.assertNotEqual(a.global_id(ia), b.global_id(ib))
        self.assertTrue(a.global_id(ia).endswith(":" + ia))

    def test_the_installation_id_does_not_change(self):
        """설치 id 가 흔들리면 본사에 모인 자료가 남의 것으로 보인다."""
        st = store()
        first = st.installation
        again = C.Store(st.path)
        self.assertEqual(first, again.installation)

    def test_the_id_survives_a_rename(self):
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        st.rename_field(fid, "전산실 상세 위치")
        self.assertEqual([f["id"] for f in st.fields()], [fid])

    def test_two_fields_with_the_same_slug_do_not_collide(self):
        st = store()
        one = st.add_field("A" * 3, why="같은 뜻이 아니지만 id 가 같아질 수 있습니다")
        two = st.add_field("A" * 3 + " 2", why="같은 뜻이 아니지만 id 가 같아질 수 있습니다2")
        self.assertNotEqual(one["id"], two["id"])

    def test_a_custom_field_cannot_duplicate_one_we_already_have(self):
        """뜻이 겹치면 파일을 읽을 때 어느 항목에 넣을지 모르게 된다."""
        st = store()
        for word in ("호스트명", "hostname", "IP주소"):
            with self.subTest(word=word), self.assertRaises(ValueError):
                st.add_field(word, why="이미 있는 항목과 겹치는 이름입니다")

    def test_control_characters_and_length_are_trimmed(self):
        st = store()
        r = st.add_field("가" * 80 + "\n\t나", why="아주 긴 이름을 넣어 보는 시험입니다")
        label = [f["label"] for f in st.fields() if f["id"] == r["id"]][0]
        self.assertLessEqual(len(label), C.MAX_LABEL)
        self.assertNotIn("\n", label)
        self.assertNotIn("\t", label)

    def test_a_half_built_kind_is_not_offered(self):
        """'고르기' 는 선택지를 받을 길이 없다 — 빈 드롭다운을 만드는 반쪽 기능은 두지 않는다."""
        self.assertNotIn("choice", C.KINDS)
        with self.assertRaises(ValueError):
            store().add_field("등급구분", kind="choice", why="상중하로 고르게 하려 합니다")

    def test_conditional_needs_a_group_to_mean_anything(self):
        """'조건부 필수' 는 '이 묶음에서 하나는' 이라는 뜻이고, 묶음은 기본 기준만 정한다."""
        with self.assertRaises(ValueError):
            store().add_field("보조 주소", level="conditional", why="주소가 하나 더 필요합니다")

    def test_unknown_types_are_refused(self):
        with self.assertRaises(ValueError):
            store().add_field("상면 위치", apply_to=["없는유형"], why="어느 랙인지 못 찾습니다")

    def test_the_number_of_custom_fields_is_bounded(self):
        st = store()
        for i in range(C.MAX_FIELDS):
            st.add_field(f"현장 항목 {i}", why="현장에서 필요한 항목입니다 시험용")
        with self.assertRaises(ValueError):
            st.add_field("하나 더", why="상한을 넘겨 보는 시험입니다")


class NoSideDoorTests(unittest.TestCase):
    """받지 않기로 한 것을 **옆문으로** 들이지 못하게.

    기본 기준에서 비밀번호를 받지 않기로 했는데, 사용자 항목으로 '비밀번호' 를 만들 수 있으면
    그 결정은 아무 뜻이 없다. 만드는 길과 **이름을 바꾸는 길** 둘 다 막혀 있어야 한다.
    """

    WORDS = ("비밀번호", "비번", "패스워드", "PW", "ＰＷ", "P.W", "svrPW", "dbPwd", "ID/PW",
             "계정정보", "API Key", "SNMP Community", "cred", "인증", "OTP", "PIN",
             "keystore", "pem", "접속 정보", "암호", "client secret", "자격증명", "Bearer Token")

    def test_a_secret_field_cannot_be_created(self):
        st = store()
        for w in self.WORDS:
            with self.subTest(word=w), self.assertRaises(ValueError):
                st.add_field(w, why="여기에 적어 두면 편하다고 합니다")

    def test_a_secret_alias_cannot_be_created(self):
        """별칭은 파일을 읽을 때 쓰는 사전이다 — 거기로 들어오면 값이 읽힌다."""
        st = store()
        for w in self.WORDS:
            with self.subTest(word=w), self.assertRaises(ValueError):
                st.add_field("접속 보조 정보 " + str(len(w)), aliases=[w],
                             why="다른 표의 이름을 함께 받으려 합니다")

    def test_renaming_goes_through_the_same_check(self):
        """**전에 열려 있던 구멍** — 무해한 이름으로 만들고 이름만 바꾸면 통과했다."""
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        for w in self.WORDS:
            with self.subTest(word=w), self.assertRaises(ValueError):
                st.rename_field(fid, w)
        self.assertEqual([f["label"] for f in st.fields()], ["상면 위치"])

    def test_renaming_also_refuses_a_name_that_already_means_something(self):
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        with self.assertRaises(ValueError):
            st.rename_field(fid, "호스트명")

    def test_renaming_to_its_own_name_is_allowed(self):
        """자기 이름과 겹친다고 막으면 손도 못 댄다 — 자기는 빼고 본다."""
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        st.rename_field(fid, "상면 위치")
        self.assertEqual(st.rename_field(fid, "랙 상면")["id"], fid)

    def test_the_message_names_the_word_that_caused_it(self):
        """막고 끝내면 사용자는 머리글을 어떻게 고칠지 모른다."""
        with self.assertRaises(ValueError) as e:
            store().add_field("서버PW 관리", why="서버 접속에 쓰는 값을 적어 두려 합니다")
        self.assertIn("pw", str(e.exception).lower())

    def test_an_alias_cannot_shadow_a_dropped_column(self):
        """사용자 별칭이 비밀번호 열을 가로채는 길이 없어야 한다 —
        받지 않을 열을 걸러내는 일이 맞추기보다 **앞에** 있다."""
        st = store()
        # 파일에서 자동으로 채워지는 종류로 본다 — 글자 항목은 애초에 자동 매핑에 안 들어간다
        st.add_field("방화벽 정책 번호", kind="code", aliases=["정책번호"],
                     why="통신이 막혔을 때 어느 정책을 풀어야 하는지 모릅니다")
        m = A.map_headers(["자산ID", "비밀번호", "정책번호"], "was", extra=st.fields())
        self.assertIn("1", m["dropped"])
        by = {c["index"]: c for c in m["columns"]}
        self.assertEqual(by[1]["field"], "")
        self.assertTrue(by[2]["field"].startswith("x_"))


class LevelTests(unittest.TestCase):
    def test_a_site_can_raise_and_lower_our_levels(self):
        st = store()
        self.assertEqual({f["id"]: f["level"] for f in A.fields("")}["location"], "optional")
        st.set_level("location", "required", actor="kim")
        self.assertEqual({f["id"]: f["level"] for f in st.spec("")["fields"]}["location"], "required")
        self.assertIn("location", st.spec("")["required"])

    def test_a_raised_level_shows_that_it_was_changed(self):
        st = store()
        st.set_level("location", "required")
        f = [x for x in st.spec("")["fields"] if x["id"] == "location"][0]
        self.assertTrue(f.get("level_changed"))

    def test_conditional_only_lands_on_a_field_that_has_a_group(self):
        st = store()
        st.set_level("mgmt_ip", "conditional")
        with self.assertRaises(ValueError):
            st.set_level("service", "conditional")

    def test_an_unknown_field_cannot_be_given_a_level(self):
        with self.assertRaises(ValueError):
            store().set_level("no_such_field", "required")

    def test_a_removed_field_is_not_deleted(self):
        """이 항목으로 이미 등록된 자산이 있을 수 있다 — 지우지 않고 '쓰지 않음' 으로 둔다."""
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        st.remove_field(fid)
        self.assertEqual(st.fields(), [])
        self.assertEqual([f["id"] for f in st.fields(active_only=False)], [fid])


class TrailTests(unittest.TestCase):
    """기준은 앞으로도 바뀐다 — 누가 언제 무엇을 바꿨는지 남아야 되짚을 수 있다."""

    def test_every_change_is_recorded_with_who(self):
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다", actor="kim/김운영")["id"]
        st.rename_field(fid, "랙 상면", actor="lee/이관리")
        st.set_level("location", "required", actor="lee/이관리")
        st.remove_field(fid, actor="lee/이관리")
        got = [(c["what"], c["actor"]) for c in st.changes(10)]
        self.assertEqual(len(got), 4)
        self.assertEqual({a for _, a in got}, {"kim/김운영", "lee/이관리"})
        self.assertIn("항목 추가", [w for w, _ in got])
        self.assertIn("등급 변경", [w for w, _ in got])

    def test_renaming_keeps_the_id(self):
        """이름은 바뀌어도 id 는 그대로 — 그래야 이미 등록된 자산이 깨지지 않는다."""
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        self.assertEqual(st.rename_field(fid, "전산실 상세 위치")["id"], fid)
        self.assertEqual([f["id"] for f in st.fields()], [fid])


if __name__ == "__main__":
    unittest.main()
