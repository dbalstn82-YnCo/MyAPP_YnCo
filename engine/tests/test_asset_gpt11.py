# -*- coding: utf-8 -*-
"""GPT 11차 적대적 검토로 막은 것들 (2026-09-30)

10차 반영을 보고하자 GPT 가 다시 상 1건·중상 2건·중 5건을 냈다. 그중 실제 결함을 여기서 고정한다.

그리고 **우리가 할 수 있는 약속의 경계**를 시험으로 적어 둔다 —
자격 정보임을 알아볼 수 있는 표기는 막지만, 뜻 표시 없이 일반 글자 칸에 적힌 비밀값까지
완전히 판별하는 것은 보장하지 않는다. 'Admin1234' 가 비밀번호인지 장비 이름인지 문자열만 보고
정할 방법이 없다. 지킬 수 없는 약속을 코드가 하는 것처럼 두지 않는다.
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import asset_custom as C           # noqa: E402
from logtriage import asset_import as I           # noqa: E402
from logtriage import asset_spec as A             # noqa: E402


def store():
    return C.Store(Path(tempfile.mkdtemp()) / "fields.sqlite3")


def base():
    b = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
    b.update(mgmt_ip="10.1.1.5", log_path="/var/log")
    return b


class ManualInputTests(unittest.TestCase):
    """[상] 파일에서 들어오는 값만 검사하고, 사람이 화면에서 적는 값은 아무 검사도 안 지났다."""

    def test_a_typed_credential_is_refused(self):
        for fid, val in (("access", "ssh pw=1234"), ("account", "admin pw=P@ss123"),
                         ("start_stop", "systemctl start; password: abcd"),
                         ("ha", "postgresql://admin:secret@db01/app"),
                         ("install_path", "-----BEGIN RSA PRIVATE KEY-----")):
            with self.subTest(field=fid):
                r = A.check(dict(base(), **{fid: val}), "was")
                self.assertTrue(r["tainted"], f"{fid} 에 적은 자격 정보를 받아들입니다")
                self.assertFalse(r["complete"])
                self.assertEqual(r["state"], "needs_review")

    def test_ordinary_typed_values_go_through(self):
        for fid, val in (("access", "SSH (22)"), ("account", "svcadm"),
                         ("start_stop", "systemctl restart jeus"), ("ha", "Active-Standby")):
            with self.subTest(field=fid):
                self.assertEqual(A.check(dict(base(), **{fid: val}), "was")["tainted"], [])

    def test_what_we_cannot_catch_is_written_down(self):
        """GPT 판단: 구분자만 보고 비밀번호라고 단정하면 오탐이 너무 많다.

        그래서 `admin / P@ss123` 처럼 **이름 표시가 없는** 값은 잡지 못한다. 잡는 척하지 않고
        여기 적어 둔다. 이 칸(접속 계정)을 '공백 없는 짧은 식별자' 로 못 박으면 모양 검사로
        걸러지겠지만, 그건 현장 표기('svcadm (운영)')를 대량으로 '확인 필요' 로 떨어뜨린다 —
        실제 고객 파일을 본 뒤 정할 일로 남겨 뒀다.
        """
        self.assertEqual(A.looks_like_secret("admin / P@ss123"), "")
        self.assertEqual(A.looks_like_secret("root:password"), "")

    def test_the_boundary_is_stated_not_overclaimed(self):
        """우리가 못 하는 것을 못 한다고 적어 둔다 — 지킬 수 없는 약속을 코드가 하지 않게."""
        doc = A.looks_like_secret.__doc__
        self.assertIn("보장하지 않는다", doc)
        # 뜻 표시가 없으면 못 잡는다는 사실 자체를 시험으로 적어 둔다
        self.assertEqual(A.looks_like_secret("Admin1234"), "")
        self.assertEqual(A.looks_like_secret("Qwer1234"), "")


class LexiconTests(unittest.TestCase):
    """[중] 머리글 사전과 칸 사전이 따로 관리되어, 한쪽만 늘리는 회귀가 생길 수 있었다."""

    ADDED = ("client_secret=abc123", "access_token=xyz789", "refresh_token=q1",
             "private_key=MIIB", "AccountKey=abcd", "SharedAccessKey=zz",
             "SharedAccessSignature=sv", "sas token: abc", "community=public",
             "snmp community public", "api-key: k1")

    def test_the_cell_scanner_comes_from_the_shared_lexicon(self):
        for w in ("client secret", "access token", "refresh token", "private key",
                  "accountkey", "sharedaccesskey", "sas token", "community"):
            with self.subTest(word=w):
                self.assertIn(w, A.LEXICON)

    def test_the_labels_gpt_listed_are_caught(self):
        for v in self.ADDED:
            with self.subTest(value=v):
                self.assertEqual(I._SECRET_IN_CELL.search(v), "labelled")

    def test_ordinary_values_still_go_through(self):
        for v in ("svcadm", "was01", "RHEL 8.6", "FW-3312", "/app/jeus/logs",
                  "이중화(Active-Standby)", "https://portal.example.com"):
            with self.subTest(value=v):
                self.assertIsNone(I._SECRET_IN_CELL.search(v))


class ShapeTests(unittest.TestCase):
    """[중] IPv6 를 못 읽었고, code 에 상위 경로 글자가 들어갈 수 있었다."""

    def test_ipv6_is_an_address_too(self):
        for v in ("10.1.1.5", "2001:db8::10", "fe80::1", "fe80::1%eth0", "::1"):
            with self.subTest(value=v):
                self.assertTrue(I._fits("ip", v), f"{v} 를 주소로 못 읽습니다")

    def test_a_wrong_address_is_still_wrong(self):
        for v in ("999.999.1.1", "10.1.1", "abc", "10.1.1.5 (VIP)"):
            with self.subTest(value=v):
                self.assertFalse(I._fits("ip", v))

    def test_a_code_cannot_carry_a_parent_path(self):
        """지금은 DB 값일 뿐이지만, 나중에 누가 경로 조각으로 쓰면 그 순간 취약점이 된다."""
        self.assertTrue(I._fits("code", "FW-3312"))
        self.assertTrue(I._fits("code", "net/vlan10"))
        for v in ("a/../../etc/passwd", "../x", "..", "a/.."):
            with self.subTest(value=v):
                self.assertFalse(I._fits("code", v))


class UnreadExitTests(unittest.TestCase):
    """[중] 못 알아본 값을 되돌려 주는 자리가 새 출구였다."""

    def test_a_credential_looking_raw_is_not_echoed(self):
        v = base()
        v["criticality"], v["criticality_raw"] = "", "pw=Secret123!"
        u = A.check(v, "was")["unread"][0]
        self.assertEqual(u["raw"], "")
        self.assertEqual(u["reason"], "sensitive_value_dropped")
        self.assertNotIn("Secret123", repr(A.check(v, "was")))

    def test_an_ordinary_raw_is_shown_so_a_person_can_choose(self):
        v = base()
        v["criticality"], v["criticality_raw"] = "", "왕중요"
        u = A.check(v, "was")["unread"][0]
        self.assertEqual(u["raw"], "왕중요")
        self.assertEqual(u["reason"], "")


class ReValidationTests(unittest.TestCase):
    """[중상] 보안 사전이 늘어도 이미 만들어진 항목은 다시 검사되지 않았다.

    보안 사전은 앞으로 계속 늘어난다. 새 검사가 새로 만들 때만 돌면 옛 항목이 그 사전을 비켜 간다.
    """

    def test_an_existing_field_is_rechecked_against_todays_rules(self):
        st = store()
        st.add_field("데이터 씨앗값", kind="code", aliases=["씨앗코드"],
                     why="시험을 위해 만든 항목입니다 열자", actor="kim")
        self.assertTrue(st.fields()[0]["from_file"])
        self.assertIsNone(st.fields()[0].get("quarantined"))

        keep = list(A.DROP["key"]["aliases"])
        A.DROP["key"]["aliases"] = keep + ["씨앗코드"]       # 다음 판에서 사전이 늘어난 상황
        try:
            f = st.fields()[0]
            self.assertEqual(f["quarantined"], "씨앗코드")
            self.assertFalse(f["from_file"], "자동 매핑에서 빠지지 않았습니다")
            self.assertTrue(f["needs_review"])
            # 지우지 않는다 — 이 항목으로 등록된 자산이 있을 수 있다
            self.assertEqual(len(st.fields()), 1)
            m = A.map_headers(["자산ID", "씨앗코드"], "was", extra=st.fields())
            self.assertEqual(m["columns"][1]["field"], "")
            self.assertEqual(m["columns"][1]["dropped"], "key")
        finally:
            A.DROP["key"]["aliases"] = keep


class PaceTests(unittest.TestCase):
    """[중] 탈취된 관리자 세션이 개칭·등급 변경을 되풀이해 디스크를 채울 수 있었다."""

    def test_too_many_changes_in_a_short_while_are_refused(self):
        st = store()
        with self.assertRaises(ValueError) as e:
            for i in range(C.WRITE_MAX + 10):
                st.set_level("location", "required" if i % 2 else "advised", actor="kim")
        self.assertIn("너무 많이", str(e.exception))

    def test_ordinary_use_is_not_hindered(self):
        st = store()
        for i in range(10):
            st.add_field(f"현장 항목 {i}", why="현장에서 실제로 필요한 항목입니다", actor="kim")
        self.assertEqual(len(st.fields()), 10)

    def test_the_limit_is_per_person(self):
        st = store()
        for i in range(C.WRITE_MAX):
            st.set_level("location", "required" if i % 2 else "advised", actor="kim")
        st.set_level("location", "required", actor="lee")     # 다른 사람은 막히지 않는다


class AmbiguityDedupTests(unittest.TestCase):
    """[중상] 같은 항목이 여러 경로로 같은 이름을 얻어도 '겹침' 으로 오판하지 않아야 한다."""

    def test_one_field_with_many_spellings_is_not_ambiguous(self):
        m = A.map_headers(["호스트명", "Hostname", "hostname"], "was")
        # 첫 열만 맞고 나머지는 이미 찬 자리라 못 맞추지만, '겹침' 으로 잡히지는 않는다
        self.assertEqual(m["ambiguous"], [])
        self.assertEqual(m["columns"][0]["field"], "hostname")

    def test_the_type_narrows_the_candidates(self):
        """유형을 고르면 그 유형의 항목만 후보가 된다 — 다른 유형 항목과 겹치지 않는다."""
        for t in ("dbms", "was", "web"):
            with self.subTest(type=t):
                self.assertEqual(A.map_headers(["인스턴스"], t)["ambiguous"], [])


if __name__ == "__main__":
    unittest.main()


class CookieAndCorsTests(unittest.TestCase):
    """[중] 쿠키·CORS 를 시험으로 못 박는다.

    CSRF 관문 셋(표시 헤더·JSON 형식·Sec-Fetch-Site)이 서 있어도, 쿠키가 다른 사이트에서
    넘어온 요청에 실려 가면 방어가 한 겹 얇아진다. 지시대로 보안을 앞세워 Strict 로 둔다 —
    바깥 링크로 들어오면 한 번 더 눌러야 하는 불편이 생긴다.
    """

    SRC = (Path(__file__).resolve().parents[1] / "logtriage" / "server.py").read_text(encoding="utf-8")

    def test_every_session_cookie_is_strict_and_httponly(self):
        import re
        found = re.findall(r'Set-Cookie": f?"(lt_\w+)=[^"]*"', self.SRC)
        self.assertGreaterEqual(len(found), 4)
        for m in re.finditer(r'Set-Cookie": f?"(lt_\w+)=([^"]*)"', self.SRC):
            with self.subTest(cookie=m.group(1)):
                self.assertIn("HttpOnly", m.group(2))
                self.assertIn("SameSite=Strict", m.group(2))
                self.assertNotIn("SameSite=Lax", m.group(2))
                self.assertNotIn("Domain=", m.group(2))

    def test_we_never_open_ourselves_to_another_origin(self):
        """Access-Control-Allow-Origin 을 한 번이라도 내보내면 관문 셋이 무의미해진다."""
        self.assertNotIn("Access-Control-Allow-Origin", self.SRC)
        self.assertNotIn("Access-Control-Allow-Credentials", self.SRC)


class ArchiveAtomicTests(unittest.TestCase):
    """[중] 옮기는 도중 죽으면 기록이 사라질 수 있다 — 한 거래로 묶여 있어야 한다."""

    def test_moving_old_records_is_one_transaction(self):
        import inspect
        src = inspect.getsource(C.Store._archive)
        # 같은 db() 안에서 넣고 지운다 — 그 블록이 끝날 때 한 번에 커밋된다
        self.assertIn("INSERT OR IGNORE INTO changes_old", src)
        self.assertIn("DELETE FROM changes", src)
        self.assertNotIn("self.db()", src, "옮기기가 별도 연결을 열면 한 거래가 아니다")

    def test_nothing_is_lost_when_records_move(self):
        st = store()
        st.CHANGES_HOT = 6
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다", actor="kim")["id"]
        for i in range(12):
            st.rename_field(fid, f"상면 위치 {i}", actor="kim")
        with st.db() as db:
            hot = db.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
            old = db.execute("SELECT COUNT(*) FROM changes_old").fetchone()[0]
            dup = db.execute("SELECT COUNT(*) FROM changes c JOIN changes_old o ON c.id=o.id").fetchone()[0]
        self.assertEqual(hot + old, 13)
        self.assertEqual(dup, 0, "같은 기록이 두 표에 함께 있습니다")


class PackagedIdentityTests(unittest.TestCase):
    """[중] 배포본에 설치 id 가 들어가면 복제된 사이트들이 같은 id 를 갖는다.

    id 는 **첫 실행 때** 만들어져야 하고, 포장본에는 들어 있어서는 안 된다.
    """

    def test_the_source_tree_carries_no_field_store(self):
        root = Path(__file__).resolve().parents[1]
        for p in root.rglob("fields.sqlite3"):
            if "data" in p.parts and p.parts[p.parts.index("data") - 1] != "engine":
                continue
            self.fail(f"소스에 금고가 들어 있습니다: {p}")

    def test_the_installation_id_is_a_whole_uuid(self):
        self.assertEqual(len(store().installation), 32)


class Gpt12Tests(unittest.TestCase):
    """GPT 12차 — 릴리스 저지급은 없다고 했으나 조건 셋과 우선순위 넷을 줬다."""

    def test_a_quarantined_field_refuses_typed_values_too(self):
        """[조건] 자동 채움에서만 빼면 반쪽이다 — 화면으로 넣으면 그대로 들어간다."""
        st = store()
        fid = st.add_field("데이터 씨앗값", kind="code", aliases=["씨앗코드"],
                           why="시험을 위해 만든 항목입니다 열자", actor="kim")["id"]
        keep = list(A.DROP["key"]["aliases"])
        A.DROP["key"]["aliases"] = keep + ["씨앗코드"]
        try:
            r = A.check(dict(base(), **{fid: "FW-1"}), "was", extra=st.fields())
            self.assertEqual([t["reason"] for t in r["tainted"]], ["quarantined_field"])
            self.assertFalse(r["complete"])
        finally:
            A.DROP["key"]["aliases"] = keep

    def test_a_quarantined_field_does_not_make_a_real_one_ambiguous(self):
        """[우선] 이미 자동 매핑에서 뺀 항목이 후보에 남아 정상 항목까지 못 맞추게 하면 안 된다."""
        st = store()
        # 만들 때는 겹치지 않는 이름이다(겹치면 _guard 가 애초에 거절한다)
        st.add_field("데이터 씨앗값", kind="code", aliases=["씨앗주소"],
                     why="시험을 위해 만든 항목입니다 열자", actor="kim")
        mgmt = next(f for f in A.COMMON if f["id"] == "mgmt_ip")
        keep_alias, keep_drop = list(mgmt["aliases"]), list(A.DROP["key"]["aliases"])
        # 다음 판에서 ① 우리가 그 이름을 관리 IP 별칭으로 들이고 ② 보안 사전이 그 항목을 격리한다
        mgmt["aliases"] = keep_alias + ["씨앗주소"]
        A.DROP["key"]["aliases"] = keep_drop + ["씨앗주소"]
        try:
            self.assertTrue(st.fields()[0]["quarantined"])
            m = A.map_headers(["자산ID", "씨앗주소"], "was", extra=st.fields())
            # 격리된 항목이 후보에 남아 있었다면 '겹침' 이 되어 관리 IP 도 못 맞췄을 것이다.
            # 다만 그 머리글은 이제 받지 않는 낱말이므로 '버림' 으로 잡힌다 — 그것이 맞는 결과다
            self.assertEqual(m["ambiguous"], [])
            self.assertEqual(m["columns"][1]["dropped"], "key")
        finally:
            mgmt["aliases"] = keep_alias
            A.DROP["key"]["aliases"] = keep_drop

    def test_nothing_tainted_carries_the_value(self):
        """[조건] tainted 응답 어디에도 원문이 없어야 한다."""
        r = A.check(dict(base(), access="ssh pw=Secret123!"), "was")
        self.assertTrue(r["tainted"])
        self.assertNotIn("Secret123", repr(r))

    def test_definitions_are_bounded_even_when_they_are_not_deleted(self):
        """[우선] 만들고 내리기를 되풀이하면 쓰는 것은 늘 적어도 표는 무한히 커진다."""
        self.assertLess(C.MAX_FIELDS, C.MAX_DEFS)
        st = store()
        st.CHANGES_HOT = 10 ** 6
        C_MAX, D_MAX = C.MAX_FIELDS, C.MAX_DEFS
        try:
            C.MAX_FIELDS, C.MAX_DEFS = 2, 3
            a = st.add_field("현장 항목 하나", why="현장에서 필요한 항목입니다 시험", actor="kim")["id"]
            st.add_field("현장 항목 둘", why="현장에서 필요한 항목입니다 시험", actor="kim")
            with self.assertRaises(ValueError) as e:
                st.add_field("현장 항목 셋", why="현장에서 필요한 항목입니다 시험", actor="kim")
            self.assertIn("쓰고 있는", str(e.exception))
            st.remove_field(a, actor="kim")                       # 쓰는 것은 1개로 줄었지만
            b = st.add_field("현장 항목 셋", why="현장에서 필요한 항목입니다 시험", actor="kim")["id"]
            st.remove_field(b, actor="kim")                       # 다시 1개 — 그런데 전체는 3개다
            with self.assertRaises(ValueError) as e2:
                st.add_field("현장 항목 넷", why="현장에서 필요한 항목입니다 시험", actor="kim")
            self.assertIn("지금까지 만든", str(e2.exception))
        finally:
            C.MAX_FIELDS, C.MAX_DEFS = C_MAX, D_MAX

    def test_a_field_id_is_a_whole_uuid(self):
        """[우선] 설치 id 는 32자를 다 쓰면서 항목 id 만 48비트로 줄일 이유가 없다."""
        fid = store().add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        self.assertEqual(len(fid), 34)          # 'x_' + 32
        self.assertTrue(fid.startswith("x_"))

    def test_the_scanner_is_not_a_way_in(self):
        """[우선] 정규식 검사 자체가 들어오는 문이 되면 안 된다 — 먼저 자르고 본다."""
        import time
        big = {"name": "a" * 500000, **{f"k{i}": "v" * 9000 for i in range(2000)}}
        t0 = time.time()
        A.check(big, "was")
        self.assertLess(time.time() - t0, 1.0)
        self.assertEqual(len(A._sane(big)), A.MAX_VALUES)
        self.assertEqual(len(A._sane({"name": "a" * 99999})["name"]), A.MAX_VALUE)
