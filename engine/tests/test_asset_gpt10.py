# -*- coding: utf-8 -*-
"""GPT 10차 적대적 검토로 막은 것들 (2026-09-30)

사용자 지시: "구멍은 다 막아야 한다. 보안이 강화되어 생기는 불편은 감수한다.
보안 강화로 구현이 불가능해지는 기능은 없앤다."

GPT 가 독립적으로 낸 상 3건·상후보 1건·중상 1건·중 6건을 여기서 고정한다.
대부분 **막히는지**를 보는 시험이고, 몇은 **기능을 없앴는지**를 보는 시험이다.
"""
import inspect
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import asset_custom as C           # noqa: E402
from logtriage import asset_import as I           # noqa: E402
from logtriage import asset_spec as A             # noqa: E402
from logtriage import server as S                 # noqa: E402


def store():
    return C.Store(Path(tempfile.mkdtemp()) / "fields.sqlite3")


class HangulStemTests(unittest.TestCase):
    """[상] 한글 합성어 안에 숨은 비밀을 놓쳤다.

    짧은 말을 '낱말 완전일치' 로만 보게 했더니, 한글은 공백 없이 붙어서 빠져나갔다.
    '접속암호' 의 낱말은 '접속암호' 하나이고 '암호'(2자)는 일치하지 않는다.
    """

    BYPASS = ("접속암호", "운영암호", "DB암호", "계정비번", "관리비번", "암호값", "비번값",
              "서비스토큰", "접속토큰", "토큰값", "API비밀키", "접속비밀키", "개인키값",
              "SSH개인키원문", "키스토어암호", "인증문자열", "로그인문자열",
              "DB 접속문자열", "Connection String", "JDBC URL", "ODBC DSN")

    def test_a_korean_stem_is_caught_inside_a_compound(self):
        for h in self.BYPASS:
            with self.subTest(header=h):
                self.assertTrue(A.is_dropped(h), f"'{h}' 를 그대로 읽습니다")

    def test_a_latin_short_word_still_needs_to_stand_alone(self):
        """한글처럼 품고 있는지로 보면 'pw' 가 'Shipping' 을 잡는다 — 영문은 낱말로만 본다."""
        for h in ("Shipping", "Pinpoint", "Spinlock", "Pipeline", "PowerShell", "Pending"):
            with self.subTest(header=h):
                self.assertFalse(A.is_dropped(h))
        self.assertTrue(A.is_dropped("PW"))

    def test_a_connection_string_is_refused_but_a_driver_version_is_not(self):
        """접속 문자열에는 대개 비밀번호가 박혀 있다. 드라이버 '버전' 은 그냥 버전이다."""
        self.assertTrue(A.is_dropped("JDBC URL"))
        self.assertFalse(A.is_dropped("JDBC 드라이버 버전"))
        self.assertFalse(A.is_dropped("DSN 이름"))


class RawNeverSatisfiesTests(unittest.TestCase):
    """[상] 못 알아본 값이 필수를 충족했다 — 뜻을 모르는 값으로 '완성' 을 선언했다."""

    def base(self):
        b = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        b.update(mgmt_ip="10.1.1.5", log_path="/var/log")
        return b

    def test_an_unreadable_enum_blocks_completion(self):
        for fid, raw in (("criticality", "왕중요"), ("env", "실서비스쯤?"),
                         ("state", "잠깐 멈춤"), ("type", "미들웨어같음")):
            with self.subTest(field=fid):
                v = self.base()
                v[fid] = ""
                v[fid + "_raw"] = raw
                r = A.check(v, "was")
                self.assertFalse(r["complete"], f"{fid} 를 못 알아봤는데 완성이라 합니다")
                self.assertEqual(r["state"], "needs_review")

    def test_an_unreadable_value_is_kept_not_thrown_away(self):
        """버리지는 않는다 — 무엇이 들어왔는지 보여 주고 사람이 고르게 한다."""
        v = self.base()
        v["criticality"] = ""
        v["criticality_raw"] = "왕중요"
        u = A.check(v, "was")["unread"]
        self.assertEqual([x["id"] for x in u], ["criticality"])
        self.assertIn("왕중요", u[0]["raw"])

    def test_a_raw_value_does_not_fill_a_group_or_a_type_requirement(self):
        v = self.base()
        v["mgmt_ip"], v["mgmt_ip_raw"] = "", "999.999.1.1"
        self.assertIn("one_of:reach", [m["id"] for m in A.check(v, "was")["missing"]])
        v2 = self.base()
        v2["port"], v2["port_raw"] = "", "http 포트요"
        self.assertIn("port", [m["id"] for m in A.check(v2, "was")["missing"]])

    def test_a_shape_that_does_not_fit_goes_to_raw(self):
        """'코드·번호' 항목에 아무 글자나 들어오면 종류를 제한한 뜻이 없어진다."""
        self.assertTrue(I._fits("code", "FW-3312"))
        for bad in ("Adm!n1234", "1층 랙 A-12", "가" * 50):
            with self.subTest(value=bad):
                self.assertFalse(I._fits("code", bad))
        self.assertTrue(I._fits("ip", "10.1.1.5"))
        self.assertFalse(I._fits("ip", "999.999.1.1"))
        rec = {}
        I._put(rec, "x_code", "Adm!n1234", {}, {"x_code": "code"})
        self.assertNotIn("x_code", rec)
        self.assertEqual(rec["x_code_raw"], "Adm!n1234")


class SiteIdentityTests(unittest.TestCase):
    """[상] 사이트마다 같은 이름이면 같은 id — 본사로 모을 때 뜻이 다른 둘이 합쳐진다."""

    def test_the_id_does_not_come_from_the_label(self):
        a, b = store(), store()
        ia = a.add_field("운영주소", why="이 장비에 어느 주소로 붙는지 적습니다")["id"]
        ib = b.add_field("운영주소", why="이 장비에 어느 주소로 붙는지 적습니다")["id"]
        self.assertNotEqual(ia, ib)
        self.assertNotEqual(a.global_id(ia), b.global_id(ib))

    def test_the_global_key_names_the_installation(self):
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        self.assertEqual(st.global_id(fid), st.installation + ":" + fid)
        self.assertEqual(len(st.installation), 32)


class AmbiguityTests(unittest.TestCase):
    """[중상] 동의어가 겹칠 때 어느 쪽도 이기지 않는다 — 틀린 매핑보다 매핑 실패가 낫다."""

    EXTRA = [dict(id="x_ops", label="운영주소", kind="code", level="advised",
                  why="시험용", aliases=[], group="현장 항목", custom=True, from_file=True)]

    def test_a_clean_name_still_maps(self):
        m = A.map_headers(["자산ID", "운영주소"], "was", extra=self.EXTRA)
        self.assertEqual(m["columns"][1]["field"], "x_ops")

    def test_a_name_with_two_meanings_maps_to_neither(self):
        mgmt = next(f for f in A.COMMON if f["id"] == "mgmt_ip")
        keep = list(mgmt["aliases"])
        mgmt["aliases"] = keep + ["운영주소"]        # 다음 판에서 우리가 별칭을 늘린 상황
        try:
            m = A.map_headers(["자산ID", "운영주소"], "was", extra=self.EXTRA)
            c = m["columns"][1]
            self.assertEqual(c["field"], "")
            self.assertEqual(sorted(c["ambiguous"]), ["mgmt_ip", "x_ops"])
            self.assertIn(1, m["ambiguous"])
            self.assertIn("골라", c["why"])
        finally:
            mgmt["aliases"] = keep

    def test_a_look_alike_character_stops_automatic_mapping(self):
        """NFKC 로도 키릴 글자는 라틴으로 바뀌지 않는다 — 자동으로 맞추지 않고 사람에게 넘긴다."""
        m = A.map_headers(["рassword", "Hostname"], "was")
        self.assertTrue(m["columns"][0].get("suspicious"))
        self.assertEqual(m["columns"][0]["field"], "")
        self.assertIn(0, m["ambiguous"])


class CellLayerTests(unittest.TestCase):
    """[중] 칸 안의 비밀을 한 겹으로만 봤다 — 주소·인증헤더·개인키가 통과했다."""

    CAUGHT = {
        "labelled": ("admin pw=1234", "pw 1234", "비번은 1234", "암호는 1234", "token ABCDEF12"),
        "uri": ("postgresql://admin:P@ss123@db01/app", "https://user:secret@example.com"),
        "auth": ("Bearer eyJhbGciOiJIUzI1NiJ9", "Authorization: Basic YWRtaW46cA=="),
        "pem": ("-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        "jwt": ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPx",),
    }
    KEPT = ("svcadm", "was01", "10.10.1.21", "RHEL 8.6", "JEUS 8 Fix#4", "/app/jeus/logs",
            "https://portal.example.com", "jdbc:postgresql://db01:5432/app", "FW-3312",
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "SHA256:ab12cd34", "이중화(Active-Standby)")

    def test_each_layer_catches_what_it_is_for(self):
        for layer, values in self.CAUGHT.items():
            for v in values:
                with self.subTest(layer=layer, value=v[:30]):
                    self.assertEqual(I._SECRET_IN_CELL.search(v), layer)

    def test_ordinary_asset_values_go_through(self):
        for v in self.KEPT:
            with self.subTest(value=v):
                self.assertIsNone(I._SECRET_IN_CELL.search(v))

    def test_entropy_alone_is_not_used(self):
        """UUID·일련번호·인증서 지문이 비밀번호와 똑같이 생겼다 — 무작위해 보인다고 버리면
        정상 값을 대량으로 잃는다(GPT 판단)."""
        for v in ("9f3a7c21b845de60", "SN-2024-0093-XK", "ab12cd34ef56ab78cd90"):
            with self.subTest(value=v):
                self.assertIsNone(I._SECRET_IN_CELL.search(v))

    def test_a_dropped_cell_never_carries_its_value(self):
        rec = {}
        I._put(rec, "account", "postgresql://admin:P@ss123@db01/app", {})
        self.assertEqual(rec["_dropped_cells"], ["account"])
        self.assertEqual(rec["_dropped_why"], {"account": "uri"})
        self.assertNotIn("P@ss123", repr(rec))


class NoFreeTextImportTests(unittest.TestCase):
    """[상] 자유 서술 칸의 무표식 비밀번호는 판별할 수 없다 — 그 경로를 없앴다.

    'Adm!n1234' 가 비밀번호인지 장비 이름인지 임시 코드인지 글자만 보고는 알 수 없다.
    막을 수 없으므로 파일에서 자동으로 채우는 길을 없앴다(지시의 마지막 줄).
    """

    def test_a_free_text_custom_field_is_not_filled_from_a_file(self):
        st = store()
        st.add_field("운영 메모", kind="text", aliases=["비고"],
                     why="현장에서 남기는 메모를 받으려고 만든 항목입니다")
        m = A.map_headers(["자산ID", "비고"], "was", extra=st.fields())
        self.assertEqual(m["columns"][1]["field"], "", "자유 서술 항목이 파일에서 채워집니다")

    def test_a_shape_checked_custom_field_is_still_filled(self):
        """기능을 통째로 없앤 것이 아니다 — 모양을 검사할 수 있는 것은 그대로 채운다."""
        st = store()
        st.add_field("방화벽 정책 번호", kind="code", aliases=["정책번호"],
                     why="통신이 막혔을 때 어느 정책을 풀어야 하는지 모릅니다")
        fid = st.fields()[0]["id"]
        m = A.map_headers(["자산ID", "정책번호"], "was", extra=st.fields())
        self.assertEqual(m["columns"][1]["field"], fid)

    def test_only_shape_checked_kinds_come_from_files(self):
        self.assertEqual(set(C.FROM_FILE), {"code", "ip", "date"})
        for kind in ("text", "multiline"):
            self.assertNotIn(kind, C.FROM_FILE)


class FloorTests(unittest.TestCase):
    """[중] 관리자 한 명이 핵심 필수를 '선택' 으로 내릴 수 있었다."""

    def test_a_core_field_cannot_be_lowered(self):
        st = store()
        for fid in C.FLOOR:
            for lv in ("optional", "advised"):
                with self.subTest(field=fid, level=lv), self.assertRaises(ValueError):
                    st.set_level(fid, lv)

    def test_raising_is_still_allowed(self):
        st = store()
        st.set_level("location", "required")
        self.assertEqual(st.levels()["location"], "required")

    def test_the_floor_covers_the_nine_we_require(self):
        self.assertEqual(set(C.FLOOR), set(A.spec("")["required"]))


class QuietAuditTests(unittest.TestCase):
    """[중] 바뀌지 않은 것을 기록하면 관리자가 기록을 무한히 불릴 수 있다."""

    def test_a_no_op_rename_is_not_recorded(self):
        st = store()
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        before = len(st.changes(100))
        self.assertTrue(st.rename_field(fid, "상면 위치")["unchanged"])
        self.assertEqual(len(st.changes(100)), before)

    def test_a_no_op_level_change_is_not_recorded(self):
        st = store()
        before = len(st.changes(100))
        self.assertTrue(st.set_level("asset_id", "required")["unchanged"])
        self.assertEqual(len(st.changes(100)), before)

    def test_going_back_to_our_default_removes_the_override(self):
        st = store()
        st.set_level("location", "required")
        self.assertTrue(st.set_level("location", "optional")["reverted"])
        self.assertEqual(st.levels(), {})

    def test_old_records_are_moved_not_deleted(self):
        """'지우지 않는다' 와 '쓰는 표를 영원히 키운다' 는 다른 말이다."""
        st = store()
        st.CHANGES_HOT = 6
        fid = st.add_field("상면 위치", why="현장 출동 때 어느 랙인지 못 찾습니다")["id"]
        for i in range(12):
            st.rename_field(fid, f"상면 위치 {i}")
        with st.db() as db:
            hot = db.execute("SELECT COUNT(*) FROM changes").fetchone()[0]
            old = db.execute("SELECT COUNT(*) FROM changes_old").fetchone()[0]
        self.assertLessEqual(hot, st.CHANGES_HOT)
        self.assertGreater(old, 0)
        self.assertEqual(hot + old, 13)


class CsrfTests(unittest.TestCase):
    """[상] 관리자 권한이 있다 와 관리자가 하려고 했다 는 다른 일이다.

    직접 확인했다 — 헤더 없이 Content-Type: text/plain 으로 asset_field_add 가 통했다.
    그러면 다른 사이트의 폼이 관리자 쿠키로 우리 기준을 고칠 수 있다.
    """

    def test_the_api_requires_our_own_marker_and_json(self):
        src = inspect.getsource(S.Handler.do_POST)
        self.assertIn("X-NMS-Request", src)
        self.assertIn("application/json", src)

    def test_a_cross_site_marker_is_refused(self):
        src = inspect.getsource(S.Handler._same_origin)
        self.assertIn("Sec-Fetch-Site", src)
        self.assertIn("same-origin", src)

    def test_every_screen_sends_the_marker(self):
        """서버가 요구하는데 화면이 안 보내면 제품이 멈춘다 — 둘을 함께 못 박는다."""
        root = Path(__file__).resolve().parents[1] / "logtriage"
        hits = 0
        for f in list((root / "gui").glob("*.html")) + [root / "server.py"]:
            t = f.read_text(encoding="utf-8")
            for mark in ("fetch('/api/'+name", "fetch('/api/'+n,"):
                at = 0
                while True:
                    at = t.find(mark, at)
                    if at < 0:
                        break
                    hits += 1
                    # 호출이 여러 줄에 걸쳐 있을 수 있어 그 뒤 한 토막을 함께 본다
                    self.assertIn("X-NMS-Request", t[at:at + 260],
                                  f"{f.name}: 표시를 안 보냅니다")
                    at += len(mark)
        # 16차: 관리 화면 '시연 자료' 탭(ltapi 호출 한 곳)을 마스터 요청으로 없애 4→3. 남은 호출은 모두 위에서 표시를 확인한다
        self.assertGreaterEqual(hits, 3)


class MaskedHeaderTests(unittest.TestCase):
    """[중] 머리글 자리에 값이 들어와 있는 파일이 있다 — 원문을 되돌려 주지 않는다."""

    def test_a_dropped_header_comes_back_masked(self):
        m = A.map_headers(["자산ID", "password=P@ssw0rd"], "was")
        c = m["columns"][1]
        self.assertTrue(c["dropped"])
        self.assertNotIn("P@ssw0rd", c["header"])
        self.assertTrue(c["header"].endswith("***"))

    def test_a_kept_header_is_shown_as_it_is(self):
        self.assertEqual(A.map_headers(["호스트명"], "was")["columns"][0]["header"], "호스트명")

    def test_control_characters_are_stripped(self):
        self.assertEqual(A.safe_header("호스트명" + chr(10) + "조작", 200), "호스트명 조작")


class CharsetTests(unittest.TestCase):
    """[중] 겉보기가 같은 다른 문자로 검사를 비켜 갈 수 있다."""

    def test_a_look_alike_label_is_refused(self):
        st = store()
        for word in ("pаssword", "рw", "bеta"):
            with self.subTest(word=word), self.assertRaises(ValueError):
                st.add_field(word, why="겉보기가 같은 다른 문자를 넣어 보는 시험입니다")

    def test_ordinary_names_are_accepted(self):
        st = store()
        for word in ("상면 위치", "FW-정책(번호)", "eth0/1 포트", "냉방 구역"):
            with self.subTest(word=word):
                st.add_field(word, why="현장에서 실제로 쓰는 이름입니다 시험용")


if __name__ == "__main__":
    unittest.main()
