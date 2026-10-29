# -*- coding: utf-8 -*-
"""기준을 바꾸는 길의 권한과 입구 (2026-09-30)

기준을 손보는 일은 하루치 운영이 아니다. 한 사람이 '필수' 를 '선택' 으로 내리면 그 뒤로
전사의 대장이 조용히 헐거워진다. 그래서 **읽기는 보기 권한, 바꾸기는 관리자 권한**이다.

그리고 현장 조정은 **서버가 가진 금고에서만** 읽는다. 요청이 항목 목록을 실어 보낼 수 있으면
아무나 '비밀번호' 항목이 있는 기준을 만들어 그 이름으로 파일을 읽힐 수 있다.
"""
import inspect
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import server as S                 # noqa: E402


WRITES = ("asset_field_add", "asset_field_rename", "asset_field_level", "asset_field_remove")


class PermissionTests(unittest.TestCase):
    def test_reading_the_standard_is_open_to_viewers(self):
        for n in ("asset_spec", "asset_check", "asset_map", "asset_fields"):
            with self.subTest(api=n):
                self.assertIn(n, S.API_NAMES)
                self.assertIn(n, S.READ_APIS)

    def test_changing_the_standard_needs_an_administrator(self):
        for n in WRITES:
            with self.subTest(api=n):
                self.assertIn(n, S.API_NAMES, f"{n} 이 등록되지 않았습니다")
                self.assertIn(n, S.ADMIN_APIS, f"{n} 은 관리자 전용이어야 합니다")
                self.assertNotIn(n, S.READ_APIS)

    def test_the_router_really_asks_for_admin(self):
        """목록에 넣어 두고 라우터가 안 보면 뜻이 없다 — 실제 판정을 확인한다."""
        h = S.Handler.__new__(S.Handler)
        for n in WRITES:
            with self.subTest(api=n):
                self.assertEqual(h._need("POST", "/api/" + n), "admin")
        self.assertEqual(h._need("POST", "/api/asset_fields"), "viewer")


class EntryTests(unittest.TestCase):
    def test_the_request_cannot_supply_its_own_field_list(self):
        """바깥에서 extra/levels 를 실어 보내는 길이 없어야 한다."""
        for n in ("asset_spec", "asset_check", "asset_map"):
            with self.subTest(api=n):
                args = inspect.signature(getattr(S.ServerApi, n)).parameters
                self.assertNotIn("extra", args, f"{n} 이 바깥에서 항목 목록을 받습니다")
                self.assertNotIn("levels", args, f"{n} 이 바깥에서 등급을 받습니다")

    def test_the_overlay_comes_from_the_server_store(self):
        src = inspect.getsource(S.ServerApi._asset_overlay)
        self.assertIn("self.asset_fields_store", src)

    def test_the_store_path_is_fixed_by_the_install(self):
        src = inspect.getsource(S.ServerApi.__init__)
        self.assertIn('asset_custom_mod.Store(base / "data" / "assets" / "fields.sqlite3")', src)

    def test_a_write_records_who_did_it(self):
        for n in WRITES:
            with self.subTest(api=n):
                self.assertIn("self._who()", inspect.getsource(getattr(S.ServerApi, n)))


class ScreenTests(unittest.TestCase):
    HTML = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "inventory.html").read_text(encoding="utf-8")

    def test_the_card_is_hidden_until_the_server_answers(self):
        """관리자가 아니면 카드를 열지 않는다 — 403 을 보고 알게 하지 않는다."""
        self.assertIn('id="fldcard" hidden', self.HTML)

    def test_user_text_is_escaped_everywhere_it_is_drawn(self):
        """항목 이름·까닭·별칭은 사람이 적은 글자다 — 그대로 붙이면 우리 화면이 남의 대본을 실행한다."""
        for token in ("${esc(f.label)}", "${esc(f.why)}", "${esc(f.id)}",
                      "${esc(c.actor||'(알 수 없음)')}", "${esc(c.detail)}"):
            with self.subTest(token=token):
                self.assertIn(token, self.HTML)

    def test_no_handler_is_built_by_string_interpolation(self):
        """붙이는 글에 onclick 을 끼워 넣지 않는다 — data-* 로 표시하고 한곳에서 받는다."""
        for bad in ("onclick=\"${", "onclick='${", "onchange=\"${"):
            with self.subTest(pattern=bad):
                self.assertNotIn(bad, self.HTML)
        self.assertIn("data-rn=", self.HTML)
        self.assertIn("data-rm=", self.HTML)
        self.assertIn("data-lv=", self.HTML)

    def test_the_screen_asks_for_the_reason_before_the_server_does(self):
        self.assertIn("무엇을 못 하는지", self.HTML)

    def test_the_screen_says_removal_does_not_delete(self):
        self.assertIn("지우지는 않습니다", self.HTML)

    def test_the_screen_never_offers_the_conditional_level(self):
        """조건부 필수는 기본 기준의 묶음에만 쓰는 등급이다 — 고를 수 있게 두면 거절만 본다."""
        self.assertIn("k!=='conditional'", self.HTML)


if __name__ == "__main__":
    unittest.main()
