# -*- coding: utf-8 -*-
"""로그인 방식 — 메일 인증을 내리고, 되돌릴 수 있게 (2026-09-30)

사용자 결정: "현재 메일 인증기능 제거, 추후 도입."

**지우는 것이 아니라 끄는 것**이다. 코드는 그대로 두고 기본값에서만 내렸다 — 되돌리는 것이
한 줄이어야 "추후 도입" 이 말이 된다.

그리고 이 결정에는 대가가 있다: 로그인이 없으면 **접속할 수 있는 사람이 모두 관리자**다.
자산 기준을 바꾸거나 본사 연동을 켜는 것도 막히지 않는다. 그 사실을 코드가 조용히 두지 않고
기동할 때와 바꿀 때 말하는지도 여기서 본다.
"""
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import auth as AU                  # noqa: E402
from logtriage import authmode as A               # noqa: E402


def base():
    return Path(tempfile.mkdtemp())


class DefaultTests(unittest.TestCase):
    def test_a_fresh_install_asks_for_a_company_account(self):
        """2026-10-01 사용자 지시로 처음 기동 기본값이 **계정 로그인**으로 돌아왔다.

        "페이지를 열고 계정 로그인" — 그래서 설정이 없는 서버는 local 로 시작하고,
        계정이 하나도 없으면 [관리자 계정 만들기] 화면으로 간다.
        """
        b = base()
        self.assertEqual(AU.ensure_conf(b)["mode"], "local")
        saved = json.loads((b / "conf" / "auth.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["mode"], "local")
        # 직접 가입 기본값은 **승인 뒤 사용** 이다 — 열어 둔 채로 시작하지 않는다
        self.assertEqual(saved["local"]["signup"], "approve")
        self.assertEqual(AU.ensure_conf(b)["local"]["signup"], "approve")

    def test_an_existing_setting_is_left_alone(self):
        """이미 이메일 로그인을 쓰고 있던 서버를 말없이 바꾸지 않는다."""
        b = base()
        (b / "conf").mkdir(parents=True)
        (b / "conf" / "auth.json").write_text(json.dumps({"mode": "local", "local": {"domain": "solideos.com"}}),
                                              encoding="utf-8")
        self.assertEqual(AU.ensure_conf(b)["mode"], "local")

    def test_the_email_login_code_is_still_there(self):
        """'추후 도입' 이 말이 되려면 코드가 남아 있어야 한다 — 끈 것이지 지운 것이 아니다."""
        self.assertIn("local", A.MODES)
        src = Path(AU.__file__).read_text(encoding="utf-8")
        self.assertIn('out["mode"] == "local"', src)


class SwitchTests(unittest.TestCase):
    def test_turning_it_back_on_is_one_line(self):
        b = base()
        AU.ensure_conf(b)
        self.assertEqual(A.main(["--base", str(b), "local"]), 0)
        self.assertEqual(A.read(b)["mode"], "local")

    def test_only_known_modes_are_accepted(self):
        b = base()
        AU.ensure_conf(b)
        with self.assertRaises(ValueError):
            A.write(b, "아무거나")

    def test_the_other_settings_are_not_touched(self):
        b = base()
        AU.ensure_conf(b)
        before = A.read(b)
        A.main(["--base", str(b), "password"])
        after = A.read(b)
        self.assertEqual(after["mode"], "password")
        for k in before:
            if k != "mode":
                self.assertEqual(after[k], before[k], f"{k} 가 함께 바뀌었습니다")

    def test_the_previous_file_is_kept(self):
        """바꾸기 전 파일을 .bak 으로 남긴다 — 되돌릴 수 있어야 한다."""
        b = base()
        AU.ensure_conf(b)
        before = A.read(b)["mode"]
        A.main(["--base", str(b), "password" if before != "password" else "local"])
        self.assertEqual(json.loads((b / "conf" / "auth.json.bak").read_text(encoding="utf-8"))["mode"], before)

    def test_a_half_written_file_is_never_left_behind(self):
        src = inspect.getsource(A.write)
        self.assertIn("tmp.replace(p)", src)
        self.assertIn("0o600", src)          # 설정에 비밀이 섞일 수 있다

    def test_no_change_is_no_write(self):
        """지금 값과 같은 것을 주면 아무것도 쓰지 않는다 — **기본값이 무엇이든** 그렇다."""
        b = base()
        AU.ensure_conf(b)
        now = A.read(b)["mode"]
        A.main(["--base", str(b), now])
        self.assertFalse((b / "conf" / "auth.json.bak").exists())


class HonestyTests(unittest.TestCase):
    """대가를 조용히 두지 않는다."""

    def test_the_first_boot_says_what_it_opens(self):
        """첫 기동이 무엇을 여는지 적어 둔다.

        기본값이 '로그인 없음' 이던 때에는 **접속할 수 있는 사람이 모두 관리자**라고 적었다.
        이제 기본값은 계정 로그인이므로 적어야 할 것이 바뀌었다 — 첫 화면이 무엇이고,
        그 뒤 사람들이 어떻게 들어오며(직접 가입), 그 가입이 **승인 뒤**라는 것.
        로그인을 내릴 때의 대가는 authmode 쪽에서 그대로 말한다(아래 시험).
        """
        src = inspect.getsource(AU.ensure_conf) + Path(AU.__file__).read_text(encoding="utf-8")
        self.assertIn("관리자 계정 만들기", src)
        self.assertIn("계정 만들기", src)
        self.assertIn("승인", src)

    def test_switching_to_an_open_mode_says_it_too(self):
        src = inspect.getsource(A.main)
        self.assertIn("들어온 사람이 모두 관리자", src)
        self.assertIn("자산 기준 바꾸기·본사 연동 켜기도 막히지 않습니다", src)

    def test_the_way_back_is_printed(self):
        self.assertIn("logtriage.authmode", Path(AU.__file__).read_text(encoding="utf-8"))


class NotFromTheWebTests(unittest.TestCase):
    """자기 로그인 방식을 웹에서 바꾸면 스스로 잠기거나 서버를 열어 버릴 수 있다."""

    def test_no_api_changes_the_login_mode(self):
        """막아야 하는 것은 **로그인 방식(mode)** 이 웹에서 바뀌는 것이다.

        전에는 server.py 에 'authmode' 글자가 있는지로 갈랐다. 2026-10-01 에 가입 방식
        (local.signup)을 화면에서 바꾸게 하면서 그 금지 목록에 걸렸다 — 가입 방식은
        화면에서 바꾸는 것이 맞고(설정 변경에 재기동 불허), 로그인 방식은 아니다.
        그래서 **글자 금지**를 걷고 바뀌는 칸을 본다.
        """
        import re
        src = (Path(__file__).resolve().parents[1] / "logtriage" / "server.py").read_text(encoding="utf-8")
        self.assertNotIn("authmode.write(", src)          # 방식을 쓰는 함수는 부르지 않는다
        self.assertNotIn("modefile.write(", src)
        self.assertNotIn("write(self._base, ", src)
        # 비교(==)가 아니라 **대입**을 찾는다
        self.assertIsNone(re.search(r'\["mode"\]\s*=(?!=)', src),
                          "서버가 로그인 방식을 직접 바꿉니다")

    def test_changing_the_signup_mode_leaves_the_login_mode_alone(self):
        """흉내가 아니라 **진짜로** 바꿔 보고, mode 가 그대로인지 파일에서 확인한다."""
        import tempfile
        from logtriage import server as S
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            AU.ensure_conf(b)
            api = S.ServerApi(b, [b])
            try:
                api.set_signup("code", actor="t@solideos.com")
                conf = json.loads((b / "conf" / "auth.json").read_text(encoding="utf-8"))
                self.assertEqual(conf["mode"], "local")            # 로그인 방식은 손대지 않았다
                self.assertEqual(conf["local"]["signup"], "code")
                self.assertEqual(api.accounts.conf["signup"], "code")   # 돌고 있는 프로세스에도 먹었다
                # '즉시 사용' 은 화면·API 에서 켤 수 없다(설정 파일로만) — GPT 20차
                with self.assertRaises(ValueError):
                    api.set_signup("open", actor="t@solideos.com")
                self.assertEqual(api.accounts.conf["signup"], "code")
            finally:
                api.close() if hasattr(api, "close") else None

    def test_no_screen_offers_it(self):
        gui = Path(__file__).resolve().parents[1] / "logtriage" / "gui"
        for f in gui.glob("*.html"):
            with self.subTest(screen=f.name):
                self.assertNotIn("authmode", f.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()


class OpenServerGuardTests(unittest.TestCase):
    """로그인 없이 **망에 열려는** 기동은 막는다.

    지시가 둘이고 여기서 충돌한다 — "메일 인증 제거" 와 "보안 위배는 반드시 제거".
    로그인이 없으면 접속할 수 있는 사람이 모두 관리자다. 자산 기준을 바꾸고, 본사 연동을 켜고,
    사용자를 만들 수 있다. 그 상태를 망에 열어 두는 것은 배너로 덮을 수 있는 일이 아니다
    (GPT: 릴리스 저지급).

    이 PC 안에서만 여는 것은 그대로 둔다 — 시험과 개인 사용을 막을 이유가 없다.
    """

    def test_no_login_on_a_network_address_is_refused(self):
        from logtriage import server as S
        for host in ("0.0.0.0", "::", "10.0.0.5", "logsvr.corp.local"):
            with self.subTest(host=host):
                self.assertTrue(S.guard_open_server(host, {"mode": "off"}, None))

    def test_this_machine_only_is_fine(self):
        from logtriage import server as S
        for host in ("127.0.0.1", "::1", "localhost"):
            with self.subTest(host=host):
                self.assertEqual(S.guard_open_server(host, {"mode": "off"}, None), "")

    def test_a_password_or_a_login_lets_it_open(self):
        from logtriage import server as S
        self.assertEqual(S.guard_open_server("0.0.0.0", {"mode": "off"}, "pw"), "")
        self.assertEqual(S.guard_open_server("0.0.0.0", {"mode": "local"}, None), "")
        self.assertEqual(S.guard_open_server("0.0.0.0", {"mode": "portal"}, None), "")

    def test_no_setting_at_all_is_treated_as_no_login(self):
        from logtriage import server as S
        self.assertTrue(S.guard_open_server("0.0.0.0", None, None))

    def test_the_message_says_the_ways_forward(self):
        from logtriage import server as S
        msg = S.guard_open_server("0.0.0.0", {"mode": "off"}, None)
        for want in ("--password", "logtriage.authmode", "--host 127.0.0.1"):
            with self.subTest(want=want):
                self.assertIn(want, msg)

    def test_serve_refuses_before_opening_a_socket(self):
        src = inspect.getsource(__import__("logtriage.server", fromlist=["serve"]).serve)
        self.assertLess(src.index("guard_open_server"), src.index("make_server"),
                        "포트를 연 뒤에 막으면 이미 열린 것입니다")

    def test_the_switch_warns_before_you_restart(self):
        src = inspect.getsource(A.main)
        self.assertIn("망에 열린 채로는 기동하지 않습니다", src)


class GuardMessageTests(unittest.TestCase):
    """막는 이유는 **반드시 보여야 한다.**

    처음엔 그냥 print 로 찍었다가, 콘솔 부호(cp949)로 못 쓰는 글자에서 터져 역추적만 남고
    왜 안 떴는지 알 수 없게 됐다 — 실제로 그렇게 됐고 여기서 고정한다.
    """

    def test_the_reason_is_printed_safely(self):
        from logtriage import server as S
        src = inspect.getsource(S.serve)
        i = src.index("기동하지 않았습니다")
        line = src[max(0, i - 120):i]
        self.assertIn("_say(", line, "콘솔 부호에서 터지면 이유가 안 보입니다")

    def test_the_safe_printer_survives_a_narrow_console(self):
        import io
        from logtriage import auth as _A
        old = sys.stdout
        try:
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp949", errors="strict")
            _A._say("막는 이유 \u2014 줄표가 들어 있습니다")      # cp949 가 못 쓰는 글자
        finally:
            sys.stdout = old


class SafeOutputTests(unittest.TestCase):
    """안내가 콘솔 부호 때문에 사라지면 안 된다.

    줄표 하나 때문에 명령 전체가 역추적을 뱉으면 사람은 무엇을 해야 하는지 모른다 —
    포장본에서 실제로 그렇게 됐다.
    """

    def test_the_command_prints_through_a_narrow_console(self):
        import io
        import tempfile as _t
        from logtriage import auth as _AU
        b = Path(_t.mkdtemp())
        _AU.ensure_conf(b)
        old = sys.stdout
        try:
            sys.stdout = io.TextIOWrapper(io.BytesIO(), encoding="cp949", errors="strict")
            self.assertEqual(A.main(["--base", str(b)]), 0)
            self.assertEqual(A.main(["--base", str(b), "local"]), 0)
        finally:
            sys.stdout = old

    def test_nothing_in_this_command_prints_unguarded(self):
        src = Path(A.__file__).read_text(encoding="utf-8")
        body = src.split("MODES = {", 1)[1]
        for line in body.splitlines():
            t = line.strip()
            if t.startswith("print(") and "file=sys.stderr" not in t:
                self.fail(f"안전하지 않은 출력이 남아 있습니다: {t[:60]}")
