# -*- coding: utf-8 -*-
"""운영 모드를 화면에서 고른다 — 단독 / 본사 / 사이트 (2026-09-30)

사용자 지시: "단독설치형이라는 이유로 통합현황 메뉴를 활용할 수 없다. 단독이든 본사 연동이든
선택할 수 있게 하고 메뉴 활성화가 필요하다."

전에는 [통합 현황] 에 들어가면 "conf/hub.json 을 손으로 만들고 서비스를 다시 시작하십시오" 만
나왔다. 설치한 사람이 그 파일을 못 만들면 그 메뉴는 **없는 것과 같다.**

모드를 바꾸는 일은 가볍지 않다 —
  · 사이트로 바꾸면 이 서버가 **데이터를 밖으로 보내기 시작한다.**
  · 본사로 바꾸면 다른 사이트의 데이터를 **받기 시작한다.**
그래서 관리자만, 되돌릴 수 있게, 누가 언제 바꿨는지 남게 한다.
"""
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

sys.path.insert(0, str(Path(__file__).resolve().parent))  # 같은 폴더의 시험 틀

import test_enterprise as E                     # noqa: E402  (Srv — 실서버 띄우기)
from logtriage import hub as H                    # noqa: E402
from logtriage import server as S                 # noqa: E402

TOK = "t" * 40


def base():
    return Path(tempfile.mkdtemp())


class CheckTests(unittest.TestCase):
    """파일로 들어오든 화면으로 들어오든 **같은 검사**를 지나야 한다."""

    def test_the_file_and_the_screen_share_one_check(self):
        src = inspect.getsource(H.load_conf)
        self.assertIn("check_conf", src, "파일 읽기가 따로 검사하면 화면으로 다른 값이 들어옵니다")

    def test_a_standalone_server_is_a_valid_choice(self):
        b = base()
        self.assertIsNone(H.save_conf(b, None))
        self.assertIsNone(H.load_conf(b))

    def test_central_needs_only_a_site_id(self):
        c = H.save_conf(base(), {"role": "central", "site_id": "HQ", "site_name": "본사"})
        self.assertEqual((c["role"], c["site_id"]), ("central", "HQ"))

    def test_a_site_needs_an_address_and_a_token(self):
        for bad in ({"role": "site", "site_id": "X"},
                    {"role": "site", "site_id": "X", "hub_url": "https://hq/"},
                    {"role": "site", "site_id": "X", "hub_token": TOK}):
            with self.subTest(conf=sorted(bad)), self.assertRaises(ValueError):
                H.check_conf(bad)

    def test_plain_http_is_refused_unless_it_is_this_machine(self):
        """사이트 토큰과 보고서가 평문으로 나간다.

        전에는 "평문 허용" 스위치로 원격 http 를 열 수 있었다. **그 스위치를 없앴다** —
        안전하게 만들 수 없는 기능은 두지 않는다는 지시 그대로다(GPT 중상).
        """
        with self.assertRaises(ValueError) as e:
            H.check_conf({"role": "site", "site_id": "X", "hub_url": "http://hq.corp.local", "hub_token": TOK})
        self.assertIn("https", str(e.exception))
        H.check_conf({"role": "site", "site_id": "X", "hub_url": "http://127.0.0.1:9", "hub_token": TOK})
        with self.assertRaises(ValueError):          # 스위치를 켜도 안 된다
            H.check_conf({"role": "site", "site_id": "X", "hub_url": "http://hq.corp.local",
                          "hub_token": TOK, "allow_http": True})

    def test_the_address_is_read_by_a_parser_not_a_pattern(self):
        for bad in ("https://hq/api/x", "https://hq/?r=1", "https://hq/#x", "notascheme://hq"):
            with self.subTest(url=bad), self.assertRaises(ValueError):
                H.check_url(bad)
        self.assertEqual(H.check_url("https://hq.corp.local/"), "https://hq.corp.local")

    def test_a_trust_list_limits_where_we_may_send(self):
        """웹 관리자 한 사람이 목적지를 정할 수 있으면, 그 계정을 얻은 사람이 목적지를 정한다."""
        b = base()
        (b / "conf").mkdir(parents=True, exist_ok=True)
        H.check_url("https://anywhere.example", b)            # 목록이 없으면 제한하지 않는다
        (b / "conf" / H.ALLOW_FILE).write_text("# 우리 본사" + chr(10) + "hq.corp.local" + chr(10),
                                               encoding="utf-8")
        # 신뢰 단위는 호스트가 아니라 **출처**다 — 호스트만 보면 :8443 · :9443 도 다 열린다
        self.assertEqual(H.trusted(b), ["https://hq.corp.local"])
        H.check_url("https://hq.corp.local", b)
        with self.assertRaises(ValueError) as e:
            H.check_url("https://evil.example", b)
        self.assertIn("목록에 없습니다", str(e.exception))
        with self.assertRaises(ValueError):          # 같은 호스트라도 다른 포트는 다른 곳이다
            H.check_url("https://hq.corp.local:8443", b)

    def test_an_origin_is_normalised(self):
        self.assertEqual(H.origin_of("https://HQ.CORP.LOCAL/"), "https://hq.corp.local")
        self.assertEqual(H.origin_of("https://hq.corp.local:443"), "https://hq.corp.local")
        self.assertEqual(H.origin_of("https://hq.corp.local:8443"), "https://hq.corp.local:8443")
        self.assertEqual(H.origin_of("http://[2001:db8::1]:9443"), "http://[2001:db8::1]:9443")
        self.assertEqual(H.origin_of("보통글자"), "")

    def test_the_trust_list_cannot_be_written_from_the_screen(self):
        """목록이 화면에서 바뀌면 제한하는 뜻이 없다."""
        for mod in (H, S):
            src = Path(mod.__file__).read_text(encoding="utf-8")
            with self.subTest(module=mod.__name__):
                self.assertNotIn("hub_allow.txt\").write", src)
                self.assertNotIn("ALLOW_FILE).write", src)

    def test_an_address_cannot_carry_a_password(self):
        """주소에 박아 넣은 아이디·비밀번호는 설정 파일과 화면·로그에 그대로 남는다."""
        with self.assertRaises(ValueError) as e:
            H.check_conf({"role": "site", "site_id": "X",
                          "hub_url": "https://admin:pw@hq.corp.local", "hub_token": TOK})
        self.assertIn("아이디", str(e.exception))

    def test_a_bad_site_id_is_refused(self):
        for sid in ("", "본 사", "a" * 33, "x/y"):
            with self.subTest(site_id=sid), self.assertRaises(ValueError):
                H.check_conf({"role": "central", "site_id": sid})

    def test_the_interval_is_clamped(self):
        self.assertEqual(H.check_conf({"role": "central", "site_id": "HQ", "interval_sec": 1})["interval_sec"], 15)
        self.assertEqual(H.check_conf({"role": "central", "site_id": "HQ", "interval_sec": 99999})["interval_sec"], 3600)


class SecretTests(unittest.TestCase):
    """사이트 토큰은 **돌려주지 않는다** — 화면을 볼 수 있는 사람이 곧 본사에 쓸 수 있는 사람이 되면 안 된다."""

    def test_the_token_never_comes_back(self):
        c = H.check_conf({"role": "site", "site_id": "X", "hub_url": "https://hq/", "hub_token": TOK})
        pub = H.public_conf(c)
        self.assertNotIn(TOK, json.dumps(pub, ensure_ascii=False))
        self.assertTrue(pub["token_set"])
        self.assertNotIn("hub_token", pub)

    def test_a_standalone_server_says_so_without_inventing_fields(self):
        pub = H.public_conf(None)
        self.assertEqual(pub["role"], "none")
        self.assertFalse(pub["token_set"])

    def test_the_stored_file_is_not_world_readable(self):
        """사이트 토큰이 들어 있는 파일이다."""
        b = base()
        H.save_conf(b, {"role": "site", "site_id": "X", "hub_url": "https://hq/", "hub_token": TOK})
        p = b / "conf" / "hub.json"
        self.assertTrue(p.exists())
        if sys.platform != "win32":              # 윈도우는 POSIX 권한 개념이 다르다
            self.assertEqual(p.stat().st_mode & 0o077, 0)


class UndoTests(unittest.TestCase):
    """잘못 바꿨을 때 되돌릴 수 있어야 한다."""

    def test_the_previous_setting_is_kept(self):
        b = base()
        H.save_conf(b, {"role": "central", "site_id": "HQ", "site_name": "본사"})
        H.save_conf(b, {"role": "site", "site_id": "BUSAN", "hub_url": "https://hq/", "hub_token": TOK})
        bak = json.loads((b / "conf" / "hub.json.bak").read_text(encoding="utf-8"))
        self.assertEqual(bak["site_id"], "HQ")

    def test_going_back_to_standalone_keeps_a_copy(self):
        b = base()
        H.save_conf(b, {"role": "central", "site_id": "HQ"})
        H.save_conf(b, None)
        self.assertFalse((b / "conf" / "hub.json").exists())
        self.assertTrue((b / "conf" / "hub.json.bak").exists())

    def test_a_half_written_file_is_never_left_behind(self):
        """쓰다가 죽어도 반쪽짜리 설정이 남지 않게 — 임시 파일에 쓰고 바꿔친다."""
        self.assertIn("tmp.replace", inspect.getsource(H.save_conf))


class ApplyTests(unittest.TestCase):
    """서비스를 다시 시작하지 않고 바뀌어야 한다 — 그러지 않으면 화면에서 고르는 뜻이 없다."""

    def test_the_switch_stops_the_old_sender_first(self):
        src = inspect.getsource(S.ServerApi.switch_hub)
        self.assertLess(src.index("old.stop(abandon=True)"), src.index("_install_hub"),
                        "옛 전송을 멈추기 전에 새 것을 세우면 두 설정이 겹칩니다")
        self.assertIn("_hub_lock", src, "동시에 두 번 바꾸면 어긋납니다")

    def test_it_will_not_switch_while_the_old_sender_is_still_sending(self):
        """두 설정이 동시에 살아 있느니 바꾸지 않는 편이 낫다(fail-closed)."""
        src = inspect.getsource(S.ServerApi.switch_hub)
        self.assertIn("not old.stop(abandon=True)", src)
        self.assertIn("모드를 바꾸지 못했습니다", src)

    def test_a_failure_puts_the_old_setting_back(self):
        """저장만 되고 적용이 실패하면, 지금은 옛 모드인데 다음 재시작부터 보내기 시작한다."""
        src = inspect.getsource(S.ServerApi.switch_hub)
        self.assertIn("before = self.hub_conf", src)
        self.assertIn("save_conf(self._base, before)", src)

    def test_it_returns_a_screen_safe_view(self):
        self.assertIn("public_conf", inspect.getsource(S.ServerApi._install_hub))

    def test_leaving_central_closes_the_central_store(self):
        """파일이 있는지로 판단하면 사이트로 바꾼 뒤에도 옛 통합 자료를 지금 것처럼 보여 준다."""
        src = inspect.getsource(S.ServerApi._install_hub)
        self.assertIn('conf["role"] == "central" else None', src)

    def test_an_abandoned_sender_can_never_send_again(self):
        """스레드가 제때 안 끝나도 밖으로 나가는 문에서 막혀야 한다."""
        import inspect as _i
        from logtriage import hub as _H
        self.assertIn("if self.abandoned", _i.getsource(_H.HubClient._post))
        self.assertIn("if self.abandoned", _i.getsource(_H.HubClient.cycle))

    def test_the_sender_never_follows_a_redirect(self):
        """허용된 본사가 302 로 다른 곳을 가리키면 토큰과 보고서가 그쪽으로 간다."""
        import inspect as _i
        from logtriage import hub as _H
        self.assertIn("_NoRedirect", _i.getsource(_H.HubClient._post))
        self.assertIn("raise urllib.error.HTTPError", _i.getsource(_H._NoRedirect))

    def test_certificate_checking_cannot_be_turned_off(self):
        import inspect as _i
        from logtriage import hub as _H
        self.assertNotIn("CERT_NONE", _i.getsource(_H.HubClient._post))
        self.assertNotIn("check_hostname = False", _i.getsource(_H.HubClient._post))


class PermissionTests(unittest.TestCase):
    """모드를 바꾸는 것은 관리자만. 보는 것은 누구나(토큰은 안 나가므로)."""

    def test_changing_the_mode_needs_an_administrator(self):
        h = S.Handler.__new__(S.Handler)
        self.assertEqual(h._need("POST", "/api/hub/admin/mode"), "admin")

    def test_reading_the_mode_is_open(self):
        h = S.Handler.__new__(S.Handler)
        self.assertEqual(h._need("GET", "/api/hub/mode"), "viewer")

    def test_the_change_is_audited_without_the_token(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        # 블록 길이에 기대지 않는다 — 다음 갈래가 시작될 때까지가 이 블록이다
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn('"hub.mode.prepare"', blk)
        for part in blk.split('a.audit')[1:]:
            self.assertNotIn("hub_token", part[:200])

    def test_an_empty_token_keeps_the_one_in_use_only_for_the_same_target(self):
        """빈칸을 '그대로 두기' 로 읽는 것은 **같은 곳일 때만** 맞다.

        hub=https://hq.company, token=SECRET-A 에서 hub 만 evil.example 로 바꾸고 토큰을
        비우면, 옛 규칙은 SECRET-A 를 evil.example 로 그대로 보냈다(GPT 상 등급).
        """
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn("hubmod.same_target(self.api.hub_conf, c)", blk)
        self.assertIn("보내는 곳이 바뀌었습니다", blk)

    def test_same_target_compares_the_origin_and_the_site(self):
        now = {"role": "site", "site_id": "BUSAN", "hub_url": "https://hq.corp.local"}
        self.assertTrue(H.same_target(now, dict(now, interval_sec=30)))
        self.assertTrue(H.same_target(now, dict(now, hub_url="https://hq.corp.local/")))
        for other in ({"hub_url": "https://evil.example"}, {"hub_url": "http://hq.corp.local"},
                      {"hub_url": "https://hq.corp.local:8443"}, {"site_id": "SEOUL"},
                      {"role": "central"}):
            with self.subTest(change=other):
                self.assertFalse(H.same_target(now, dict(now, **other)))
        self.assertFalse(H.same_target(None, now))


class ScreenTests(unittest.TestCase):
    """메뉴가 보이고, 그 화면에서 실제로 고를 수 있어야 한다."""

    GUI = Path(__file__).resolve().parents[1] / "logtriage" / "gui"
    HUB = (GUI / "hub.html").read_text(encoding="utf-8")

    def test_the_menu_item_is_on_every_screen(self):
        for f in self.GUI.glob("*.html"):
            if f.name in ("login.html",):
                continue
            t = f.read_text(encoding="utf-8")
            if 'nav class="nav"' not in t and "<nav" not in t:
                continue
            with self.subTest(screen=f.name):
                self.assertIn('data-href="/hub"', t, f"{f.name}: 통합 현황 메뉴가 없습니다")

    def test_the_hand_written_file_instruction_is_gone(self):
        """이 문장이 남아 있으면 사용자는 여전히 파일을 손으로 만들어야 한다."""
        self.assertNotIn("conf/hub.json</code> 을 만들고 서비스를 다시 시작", self.HUB)

    def test_all_three_modes_can_be_chosen(self):
        i = self.HUB.index("const MODES=")
        row = self.HUB[i:i + 120]
        for v in ("none", "central", "site"):
            with self.subTest(mode=v):
                self.assertIn(v + ":", row, f"{v} 모드를 고를 수 없습니다")
        self.assertIn("${pick('none')}${pick('central')}${pick('site')}", self.HUB)

    def test_the_mode_card_stays_visible_on_a_central_server(self):
        """본사에서 숨기면 본사는 자기 모드를 못 바꾼다(실제로 그렇게 되어 있었다)."""
        i = self.HUB.index("if(j.role==='central')")
        blk = self.HUB[i:self.HUB.index("else{$('central').hidden=true", i)]
        self.assertIn("modeForm()", blk)
        self.assertNotIn("$('sitecard').hidden=true", blk)

    def test_the_screen_hides_the_form_from_non_admins(self):
        """서버도 막지만 화면이 먼저 말한다 — 눌러 보고 거절당해 알게 하지 않는다."""
        self.assertIn("if(!CANSET)", self.HUB)
        self.assertIn("can_change", self.HUB)

    def test_the_token_field_is_a_password_box_and_is_never_prefilled(self):
        self.assertIn('id="m_tok" type="password"', self.HUB)
        self.assertNotIn('id="m_tok" type="password" maxlength="200" autocomplete="new-password" value=', self.HUB)

    def test_the_screen_says_what_will_happen_before_it_happens(self):
        for word in ("본사로 데이터를 보내기 시작합니다", "받기 시작합니다", "confirm("):
            with self.subTest(word=word):
                self.assertIn(word, self.HUB)

    def test_the_screen_says_plain_http_is_not_an_option(self):
        """전에는 켤 수 있는 스위치였다. 없앴으므로 화면도 그렇게 말해야 한다."""
        self.assertIn("평문으로 내보내는 길은 두지 않았습니다", self.HUB)
        self.assertNotIn('id="m_http"', self.HUB)
        self.assertNotIn('id="m_tls"', self.HUB)

    def test_the_screen_says_whether_the_trust_list_is_set(self):
        """목록이 없으면 '아무 데나 보낼 수 있는 상태' 라고 말해야 한다 — 조용히 두지 않는다."""
        self.assertIn("allow_list", self.HUB)
        self.assertIn("정해져 있지 않습니다", self.HUB)
        self.assertIn("hub_allow.txt", self.HUB)

    def test_user_text_is_escaped(self):
        for token in ("esc(locked ? m.locked_site_id : (m.site_id||''))",
                      "esc(m.site_name", "esc(m.hub_url"):
            with self.subTest(token=token):
                self.assertIn(token, self.HUB)

    def test_the_request_carries_our_own_marker(self):
        i = self.HUB.index("/api/hub/admin/mode")
        self.assertIn("X-NMS-Request", self.HUB[i:i + 260])




class TrustListOnScreenTests(unittest.TestCase):
    """화면이 허용 목록 상태를 알아야 "아무 데나 보낼 수 있다" 고 말할 수 있다."""

    def test_the_mode_api_hands_over_the_trust_list(self):
        src = inspect.getsource(S.Handler._hub_get)
        i = src.index('/api/hub/mode')
        self.assertIn("hubmod.trusted(self.api._base)", src[i:i + 500])

    def test_the_install_also_hands_it_over(self):
        self.assertIn("hubmod.trusted(self._base)", inspect.getsource(S.ServerApi._install_hub))


class TimeoutTests(unittest.TestCase):
    """멈추기를 기다리는 시간이 요청 하나보다 짧으면, 정상 운영에서도 모드 변경이 자주 막힌다.

    안전한 쪽으로 실패하는 것은 맞지만 늘 걸리면 사람은 그 기능을 안 쓰게 된다(GPT 지적).
    """

    def test_the_wait_is_longer_than_one_request(self):
        self.assertGreater(H.STOP_WAIT, H.SEND_TIMEOUT)

    def test_a_summary_send_does_not_hang_for_a_minute(self):
        self.assertLessEqual(H.SEND_TIMEOUT, 30)

    def test_a_report_upload_may_take_longer_but_is_still_bounded(self):
        self.assertGreaterEqual(H.FILE_TIMEOUT, H.SEND_TIMEOUT)
        self.assertLessEqual(H.FILE_TIMEOUT, 120)

    def test_the_timeouts_are_named_not_scattered(self):
        src = inspect.getsource(H.HubClient._post)
        self.assertIn("SEND_TIMEOUT", src)
        self.assertNotIn("timeout=60", src)


class SiteIdLockTests(unittest.TestCase):
    """사이트 ID 는 본사에 쌓인 자료를 가리키는 이름이다 — 보낸 뒤에 바꾸면 과거 자료와 끊긴다.

    화면 안내만으로는 부족하다는 GPT 지적에 사용자가 "바꾸지 못하게" 로 결정했다(2026-09-30).
    """

    def test_the_server_refuses_to_change_it_after_the_first_send(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        # 잠금 근거를 '보낸 적 있음' 에서 **못 박은 신원**으로 바꿨다 —
        # 전자는 단독으로 되돌리면 풀렸다(GPT 중상)
        self.assertIn("hubmod.locked_site(self.api._base)", blk)
        self.assertIn("못 박혀 있습니다", blk)
        self.assertNotIn("[단독 설치] 로", blk, "우회 절차를 알려 주면 안 됩니다")
        # 글귀가 있는 것만 보면 **가지를 잘못 타고 있어도 통과한다** — 실제로 그랬다.
        # 본사 모드로는 안 걸려서 포장본을 눌러 보고서야 찾았다.
        # 그래서 모드 가지보다 앞인지까지 본다(실제 동작은 LockHoldsInEveryModeTests).
        self.assertLess(blk.index("hubmod.locked_site(self.api._base)"),
                        blk.index('if want == "site":'),
                        "잠금 검사는 모드 가지보다 앞에 있어야 모든 모드에 걸린다")

    def test_the_screen_locks_on_the_same_ground_as_the_server(self):
        """서버는 못 박은 신원으로 막는데 화면이 다른 기준으로 잠그면,
        "칸은 열렸는데 거절당한다" 가 생긴다."""
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        self.assertIn("m.locked_site_id", hub)
        self.assertNotIn("m.ever_sent", hub)
        self.assertIn("readonly", hub)

    def test_the_mode_api_hands_over_the_locked_identity(self):
        src = inspect.getsource(S.Handler._hub_get)
        i = src.index('/api/hub/mode')
        self.assertIn('mode["locked_site_id"]', src[i:i + 700])


class AuditBeforeSendTests(unittest.TestCase):
    """밖으로 내보내기 전에 근거가 먼저 있어야 한다.

    시작하고 나서 기록하면, 첫 전송이 나간 뒤 기록이 실패할 수 있다 —
    **자료는 나갔는데 바꾼 근거가 없습니다**(GPT 중상).
    """

    def test_the_switch_does_not_start_sending_yet(self):
        self.assertIn("started=False", inspect.getsource(S.ServerApi.switch_hub))

    def test_the_handler_audits_then_starts(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertLess(blk.index('a.audit'), blk.index('self.api.start_hub()'),
                        "보내기를 시작한 뒤에 기록하면 근거 없는 전송이 생깁니다")

    def test_a_failed_audit_rolls_back(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn("self.api.rollback_hub(before_conf)", blk)
        self.assertIn("되돌렸습니다", blk)


class SendLockTests(unittest.TestCase):
    """동시에 보낼 수 있는 전송기가 언제나 정확히 하나여야 한다."""

    def test_sending_holds_a_lock(self):
        src = inspect.getsource(H.HubClient._post)
        self.assertIn("with self.sending:", src)

    def test_stopping_waits_for_a_send_in_flight(self):
        src = inspect.getsource(H.HubClient.stop)
        self.assertIn("self.sending.acquire(timeout=", src)
        self.assertIn("return False", src)

    def test_the_network_wait_is_not_a_minute(self):
        self.assertLessEqual(H.SEND_TIMEOUT, 15)
        self.assertGreaterEqual(H.STOP_WAIT, H.SEND_TIMEOUT)


class CompoundRiskTests(unittest.TestCase):
    """두 결정이 겹칠 때만 생기는 구멍.

    ① 허용 목록은 선택 — '관리자만' 이라는 경계가 있다는 전제 위에 선다.
    ② 로그인은 없음 — 내부망 전용이라는 전제 위에 선다.
    하나씩은 감수할 만한데, **겹치면 전제가 서로를 지운다** — 접속만 되면 누구나 이 서버가
    자료를 임의의 주소로 보내게 켤 수 있다(GPT 판정). 겹치는 자리만 막는다.
    """

    def test_no_login_and_no_trust_list_blocks_site_mode(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn("hubmod.trusted(self.api._base)", blk)
        self.assertIn("로그인이 없어", blk)

    def test_standalone_and_central_are_not_blocked(self):
        """자료가 밖으로 나가지 않는 모드까지 막으면, 고치라고 한 문제로 되돌아간다."""
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        guard = blk[blk.index("no_login"):blk.index("c[\"hub_url\"]")]
        self.assertIn('if want == "site":', blk[:blk.index("no_login")])
        self.assertNotIn('want == "central"', guard)

    def test_the_screen_disables_the_choice_and_says_why(self):
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        self.assertIn("m.site_blocked", hub)
        self.assertIn("disabled", hub)
        self.assertIn("지금은 쓸 수 없습니다", hub)

    def test_the_mode_api_reports_both_facts(self):
        src = inspect.getsource(S.Handler._hub_get)
        i = src.index('/api/hub/mode')
        blk = src[i:i + 900]
        self.assertIn('mode["no_login"]', blk)
        self.assertIn('mode["site_blocked"]', blk)


class IdentityPersistTests(unittest.TestCase):
    """[중상] 사이트 ID 잠금을 **단독 경유로 우회**할 수 있었다.

    BUSAN 으로 6개월 보내다 → 단독으로 → 다시 사이트 → SEOUL.
    화면이 "단독으로 되돌린 뒤 다시 설정하십시오" 라고 우회 절차를 알려 주는 셈이었다(GPT).
    """

    def test_the_identity_survives_a_trip_through_standalone(self):
        b = base()
        self.assertEqual(H.locked_site(b), "")
        H.lock_site(b, "BUSAN")
        self.assertEqual(H.locked_site(b), "BUSAN")
        H.save_conf(b, None)                      # 단독으로 되돌려도
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_it_is_written_once_and_not_overwritten(self):
        b = base()
        H.lock_site(b, "BUSAN")
        H.lock_site(b, "SEOUL")
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_the_server_checks_the_locked_identity(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn("hubmod.locked_site(self.api._base)", blk)
        self.assertIn("본사 담당자와 함께 재등록", blk)
        # 검사가 site 가지 **안에** 있으면 본사 모드로는 안 걸린다 — 실제로 그랬다.
        # 그래서 가지보다 앞인지(들여쓰기가 더 얕은지)까지 본다.
        want_site = blk.index('if want == "site":')
        self.assertLess(blk.index("hubmod.locked_site(self.api._base)"), want_site,
                        "사이트 ID 잠금 검사는 모드 가지보다 앞에 있어야 한다")

    def test_it_is_locked_when_a_send_succeeds(self):
        self.assertIn("lock_site(self.api._base", inspect.getsource(H.HubClient.cycle))


class RecoveryTests(unittest.TestCase):
    """[중상] 되돌리기까지 실패하면 조용히 넘기지 않는다."""

    def test_a_failed_rollback_leaves_a_marker_and_stops_sending(self):
        src = inspect.getsource(S.ServerApi.rollback_hub)
        self.assertIn("stop(abandon=True)", src)
        # 까닭 코드로 남긴다 — 설정 오류·신원 충돌과 복구 절차가 다르다(GPT 7차)
        self.assertIn("rollback_failed", src)
        self.assertNotIn("except Exception:\n                pass", src)

    def test_further_changes_are_refused_while_broken(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn("self.api.hub_broken()", blk)
        self.assertIn("더 바꾸지 않습니다", blk)

    def test_the_marker_does_not_teach_people_to_delete_it(self):
        """**표식을 손으로 지우라고 가르치지 않는다**(GPT 7차).

        그것이 정식 절차가 되면, 같은 손놀림으로 실제 송신했던 서버의 신원 잠금도
        풀 수 있다고 가르치는 셈이다. 검사를 지나야 풀리는 명령으로 안내한다.
        """
        src = inspect.getsource(S.ServerApi.rollback_hub)
        self.assertNotIn("이 파일을 지우고", src)
        boot = inspect.getsource(S.serve)
        self.assertIn("hubadmin", boot, "푸는 명령을 안내하지 않습니다")
        self.assertNotIn("를 지우고 다시 시작하십시오", boot)


class TwoStageAuditTests(unittest.TestCase):
    """[중상] '성공' 이라고 적었지만 아직 사실이 아니었다 — 시작이 뒤에 실패할 수 있다."""

    def test_prepare_then_applied(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertLess(blk.index('"hub.mode.prepare"'), blk.index('self.api.start_hub()'))
        self.assertLess(blk.index('self.api.start_hub()'), blk.index('"hub.mode.applied"'))

    def test_a_failed_start_is_recorded_and_rolled_back(self):
        src = inspect.getsource(S.Handler._admin_post)
        i = src.index('/api/hub/admin/mode')
        blk = src[i:src.index('if u.path.startswith("/api/hub/admin/"):', i)]
        self.assertIn('"hub.mode.failed"', blk)
        self.assertIn("ok=False", blk)


class TrustAnchorTests(unittest.TestCase):
    """[중상] 목록이 서비스 계정이 쓸 수 있는 폴더에 있으면 진짜 기준점이 아니다.

    유닉스에서는 파일이 읽기 전용이어도 **부모 폴더에 쓸 수 있으면** 지우고 새로 만들 수 있다.
    """

    def test_a_system_location_is_checked_first(self):
        self.assertTrue(H.SYSTEM_ALLOW)
        self.assertIn("/etc/logtriage/trusted_hubs", H.SYSTEM_ALLOW)
        self.assertIn("SYSTEM_ALLOW", inspect.getsource(H.trusted))

    def test_the_two_are_not_merged(self):
        """섞으면 약한 쪽(서비스가 쓸 수 있는 곳)이 이긴다."""
        src = inspect.getsource(H.trusted)
        self.assertIn("src or (Path(base)", src)


class PayloadTests(unittest.TestCase):
    """제품 약속: **원본 로그는 보내지 않습니다.**

    말로만 적어 두면 나중에 "요약 필드에 원문 일부를 넣자" 는 변경이 조용히 들어온다.
    표식을 심고 **실제로 나가는 내용**을 훑는다(GPT 권고: 이번 판에 넣을 것).
    """

    CANARY = "RAWLOGCANARY92731"

    def test_the_outgoing_summary_carries_no_raw_log_text(self):
        import json as _j
        from logtriage import server as _S
        api = _S.ServerApi(base(), [])
        rec = {"id": "t1", "analyzed_at": "2026-09-30 10:00:00", "name": "app.log",
               "files": [{"name": "app.log"}],
               "first": {"layer_ko": "WAS", "verdict": "OOM",
                         "lines": [self.CANARY], "evidence": self.CANARY},
               "sev_totals": {"critical": 1}, "events_total": 3,
               "events": [{"raw": self.CANARY, "msg": self.CANARY}]}
        api.store.save_incident(rec)
        conf = {"role": "site", "site_id": "X", "site_name": "X", "hub_url": "https://hq/",
                "hub_token": TOK, "interval_sec": 60, "send_reports": False}
        payload, _newest, _run = H.HubClient(api, conf).collect()
        body = _j.dumps(payload, ensure_ascii=False, default=str)
        self.assertNotIn(self.CANARY, body, "원본 로그가 본사로 나갑니다")
        for inc in payload.get("incidents", []):
            for key in ("lines", "evidence", "events", "raw", "text"):
                with self.subTest(field=key):
                    self.assertNotIn(key, inc, f"요약에 {key} 가 실려 나갑니다")

    def test_the_payload_keys_are_a_fixed_list(self):
        """목록 밖의 것을 통째로 얹는 코드가 생기면 여기서 걸린다."""
        src = inspect.getsource(H.HubClient.collect)
        i = src.index("payload = {")
        keys = src[i:]
        for want in ('"site"', '"targets"', '"alerts"', '"incidents"', '"runs"'):
            with self.subTest(key=want):
                self.assertIn(want, keys)
        self.assertNotIn("payload.update(", src)



class LockHoldsInEveryModeTests(unittest.TestCase):
    """사이트 ID 잠금은 **본사 모드에서도** 걸려야 한다 — 포장본을 눌러 보고 찾은 결함.

    포장한 서버를 띄워 눌러 보니 이렇게 됐다.
        화면: 사이트 ID 칸이 읽기 전용 — "'HQ' 로 등록되어 있어 바꿀 수 없습니다"
        서버: role=central 로 site_id=ATTACKER 를 보내면 **200 으로 받았다**
    그러면 설정은 ATTACKER, 못 박은 신원은 HQ 로 어긋난다. 그 뒤 사이트 모드로 바꾸면
    그때는 잠금이 걸려 HQ 를 요구하므로 화면과 설정이 서로 다른 값을 들고 있게 된다.
    본사 서버도 자기 자료를 이 이름으로 묶어 두므로 바꾸면 과거 자료와 끊긴다.

    소스를 훑는 시험은 이것을 놓쳤다 — 글자는 있었고 **가지만 틀렸다.**
    그래서 서버를 띄워서 본다.
    """

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        b = Path(self.td.name)
        (b / "conf").mkdir(parents=True, exist_ok=True)
        (b / "data").mkdir(parents=True, exist_ok=True)
        H.lock_site(b, "HQ")          # 이미 못 박힌 서버
        self.s = E.Srv(b)
        self.addCleanup(self.s.close)
        self.addCleanup(self.td.cleanup)

    def post(self, body):
        r, d = self.s.req("POST", "/api/hub/admin/mode", body)
        return r.status, json.loads(d.decode("utf-8"))

    def test_central_cannot_change_a_locked_site_id(self):
        st, j = self.post({"role": "central", "site_id": "ATTACKER", "site_name": "x"})
        self.assertEqual(st, 400, j)
        self.assertIn("HQ", j.get("error", ""))
        self.assertEqual((self.s.api.hub_conf or {}).get("site_id", ""), "")

    def test_central_with_the_locked_site_id_goes_through(self):
        st, j = self.post({"role": "central", "site_id": "HQ", "site_name": "본사"})
        self.assertEqual(st, 200, j)
        self.assertEqual(j["mode"]["site_id"], "HQ")

    def test_site_cannot_change_a_locked_site_id_either(self):
        st, j = self.post({"role": "site", "site_id": "OTHER",
                           "hub_url": "https://hq.example", "hub_token": "t" * 20})
        self.assertEqual(st, 400, j)
        self.assertIn("HQ", j.get("error", ""))

    def test_the_screen_also_does_not_send_a_central_admin_to_call_itself(self):
        """서버 글귀만 고치고 화면을 두면, 화면이 본사에게 자기한테 전화하라고 한다.

        포장본에서 실제로 그랬다 — 서버는 모드에 맞게 답하는데 화면 안내는 한 벌이었다.
        """
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        i = hub.index("locked ? (r===")
        blk = hub[i:hub.index("영문·숫자·_- 1~32자", i)]
        self.assertIn("r==='site'", blk, "잠금 안내가 모드에 따라 갈리지 않습니다")
        head, _, tail = blk.partition("본사 담당자와 함께 재등록")
        self.assertTrue(tail, "사이트 모드 안내에는 본사 담당자 안내가 있어야 합니다")
        self.assertNotIn("본사 담당자", tail, "본사 모드 안내에 본사 담당자 안내가 있습니다")

    def test_the_message_does_not_send_a_central_admin_to_call_itself(self):
        """본사 서버에는 전화할 '본사 담당자' 가 없다 — 그 자리에서 할 일을 적는다."""
        _, j = self.post({"role": "central", "site_id": "ATTACKER"})
        self.assertNotIn("본사 담당자", j["error"])
        _, j2 = self.post({"role": "site", "site_id": "OTHER",
                           "hub_url": "https://hq.example", "hub_token": "t" * 20})
        self.assertIn("본사 담당자", j2["error"])

    def test_standalone_is_not_blocked_by_the_lock(self):
        """단독은 사이트 ID 를 쓰지 않으므로 잠금과 무관하게 된다."""
        st, j = self.post({"role": "none"})
        self.assertEqual(st, 200, j)


class IdentityMigrationTests(unittest.TestCase):
    """옛 설치를 올릴 때 사이트 신원을 승계한다 — **없으면 업그레이드 한 번으로 잠금이 풀린다.**

    GPT 지적(상 후보). 구버전에는 data/hub_identity.json 이 없었다. 새 코드가 그 파일만
    권위로 삼으므로, 이미 BUSAN 으로 보내 오던 서버가 '잠기지 않은 새 설치' 로 보였다.
    실제로 재현했다 — BUSAN 을 SEOUL 로 바꾸고 보내는 곳까지 바꾸는 요청이 200 이었다.

    고른 기준: **보낸 적이 없다고 확인될 때만** 열어 둔다. '보낸 증거' 를 찾는 쪽으로 짜면
    증거 파일이 서비스 계정이 쓸 수 있는 자리라 지우는 것만으로 잠금이 풀린다.
    """

    def base(self, cycles=0, state=True, site_id="BUSAN", role="site"):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        conf = {"role": role, "site_id": site_id, "site_name": "x", "interval_sec": 60,
                "send_reports": True}
        if role == "site":
            conf.update({"hub_url": "https://hq.example", "hub_token": "t" * 24})
        (b / "conf" / "hub.json").write_text(json.dumps(conf), encoding="utf-8")
        if state:
            (b / "data" / "hub_client.json").write_text(json.dumps(
                {"last_ok": 1790000000.0 if cycles else 0.0,
                 "sent": {"incidents": 0, "reports": 0, "cycles": cycles}, "seq": cycles}),
                encoding="utf-8")
        return b

    def test_a_server_that_already_sent_gets_its_identity_locked(self):
        b = self.base(cycles=310)
        self.assertEqual(H.migrate_identity(b, H.load_conf(b)), "BUSAN")
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_it_locks_even_before_anything_was_sent(self):
        """송신 기록이 비어 있어도 잠근다 — **그 기록 자체가 위조된다**(GPT 5차).

        처음에는 "보낸 적 없는 것이 분명하면 연다" 로 짰다. 그런데 그 증거 파일
        data/hub_client.json 은 서비스 계정이 **쓸 수도** 있다. 지우는 것뿐 아니라 0 으로
        채워 넣는 것도 된다 — 열어 두는 쪽이 똑같이 위조되므로 경계가 아니다.
        """
        b = self.base(cycles=0)
        self.assertEqual(H.migrate_identity(b, H.load_conf(b)), "BUSAN")

    def test_a_missing_or_broken_state_file_changes_nothing(self):
        """송신 기록을 아예 보지 않으므로, 없든 깨졌든 결과가 같다."""
        # 역할이 뜻을 가져야 승계한다 — 역할 없는 사전은 UpgradeRobustnessTests 에서 본다
        self.assertEqual(H.migrate_identity(self.base(state=False),
                                            {"role": "site", "site_id": "BUSAN"}), "BUSAN")
        b = self.base(cycles=0)
        (b / "data" / "hub_client.json").write_text("{깨진", encoding="utf-8")
        self.assertEqual(H.migrate_identity(b, H.load_conf(b)), "BUSAN")

    def test_a_conflict_is_not_decided_by_the_server(self):
        """못 박은 신원과 설정이 다르면 **자동으로 정하지 않는다**(GPT 5차).

        어느 쪽이 맞는지는 본사에 무엇이 쌓여 있는지를 봐야 알 수 있고, 이 서버는 모른다.
        """
        b = self.base(cycles=5)
        H.lock_site(b, "SEOUL")
        why = H.identity_conflict(b, H.load_conf(b))
        self.assertIn("SEOUL", why)
        self.assertIn("BUSAN", why)
        self.assertEqual(H.identity_conflict(b, {"site_id": "SEOUL"}), "", "같으면 어긋남이 아니다")

    def test_a_conflict_stops_sending_at_boot(self):
        b = self.base(cycles=5)
        H.lock_site(b, "SEOUL")
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertTrue(srv.api.hub_broken(), "어긋났는데 전송을 멈추지 않았습니다")
        r, d = srv.req("GET", "/api/hub/mode")
        self.assertIn("SEOUL", json.loads(d)["mode"]["broken"])

    def test_the_identity_file_is_written_atomically(self):
        """보안 경계를 평범한 쓰기로 적지 않는다 — 반쪽 JSON 이 남으면 잠금이 풀린다(GPT 5차)."""
        src = inspect.getsource(H.lock_site)
        self.assertIn("os.replace", src)
        self.assertIn("fsync", src)
        self.assertIn("0o600", src)
        self.assertNotIn("write_text", src)

    def test_it_does_not_overwrite_an_identity_that_already_exists(self):
        b = self.base(cycles=310)
        H.lock_site(b, "SEOUL")
        self.assertEqual(H.migrate_identity(b, H.load_conf(b)), "")
        self.assertEqual(H.locked_site(b), "SEOUL")

    def test_standalone_has_nothing_to_migrate(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        self.assertEqual(H.migrate_identity(b, None), "")

    def test_a_central_server_is_migrated_too(self):
        """본사도 자기를 한 사이트로 포함한다 — 같은 이유로 승계한다."""
        b = self.base(cycles=5, site_id="HQ", role="central")
        self.assertEqual(H.migrate_identity(b, H.load_conf(b)), "HQ")

    def test_the_server_migrates_at_boot(self):
        """승계를 기동 때 부르지 않으면 아무 효과가 없다 — 실제로 띄워서 본다."""
        b = self.base(cycles=310)
        (b / "conf" / "hub_allow.txt").write_text(
            "https://hq.example" + chr(10) + "https://evil.example" + chr(10),
            encoding="utf-8")
        s = E.Srv(b)
        self.addCleanup(s.close)
        r, d = s.req("POST", "/api/hub/admin/mode",
                     {"role": "site", "site_id": "SEOUL",
                      "hub_url": "https://evil.example", "hub_token": "u" * 24})
        self.assertEqual(r.status, 400, d)
        self.assertIn("BUSAN", d.decode("utf-8"))
        self.assertEqual((s.api.hub_conf or {}).get("site_id"), "BUSAN")
        self.assertEqual((s.api.hub_conf or {}).get("hub_url"), "https://hq.example")


class RecoveryGuidanceTests(unittest.TestCase):
    """어긋난 채로 남은 상태를 **사람이 보는 자리에서** 말하고, 무엇을 확인할지 적는다.

    GPT 지적(중상): "표식을 지우고 다시 시작하십시오" 만 적으면 위험하다. 표식이 생겼다는 것은
    새 설정·옛 설정·실행 중인 전송기·감사 기록의 아귀를 맞추지 못했다는 뜻이라, 표식만
    지운다고 설정이 맞다는 보장이 없다. 그리고 서버 기록에만 적으면 아무도 보지 않는다.
    """

    def test_the_boot_message_points_at_the_screen_not_a_restart(self):
        """**설정을 바꾸려고 서비스를 내리지 않는다**(사용자 지시 2026-10-01).

        복구는 서버가 스스로 한다 — 화면에서 검사하고 다시 켠다. 콘솔 명령은 서버가
        아예 못 떠서 화면을 열 수 없을 때를 위한 것이다.
        """
        src = inspect.getsource(S.serve)
        self.assertIn("[통합 현황] 화면에서", src, "화면에서 된다고 말하지 않습니다")
        self.assertIn("다시 시작하지 않아도", src, "재기동이 필요 없다고 말해야 합니다")
        self.assertIn("그대로 쓸 수 있습니다", src, "로컬 기능은 쓸 수 있다고 말해야 합니다")
        self.assertIn("화면을 열 수 없을 때만", src, "콘솔은 마지막 수단이라고 말해야 합니다")

    def test_the_mode_api_tells_the_screen_about_it(self):
        """화면이 모르면 큰 경고를 띄울 수 없다."""
        src = inspect.getsource(S.Handler)
        i = src.index("/api/hub/mode")
        self.assertIn("mode[" + chr(34) + "broken" + chr(34) + "]", src[i:i + 2200])

    def test_the_screen_shows_a_warning_and_a_checklist(self):
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        self.assertIn("m.broken", hub)
        blk = hub[hub.index("brokenBox"):][:1600]
        self.assertIn("설정부터 확인하십시오", blk)
        for item in ("conf/hub.json", "사이트 토큰", "hub.json.bak"):
            self.assertIn(item, blk, f"화면 확인 목록에 {item} 가 없습니다")

    def test_a_broken_server_actually_reports_it(self):
        """실제로 띄워서 본다 — 표식이 있으면 모드 조회가 그 사실을 들고 온다."""
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "data").mkdir(parents=True)
        (b / "data" / S.ServerApi.RECOVERY).write_text("되돌리기까지 실패했습니다", encoding="utf-8")
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        r, d = srv.req("GET", "/api/hub/mode")
        self.assertEqual(r.status, 200)
        self.assertIn("되돌리기까지 실패", json.loads(d)["mode"]["broken"])


class RoleFieldTests(unittest.TestCase):
    """역할마다 받는 값이 다르다 — **다른 역할의 값은 거절한다**(GPT 5차).

    단독에 site_id 를 섞어 보내면 지금도 무시된다(확인했다). 그러나 무시하는 것과 거절하는
    것은 다르다 — 다음에 누가 그 값을 쓰기 시작하면 그 자리가 곧 우회로가 된다.
    이번에 찾은 본사 모드 우회와 같은 계열이다.
    """

    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.b = Path(td.name)
        (self.b / "conf").mkdir(parents=True)
        (self.b / "conf" / "hub_allow.txt").write_text("https://hq.example" + chr(10),
                                                       encoding="utf-8")
        self.s = E.Srv(self.b)
        self.addCleanup(self.s.close)

    def post(self, body):
        r, d = self.s.req("POST", "/api/hub/admin/mode", body)
        return r.status, d.decode("utf-8", "replace")

    def test_standalone_refuses_other_roles_fields(self):
        st, d = self.post({"role": "none", "site_id": "ATTACKER",
                           "hub_url": "https://evil.example", "hub_token": "x" * 24})
        self.assertEqual(st, 400, d)
        for k in ("site_id", "hub_url", "hub_token"):
            self.assertIn(k, d)

    def test_central_refuses_site_only_fields(self):
        st, d = self.post({"role": "central", "site_id": "HQ",
                           "hub_url": "https://evil.example", "hub_token": "x" * 24})
        self.assertEqual(st, 400, d)
        self.assertIn("hub_url", d)

    def test_nothing_leaks_into_the_stored_config(self):
        """거절되는 것은 물론, **저장에도 신원에도 닿지 않아야** 한다."""
        self.post({"role": "none", "site_id": "ATTACKER", "hub_url": "https://evil.example"})
        self.assertFalse((self.b / "conf" / "hub.json").exists())
        self.assertEqual(H.locked_site(self.b), "")
        r, d = self.s.req("GET", "/api/hub/mode")
        m = json.loads(d)["mode"]
        self.assertEqual((m["role"], m["site_id"], m["hub_url"]), ("none", "", ""))

    def test_what_the_screen_sends_is_accepted(self):
        """막는 것만 보면 '전부 막힘' 도 통과한다 — 화면이 보내는 그대로가 지나야 한다."""
        self.assertEqual(self.post({"role": "none"})[0], 200)
        st, d = self.post({"role": "central", "site_id": "HQ", "site_name": "본사",
                           "interval_sec": 60, "send_reports": True})
        self.assertEqual(st, 200, d)


class UpgradeRobustnessTests(unittest.TestCase):
    """옛 설치를 올릴 때 생기는 모습들 — **업그레이드가 서비스 중단이 되면 안 된다.**

    GPT 5차: 구버전 설정에 역할을 바꾸며 지우지 않은 사이트 ID 가 남아 있을 수 있고,
    없앤 항목(allow_http·verify_tls=false)이 남아 있을 수도 있다. 되살아나면 보안이 후퇴하고,
    읽기를 거절하다 서버가 아예 안 뜨면 업그레이드가 곧 서비스 중단이 된다.
    """

    def base(self, hub=None, extra=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub_allow.txt").write_text("https://hq.example" + chr(10), encoding="utf-8")
        if hub is not None:
            (b / "conf" / "hub.json").write_text(
                hub if isinstance(hub, str) else json.dumps(hub, ensure_ascii=False),
                encoding="utf-8")
        for rel, body in (extra or {}).items():
            (b / rel).parent.mkdir(parents=True, exist_ok=True)
            (b / rel).write_text(body, encoding="utf-8")
        return b

    def test_an_unreadable_config_does_not_stop_the_server(self):
        """읽을 수 없는 hub.json 때문에 서버가 아예 안 뜨면, 업그레이드가 서비스 중단이 된다."""
        for bad in ("{깨진", json.dumps({"role": "none", "site_id": "OLD-BUSAN"}),
                    json.dumps({"role": "site", "site_id": "X"})):
            with self.subTest(conf=bad[:30]):
                srv = E.Srv(self.base(hub=bad))
                self.addCleanup(srv.close)
                self.assertIsNone(srv.api.hub_conf, "쓸 수 없는 설정으로 연동을 켜면 안 됩니다")
                self.assertTrue(srv.api.hub_broken(), "멈춘 까닭을 남기지 않았습니다")
                self.assertEqual(srv.req("GET", "/healthz")[0].status, 200)

    def test_a_stale_site_id_is_not_turned_into_an_identity(self):
        """역할을 바꾸며 남은 사이트 ID 를 진짜 신원으로 못 박으면,
        이 서버는 쓴 적도 없는 이름에 영영 묶인다(GPT 5차)."""
        b = self.base(hub={"role": "none", "site_id": "OLD-BUSAN"})
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertEqual(H.locked_site(b), "")
        self.assertFalse((b / "data" / "hub_identity.json").exists())

    def test_migration_refuses_a_config_whose_role_means_nothing(self):
        """검증을 거치지 않은 사전을 넘겨도 승계하지 않는다 — 함수가 **스스로** 따진다."""
        b = self.base()
        for conf in ({"role": "none", "site_id": "OLD"}, {"site_id": "OLD"},
                     {"role": "", "site_id": "OLD"}, {"role": "site"}):
            with self.subTest(conf=conf):
                self.assertEqual(H.migrate_identity(b, conf), "")

    def test_a_half_written_identity_does_not_fool_us(self):
        """적다가 죽어 임시 파일만 남은 모습 — 반쪽에 속지 않고 제대로 적는다."""
        b = self.base(hub={"role": "site", "site_id": "BUSAN",
                           "hub_url": "https://hq.example", "hub_token": "t" * 24},
                      extra={"data/hub_identity.json.tmp": chr(123) + chr(34) + "site_id"})
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertEqual(H.locked_site(b), "BUSAN")
        self.assertFalse((b / "data" / "hub_identity.json.tmp").exists(), "임시 파일이 남았습니다")

    def test_retired_settings_are_rewritten_out_of_the_file(self):
        """돌고 있는 설정은 이미 안전하다. 그런데 파일에 'verify_tls': false 가 남아 있으면
        운영자가 그것을 읽고 \"검사가 꺼져 있다\" 고 믿고, 나중에 파일을 그대로 읽는 코드가
        생기면 그 순간 되살아난다(GPT 5차)."""
        b = self.base(hub={"role": "site", "site_id": "BUSAN",
                           "hub_url": "https://hq.example", "hub_token": "t" * 24,
                           "allow_http": True, "verify_tls": False})
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertIs(srv.api.hub_conf["verify_tls"], True, "돌고 있는 설정이 안전해야 합니다")
        saved = json.loads((b / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
        self.assertIs(saved.get("verify_tls"), True, "파일에 끄기가 남아 있습니다")
        self.assertNotIn("allow_http", saved, "없앤 항목이 파일에 남아 있습니다")
        self.assertTrue((b / "conf" / "hub.json.bak").exists(), "옛 파일을 남기지 않았습니다")

    def test_a_plain_http_hub_never_comes_back(self):
        """평문 주소가 남아 있으면 **사이트 서버로 올라오지 않는다** — 토큰이 평문으로 나간다."""
        b = self.base(hub={"role": "site", "site_id": "BUSAN",
                           "hub_url": "http://hq.example", "hub_token": "t" * 24,
                           "allow_http": True, "verify_tls": False})
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertIsNone(srv.api.hub_conf)
        self.assertIsNone(srv.api.hub_client)
        self.assertTrue(srv.api.hub_broken())


class SchemaVersionTests(unittest.TestCase):
    """내가 모르는 판이 적어 둔 설정은 **읽지도 고치지도 않는다**(GPT 7차).

    구판 프로그램이 신판 파일을 읽고 자기가 아는 칸만 다시 쓰면 새 보안 설정이 조용히
    사라진다 — 되돌리기·내리기에서 실제로 생기는 일이다.
    """

    def base(self, conf):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "conf" / "hub.json").write_text(
            conf if isinstance(conf, str) else json.dumps(conf, ensure_ascii=False),
            encoding="utf-8")
        return b

    def site(self, **extra):
        c = {"role": "site", "site_id": "BUSAN", "hub_url": "https://hq.example",
             "hub_token": "t" * 24}
        c.update(extra)
        return c

    def test_a_future_schema_is_refused(self):
        b = self.base(self.site(schema_version=H.SCHEMA_VERSION + 1, new_security_option=True))
        with self.assertRaises(H.FutureConf):
            H.load_conf(b)

    def test_a_future_schema_file_is_never_rewritten(self):
        """원본을 잃으면 장애 원인과 운영자의 증거를 한꺼번에 없앤다."""
        b = self.base(self.site(schema_version=H.SCHEMA_VERSION + 1, new_security_option=True))
        before = (b / "conf" / "hub.json").read_bytes()
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertEqual((b / "conf" / "hub.json").read_bytes(), before, "원본을 고쳤습니다")
        self.assertFalse((b / "conf" / "hub.json.bak").exists())
        self.assertIsNone(srv.api.hub_conf)
        self.assertEqual(srv.api.hub_recovery().get("reason"), "config_future")

    def test_our_own_schema_is_accepted_and_stamped(self):
        self.assertEqual(H.load_conf(self.base(self.site()))["schema_version"], H.SCHEMA_VERSION)

    def test_a_broken_file_is_never_rewritten_either(self):
        b = self.base("{깨진")
        before = (b / "conf" / "hub.json").read_bytes()
        srv = E.Srv(b)
        self.addCleanup(srv.close)
        self.assertEqual((b / "conf" / "hub.json").read_bytes(), before)
        self.assertEqual(srv.api.hub_recovery().get("reason"), "config_invalid")


class DegradedStateTests(unittest.TestCase):
    """**단독과 연동 차단은 뜻이 다르다**(GPT 7차).

    단독은 사용자가 정상적으로 고른 운영 방식이고, 차단은 본사 연동을 하려 했는데 설정
    이상으로 안전하게 막힌 상태다. 같은 none 으로 보여 주면, 보내고 있다고 믿는 서버가
    조용히 멈춰 있는 것을 아무도 모른다.
    """

    def srv(self, conf=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        if conf is not None:
            (b / "conf" / "hub.json").write_text(conf, encoding="utf-8")
        s = E.Srv(b)
        self.addCleanup(s.close)
        return s, b

    def test_a_server_the_user_chose_to_run_alone_is_standalone(self):
        s, _ = self.srv()
        self.assertEqual(s.api.hub_state(), "none")
        self.assertEqual(json.loads(s.req("GET", "/api/hub/mode")[1])["mode"]["hub_state"], "none")

    def test_a_blocked_server_is_not_called_standalone(self):
        s, _ = self.srv(conf="{깨진")
        self.assertEqual(s.api.hub_state(), "degraded",
                         "차단 상태를 단독으로 보여 주면 멈춘 것을 아무도 모릅니다")
        m = json.loads(s.req("GET", "/api/hub/mode")[1])["mode"]
        self.assertEqual(m["hub_state"], "degraded")
        self.assertEqual(m["broken_reason"], "config_invalid")
        self.assertTrue(m["broken_at"])

    def test_the_screen_shows_it_apart_from_standalone(self):
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        self.assertIn("본사 연동 중지됨", hub)
        self.assertIn("m.broken_reason", hub)
        self.assertIn("기능은 그대로 쓸 수 있습니다", hub, "로컬 기능은 쓸 수 있다고 말해야 합니다")

    def test_the_local_features_keep_working_while_the_hub_is_blocked(self):
        """연동이 막혔다고 로그 분석·자산·게시판까지 죽이면 가용성이 과도하게 상한다."""
        s, _ = self.srv(conf="{깨진")
        for path in ("/", "/resources", "/nms", "/automation", "/board", "/healthz"):
            with self.subTest(path=path):
                self.assertEqual(s.req("GET", path)[0].status, 200)
        self.assertIsNone(s.api.hub_client, "차단 상태에서 전송기가 살아 있습니다")


class RecoveryReasonTests(unittest.TestCase):
    """멈춘 까닭이 하나로 뭉뚱그려지면 **복구 명령이 틀린 절차를 고른다**(GPT 7차)."""

    def base(self, conf=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub.json").write_text(
            json.dumps(conf or {"role": "site", "site_id": "BUSAN"}), encoding="utf-8")
        return b

    def test_it_records_a_reason_a_time_and_a_fingerprint(self):
        b = self.base()
        H.mark_recovery(b, "identity_conflict", "신원과 설정이 달랐습니다")
        r = H.read_recovery(b)
        self.assertEqual(r["reason"], "identity_conflict")
        self.assertTrue(r["at"])
        self.assertTrue(r["config_hash"], "설정 지문이 없으면 그때 그 설정인가를 못 본다")

    def test_it_never_writes_the_token(self):
        b = self.base({"role": "site", "site_id": "BUSAN", "hub_token": "SUPERSECRET-TOKEN"})
        H.mark_recovery(b, "config_invalid", "설정을 읽을 수 없었습니다")
        raw = (b / "data" / H.RECOVERY_FILE).read_text(encoding="utf-8")
        self.assertNotIn("SUPERSECRET", raw, "멈춤 표식에 토큰이 들어갔습니다")

    def test_the_first_reason_is_kept(self):
        """나중 까닭이 첫 까닭을 덮으면 진짜 원인을 잃는다."""
        b = self.base()
        H.mark_recovery(b, "config_invalid", "처음")
        H.mark_recovery(b, "rollback_failed", "나중")
        self.assertEqual(H.read_recovery(b)["reason"], "config_invalid")

    def test_an_old_plain_text_marker_still_reads(self):
        """옛 판이 남긴 글자만 있는 표식도 받아 준다 — 업그레이드가 멈춤을 잃으면 안 된다."""
        b = self.base()
        (b / "data" / H.RECOVERY_FILE).write_text("되돌리기까지 실패했습니다", encoding="utf-8")
        r = H.read_recovery(b)
        self.assertEqual(r["reason"], "unknown")
        self.assertIn("되돌리기까지 실패", r["why"])



class NoRestartTests(unittest.TestCase):
    """**설정을 바꾸려고 서비스를 다시 시작하지 않는다** (사용자 지시 2026-10-01).

    한때 복구 두 가지(멈춤 표식 풀기·사이트 신원 바꾸기)를 콘솔 명령으로만 되게 했다.
    서버와 다른 프로세스가 동시에 같은 파일을 고치면 돌고 있는 것과 디스크가 어긋나기
    때문이었다. 그런데 그 어긋남을 없애는 길이 "서비스를 내려라" 만 있는 것이 아니다 —
    **서버 자신이 하면** 애초에 두 프로세스가 아니다. 그래서 서버 안으로 옮겼다.
    콘솔 명령은 서버가 아예 못 떠서 화면을 열 수 없을 때를 위해 남긴다.
    """

    def base(self, broken=None, conf=None):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub_allow.txt").write_text("https://hq.example" + chr(10), encoding="utf-8")
        (b / "conf" / "hub.json").write_text(json.dumps(conf or {
            "role": "site", "site_id": "BUSAN", "hub_url": "https://hq.example",
            "hub_token": "t" * 24, "interval_sec": 3600}), encoding="utf-8")
        self.srv = E.Srv(b)
        self.addCleanup(self.srv.close)
        if broken:
            H.mark_recovery(b, broken, "시험")
        return b

    def post(self, path, body=None):
        r, d = self.srv.req("POST", path, body if body is not None else {})
        return r.status, d.decode("utf-8", "replace")

    def test_every_ordinary_change_works_while_running(self):
        self.base()
        for label, body in (
                ("단독으로", {"role": "none"}),
                ("본사로", {"role": "central", "site_id": "BUSAN", "site_name": "x",
                            "interval_sec": 60, "send_reports": True}),
                ("사이트로", {"role": "site", "site_id": "BUSAN", "site_name": "x",
                              "hub_url": "https://hq.example", "hub_token": "u" * 24,
                              "interval_sec": 60, "send_reports": True}),
                ("주기만", {"role": "site", "site_id": "BUSAN", "site_name": "x",
                            "hub_url": "https://hq.example", "hub_token": "u" * 24,
                            "interval_sec": 300, "send_reports": False})):
            with self.subTest(label):
                st, d = self.post("/api/hub/admin/mode", body)
                self.assertEqual(st, 200, f"{label}: {d[:160]}")

    def test_clearing_needs_the_config_to_change_first(self):
        """고치지 않고 푸는 것은 **같은 일을 또 겪는 길**이다."""
        self.base(broken="rollback_failed")
        st, d = self.post("/api/hub/admin/recover")
        self.assertEqual(st, 409, d)
        self.assertIn("같습니다", d)

    def test_clearing_works_in_place_once_the_config_was_fixed(self):
        b = self.base(broken="rollback_failed")
        (b / "conf" / "hub.json").write_text(json.dumps({
            "role": "site", "site_id": "BUSAN", "hub_url": "https://hq.example",
            "hub_token": "t" * 24, "interval_sec": 120}), encoding="utf-8")
        st, d = self.post("/api/hub/admin/recover")
        self.assertEqual(st, 200, d)
        self.assertFalse(self.srv.api.hub_broken(), "표식이 남았습니다")
        self.assertIsNotNone(self.srv.api.hub_client, "그 자리에서 다시 세우지 않았습니다")
        m = json.loads(self.srv.req("GET", "/api/hub/mode")[1])["mode"]
        self.assertEqual(m["hub_state"], "site", "아직 차단으로 보입니다")

    def test_identity_change_needs_an_explicit_confirmation(self):
        b = self.base()
        H.lock_site(b, "BUSAN")
        st, d = self.post("/api/hub/admin/identity_reset", {"site_id": "SEOUL"})
        self.assertEqual(st, 400, d)
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_identity_change_works_in_place(self):
        b = self.base()
        H.lock_site(b, "BUSAN")
        st, d = self.post("/api/hub/admin/identity_reset", {"site_id": "SEOUL", "confirm": "1", "hub_token": "SEOUL-NEW-TOKEN-zzzzzzz"})
        self.assertEqual(st, 200, d)
        self.assertEqual(H.locked_site(b), "SEOUL")
        self.assertEqual(json.loads(self.srv.req("GET", "/api/hub/mode")[1])["mode"]["site_id"],
                         "SEOUL", "설정의 사이트 ID 를 같이 맞추지 않았습니다")
        self.assertEqual(H.identity_conflict(b, H.load_conf(b)), "")

    def test_a_bad_site_id_is_refused(self):
        b = self.base()
        H.lock_site(b, "BUSAN")
        st, d = self.post("/api/hub/admin/identity_reset",
                          {"site_id": "나쁜 이름!", "confirm": "1"})
        self.assertEqual(st, 400, d)
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_the_old_name_is_kept(self):
        b = self.base()
        H.lock_site(b, "BUSAN")
        self.post("/api/hub/admin/identity_reset", {"site_id": "SEOUL", "confirm": "1", "hub_token": "SEOUL-NEW-TOKEN-zzzzzzz"})
        d = json.loads((b / "data" / H.IDENTITY_FILE).read_text(encoding="utf-8"))
        self.assertEqual(d["previous"], "BUSAN")

    def test_both_are_written_to_the_audit(self):
        b = self.base(broken="rollback_failed")
        H.lock_site(b, "BUSAN")
        (b / "conf" / "hub.json").write_text(json.dumps({
            "role": "site", "site_id": "BUSAN", "hub_url": "https://hq.example",
            "hub_token": "t" * 24, "interval_sec": 120}), encoding="utf-8")
        self.post("/api/hub/admin/recover")
        self.post("/api/hub/admin/identity_reset", {"site_id": "SEOUL", "confirm": "1", "hub_token": "SEOUL-NEW-TOKEN-zzzzzzz"})
        import sqlite3
        con = sqlite3.connect(b / "data" / "auth" / "auth.sqlite3")
        acts = [r[0] for r in con.execute("SELECT action FROM audit")]
        con.close()
        self.assertIn("hub.recovery.cleared", acts)
        self.assertIn("hub.identity.reset", acts)

    def test_the_screen_offers_both_without_a_restart(self):
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        self.assertIn("/api/hub/admin/recover", hub, "화면에 푸는 길이 없습니다")
        self.assertIn("/api/hub/admin/identity_reset", hub)
        self.assertIn("다시 시작하지 않아도", hub, "재기동이 필요 없다고 말해야 합니다")

    def test_the_fingerprint_survives_our_own_normalising(self):
        """서버가 기동하며 정리한 것만으로 **'고쳤다' 가 되면 안 된다.**

        실제로 그래서 고치지 않은 설정이 풀렸다 — 처음 기동 때 서버 열쇠가 생기면서
        지문이 통째로 달라졌다.
        """
        b = self.base()
        a = H.conf_fingerprint(b)
        (b / "conf" / "secret.key").write_bytes(b"new-key-material")
        self.assertEqual(H.conf_fingerprint(b), a, "열쇠가 생겼다고 지문이 달라집니다")
        raw = json.loads((b / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
        (b / "conf" / "hub.json").write_text(json.dumps(raw, indent=4), encoding="utf-8")
        self.assertEqual(H.conf_fingerprint(b), a, "공백만 바꿔도 달라집니다")



class IdentityResetTokenTests(unittest.TestCase):
    """신원을 바꿀 때 **옛 토큰을 물려주지 않는다** (GPT 9차, 상 등급).

    재현했다 — 'HQ' 로 쓰던 토큰이 남은 채 'BUSAN' 으로 이름만 바뀌고 전송기가 그대로 돌았다.
    앞서 정한 규칙은 "보내는 곳이나 사이트가 바뀌면 쓰던 토큰을 물려주지 않는다" 였는데,
    신원 바꾸기가 그 경계를 비켜 갔다.
    """

    OLD = "HQ-ONLY-TOKEN-xxxxxxxx"

    def srv(self, role="site"):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub_allow.txt").write_text("https://hq.example" + chr(10), encoding="utf-8")
        conf = {"role": role, "site_id": "HQ", "site_name": "x", "interval_sec": 3600}
        if role == "site":
            conf.update({"hub_url": "https://hq.example", "hub_token": self.OLD})
        (b / "conf" / "hub.json").write_text(json.dumps(conf), encoding="utf-8")
        H.lock_site(b, "HQ")
        s = E.Srv(b)
        self.addCleanup(s.close)
        return s, b

    def post(self, s, body):
        r, d = s.req("POST", "/api/hub/admin/identity_reset", body)
        return r.status, d.decode("utf-8", "replace")

    def test_a_site_server_must_bring_a_new_token(self):
        s, b = self.srv()
        st, d = self.post(s, {"site_id": "BUSAN", "confirm": "1"})
        self.assertEqual(st, 400, d)
        self.assertIn("새 사이트 토큰", d)
        self.assertEqual(H.locked_site(b), "HQ", "토큰 없이 신원이 바뀌었습니다")

    def test_the_old_token_is_never_carried_over(self):
        s, b = self.srv()
        st, d = self.post(s, {"site_id": "BUSAN", "confirm": "1",
                              "hub_token": "BUSAN-NEW-TOKEN-yyyyyyy"})
        self.assertEqual(st, 200, d)
        saved = json.loads((b / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
        self.assertNotEqual(saved["hub_token"], self.OLD, "옛 토큰이 그대로 남았습니다")
        self.assertEqual(saved["site_id"], "BUSAN")
        self.assertEqual(s.api.hub_client.conf["hub_token"], "BUSAN-NEW-TOKEN-yyyyyyy",
                         "전송기가 아직 옛 토큰을 들고 있습니다")

    def test_a_central_server_needs_no_token(self):
        """본사는 보내는 쪽이 아니다 — 토큰을 요구하면 쓸 수 없는 기능이 된다."""
        s, b = self.srv(role="central")
        st, d = self.post(s, {"site_id": "BUSAN", "confirm": "1"})
        self.assertEqual(st, 200, d)
        self.assertEqual(H.locked_site(b), "BUSAN")

    def test_the_screen_asks_for_the_new_token(self):
        hub = (Path(__file__).resolve().parents[1] / "logtriage" / "gui" / "hub.html").read_text(encoding="utf-8")
        i = hub.index("doIdReset")
        blk = hub[i:i + 2000]
        self.assertIn("hub_token", blk, "화면이 새 토큰을 보내지 않습니다")
        self.assertIn("새 사이트 토큰", blk)


class KeyRotationTests(unittest.TestCase):
    """서버 열쇠를 갈아 끼우는 것만으로 **복구를 풀 수 있으면 안 된다** (GPT 9차).

    토큰 지문은 열쇠로 덮는다. 그래서 열쇠가 바뀌면 토큰이 그대로인데도 지문이 달라진다 —
    그것을 '토큰이 바뀌었다'(= 설정을 고쳤다) 로 세면 열쇠만 바꾸고 풀 수 있다.
    """

    def base(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub.json").write_text(json.dumps(
            {"role": "site", "site_id": "X", "hub_url": "https://hq.example",
             "hub_token": "t" * 24}), encoding="utf-8")
        return b

    def fixed(self, b):
        return [c for c in H.state_report(b)["checks"] if "멈춘 뒤" in c["name"]][0]["ok"]

    def test_rotating_the_key_is_not_a_config_change(self):
        b = self.base()
        (b / "conf" / "secret.key").write_bytes(b"KEY-A")
        H.mark_recovery(b, "config_invalid", "x")
        (b / "conf" / "secret.key").write_bytes(b"KEY-B")
        self.assertFalse(self.fixed(b), "열쇠만 바꿨는데 '고쳤다' 가 됐습니다")

    def test_a_real_token_change_under_the_same_key_still_counts(self):
        """막기만 보면 '늘 막힘' 도 통과한다 — 진짜 토큰 바뀜은 보여야 한다."""
        b = self.base()
        (b / "conf" / "secret.key").write_bytes(b"KEY-A")
        H.mark_recovery(b, "config_invalid", "x")
        (b / "conf" / "hub.json").write_text(json.dumps(
            {"role": "site", "site_id": "X", "hub_url": "https://hq.example",
             "hub_token": "u" * 24}), encoding="utf-8")
        self.assertTrue(self.fixed(b), "같은 열쇠인데 토큰 바뀜을 못 봅니다")

    def test_the_marker_records_which_key_was_used(self):
        b = self.base()
        (b / "conf" / "secret.key").write_bytes(b"KEY-A")
        H.mark_recovery(b, "config_invalid", "x")
        self.assertEqual(H.read_recovery(b)["token_fp_key"], H.key_id(b))

    def test_the_key_id_does_not_reveal_the_key(self):
        b = self.base()
        (b / "conf" / "secret.key").write_bytes(b"SUPERSECRET-KEY")
        self.assertNotIn("SUPERSECRET", H.key_id(b))
        self.assertRegex(H.key_id(b), "^[0-9a-f]{8}$")


class CliLockTests(unittest.TestCase):
    """콘솔 명령은 **자물쇠를 쥔 채로** 고친다 (GPT 9차).

    전에는 "서버가 돌고 있나" 를 묻고 아니면 고쳤다. 묻고 고치는 사이에 서버가 뜨면
    그대로 겹친다 — 확인과 변경 사이에 틈을 두지 않는다.
    """

    def test_it_holds_the_lock_instead_of_only_asking(self):
        src = (Path(__file__).resolve().parents[1] / "logtriage" / "hubadmin.py").read_text(encoding="utf-8")
        self.assertIn("_hold_or_refuse", src)
        for fn in ("def recover(", "def identity_reset("):
            i = src.index(fn)
            blk = src[i:i + 420]
            self.assertIn("_hold_or_refuse(base)", blk, f"{fn} 가 자물쇠를 쥐지 않습니다")
            self.assertIn("held.release()", blk, f"{fn} 가 자물쇠를 놓지 않습니다")

    def test_it_points_at_the_screen_first(self):
        """바꾸는 것은 서버가 한다 — 콘솔은 화면을 열 수 없을 때를 위한 것이다."""
        src = (Path(__file__).resolve().parents[1] / "logtriage" / "hubadmin.py").read_text(encoding="utf-8")
        i = src.index("_hold_or_refuse")
        blk = src[i:i + 1200]
        self.assertIn("[통합 현황] 화면에서", blk)
        self.assertIn("다시 시작할 필요가 없습니다", blk)



class IdentityResetFaultTests(unittest.TestCase):
    """바꾸다 실패하면 **아무것도 바뀌지 않아야** 한다 (GPT 9차 마지막 숙제).

    처음엔 신원을 먼저 적고 설정을 뒤에 적었다. 저장이 실패하자 **신원은 'BUSAN' 인데**
    **설정과 토큰은 'HQ' 것인 혼합 상태**가 남았다. 다음 기동에서 어긋남으로 잡혀 송신은
    멈추지만(그래서 우회는 아니다), 서버는 망가진 채로 남아 손으로 고쳐야 한다.

    차례를 바꿨다 — 설정을 먼저 고르고 저장한 뒤 신원을 적고, 신원 적기가 실패하면 설정을
    되돌린다. 어느 쪽이 실패해도 **옛 상태 그대로**다.
    """

    OLD = "HQ-ONLY-TOKEN-xxxxxxxx"

    def srv(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        b = Path(td.name)
        (b / "conf").mkdir(parents=True)
        (b / "data").mkdir(parents=True)
        (b / "conf" / "hub_allow.txt").write_text("https://hq.example" + chr(10), encoding="utf-8")
        (b / "conf" / "hub.json").write_text(json.dumps(
            {"role": "site", "site_id": "HQ", "hub_url": "https://hq.example",
             "hub_token": self.OLD, "interval_sec": 3600}), encoding="utf-8")
        H.lock_site(b, "HQ")
        s = E.Srv(b)
        self.addCleanup(s.close)
        return s, b

    def reset(self, s):
        r, d = s.req("POST", "/api/hub/admin/identity_reset",
                     {"site_id": "BUSAN", "confirm": "1", "hub_token": "BUSAN-NEW-TOKEN-yyy"})
        return r.status, d.decode("utf-8", "replace")

    def state(self, b):
        saved = json.loads((b / "conf" / "hub.json").read_text(encoding="utf-8-sig"))
        return H.locked_site(b), saved["site_id"], saved["hub_token"]

    def break_it(self, name):
        """hub 모듈의 한 걸음을 일부러 실패시킨다."""
        keep = getattr(H, name)

        def boom(*a, **k):
            raise OSError("일부러 낸 실패")

        setattr(H, name, boom)
        self.addCleanup(setattr, H, name, keep)

    def test_it_works_when_nothing_fails(self):
        """막기만 보면 '늘 막힘' 도 통과한다 — 정상 경로부터 본다."""
        s, b = self.srv()
        st, d = self.reset(s)
        self.assertEqual(st, 200, d)
        ident, sid, tok = self.state(b)
        self.assertEqual((ident, sid), ("BUSAN", "BUSAN"))
        self.assertNotEqual(tok, self.OLD)

    def test_a_failed_config_save_changes_nothing(self):
        s, b = self.srv()
        self.break_it("save_conf")
        st, _ = self.reset(s)
        self.assertNotEqual(st, 200)
        self.assertEqual(self.state(b), ("HQ", "HQ", self.OLD), "설정 저장이 실패했는데 뭔가 바뀌었습니다")

    def test_a_failed_identity_write_rolls_the_config_back(self):
        s, b = self.srv()
        self.break_it("set_identity")
        st, _ = self.reset(s)
        self.assertNotEqual(st, 200)
        self.assertEqual(self.state(b), ("HQ", "HQ", self.OLD), "설정이 되돌아가지 않았습니다")

    def test_no_failure_leaves_the_old_token_under_a_new_name(self):
        """가장 나쁜 꼴 — 새 이름인데 옛 토큰. 어떤 실패에서도 나오면 안 된다."""
        for step in ("save_conf", "set_identity"):
            with self.subTest(step=step):
                s, b = self.srv()
                self.break_it(step)
                self.reset(s)
                ident, _, tok = self.state(b)
                self.assertFalse(ident == "BUSAN" and tok == self.OLD,
                                 "새 이름에 옛 토큰이 붙은 채 남았습니다")

    def test_the_config_and_the_identity_never_disagree(self):
        for step in ("save_conf", "set_identity"):
            with self.subTest(step=step):
                s, b = self.srv()
                self.break_it(step)
                self.reset(s)
                ident, sid, _ = self.state(b)
                self.assertEqual(ident, sid, "신원과 설정이 어긋난 채 남았습니다")


if __name__ == "__main__":
    unittest.main()


class RecoveryOnBootTests(unittest.TestCase):
    """표식만 남기고 다음 기동에서 다시 보내면 뜻이 없다."""

    def test_a_broken_state_stops_the_sender_at_boot(self):
        src = inspect.getsource(S.serve)
        self.assertIn("api.hub_broken()", src)
        self.assertLess(src.index("api.hub_broken()"), src.index("api.hub_client.start()"))
        self.assertIn("elif api.hub_client:", src)

    def test_it_tells_the_operator_how_to_clear_it(self):
        """푸는 길을 알려 주되, **파일을 지우라고 하지 않는다**(GPT 7차)."""
        src = inspect.getsource(S.serve)
        self.assertIn("logtriage.hubadmin", src)
        self.assertNotIn("를 지우고 다시 시작하십시오", src)
