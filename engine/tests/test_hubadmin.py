# -*- coding: utf-8 -*-
"""본사 연동 관리 명령 — 파일을 손으로 지우던 길을 **검사를 지나는 길**로 바꿨다 (2026-10-01)

지금까지 두 가지를 "파일을 지우십시오" 로 안내하고 있었다.
  · 사이트 신원 잠금  data/hub_identity.json
  · 멈춤 표식          data/hub_recovery_required

GPT 지적: 이것이 정식 절차가 되면 안 된다.
  ① 신원 파일 지우기는 **실제로 송신했던 서버에서도 똑같이 잠금을 무력화한다.**
     파일 권한이 있는 관리자는 원래 강한 권한을 갖지만, 정상 절차 자체가 보안 불변식을
     손으로 지우도록 가르치는 것은 다른 문제다.
  ② 멈춤 표식이 생겼다는 것은 아귀가 맞지 않았다는 뜻이다. 표식만 지운다고 설정이
     맞다는 보장이 없다.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import hub as H          # noqa: E402
from logtriage import hubadmin          # noqa: E402

ENG = Path(__file__).resolve().parents[1]
SITE = {"role": "site", "site_id": "BUSAN", "hub_url": "https://hq.example",
        "hub_token": "t" * 24, "interval_sec": 60}


class Base(unittest.TestCase):

    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.b = Path(self.td.name)
        (self.b / "conf").mkdir(parents=True)
        (self.b / "data").mkdir(parents=True)
        self.write(SITE)

    def write(self, conf):
        (self.b / "conf" / "hub.json").write_text(
            conf if isinstance(conf, str) else json.dumps(conf, ensure_ascii=False),
            encoding="utf-8")

    def cli(self, *args):
        """**실제로 명령을 돌린다** — 함수만 부르면 인자 처리·종료 코드를 못 본다."""
        # 콘솔 글자셋을 UTF-8 로 못 박는다. 그러지 않으면 cp949 콘솔에서 글자가 뭉개져
        # **무엇을 말했는지 시험이 읽지 못한다** — 뭉개져도 죽지 않는 것은 따로 본다.
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        r = subprocess.run([sys.executable, "-m", "logtriage.hubadmin",
                            "--base", str(self.b), "--actor", "tester", *args],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", cwd=str(ENG), env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")


class StatusTests(Base):

    def test_status_reports_a_healthy_server(self):
        rc, out = self.cli("status")
        self.assertEqual(rc, 0, out)
        self.assertIn("BUSAN", out)
        self.assertNotIn("t" * 24, out, "사이트 토큰이 화면에 나왔습니다")

    def test_status_never_prints_the_token(self):
        self.write(dict(SITE, hub_token="SUPERSECRET-TOKEN"))
        rc, out = self.cli("status")
        self.assertNotIn("SUPERSECRET", out, "토큰이 상태 출력에 나왔습니다")

    def test_status_fails_when_something_is_wrong(self):
        H.lock_site(self.b, "SEOUL")                 # 신원과 설정이 어긋난다
        rc, out = self.cli("status")
        self.assertEqual(rc, 1, out)


class RecoverTests(Base):

    def mark(self):
        H.mark_recovery(self.b, "config_invalid", "설정을 읽을 수 없었습니다")

    def test_it_refuses_while_the_config_is_unchanged(self):
        """고치지 않고 푸는 것은 **같은 일을 또 겪는 길**이다."""
        self.mark()
        rc, out = self.cli("recover", "--confirm")
        self.assertEqual(rc, 2, out)
        self.assertTrue((self.b / "data" / H.RECOVERY_FILE).exists(), "그냥 풀렸습니다")

    def test_it_refuses_while_a_check_fails(self):
        self.mark()
        H.lock_site(self.b, "SEOUL")                 # 신원 충돌을 만든다
        self.write(dict(SITE, interval_sec=120))     # 설정은 고쳤다
        rc, out = self.cli("recover", "--confirm")
        self.assertEqual(rc, 2, out)
        self.assertTrue((self.b / "data" / H.RECOVERY_FILE).exists())

    def test_it_does_nothing_without_confirm(self):
        self.mark()
        self.write(dict(SITE, interval_sec=120))
        rc, out = self.cli("recover")
        self.assertEqual(rc, 0, out)
        self.assertTrue((self.b / "data" / H.RECOVERY_FILE).exists(), "확인 없이 풀렸습니다")

    def test_it_clears_once_the_config_was_fixed(self):
        self.mark()
        self.write(dict(SITE, interval_sec=120))
        rc, out = self.cli("recover", "--confirm")
        self.assertEqual(rc, 0, out)
        self.assertFalse((self.b / "data" / H.RECOVERY_FILE).exists())

    def test_clearing_is_written_to_the_audit(self):
        """콘솔에서 한 일도 **기록이 있어야 한다.**"""
        self.mark()
        self.write(dict(SITE, interval_sec=120))
        self.cli("recover", "--confirm")
        import sqlite3
        db = self.b / "data" / "auth" / "auth.sqlite3"
        self.assertTrue(db.exists(), "감사 저장소가 없습니다")
        con = sqlite3.connect(db)
        acts = [r[0] for r in con.execute("SELECT action FROM audit")]
        con.close()
        self.assertIn("hub.recovery.cleared", acts)

    def test_nothing_to_do_is_not_an_error(self):
        rc, out = self.cli("recover", "--confirm")
        self.assertEqual(rc, 0, out)


class IdentityResetTests(Base):

    def test_it_does_nothing_without_confirm(self):
        H.lock_site(self.b, "BUSAN")
        rc, out = self.cli("identity-reset", "--new-site", "SEOUL")
        self.assertEqual(rc, 0, out)
        self.assertEqual(H.locked_site(self.b), "BUSAN", "확인 없이 바뀌었습니다")

    def test_it_warns_about_the_consequence(self):
        H.lock_site(self.b, "BUSAN")
        _, out = self.cli("identity-reset", "--new-site", "SEOUL")
        self.assertIn("과거 자료와 끊깁니다", out)
        self.assertIn("본사 담당자", out, "본사와 먼저 맞추라고 말해야 합니다")

    def test_it_changes_the_identity_with_confirm(self):
        H.lock_site(self.b, "BUSAN")
        rc, out = self.cli("identity-reset", "--new-site", "SEOUL", "--confirm")
        self.assertEqual(rc, 0, out)
        self.assertEqual(H.locked_site(self.b), "SEOUL")

    def test_it_keeps_the_previous_name_and_who_did_it(self):
        H.lock_site(self.b, "BUSAN")
        self.cli("identity-reset", "--new-site", "SEOUL", "--confirm")
        d = json.loads((self.b / "data" / H.IDENTITY_FILE).read_text(encoding="utf-8"))
        self.assertEqual(d["previous"], "BUSAN")
        self.assertEqual(d["changed_by"], "tester")

    def test_it_refuses_a_bad_site_id(self):
        H.lock_site(self.b, "BUSAN")
        rc, _ = self.cli("identity-reset", "--new-site", "나쁜 이름!", "--confirm")
        self.assertEqual(rc, 2)
        self.assertEqual(H.locked_site(self.b), "BUSAN")

    def test_the_change_is_written_to_the_audit(self):
        H.lock_site(self.b, "BUSAN")
        self.cli("identity-reset", "--new-site", "SEOUL", "--confirm")
        import sqlite3
        con = sqlite3.connect(self.b / "data" / "auth" / "auth.sqlite3")
        acts = [r[0] for r in con.execute("SELECT action FROM audit")]
        con.close()
        self.assertIn("hub.identity.reset", acts)


class SafePrintTests(unittest.TestCase):
    """cp949 콘솔에서 글자 하나 때문에 **안내가 통째로 사라진** 일이 있었다.

    복구 명령이 바로 그 자리에서 입을 다물면 안 된다.
    """

    def test_every_output_goes_through_the_safe_printer(self):
        src = (ENG / "logtriage" / "hubadmin.py").read_text(encoding="utf-8")
        body = src.split("def _say", 1)[1].split("# ── 검사", 1)[-1]
        self.assertNotIn(chr(10) + "    print(", body, "안전 출력기를 거치지 않은 print 가 있습니다")

    def test_it_survives_a_console_that_cannot_print_korean(self):
        hubadmin._say("줄표 — 와 한글")



class FingerprintTests(Base):
    """설정 지문은 **뜻을 보고** 만든다 — 공백만 바꿔서 빠져나가지 못하게(GPT 8차).

    처음엔 파일 바이트를 그대로 해시했다. 그러면 들여쓰기만 바꿔도 지문이 달라져,
    "설정을 고쳤습니까" 를 묻는 자리를 **고치지 않고 지날 수 있었다.**
    """

    def test_whitespace_alone_does_not_count_as_a_fix(self):
        self.write(json.dumps(SITE, separators=(",", ":")))
        a = H.conf_fingerprint(self.b)
        self.write(json.dumps(SITE, indent=2))
        self.assertEqual(H.conf_fingerprint(self.b), a, "공백만 바꿔도 고친 것으로 봅니다")

    def test_key_order_alone_does_not_count_either(self):
        self.write(json.dumps(SITE, sort_keys=True))
        a = H.conf_fingerprint(self.b)
        self.write(json.dumps(dict(reversed(list(SITE.items())))))
        self.assertEqual(H.conf_fingerprint(self.b), a)

    def test_a_real_change_counts(self):
        a = H.conf_fingerprint(self.b)
        self.write(dict(SITE, interval_sec=120))
        self.assertNotEqual(H.conf_fingerprint(self.b), a)

    def test_a_new_token_counts_through_its_own_fingerprint(self):
        """새 토큰을 받아 복구하는 일이 흔하다 — 토큰이 바뀐 것도 고친 것이다.

        다만 토큰은 **뜻 지문에 넣지 않는다.** 넣으면 서버 열쇠로 덮어야 하는데, 열쇠가
        생기거나 바뀌면 아무도 손대지 않아도 지문이 달라진다(실제로 첫 기동 때 그랬다).
        그래서 토큰은 따로 본다 — 열쇠가 있을 때만 적고, 양쪽에 다 있을 때만 견준다.
        """
        (self.b / "conf" / "secret.key").write_bytes(b"server-key-material")
        a_cfg, a_tok = H.conf_fingerprint(self.b), H.token_fingerprint(self.b)
        self.assertTrue(a_tok, "열쇠가 있는데 토큰 지문이 비어 있습니다")
        self.write(dict(SITE, hub_token="u" * 24))
        self.assertEqual(H.conf_fingerprint(self.b), a_cfg, "뜻 지문이 토큰에 흔들립니다")
        self.assertNotEqual(H.token_fingerprint(self.b), a_tok, "토큰 바뀜을 못 봅니다")

    def test_the_token_fingerprint_is_empty_without_a_server_key(self):
        """견줄 수 없는 값을 '달라졌다' 로 세면, 손대지 않은 설정이 고쳐진 것처럼 보인다."""
        self.assertEqual(H.token_fingerprint(self.b), "")

    def test_a_different_hub_counts(self):
        a = H.conf_fingerprint(self.b)
        self.write(dict(SITE, hub_url="https://other.example"))
        self.assertNotEqual(H.conf_fingerprint(self.b), a)

    def test_the_marker_never_carries_the_token(self):
        self.write(dict(SITE, hub_token="SUPERSECRET-TOKEN"))
        H.mark_recovery(self.b, "config_invalid", "시험")
        raw = (self.b / "data" / H.RECOVERY_FILE).read_text(encoding="utf-8")
        self.assertNotIn("SUPERSECRET", raw)

    def test_the_server_key_covers_only_the_token_fingerprint(self):
        """토큰 지문은 열쇠로 덮는다(그 값이 또 하나의 단서가 되지 않게).

        **뜻 지문은 덮지 않는다** — 덮으면 열쇠가 생기는 것만으로 "고쳤다" 가 된다.
        """
        a = H.conf_fingerprint(self.b)
        (self.b / "conf" / "secret.key").write_bytes(b"server-key-material")
        self.assertEqual(H.conf_fingerprint(self.b), a, "열쇠가 생겼다고 뜻 지문이 달라집니다")
        one = H.token_fingerprint(self.b)
        (self.b / "conf" / "secret.key").write_bytes(b"another-key-material")
        self.assertNotEqual(H.token_fingerprint(self.b), one, "토큰 지문이 열쇠를 쓰지 않습니다")

    def test_the_marker_carries_both_parts(self):
        (self.b / "conf" / "secret.key").write_bytes(b"server-key-material")
        H.mark_recovery(self.b, "config_invalid", "시험")
        r = H.read_recovery(self.b)
        self.assertTrue(r["config_hash"])
        self.assertTrue(r["token_fp"])
        raw = (self.b / "data" / H.RECOVERY_FILE).read_text(encoding="utf-8")
        self.assertNotIn("t" * 24, raw, "표식에 토큰 원문이 있습니다")

    def test_an_unreadable_config_still_has_a_fingerprint(self):
        """뜻을 고를 수 없으면 원문으로 본다 — 지문이 없으면 비교 자체를 못 한다."""
        self.write("{깨진")
        a = H.conf_fingerprint(self.b)
        self.assertTrue(a)
        self.write("{더 깨진")
        self.assertNotEqual(H.conf_fingerprint(self.b), a)


class RunningServerTests(Base):
    """서버가 도는 중에 바꾸면 **돌고 있는 것과 파일이 어긋난다**(GPT 8차).

    이 명령은 서버와 다른 프로세스라 서버 안의 자물쇠가 닿지 않는다. 실제로 재현했다 —
    서버 메모리는 BUSAN 인데 파일은 SEOUL 이 됐다.
    """

    def hold(self):
        from logtriage import runlock
        held = runlock.acquire(self.b)
        self.assertTrue(held, "자물쇠를 못 쥐었습니다")
        self.addCleanup(held.release)

    def test_status_is_allowed_while_running(self):
        self.hold()
        rc, out = self.cli("status")
        self.assertIn("서버가 돌고 있습니다", out)

    def test_recover_is_refused_while_running(self):
        H.mark_recovery(self.b, "config_invalid", "시험")
        self.write(dict(SITE, interval_sec=120))
        self.hold()
        rc, out = self.cli("recover", "--confirm")
        self.assertEqual(rc, 2, out)
        self.assertTrue((self.b / "data" / H.RECOVERY_FILE).exists(), "도는 중에 풀렸습니다")
        # 안내가 바뀌었다 — **바꾸는 것은 서버가 한다.** 콘솔은 화면을 열 수 없을 때만이고,
        # 그때도 서비스를 내리라고 하지 않는다(사용자 지시: 설정 변경에 재기동 불허).
        self.assertIn("[통합 현황] 화면에서", out)
        self.assertNotIn("서비스를 내린 뒤", out)

    def test_identity_reset_is_refused_while_running(self):
        H.lock_site(self.b, "BUSAN")
        self.hold()
        rc, out = self.cli("identity-reset", "--new-site", "SEOUL", "--confirm")
        self.assertEqual(rc, 2, out)
        self.assertEqual(H.locked_site(self.b), "BUSAN", "도는 중에 신원이 바뀌었습니다")

    def test_it_works_once_the_server_is_down(self):
        """막기만 보면 '늘 막힘' 도 통과한다 — 내린 뒤에는 되어야 한다."""
        H.lock_site(self.b, "BUSAN")
        rc, out = self.cli("identity-reset", "--new-site", "SEOUL", "--confirm")
        self.assertEqual(rc, 0, out)
        self.assertEqual(H.locked_site(self.b), "SEOUL")


if __name__ == "__main__":
    unittest.main()
