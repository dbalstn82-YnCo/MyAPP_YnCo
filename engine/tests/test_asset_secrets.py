# -*- coding: utf-8 -*-
"""받지 않기로 한 열을 **정말로** 알아보는지 (2026-09-30)

사용자 지시: "구멍은 다 막아야 한다. 보안이 강화되어 생기는 불편은 감수한다."

전에는 규칙이 하나였다 — 정규화한 머리글에 별칭이 들어 있으면 버린다. 이 한 규칙이 두 방향으로
틀렸다.

  · 거짓 양성 — 'pw' 가 짧아서 'Shipping'(→shipping) 이 걸렸다. 정상 열을 못 읽었다.
  · 거짓 음성 — 그래서 짧은 말을 아예 못 넣었다. 'cred'·'OTP'·'PIN'·'pem' 같은 흔한 표기가
    안 걸려 **자격 정보 열이 그대로 읽혔다.** 이쪽이 보안 구멍이다.

그래서 긴 말은 품고 있는지로, 짧은 말은 낱말이 딱 맞는지로 본다. 아래 표가 그 경계를 못 박는다.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logtriage import asset_spec as A             # noqa: E402
from logtriage import asset_import as I           # noqa: E402

# 반드시 버려야 하는 머리글 — 실제 고객 자산표에서 보이는 표기를 모았다
SECRET = [
    "비밀번호", "비 밀 번 호", "비번", "초기 비번", "임시비번", "패스워드", "암호", "암호문",
    "PW", "ＰＷ", "P.W", "P W", "pw(초기)", "PW_1", "svrPW", "dbPwd", "Passwd", "PWD",
    "관리자PW", "최초PASSWORD", "WAS_PW", "ID/PW", "id pw", "userPW",
    "계정정보", "접속 정보", "접속계정정보", "인증정보", "로그인 정보", "자격증명", "cred",
    "인증", "인증키", "인증값", "API Key", "apikey", "SNMP Community", "community string",
    "OTP", "PIN", "passphrase", "keystore", "truststore", "pem", "pfx", "p12", "jks",
    "개인키", "비밀키", "SSH Key", "client secret", "Bearer Token", "refresh token",
    "토큰", "secret", "비밀",
]

# 반드시 살려야 하는 머리글 — 이것들이 버려지면 정상 자산표를 못 읽는다
FINE = [
    "자산ID", "자산명", "호스트명", "Hostname", "IP 주소", "관리IP", "서비스 IP", "포트",
    "서비스 포트", "접속 계정", "계정", "계정명", "사용자 계정", "운영체제", "OS", "OS 버전",
    "제품명", "제품·버전", "인스턴스", "SID", "문서 루트", "doc_root", "연결 풀", "pool",
    "힙 설정", "로그 경로", "이벤트 로그", "설치 경로", "랙 위치", "상면", "서비스 시간",
    "담당팀", "운영 책임 조직", "1차 담당자", "제조사 연락처", "유지보수 만료일", "중요도",
    "운영 환경", "운영 상태", "백업 주기", "이중화", "상위 연계", "최종 확인일",
    # 우연히 걸릴 만한 남의 말들 — 'pw'·'pin' 이 안에 들어 있다
    "Shipping", "Spinlock", "Pinpoint", "Pipeline", "Endpoint", "Campaign", "opening",
    "PowerShell", "Pending", "Owner", "Windows", "Application", "Spec", "Support",
]


class DetectionTests(unittest.TestCase):
    def test_every_secret_header_is_dropped(self):
        for h in SECRET:
            with self.subTest(header=h):
                self.assertTrue(A.is_dropped(h), f"'{h}' 를 그대로 읽습니다")

    def test_no_ordinary_header_is_dropped(self):
        """정상 열을 버리면 대장을 못 읽는다 — 강화가 곧 무용지물이 된다."""
        for h in FINE:
            with self.subTest(header=h):
                got = A.dropped_because(h)
                self.assertFalse(got, f"'{h}' 를 '{got.get('word')}' 때문에 버립니다")

    def test_a_short_word_only_matches_as_a_whole_word(self):
        """'pw' 는 낱말일 때만 — 'Shipping' 안의 pw 는 아니다."""
        self.assertEqual(A.dropped_because("PW")["how"], "word")
        self.assertFalse(A.is_dropped("Shipping"))

    def test_a_long_word_matches_even_when_glued(self):
        self.assertEqual(A.dropped_because("DB접속패스워드")["how"], "contains")

    def test_the_reason_names_the_word(self):
        """사람이 머리글을 고쳐 다시 올릴 수 있어야 한다."""
        got = A.dropped_because("svrPW")
        self.assertEqual(got["word"], "pw")
        self.assertEqual(got["key"], "password")

    def test_full_width_and_zero_width_do_not_get_through(self):
        for h in ("ＰＷ", "비​밀​번​호", "ｐａｓｓｗｏｒｄ"):
            with self.subTest(header=h):
                self.assertTrue(A.is_dropped(h))

    def test_an_empty_header_is_not_a_secret(self):
        for h in ("", "   ", None):
            self.assertFalse(A.is_dropped(h))


class PipelineTests(unittest.TestCase):
    """머리글 단계에서 놓쳐도 **칸 단계**에서 한 번 더 막는다."""

    def test_a_cell_carrying_a_secret_marker_is_dropped_whole(self):
        """'계정' 열에 'admin / pw=1234' 로 적어 오는 일이 있다 — 아이디만 살리려고
        칸 안을 갈라 보는 순간 비밀번호를 읽는다. 칸째 버린다."""
        rec = {}
        I._put(rec, "account", "admin pw=1234", {})
        self.assertNotIn("account", rec)
        self.assertEqual(rec["_dropped_cells"], ["account"])

    def test_an_ordinary_cell_goes_through(self):
        rec = {}
        I._put(rec, "account", "svcadm", {})
        self.assertEqual(rec["account"], "svcadm")

    def test_a_custom_field_is_not_an_exception(self):
        """현장이 만든 항목도 같은 검사를 지난다 — '메모' 칸에 비밀번호를 적어 오는 일이 있다."""
        rec = {}
        I._put(rec, "x_memo", "초기 password: abcd", {})
        self.assertNotIn("x_memo", rec)

    def test_a_header_row_keeps_its_name_after_scrubbing(self):
        """지운 열도 **왜 지웠는지 보이게** 이름은 남긴다 —
        '(빈 칸) — 모름' 으로 보이면 사람이 무엇이 지워졌는지 모른다."""
        rows = [["자산ID", "비밀번호", "호스트명"], ["S-1", "p@ss", "was01"]]
        got = I.scrub(rows, 0)
        self.assertEqual(rows[0][1], "비밀번호")
        self.assertEqual(rows[1][1], "")
        self.assertEqual(got["count"], 1)


class OrderTests(unittest.TestCase):
    """걸러내기가 맞추기보다 **앞에** 있어야 한다 — 순서가 뒤집히면 별칭이 비밀 열을 가로챈다."""

    def test_a_dropped_column_is_never_mapped(self):
        m = A.map_headers(["자산ID", "비밀번호", "PW", "호스트명"], "was")
        by = {c["index"]: c for c in m["columns"]}
        self.assertEqual(by[1]["field"], "")
        self.assertEqual(by[2]["field"], "")
        self.assertEqual(by[3]["field"], "hostname")
        self.assertEqual(sorted(m["dropped"]), ["1", "2"])

    def test_a_secret_column_does_not_win_the_header_row(self):
        """자격증명 표가 '좋은 머리글' 로 뽑히면 거기부터 읽는다 — 점수에 넣지 않는다."""
        rows = [["관리자 계정", "비밀번호", "PW", "비고"],
                ["자산ID", "자산명", "호스트명", "관리IP"],
                ["S-1", "was01", "was01", "10.1.1.5"]]
        self.assertEqual(I.find_header(rows, "was")["row"], 1)


if __name__ == "__main__":
    unittest.main()


class LeakTests(unittest.TestCase):
    """버렸다는 **사실**은 남기고, 버린 **값**은 남기지 않는다.

    진단이 편하다는 이유로 원문을 함께 남기면 그 순간 scrub 이 뚫린다(GPT 교차 검토).
    """

    def test_a_dropped_cell_records_only_which_field(self):
        rec = {}
        I._put(rec, "account", "admin pw=Secret123!", {})
        self.assertEqual(rec["_dropped_cells"], ["account"])
        self.assertNotIn("Secret123", repr(rec))

    def test_the_refusal_message_does_not_carry_the_value(self):
        """머리글은 사용자가 적은 이름이라 되돌려 주지만, 칸 안의 값은 절대 아니다."""
        got = A.dropped_because("관리자 비밀번호")
        self.assertEqual(got["word"], "비밀번호")
        self.assertNotIn("value", got)


class GroupReportTests(unittest.TestCase):
    """기준을 화면 한쪽에서만 지키면 지키지 않는 것과 같다.

    check() 는 조건부 묶음을 보는데 map_headers() 는 안 봤다 — 그래서 로그 경로도
    로그 채널도 없는 표가 '아직 없는 필수 항목' 에 아무것도 안 띄우고 통과했다.
    """

    def test_a_file_with_nowhere_to_read_logs_is_flagged(self):
        m = A.map_headers(["자산ID", "구성자원명", "Hostname", "IP 주소", "중요도",
                           "환경", "사용여부", "담당팀", "서비스", "사이트"], "was")
        self.assertIn("one_of:observe", m["missing_groups"])
        row = [x for x in m["missing_required"] if x["id"] == "one_of:observe"][0]
        self.assertEqual(row["label"], "로그를 볼 곳")
        self.assertIn("또는", row["why"])

    def test_any_one_member_clears_the_group(self):
        for col in ("로그 경로", "이벤트 로그"):
            with self.subTest(column=col):
                m = A.map_headers(["자산ID", "Hostname", col], "was")
                self.assertNotIn("one_of:observe", m["missing_groups"])

    def test_a_reachable_address_clears_its_group(self):
        self.assertIn("one_of:reach", A.map_headers(["자산ID", "Hostname"], "was")["missing_groups"])
        for col in ("관리IP", "FQDN", "원격 콘솔"):
            with self.subTest(column=col):
                m = A.map_headers(["자산ID", "Hostname", col], "was")
                self.assertNotIn("one_of:reach", m["missing_groups"])

    def test_the_two_checks_agree_on_a_group(self):
        """check() 와 map_headers() 가 같은 기준으로 봐야 한다 —
        한쪽만 지키면 지키지 않는 것과 같다."""
        base = {f["id"]: "x" for f in A.fields("was") if f["level"] == "required"}
        base["log_path"] = "/l"
        for fid in ("mgmt_ip", "fqdn", "console"):
            with self.subTest(field=fid):
                self.assertTrue(A.check(dict(base, **{fid: "v"}), "was")["complete"])
