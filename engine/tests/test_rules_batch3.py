"""룰 학습 3차(WEB, 2026-10-15) — 마스터 지시 "남은 일 순차 적용". GPT 12차 벤더 소스·문서 대조 반영.

- IIS 액세스 로그 파서가 sc-substatus 를 버려 사전의 500.19·500.30·502.5·503.2 원인이 닿지 못하던 결함 → 하위 상태 보존
  + 일반 룰(WEB-IIS-001·002)은 defer_to_code(사전에 정확한 코드가 있으면 물러남 — 손으로 고치는 제외 목록 대신)
- IIS 30초 이상 5xx 성능 판정은 auxiliary(보조) — 같은 줄의 사전 주 원인을 가리지 않는다
- nginx 새 룰 7개(메모리·스레드 풀·임시 파일·EIO·shmtx 잠금 2·부분 쓰기)
- Apache AH00023(뮤텍스 생성 실패)·AH00086·AH00649·AH02297 은 룰이 아니라 사전(파서가 AH 코드를 뽑는다)
- 기존 레거시 LEG-AH-403 오탐(로그 파일 열기 실패를 403 으로) → defer_to_code
- 지금까지의 룰(409)은 그대로
"""
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.rules import load_rules  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

KW = dict(rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
IIS_HEAD = ("#Software: Microsoft Internet Information Services 10.0\n"
            "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n")


def analyze(product, text):
    f = Path(tempfile.mkdtemp()) / "x.log"
    f.write_text(text, encoding="utf-8")
    r = run_analysis([{"path": str(f), "product": product, "host": "h1"}], None, **KW)
    return [(t["rule_id"], t["source"]) for t in r["timeline"]]


class Batch3(unittest.TestCase):
    def test_previous_rules_are_kept(self):
        rules = load_rules(ENGINE / "rules", ENGINE / "rules-local")
        ids = {r.id for r in rules}
        self.assertGreaterEqual(len(ids), 417)
        for keep in ("WEB-NGX-005", "WEB-NGX-006", "WEB-IIS-001", "WEB-IIS-002", "WEB-APA-001", "LEG-AH-403", "DB-MSS-001", "WAS-TC-015"):
            self.assertIn(keep, ids)
        self.assertNotIn("WEB-APA-003", ids)                               # GPT 12차: AH 코드 줄은 룰이 아니라 사전
        self.assertNotIn("WEB-NGX-017", ids)                               # 사전 별칭 NGX-NO-SPACE 가 이미 판정
        self.assertEqual(sorted(r.id for r in rules if r.defer_to_code), ["LEG-AH-403", "WEB-IIS-001", "WEB-IIS-002"])
        self.assertEqual([r.id for r in rules if r.auxiliary], ["WEB-IIS-003"])

    def test_iis_substatus_reaches_dictionary(self):
        rows = ["2026-10-12 09:00:01 10.0.0.1 GET /app - 443 - 10.0.0.9 M - 500 19 13 15",        # 구성 오류 → 사전 500.19
                "2026-10-12 09:00:02 10.0.0.1 GET /core - 443 - 10.0.0.9 M - 502 5 0 31000",     # ANCM 시작 실패 → 사전 502.5 + 30초 보조
                "2026-10-12 09:00:03 10.0.0.1 GET /x - 443 - 10.0.0.9 M - 500 0 0 20",           # 하위 상태 0 → 예전처럼 일반 룰
                "2026-10-12 09:00:04 10.0.0.1 GET /y - 443 - 10.0.0.9 M - 500 24 0 20",          # 사전에 없는 하위 상태 → 일반 룰(빠지지 않음)
                "2026-10-12 09:00:05 10.0.0.1 GET /z - 443 - 10.0.0.9 M - 503 0 0 2",
                "2026-10-12 09:00:06 10.0.0.1 GET /q - 443 - 10.0.0.9 M - 503 2 0 2"]            # 동시 요청 한도 → 사전 503.2
        got = analyze("iis", IIS_HEAD + "\n".join(rows) + "\n")
        self.assertEqual(sorted(got), sorted([("500.19", "벤더 에러코드"), ("WEB-IIS-003", "시그니처 룰"), ("502.5", "벤더 에러코드"),
                                             ("WEB-IIS-002", "시그니처 룰"), ("WEB-IIS-002", "시그니처 룰"), ("WEB-IIS-001", "시그니처 룰"),
                                             ("503.2", "벤더 에러코드")]))

    def test_nginx_new_rules(self):
        lines = ["2026/10/12 09:00:01 [emerg] 1#1: *1 malloc(16384) failed (12: Cannot allocate memory)",
                 '2026/10/12 09:00:02 [error] 1#1: thread pool "default" queue overflow: 65536 tasks waiting',
                 "2026/10/12 09:00:03 [warn] 1#1: *2 a client request body is buffered to a temporary file /var/cache/nginx/client_temp/1",
                 '2026/10/12 09:00:04 [crit] 1#1: *3 pread() "/data/a.iso" failed (5: Input/output error)',
                 "2026/10/12 09:00:05 [alert] 1#1: sem_wait() failed while waiting on shmtx (22: Invalid argument)",
                 "2026/10/12 09:00:06 [alert] 1#1: sem_init() failed (38: Function not implemented)",
                 '2026/10/12 09:00:07 [crit] 1#1: *4 pwrite() "/var/cache/nginx/proxy_temp/1" has written only 4096 of 8192',
                 "2026/10/12 09:00:08 [info] 1#1: *5 readv() failed (104: Connection reset by peer) while reading upstream",   # 소켓 — EIO 룰 아님
                 "2026/10/12 09:00:09 [warn] 1#1: *6 an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/2 while reading upstream"]
        got = [x[0] for x in analyze("nginx", "\n".join(lines) + "\n")]
        for rid in ("WEB-NGX-011", "WEB-NGX-012", "WEB-NGX-013", "WEB-NGX-014", "WEB-NGX-015", "WEB-NGX-016", "WEB-NGX-018"):
            self.assertIn(rid, got)
        self.assertEqual(got.count("WEB-NGX-014"), 1)                      # 소켓 readv 는 파일 EIO 로 세지 않는다
        self.assertIn("NGX-UPSTREAM-BIG-BODY", got)                         # 기존 사전 판정 그대로

    def test_apache_codes_via_dictionary(self):
        lines = ["[Wed Oct 12 09:00:01.123456 2026] [core:emerg] [pid 2345] (28)No space left on device: AH00023: Couldn't create the proxy mutex",
                 "[Wed Oct 12 09:00:02.123456 2026] [core:emerg] [pid 2345] (13)Permission denied: AH00086: could not open error log file /var/log/httpd/error_log.",
                 "[Wed Oct 12 09:00:03.123456 2026] [authz_core:error] [pid 2345] [client 10.0.0.9:5000] AH01630: client denied by server configuration: /var/www/x"]
        # 레거시 LEG-AH-403 이 'Permission denied …/httpd/' 로 로그 파일 열기 실패까지 403 으로 판정하던 오탐 → defer_to_code
        self.assertEqual(analyze("apache", "\n".join(lines) + "\n"),
                         [("AH00023", "벤더 에러코드"), ("AH00086", "벤더 에러코드"), ("AH01630", "벤더 에러코드")])

    def test_old_format_without_code_keeps_legacy_rule(self):
        """AH 코드가 없는 2.2 형식은 사전에 닿지 않으니 레거시 룰이 그대로 판정한다(defer 는 코드가 사전에 있을 때만)."""
        got = analyze("apache", "[Wed Oct 11 14:32:52 2026] [error] [client 10.0.0.9] (13)Permission denied: access to /httpd/x denied\n")
        self.assertIn(("LEG-AH-403", "시그니처 룰"), got)

    def test_apache22_404_is_not_backend_failure(self):
        """기존 별칭 오탐: 2.2 의 404 문구 'File does not exist:' 가 AH01084(백엔드 본문 전달 실패)로 이어졌다 → AH00128(정보)."""
        got = analyze("apache", "[Wed Oct 11 14:32:52 2026] [error] [client 10.0.0.9] File does not exist: /var/www/html/favicon.ico\n")
        self.assertEqual(got, [("AH00128", "벤더 에러코드")])

    def test_auxiliary_never_becomes_the_representative(self):
        """보조 판정(30초 이상 5xx)은 같은 분석에 주 판정이 있으면 대표 판정이 되지 않는다 — 원인 대신 '느렸다' 가 맨 위에 서지 않게."""
        f = Path(tempfile.mkdtemp()) / "u.log"
        f.write_text(IIS_HEAD + "2026-10-12 09:00:01 10.0.0.1 GET /core - 443 - 10.0.0.9 M - 502 3 0 45000\n", encoding="utf-8")
        r = run_analysis([{"path": str(f), "product": "iis", "host": "h1"}], None, **KW)
        self.assertEqual(sorted(t["rule_id"] for t in r["timeline"]), ["502.3", "WEB-IIS-003"])
        self.assertEqual(r["first"]["rule_id"], "502.3")

    def test_apache22_proxy_aliases_corrected(self):
        """GPT 13차: 예전 별칭이 응답 읽기·본문 전달 실패를 AH01114(연결 생성 실패)로 묶었다 → 문구별 2.4 코드로."""
        from logtriage.codes import alias_code, load_aliases
        al = load_aliases(ENGINE / "errorcodes")
        want = {"proxy: HTTP: failed to make connection to backend: 10.0.0.5": "AH01114",
                "proxy: HTTP: attempt to connect to 10.0.0.5:8080 (x) failed": "AH00957",
                "proxy: error reading response": "AH01110",
                "proxy: pass request body failed to 10.0.0.5:8080": "AH01084",
                "proxy: error reading status line from remote server x": "AH01102",
                "File does not exist: /var/www/x": "AH00128"}
        self.assertEqual({m: alias_code(al, "apache", m) for m in want}, want)


if __name__ == "__main__":
    unittest.main()
