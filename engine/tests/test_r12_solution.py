"""12차(2026-10-20 마스터: "장애 로그 예시가 없더라도 각 제품의 에러코드마다 해법을 OS 와 제품의 조합으로 명령어와 함께") — OS × 제품 해법.

① 모든 에러코드 × 그 제품이 도는 모든 OS 에서 해법이 나온다(1차 명령 ≥1 · 2차 ≥1 · 3차 ≥1)
② Windows 해법의 OS 명령에 유닉스 명령이, 유닉스 해법에 PowerShell 이 섞이지 않는다
③ 자동 자리표시자(<PROC> <PROC_WIN> {code})가 남지 않는다 · 제품 프로필이 없는 코드 제품이 없다
④ 지원하지 않는 OS 는 해법 대신 지원 OS 목록 · API·CLI·화면(값은 글자로만)
"""
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import os_solution as O  # noqa: E402
from logtriage.codes import load_codes  # noqa: E402
from logtriage.procedures import load_procedures  # noqa: E402

M = O.load_matrix(ENGINE / "manuals")
CODES = {k: v for k, v in load_codes(ENGINE / "errorcodes").items() if ":" in k}
PROCS = load_procedures(ENGINE / "manuals")
UNIXY = re.compile(r"(^|[\s;|(])(grep|ps -e|tail -n|awk|sed |ulimit|df -|lsattr|errpt|svcs|/proc/)")
PSY = re.compile(r"\b(Get-[A-Z]\w+|Select-Object|Where-Object|Restart-Service|Invoke-WebRequest)\b")


class Coverage(unittest.TestCase):
    def test_every_code_every_os(self):
        n = 0
        for k, e in CODES.items():
            oses = O.applicable_os(M, e.product)
            self.assertTrue(oses, f"{e.product} 프로필 없음")
            for o in oses:
                s = O.solution(e, o, ENGINE / "manuals", PROCS)
                self.assertNotIn("error", s, (k, o, s.get("error")))
                st = {x["stage"]: x["items"] for x in s["stages"]}
                cmd1 = [i for i in st[1] if i.get("cmd") or "`" in i.get("text", "")]
                self.assertTrue(cmd1, (k, o, "1차 명령 없음"))
                self.assertTrue(st[2], (k, o, "2차 없음"))
                self.assertTrue(st[3], (k, o, "3차 없음"))
                n += 1
        self.assertGreater(n, 5000)

    def test_os_commands_match_os(self):
        for k, e in list(CODES.items()):
            for o in O.applicable_os(M, e.product):
                s = O.solution(e, o, ENGINE / "manuals", PROCS)
                for stg in s["stages"]:
                    for it in stg["items"]:
                        c = it.get("cmd") or ""
                        if it.get("kind") not in ("OS", "제품 상태", "코드", "재기동") and stg["stage"] != 3:
                            continue                                   # 지식·절차의 원문 명령은 제품 공통(SQL 등) — 따로 표시
                        if o == "windows":
                            self.assertIsNone(UNIXY.search(c), (k, o, it.get("title"), c))
                        else:
                            self.assertIsNone(PSY.search(c), (k, o, it.get("title"), c))
                        for ph in ("<PROC>", "<PROC_WIN>", "{code}"):
                            self.assertNotIn(ph, c, (k, o, c))

    def test_profiles_consistent(self):
        prods = {e.product for e in CODES.values()}
        self.assertEqual(prods - set(M["products"]), set())
        for p, prof in M["products"].items():
            for o in prof.get("os") or []:
                self.assertIn(o, M["os"], (p, o))
        for g, chk in M["checks"].items():
            for o in M["os"]:
                fam = M["os"][o]["family"]
                self.assertTrue(chk.get(o) or chk.get(fam), (g, o, "OS 명령 없음"))
        for cat in {e.category for e in CODES.values()}:
            self.assertIn(cat, M["category_checks"], cat)

    def test_unsupported_os(self):
        e = CODES["iis:" + next(k.split(":", 1)[1] for k in CODES if k.startswith("iis:"))]
        s = O.solution(e, "aix", ENGINE / "manuals", PROCS)
        self.assertIn("지원 OS", s["error"])
        self.assertEqual([x["id"] for x in s["os_list"]], ["windows"])

    def test_code_specific(self):
        s = O.solution(CODES["aix:DCB47997"], "aix", ENGINE / "manuals", PROCS)
        cmds = " ".join(i.get("cmd", "") for i in s["stages"][0]["items"])
        self.assertIn("errpt -a -j DCB47997", cmds)
        s = O.solution(CODES["oracle:ORA-12541"], "windows", ENGINE / "manuals", PROCS)
        self.assertIn("Oracle*TNSListener", " ".join(i.get("cmd", "") for i in s["stages"][0]["items"]))

    def test_matrix_not_a_manual(self):
        from logtriage.kb import load_manuals
        self.assertFalse(any(str(m.get("product")) == "solutions_osmatrix" for m in load_manuals(ENGINE / "manuals")))


class Gpt85(unittest.TestCase):
    """GPT 85차 반대 — 지원 상태·비밀번호·능동 진단·재기동 근거·Windows 현지화·고부하·경로."""
    RAW = (ENGINE / "manuals" / "solutions_osmatrix.yaml").read_text(encoding="utf-8")
    # 시험 쪽 목록은 코드와 따로 둔다(코드 목록에서 하나를 빼도 시험이 잡게) — GPT 86·87차 반례 포함
    ACTIVE = re.compile(r"\b(ping|telnet|curl|wget|tnsping|nc|ncat|nslookup|dig|traceroute|tracert|ssh|ldapsearch|Test-NetConnection|Test-Connection"
                        r"|Resolve-DnsName|Invoke-WebRequest|Invoke-RestMethod)\b|openssl\s+s_client|/dev/(tcp|udp)/", re.I)
    PW = re.compile(r"\b(mysql\w*|mariadb\w*)\b[^|;&\n]*?\s-p(?![\s<\"']|$)\S+|-p<PW>|(?i:--password[=\s]+\S|identified\s+by\s|(?<![/\w.])(sys|system|scott)/\S|-pw\s+\S|PGPASSWORD=|MYSQL_PWD=|password=<)|-P\s*<PW>")

    def _all(self):
        for k, e in CODES.items():
            for o in O.applicable_os(M, e.product):
                yield k, o, O.solution(e, o, ENGINE / "manuals", PROCS)

    def test_support_status(self):
        def first(p):
            return CODES[next(k for k in CODES if k.startswith(p + ":"))]
        self.assertEqual(O.solution(first("altibase"), "solaris", ENGINE / "manuals", PROCS)["support"]["status"], "레거시")
        self.assertNotIn("windows", O.applicable_os(M, "altibase"))
        self.assertEqual(O.solution(first("postgresql"), "aix", ENGINE / "manuals", PROCS)["support"]["status"], "조건부")
        self.assertEqual(O.solution(first("mysql"), "solaris", ENGINE / "manuals", PROCS)["support"]["status"], "레거시")
        self.assertEqual(O.solution(first("jeus"), "hpux", ENGINE / "manuals", PROCS)["support"]["status"], "미확인")
        g = O.solution(first("goldilocks"), "linux", ENGINE / "manuals", PROCS)
        self.assertEqual(g["support"]["status"], "미확인")
        self.assertTrue(any("미검증" in (i.get("note") or "") for i in g["stages"][0]["items"]))   # 제품 전용 명령은 미검증 표시
        self.assertEqual(O.solution(first("oracle"), "linux", ENGINE / "manuals", PROCS)["support"]["status"], "지원")

    def test_no_password_on_command_line(self):
        """비밀번호는 프롬프트로만 — 명령행 인자(-pXXX·--password=·user/pass·IDENTIFIED BY·환경변수)로 두지 않는다."""
        self.assertIsNone(self.PW.search(self.RAW), (self.PW.search(self.RAW) or [None])[0])
        for bad in ["mysqladmin -u root -pSECRET status", "sqlplus sys/x as sysdba", "psql --password=x", "PGPASSWORD=x psql", "is -u sys -P <PW>"]:
            self.assertRegex(bad, self.PW)
        for ok in ["ps -p <PID>", "pg_isready -p 5432", "mysql -u root -p -e \"select 1\"", "Get-PSDrive -PSProvider FileSystem"]:
            self.assertNotRegex(ok, self.PW)
        # GPT 88차 P0-03: 대화형 프롬프트(SQL>·gSQL>) 표시로 면제하지 않는다 — 값이 든 IDENTIFIED BY 는 주석·본문 어디에도 두지 않는다
        # (허용: 값이 없는 'IDENTIFIED BY …' 설명, 서버가 값을 만드는 'IDENTIFIED BY RANDOM PASSWORD')
        IDBY = re.compile(r"(?i)identified\s+by\s+(?!random\s+password)(?!…)(?!문)\S")
        for bad in ['SQL> ALTER USER app IDENTIFIED BY "<새비밀번호>";', "gSQL> ALTER USER u IDENTIFIED BY <new_password>;", "# isql: ALTER USER u IDENTIFIED BY x;"]:
            self.assertRegex(bad, IDBY)
        for ok in ["ALTER USER … IDENTIFIED BY …", "ALTER USER 'u'@'h' IDENTIFIED BY RANDOM PASSWORD;", "SQL> password <user>"]:
            self.assertNotRegex(ok, IDBY)
        for k, o, s in self._all():
            for st in s["stages"]:
                for it in st["items"]:
                    for f in ("cmd", "text"):
                        self.assertIsNone(IDBY.search(it.get(f) or ""), (k, o, f, (it.get(f) or "")[:120]))
                    for ln in (it.get("cmd") or "").splitlines():   # 그 밖의 명령행 비밀번호 형태는 주석(# 뒤 설명)을 뺀 명령 부분에서
                        self.assertIsNone(self.PW.search(ln.split("#", 1)[0]), (k, o, ln))
        for p in (ENGINE / "manuals").glob("*.yaml"):
            self.assertIsNone(IDBY.search(p.read_text(encoding="utf-8")), p.name)
        for p in (ENGINE / "errorcodes").glob("*.yaml"):
            self.assertIsNone(IDBY.search(p.read_text(encoding="utf-8")), p.name)

    def test_active_separated_from_read_only(self):
        for k, o, s in self._all():
            for it in s["stages"][0]["items"]:
                c = (it.get("cmd") or "").split("#", 1)[0]
                if it.get("kind") in ("OS", "제품 상태", "코드"):
                    self.assertIsNone(self.ACTIVE.search(c), (k, o, it.get("title"), c))
                if it.get("kind") == "능동(선택)":
                    self.assertIn("능동 진단", it.get("note", ""))

    def test_restart_only_with_basis(self):
        for k, o, s in self._all():
            e = CODES[k]
            s2 = s["stages"][1]["items"]
            # 근거 문장은 재기동 항목에 그대로 보이므로, 그 문장이 이 코드의 2차 조치(short) 또는 이 판정 전용 절차 단계에 실제로 있는지만 본다
            own = [i["text"] for i in s2 if i.get("kind") == "절차" and i.get("link") == "이 판정 전용"]
            sentences = list(e.short or []) + own
            has = any(i.get("kind") == "재기동" for i in s2)
            if has:
                it = next(i for i in s2 if i.get("kind") == "재기동")
                shown = (it.get("text") or "").removeprefix("근거: ")
                self.assertTrue(it.get("text", "").startswith("근거: ") and shown, (k, o, "근거 문장을 보여 주지 않음"))
                self.assertTrue(any(O.restart_basis([x], e.product, e.layer) == shown for x in sentences), (k, o, shown))
                self.assertEqual(s["support"]["status"] in ("미확인", "레거시"), False, (k, o, "미확인·레거시 조합에 재기동 명령"))
                self.assertTrue(it.get("note"), (k, o, "영향·성공 기준 메모 없음"))
            elif s["support"]["status"] not in ("미확인", "레거시") and any(i.get("kind") == "판단" for i in s2):
                # 이 코드 자신의 2차 조치(short)에 긍정형·대상 일치 근거가 있으면 재기동 명령이 빠지면 안 된다
                self.assertFalse(O.restart_basis(list(e.short or []), e.product, e.layer), (k, o, "근거가 있는데 재기동 명령이 없음"))

    def test_restart_basis_negations(self):
        """GPT 86차 P0-02 · 87차 P0-01: 부정·조건·사건·인용·식별자 문장은 근거가 아니다."""
        for s in ["재기동하지 말 것", "원인 해소 전 재기동 금지", "리스너 재시작은 마지막 수단", "재기동 없이 세션만 정리",
                  "재기동보다 풀 회수가 먼저", "restart 는 권하지 않는다",
                  "재기동 필요 없음", "재기동 여부만 확인", "재기동 실패 시 로그 확인", "재기동 불필요", "서비스 재시작 판단", "재기동이 필요할 수 있음",
                  "재시작이 필요하면 service auditd restart", "예정에 없던 재기동이면 원인 확인", "Windows Update 자동 재시작 정책 점검", "CAS 재시작 횟수 분석",
                  "롤백: 재시작 전 덤프", "롤백: 서비스 재기동", "startupTimeLimit 상향", "periodicRestart 조정", "LEG-JEUS-ABNORMAL-SHUTDOWN 참고",
                  "'cannot be changed during restart' 면 완전 정지", "tbdown 후 `tbboot -t RESETLOGS` 로 기동", "원인 확인 뒤 해당 서버만 기동(wsboot)",
                  "반복 원인(배치·재기동 작업) 식별 후 대상 조건 조정 협의", "설정 조정 — 영향: 일부 설정은 재기동 필요"]:
            self.assertFalse(O.restart_basis([s]), s)
            self.assertFalse(O.restart_basis([s], "tomcat", "was"), s)
        for s in ["(2차·승인 후) 설정 수정 후 Tomcat 재기동", "alter system set x scope=spfile; 뒤 계획 재기동", "잔존 공유메모리 정리 후 재기동"]:
            self.assertTrue(O.restart_basis([s]), s)

    def test_restart_target_must_match(self):
        """GPT 87차 P0-02: 재기동 대상이 이 제품 재기동 명령의 대상과 같을 때만 — '리스너 재시작'이 DB 전체 shutdown 근거가 되면 안 된다."""
        no = [("oracle", "db", "리스너 재시작 (TNS-12514/12541)"), ("oracle", "db", "리스너 재시작 후 연결 확인"), ("oracle", "db", "누수 WAS 풀 재시작으로 회수"),
              ("oracle", "db", "LDAP 클라이언트 재기동"), ("tomcat", "was", "클라이언트 재기동 후 재접속"), ("tomcat", "was", "연결 풀 재시작"),
              ("websphere", "was", "애플리케이션 재시작"), ("jeus", "was", "WebtoB 재기동 또는 JSV 재접속"), ("postgresql", "db", "복제 문제 해소 후 대기 서버 재시작"),
              ("mssql", "db", "수정 — MSDTC 재시작 필요"), ("iis", "web", "설치 후 IIS 재시작 필요"), ("windows", "os", "COM+ 애플리케이션 재기동"),
              ("jeus", "was", "상대 서버 재기동"), ("php", "was", "백엔드 재기동 일정 협의")]
        yes = [("oracle", "db", "PROCESSES/SESSIONS 상향 (재기동 필요) — WAS 풀 합계 기준 산정"), ("weblogic", "was", "서버 재기동 (Node Manager 또는 스크립트)"),
               ("webtob", "web", "WebtoB 재기동 또는 JSV 재접속"), ("iis", "web", "앱 풀 재시작 및 빠른 실패 보호"), ("tomcat", "was", "설정 수정 후 Tomcat 재기동"),
               ("mssql", "db", "WSFC 서비스 또는 SQL Server 인스턴스 재시작 — 영향: 복제본 이탈"), ("jeus", "was", "MASTER 기동 확인 후 서버 재기동"),
               ("linux", "os", "누수 프로세스는 담당자 확인 후 재시작 일정"), ("tibero", "db", "롤백: tip 백업본 복원 후 재기동) DB_CACHE_SIZE 상향 후 계획 재기동")]
        for p, l, s in no:
            self.assertFalse(O.restart_basis([s], p, l), (p, s))
        for p, l, s in yes:
            self.assertTrue(O.restart_basis([s], p, l), (p, s))
        # 실제 지식 전수: 오라클 리스너 코드(TNS-)에 DB 전체 재기동 명령이 붙지 않는다
        for k, e in CODES.items():
            if e.product == "oracle" and e.code.startswith("TNS-"):
                s = O.solution(e, "linux", ENGINE / "manuals", PROCS)
                for it in s["stages"][1]["items"]:
                    if it.get("kind") == "재기동":
                        self.assertNotRegex(it["text"], r"리스너|listener", k)
        # 유형만으로 붙은 절차의 문장은 근거가 아니다 — 리스너 없음(TNS-12541)에 접속 폭주 절차의 'PROCESSES 상향(재기동)'으로 DB 재기동이 붙지 않는다
        for c in ("TNS-12541", "TNS-12514", "TNS-00511"):
            s = O.solution(CODES["oracle:" + c], "linux", ENGINE / "manuals", PROCS)
            self.assertFalse(any(i.get("kind") == "재기동" for i in s["stages"][1]["items"]), c)
            self.assertTrue(any(i.get("kind") == "판단" for i in s["stages"][1]["items"]), c)
        # 묶음 절차의 코드 없는 단계는 근거로 안 쓰지만, ORA-00020 은 자기 2차 조치(short)의 'processes … scope=spfile; 후 계획 재기동' 으로 재기동이 붙고
        # 근거 문장이 `명령` 안의 ; 에서 잘리지 않는다
        s = O.solution(CODES["oracle:ORA-00020"], "linux", ENGINE / "manuals", PROCS)
        rs = [i for i in s["stages"][1]["items"] if i.get("kind") == "재기동"]
        self.assertTrue(rs and "processes" in rs[0]["text"].lower() and "scope=spfile;` 후 계획 재기동" in rs[0]["text"], rs)
        self.assertEqual(O._codes_in("리스너 재시작 (TNS-12514/12541) · ORA-00020"), {"TNS-12514", "TNS-12541", "ORA-00020"})
        self.assertEqual(O._codes_in("한도 (ERR-410E3 · ERR-01027) · ERR-0109D/6100D"), {"ERR-410E3", "ERR-01027", "ERR-0109D", "ERR-6100D"})
        self.assertEqual(O.restart_basis(["(2차·승인 후) 한도 상향 (altibase.properties, 재기동 필요)"], "altibase", "db"), "재기동 필요)")
        # 묶음 절차(제목에 코드 둘 이상)에서 코드를 안 적은 단계는 어느 코드의 것인지 몰라 근거로 쓰지 않는다
        e = CODES["altibase:ERR-410E3"]
        s = O.solution(e, "linux", ENGINE / "manuals", PROCS)
        self.assertFalse(any(i.get("kind") == "재기동" for i in s["stages"][1]["items"]), [i.get("text") for i in s["stages"][1]["items"]])

    def test_remote_change_is_stage2(self):
        """GPT 88차 P0-02: 상태를 바꾸는 원격 요청(POST/PUT/DELETE/PATCH·본문 전송)은 능동 진단(선택)도 아니다 — 2차 '원격 변경'."""
        for c in ["Get-Service a; irm -Method Post -Uri https://h/admin/restart", "nginx -t; curl -X POST http://h/x", "id; curl -s --request DELETE http://h/x",
                  "id; curl -d a=1 http://h/x", "id; wget --post-data=a http://h", "Invoke-RestMethod -Uri http://h -Method 'Delete'",
                  "iwr http://h -Method Put -Body x",
                  # GPT 89차 P0-02
                  "curl --json '{\"action\":\"restart\"}' https://host/api", "irm -Uri https://host/api -CustomMethod 'POST'", "iwr https://h -CM POST",
                  "curl -X 'DELETE' http://h/x", "curl --request=PATCH http://h/x", "wget --method=PUT --body-data=x http://h",
                  # GPT 90차 P0-01: PowerShell 5.1 별칭
                  "curl -Method Post -Uri https://host/admin/restart", "wget -Method Post -Uri https://host/x", "curl -Uri https://h -Body x"]:
            keep, act, chg = O._split_three(c)
            self.assertTrue(chg, c)
            self.assertIsNone(O.MUTATING.search(keep + " " + act), c)
        for c in ["curl -s http://h/health", "curl -s -D - -o /dev/null http://h/", "irm https://h/health", "wget -q -O- http://h/"]:
            self.assertFalse(O._split_three(c)[2], c)
        for k, o, s in self._all():
            for it in s["stages"][0]["items"]:
                self.assertIsNone(O.MUTATING.search(it.get("cmd") or ""), (k, o, it.get("cmd")))
                if O.MUTATING.search(it.get("text") or ""):
                    self.assertIn("1차에서 실행하지 않는다", it.get("note", ""), (k, o))

    def test_observation_is_not_restart_basis(self):
        """GPT 88차 P0-01: 관찰 문장(이력·기록·원인·시각·로그)은 실행 권고가 아니다."""
        for p, l, s in [("oracle", "db", "DB 재기동 이력 조회"), ("tomcat", "was", "재기동 원인 분석"), ("tomcat", "was", "재기동 기록 확인"),
                        ("weblogic", "was", "서버 재기동 시각과 오류 시각 대조"), ("linux", "os", "reboot 로그 확인"), ("jeus", "was", "재기동 직전 스레드 덤프 비교"),
                        # GPT 89차 P0-01: 지난 사건 서술
                        ("oracle", "db", "DB 재기동 후 장애가 발생했다"), ("tomcat", "was", "재기동 뒤 같은 오류 재발"), ("weblogic", "was", "서버를 재시작했다"),
                        ("linux", "os", "reboot 이후 문제 발생")]:
            self.assertFalse(O.restart_basis([s], p, l), s)
        self.assertTrue(O.restart_basis(["로그 보존 후 재기동하고 상태 확인"], "webtob", "web"))

    def test_compound_active_counterexamples(self):
        """GPT 86차 P0-01: && · || · | · 줄바꿈 · $() · 백틱 안의 능동 명령도 1차 읽기 전용으로 새지 않는다."""
        for c in ["nginx -t && curl -s http://x/", "lsnrctl status || tnsping X", "echo q | nc -zv h 1521", "ps -ef\ncurl x",
                  "x=$(ping -c1 h); echo $x", "echo `ping -c1 h`", "Get-Service a; Test-NetConnection h -Port 1",
                  # GPT 87차 P1: 목록 밖이던 능동 통신
                  "Get-Service a; Test-Connection h -Count 1", "Get-Service a; Resolve-DnsName h", "ls; openssl s_client -connect h:443 </dev/null",
                  "uptime; echo x >/dev/udp/h/53", "uptime; traceroute h", "id; ssh h uptime", "id; ldapsearch -x -H ldap://h",
                  # GPT 88차 P0-02: PowerShell 별칭
                  "Get-Service a; irm https://h/health", "Get-Service a; iwr https://h/"]:
            keep, act = O._split_active(c)
            self.assertIsNone(self.ACTIVE.search(keep.split("#", 1)[0]), (c, keep))
            self.assertTrue(act, c)
        e = next(v for v in CODES.values() if v.immediate and any(re.search(r"\bnc\b|curl", str(x)) for x in v.immediate))
        s = O.solution(e, O.applicable_os(M, e.product)[0], ENGINE / "manuals", PROCS)
        it = next(i for i in s["stages"][0]["items"] if i.get("kind") == "제품" and re.search(r"\bnc\b|curl", i.get("text", "")))
        self.assertIn("능동 진단", it.get("note", ""))

    def test_unverified_no_change_commands(self):
        """GPT 86차 P1: 미확인·레거시 조합 전부 — 재기동 명령 없음, 2차 항목마다 '지원 확인 전 실행 금지'."""
        n = 0
        for k, o, s in self._all():
            if s["support"]["status"] not in ("미확인", "레거시"):
                continue
            n += 1
            s2 = s["stages"][1]["items"]
            self.assertFalse(any(i.get("kind") == "재기동" for i in s2), (k, o))
            self.assertTrue(all("지원 확인 전 실행 금지" in (i.get("note") or "") for i in s2 if i.get("kind") != "판단"), (k, o))
        self.assertGreater(n, 100)
        # 근거가 있는 코드라도 레거시 조합이면 재기동 명령이 없다(근거 있는 지원 조합과 짝 대조)
        e = next(v for v in CODES.values() if v.product == "mysql" and O.restart_basis(list(v.short or []), "mysql", v.layer))
        self.assertTrue(any(i.get("kind") == "재기동" for i in O.solution(e, "linux", ENGINE / "manuals", PROCS)["stages"][1]["items"]))
        self.assertFalse(any(i.get("kind") == "재기동" for i in O.solution(e, "solaris", ENGINE / "manuals", PROCS)["stages"][1]["items"]))
        jeus = O.solution(CODES[next(k for k in CODES if k.startswith("jeus:"))], "linux", ENGINE / "manuals", PROCS)
        self.assertIn("강제 종료", self.RAW[self.RAW.index("  jeus:"):self.RAW.index("  tomcat:")])

    def test_windows_locale_and_paths(self):
        self.assertNotIn("Get-Counter", self.RAW)                              # 성능 카운터 이름은 한글 Windows 에서 현지화돼 실패
        for k, o, s in self._all():
            if o != "windows":
                continue
            for stg in s["stages"]:
                for it in stg["items"]:
                    c = (it.get("cmd") or "").split("#", 1)[0]
                    if "Get-Content" in c or "Select-String" in c:
                        self.assertNotRegex(c, r"%[A-Za-z_]+%", (k, c))          # PowerShell 에서 안 풀리는 %VAR%
                        self.assertNotIn("'$env:", c)

    def test_unix_log_quotes_expand(self):
        for k, o, s in self._all():
            if o == "windows":
                continue
            for it in s["stages"][0]["items"]:
                c = it.get("cmd") or ""
                if c.startswith(("tail ", "ls -lt")):
                    self.assertNotRegex(c, r"'\$[A-Z]", (k, c))                  # 작은따옴표 안 $VAR 은 안 풀린다
                    self.assertNotIn("(", c.split("|")[0].replace("$(", ""), (k, c))   # 경로에 설명문이 섞이지 않음

    def test_heavy_java_not_default(self):
        for line in self.RAW.splitlines():
            if "GC.class_histogram" in line:
                self.assertIn("# GC.class_histogram 은 고부하", line)

    def test_split_respects_quotes(self):
        self.assertEqual(O._split_cmds("lsnrctl status; echo 'select a;' | sqlplus -s / as sysdba"),
                         ["lsnrctl status", "echo 'select a;' | sqlplus -s / as sysdba"])
        self.assertEqual(len(O._split_cmds("Get-PSDrive | Select-Object @{n='A';e={1}}")), 1)
        self.assertEqual(O._split_cmds("tbsql sys   # 프롬프트 뒤: select a; select b;"), ["tbsql sys   # 프롬프트 뒤: select a; select b;"])


class Surfaces(unittest.TestCase):
    def test_api(self):
        from logtriage.server import make_server
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "rules-local", "errorcodes", "manuals", "report-template"):
            shutil.copytree(ENGINE / d, td / d)
        httpd, h = make_server("127.0.0.1", 0, td, None, desktop=True, native=False)
        self.addCleanup(httpd.server_close)
        r = h.api.code_solution("oracle", "ORA-00018", "aix")
        self.assertEqual(r["os"], "aix")
        self.assertEqual([x["stage"] for x in r["stages"]], [1, 2, 3])
        self.assertEqual(h.api.code_solution("oracle", "ORA-00018", "")["os"], "linux")    # 비우면 첫 지원 OS
        self.assertIn("error", h.api.code_solution("oracle", "없는코드", "linux"))
        from logtriage.server import API_NAMES, READ_APIS
        self.assertIn("code_solution", API_NAMES)
        self.assertIn("code_solution", READ_APIS)

    def test_cli(self):
        r = subprocess.run([sys.executable, "-m", "logtriage.cli", "--solution", "tomcat:" + next(k.split(":", 1)[1] for k in CODES if k.startswith("tomcat:")),
                            "--os", "windows"], cwd=str(ENGINE), capture_output=True, text=True, encoding="utf-8", errors="replace",
                           env={**__import__("os").environ, "PYTHONIOENCODING": "utf-8"})
        self.assertEqual(r.returncode, 0, r.stderr)
        for k in ("1차 확인", "2차 조치", "3차 제조사 의뢰 자료", "Windows Server"):
            self.assertIn(k, r.stdout)

    def test_ui_safe(self):
        ui = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
        f = ui[ui.index("async function kbSolution("):ui.index("function kbPick(i){")]
        self.assertNotIn("innerHTML", f)
        self.assertIn("SOLKEY!==key", f)                                       # 늦게 온 응답이 다른 코드 화면을 덮지 않음
        self.assertIn('kbSolution(KBCUR||"",c.code,"")', ui)
        self.assertIn('"code_solution"', ui)


if __name__ == "__main__":
    unittest.main()
