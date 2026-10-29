"""제품별 지식 완결성 관문(2026-10-16 마스터 지시 · GPT 45차 관문) — 판정(룰·에러코드)마다 1차 대응자가 그대로 따라 할 수 있어야 한다.
  · 코드: 원인(20자+) · 즉시 조치 구체(합 25자+) · 단기/중기/장기 · 수행 절차 연결(1차 실행 명령 있음)
  · 룰: 즉시 조치 구체 · 단기/중기/장기 · 수행 절차 연결
  · 절차: 1차는 읽기 전용(재기동·삭제·설정 변경 등 없음) · 2차는 사전조건/영향/승인/백업·롤백 + 성공·실패 판단 · 3차는 민감정보 마스킹·전달 승인
  · 즉시(1차) 줄에 재기동·삭제 같은 조치가 있으면 '(2차·승인 후)' 표시
  · 원인 출처 표시: 제조사 URL 이 없으면 '제조사 문서'라 부르지 않는다
확인하지 못한 내용은 verify_note 로 남긴다(허위로 채우지 않는다) — 그 항목도 형식 관문은 통과해야 한다."""
import re
import sys
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage.codes import cause_label, load_codes  # noqa: E402
from logtriage.procedures import load_procedures, match_procedures  # noqa: E402
from logtriage.yamlsafe import load as yload  # noqa: E402

RISKY_CMD = re.compile(r"(?i)(\bsystemctl\s+(restart|stop|start|reload)\b|\bservice\s+\S+\s+(restart|stop|start)\b|\bp?kill(all)?\b(?!\s+-(3|QUIT|SIGQUIT)\b)|\brm\s+-|\brm\s+/|\s-delete\b"
                       r"|\btruncate\b|\bdrop\s+(table|index|user|tablespace|database)|\balter\s+(system|database|table|user|tablespace|session\s+kill)"
                       r"|\bshutdown\b|\breboot\b|explain\s+analyze|\bchmod\b|\bchown\b|\bmv\s|\bswapoff\b|\bumount\b|\bfsck\b(?!.*-n\b)|xfs_repair(?!.*\s-n\b)"
                       r"|e2fsck(?!.*\s-n\b)|\biisreset\b|net\s+stop|stop-service|restart-service|\bvacuum\s+full|\breindex\b|lsnrctl\s+(stop|start|reload)"
                       r"|apachectl\s+(-k\s+)?(restart|graceful|stop)|nginx\s+-s\s|\bsysctl\s+-w|\bchdev\b|remount|\bfind\s+/\s(?!.*-xdev))")
RISKY_KO = re.compile(r"(재기동|재시작|강제 ?종료|삭제|\bkill\b|중지|drop |truncate|rm -)", re.I)   # 'Killed process'(grep 문자열)는 조치가 아니다
TAG_OK = re.compile(r"(2차|승인)")
# 1차 줄에 실행할 것이 있는가 — 백틱 명령·SQL·변수·경로·옵션 달린 명령·대표 진단 도구 이름
CMD = re.compile(r"`[^`]+`|\b(SELECT|select|SHOW|show)\b|\$[A-Z_]+|/[a-z]+/|[A-Za-z]:\\|\b[a-z]{2,}\s+-[a-zA-Z]|V\$|v\$|\b(jcmd|jstack|errpt|lsps|bdf|svmon|prctl|fmadm|wsadmin|jeusadmin|tbsql|isql|gsql|csql|cubrid|sqlplus|lsnrctl|appcmd|Get-[A-Za-z]+|netsh|journalctl|dmesg|df|du|free|vmstat|iostat|netstat|ss|ps|grep|tail)\b")


def _rules():
    out = []
    for f in sorted((ENGINE / "rules").rglob("*.yaml")):
        doc = yload(f.read_text(encoding="utf-8")) or {}
        for r in (doc.get("rules") or []) if isinstance(doc, dict) else []:
            if isinstance(r, dict) and r.get("id"):
                lay = r.get("layer")
                prods = r.get("product") or ["*"]
                for p in (prods if isinstance(prods, list) else [prods]):
                    out.append({"id": r["id"], "product": str(p).lower(), "layer": lay[0] if isinstance(lay, list) else lay,
                                "category": r.get("category", "etc"), "immediate": r.get("immediate") or [],
                                "short": r.get("short") or [], "mid": r.get("mid") or [], "long": r.get("long") or []})
    return out


def _codes():
    return [{"id": c.code, "product": c.product, "layer": c.layer, "category": c.category, "immediate": c.immediate, "short": c.short,
             "mid": c.mid, "long": c.long, "cause": c.cause} for k, c in load_codes(ENGINE / "errorcodes").items() if ":" in k]


class KnowledgeCompleteness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.procs = load_procedures(ENGINE / "manuals")
        cls.codes = _codes()
        cls.rules = _rules()

    def _fmt(self, items):
        bad = []
        for x in items:
            if sum(len(str(s)) for s in x["immediate"]) < 25:
                bad.append(f"{x['product']}:{x['id']} 즉시 조치 막연")
            for f in ("short", "mid", "long"):
                if not x[f]:
                    bad.append(f"{x['product']}:{x['id']} {f} 없음")
            if any(RISKY_KO.search(str(l)) and not TAG_OK.search(str(l)) for l in x["immediate"]):
                bad.append(f"{x['product']}:{x['id']} 즉시(1차)에 재기동·삭제 — '(2차·승인 후)' 표시 필요")
            if not any(CMD.search(str(l)) for l in x["immediate"]):   # 3단계: '무엇을 확인'만 있고 '어떻게'(명령·뷰·경로)가 없으면 미달
                bad.append(f"{x['product']}:{x['id']} 즉시(1차)에 실행 명령 없음")
            if (x.get("cause") or "").startswith("문서 사례"):          # 원인은 일반 의미가 먼저, 사례는 '예:'
                bad.append(f"{x['product']}:{x['id']} 원인이 특정 사례 문구")
        return bad

    def test_codes_have_cause_and_concrete_actions(self):
        bad = self._fmt(self.codes) + [f"{x['product']}:{x['id']} 원인 없음" for x in self.codes if len(x["cause"] or "") < 20]
        self.assertEqual(bad, [], f"{len(bad)}건:\n" + "\n".join(bad[:60]))

    def test_rules_have_concrete_actions(self):
        bad = self._fmt(self.rules)
        self.assertEqual(bad, [], f"{len(bad)}건:\n" + "\n".join(bad[:60]))

    def test_every_verdict_has_a_procedure_with_commands(self):
        bad = []
        for x in self.codes + self.rules:
            m = match_procedures(self.procs, x["product"], x["layer"], x["category"], [x["id"]], limit=1)
            if not m or not any(s["cmd"].strip() for st in m[0]["stages"] if st["stage"] == 1 for s in st["steps"]):
                bad.append(f"{x['product']}:{x['id']} ({x['layer']}/{x['category']})")
        self.assertEqual(bad, [], f"수행 절차 없는 판정 {len(bad)}건:\n" + "\n".join(bad[:60]))

    def test_procedure_stage_safety(self):
        bad = []
        for p in self.procs:
            has3 = mask3 = False
            for st in p["stages"]:
                n = int(st.get("stage", 2))
                for s in st.get("steps") or []:
                    if not isinstance(s, dict):
                        continue
                    cmd = re.sub(r"\"[^\"\n]*\"|'[^'\n]*'", '""', str(s.get("cmd", "")))
                    cfg = s.get("config") if isinstance(s.get("config"), dict) else {}
                    note = str(s.get("note", "")) + str(cfg.get("note", ""))
                    if n == 1 and RISKY_CMD.search(cmd):
                        bad.append(f"{p['id']} 1차에 위험 명령: {RISKY_CMD.search(cmd).group(0)}")
                    if n == 2 and (str(s.get("cmd", "")).strip() or cfg):
                        if not ("승인" in note and re.search("롤백|원복|백업", note) and str(s.get("check", "")).strip()):
                            bad.append(f"{p['id']} 2차 통제(사전조건·승인·백업/롤백·판단) 없음")
                    if n == 3:
                        has3 = True
                        if re.search("마스킹|가림|민감", note + str(s.get("check", "")) + str(s.get("do", ""))):
                            mask3 = True
            if has3 and not mask3:
                bad.append(f"{p['id']} 3차 민감정보 마스킹 없음")
        self.assertEqual(sorted(set(bad)), [], "\n".join(sorted(set(bad))[:60]))

    def test_every_knowledge_yaml_parses(self):
        """YAML 하나가 깨지면 로더가 그 파일을 조용히 건너뛴다(2026-10-16: 따옴표 안 아포스트로피로 HP-UX 로그 카탈로그가 통째로 빠질 뻔함)."""
        import yaml
        bad = []
        for p in list((ENGINE / "manuals").glob("*.yaml")) + list((ENGINE / "errorcodes").glob("*.yaml")) + list((ENGINE / "rules").rglob("*.yaml")):
            try:
                yaml.safe_load(p.read_text(encoding="utf-8"))
            except Exception as e:   # noqa: BLE001 — 어떤 오류든 '깨진 파일'
                bad.append(f"{p.relative_to(ENGINE)}: {str(e).splitlines()[0][:80]}")
        self.assertEqual(bad, [])

    def test_no_password_on_command_lines(self):
        """GPT 50차: 명령행 비밀번호(-p<pw>·user/<pw>·-u user:<pw>)는 ps·셸 이력에 남는다 — 도구가 묻게 한다."""
        # 10-16: -D…=<pw>·keytool, WLST connect('<admin>','<pw>')·-password <pw>·appcmd /processModel.password:<…>·sc.exe password= <…> 도
        pat = re.compile(r"-p ?<pw>|\w/<pw>\b|:<pw>|sys <pw>|-P ?<pw>|=<pw>|-storepass\s+\S+|-keypass\s+\S+"
                         r"|'<[a-z-]*pw>'|-password\s+<|/processModel\.password:<|\bpassword= <")
        bad = []
        for p in list((ENGINE / "manuals").glob("*.yaml")) + list((ENGINE / "errorcodes").glob("*.yaml")) + list((ENGINE / "rules").rglob("*.yaml")):
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if pat.search(line) and not re.search(r"(주의|쓰면|쓰지 말|쓰지 않음|금지|빼고|옵션:)", line):   # 경고 문구 자체는 제외
                    bad.append(f"{p.name}:{i}")
        self.assertEqual(bad, [], "\n".join(bad[:40]))

    def test_broken_or_missing_knowledge_is_reported(self):
        """GPT 53차: 실행 중 지식 파일이 깨지거나 줄면 조용히 넘어가지 않는다 — 분석은 계속하되(장애 중 도구가 멈추면 안 됨)
        '읽지 못한 지식 파일' 알림(kb_skipped)에 올린다. 반입(룰팩 적용)은 깨진 YAML 이면 통째로 거부(rulepack.apply)."""
        import json
        import shutil
        import tempfile
        from logtriage.service import run_analysis
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for d in ("rules", "errorcodes", "manuals"):
            shutil.copytree(ENGINE / d, td / d)
        (td / "manuals" / "zz_broken_procedures.yaml").write_text("procedures:\n- id: X\n  title: 'a'b\n", encoding="utf-8")
        (td / "knowledge-manifest.json").write_text(json.dumps({"rules": 99999, "codes": 999999}), encoding="utf-8")
        inc = run_analysis([{"path": str(ENGINE / "samples" / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                           rules_dir=td / "rules", codes_dir=td / "errorcodes", manuals_dir=td / "manuals")
        sk = inc.get("kb_skipped") or []
        self.assertIn("manuals/zz_broken_procedures.yaml", sk)
        self.assertTrue(any("코드 수가 설치 기록보다 적음" in x for x in sk), sk)
        self.assertTrue(any("룰 수가 설치 기록보다 적음" in x for x in sk), sk)
        self.assertTrue(inc.get("checklist"))                       # 분석은 계속된다

    def test_cause_label_is_honest(self):
        self.assertEqual(cause_label("https://docs.oracle.com/x"), "제조사 문서 원인")
        self.assertIn("분석기 지식", cause_label(""))
        self.assertIn("미대조", cause_label(""))


if __name__ == "__main__":
    unittest.main()
