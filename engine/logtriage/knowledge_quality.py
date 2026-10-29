"""지식 품질 도구 — 2026-10-16 아이디어 12건(GPT 55차 보완 반영).

· 검증 축(①): 근거 · 교차 실검증 · 문법 · 실행 · 현장 을 **따로** 기록한다(한 줄 등급으로 섞지 않는다 — '문법 통과 ≠ 실행 성공 ≠ 진단 정확성').
· 판 추정(⑥): 분석한 로그 머리의 판 문자열로 제품 판을 '추정'하고, 1차 명령 줄의 판 표기와 맞춰 본다. 안 맞는 줄은 명령 모음에서 뺀다.
· 1차 명령 모음(⑦ 대체): 실행 스크립트는 만들지 않는다(GPT 55차 — 자동 실행·셸 확장·출력 유출 위험). 위험 명령 검사를 통과하고
  비밀번호가 없고 판이 어긋나지 않은 명령만 한 줄씩 복사할 수 있게 준다.
· 결과 해석(⑧): 판단 기준 중 기계로 읽을 수 있는 것('N% 이상', '있으면/나오면')만 '보조 판정', 못 읽으면 '판정 불가', 나머지는 '사람 판단'.
· 지식 지문(⑩): rules·errorcodes·manuals 파일별 해시 — 설치 매니페스트와 대조해 추가·삭제·변경을 알리고, 분석 이력에 그때 쓴 지식 지문을 남긴다.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

# ── 1차(읽기 전용) 안전 검사 — 시험(test_knowledge_completeness)과 같은 기준 ──
RISKY_CMD = re.compile(r"(?i)(\bsystemctl\s+(restart|stop|start|reload)\b|\bservice\s+\S+\s+(restart|stop|start)\b|\bp?kill(all)?\b(?!\s+-(3|QUIT|SIGQUIT)\b)|\brm\s+-|\brm\s+/|\s-delete\b"
                       r"|\btruncate\b|\bdrop\s+(table|index|user|tablespace|database)|\balter\s+(system|database|table|user|tablespace|session\s+kill)"
                       r"|\bshutdown\b|\breboot\b|explain\s+analyze|\bchmod\b|\bchown\b|\bmv\s|\bswapoff\b|\bumount\b|\bfsck\b(?!.*-n\b)|xfs_repair(?!.*\s-n\b)"
                       r"|e2fsck(?!.*\s-n\b)|\biisreset\b|net\s+stop|stop-service|restart-service|\bvacuum\s+full|\breindex\b|lsnrctl\s+(stop|start|reload)"
                       r"|apachectl\s+(-k\s+)?(restart|graceful|stop)|nginx\s+-s\s|\bsysctl\s+-w|\bchdev\b|remount|\bfind\s+/\s(?!.*-xdev)"
                       r"|\bkill\s+session|\bgrant\b|\brevoke\b|\bcreate\s|\bdelete\s+from|\bupdate\s+\S+\s+set|\binsert\s+into|\bset-\w+|\bremove-\w+|\bstart-\w+|\bstop-\w+|\brestart-\w+)")
PW = re.compile(r"-p ?<pw>|\w/<pw>\b|:<pw>|sys <pw>|-P ?<pw>|=<pw>|-storepass\s+\S+|-keypass\s+\S+|password\s*=|"
                r"'<[a-z-]*pw>'|-password\s+\S|/processModel\.password:", re.I)
BACKTICK = re.compile(r"`([^`]+)`")


def first_commands(lines: list[str]) -> list[dict]:
    """즉시(1차) 줄에서 백틱 명령과 판단 기준(— 뒤)을 뽑는다. 안전 검사를 통과한 것만 copy=True."""
    out = []
    for i, line in enumerate(lines or []):
        line = str(line)
        crit = line.split("—", 1)[1].strip() if "—" in line else ""
        ms = list(BACKTICK.finditer(line))
        for k, m in enumerate(ms):
            cmd = m.group(1).strip()
            # 이 명령 바로 뒤(다음 명령 전까지)의 글 — '(16 이하)'·'(17+)' 같은 판 표기는 명령마다 따로 읽는다(10-16 실측: 한 줄에 판이 다른 두 명령)
            tail = line[m.end(): ms[k + 1].start() if k + 1 < len(ms) else len(line)]
            bare = re.sub(r"\"[^\"\n]*\"|'[^'\n]*'", '""', cmd)
            risky = bool(RISKY_CMD.search(bare)) or bool(PW.search(cmd))
            out.append({"line": i, "cmd": cmd, "tail": tail[:120], "criterion": crit[:200], "safe": not risky,
                        "hash": hashlib.sha256(cmd.encode("utf-8")).hexdigest()[:16]})
    return out


# ── 판 추정(⑥) — 로그 머리의 판 문자열. '추정'일 뿐 실제 실행 판과 다를 수 있다(GPT 55차) ──
_VER = {
    "oracle": [r"Oracle Database (\d+)[cgai]*\b", r"Release (\d+)\.\d+\.\d+"],
    "tomcat": [r"Apache Tomcat/(\d+(?:\.\d+)?)", r"Server version(?: name)?:?\s*Apache Tomcat/(\d+(?:\.\d+)?)"],
    "weblogic": [r"WebLogic Server (\d+\.\d+)"], "websphere": [r"WebSphere Platform (\d+\.\d+)"],
    "jboss": [r"JBoss EAP (\d+)\.\d+", r"WildFly (?:Full|Core) (\d+)"], "jeus": [r"JEUS (\d+)"],
    "postgresql": [r"PostgreSQL (\d+)(?:\.\d+)?"], "mysql": [r"Version: '(\d+\.\d+)", r"mysqld[^\n]{0,40}?(\d+\.\d+)\.\d+"],
    "mssql": [r"Microsoft SQL Server (\d{4})"], "nginx": [r"nginx/(\d+\.\d+)"], "apache": [r"Apache/(\d+\.\d+)"],
    "linux": [r"Red Hat Enterprise Linux[^\n]{0,40}?release (\d+)", r"\.el(\d+)[._]"], "windows": [r"Windows Server (\d{4})"],
    "tibero": [r"Tibero (\d+)"], "cubrid": [r"CUBRID (\d+\.\d+)"], "java": [r"java version \"(?:1\.)?(\d+)", r"JRE version: [^\n]{0,30}?\((?:1\.)?(\d+)"],
}
# 1차 줄의 판 표기를 읽는 제품별 꼴 — 표기와 감지 판이 둘 다 있을 때만 맞춤/어긋남을 판단(그 밖은 판단하지 않음)
_TAG = {
    "oracle": r"\b(\d{2})(?:g|c|ai)(\+)?", "linux": r"RHEL ?(\d)(\+)?", "tomcat": r"Tomcat ?(\d+(?:\.\d+)?)(\+)?",
    "mysql": r"\b(5\.7|8\.0|8\.4)(\+)?", "postgresql": r"(?:PG|PostgreSQL) ?(\d{1,2})(\+)?", "mssql": r"\b(20\d\d)(\+)?",
    "windows": r"\b(20\d\d(?: R2)?)(\+)?",
}


def _num(v: str) -> float:
    m = re.match(r"(\d+(?:\.\d+)?)", v or "")
    return float(m.group(1)) if m else -1.0


def detect_versions(files: list[dict], max_lines: int = 300) -> dict:
    """{제품: 판} — 분석한 파일 앞부분에서 처음 보이는 판 문자열(추정)."""
    found = {}
    for f in files or []:
        prod = str(f.get("product", "")).split("-")[0]
        pats = _VER.get(prod)
        path = f.get("path")
        if not pats or prod in found or not path:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                head = "".join(fh.readline() for _ in range(max_lines))
        except OSError:
            continue
        for p in pats:
            m = re.search(p, head)
            if m:
                found[prod] = m.group(1)
                break
    return found


# 괄호 전체가 판 표기인 것: '(16 이하)'·'(17+)'·'(9.5+)'·'(PG 12+)'·'(8.0 미만)' — 제품 이름이 없어도 그 제품 줄이면 판으로 읽는다
_WHOLE = re.compile(r"^\s*(?:PG|PostgreSQL|MySQL|Tomcat|JEUS|Tibero|CUBRID|JDK|Java|v)?\s*(\d{1,2}(?:\.\d{1,2})?)\s*(\+|이상|이하|미만)?\s*$", re.I)


def version_fit(line: str, product: str, detected: str | None) -> str:
    """'맞음' / '어긋남' / '' (판단 안 함). 표기 'N+'·'N 이상' 은 N 이상, 'N 이하'·'N 미만', 나열은 그 판들.
    line 은 명령 바로 뒤의 글(first_commands 의 tail)을 주면 명령마다 판단한다."""
    if not detected:
        return ""
    tags = re.findall(r"\(([^()]{1,60})\)", str(line))
    seen = False
    d = _num(detected)
    for t in tags:
        found = []
        w = _WHOLE.match(t)
        if w and product in _VER:
            found.append((w.group(1), w.group(2) or ""))
        elif product in _TAG:
            found += [(m.group(1), m.group(2) or "") for m in re.finditer(_TAG[product], t)]
        for v, op in found:
            seen = True
            n = _num(v)
            if (op in ("+", "이상") and d >= n) or (op == "이하" and d <= n) or (op == "미만" and d < n) \
                    or (not op and (str(detected).startswith(v) or n == d)):
                return "맞음"
    return "어긋남" if seen else ""


# ── 결과 해석(⑧) — 보조 판정. 못 읽으면 '판정 불가', 사람 판단이 필요한 기준은 '사람 판단' ──
_CMD_ERR = re.compile(r"(?im)(command not found|not recognized as|permission denied|access is denied|no such file|"
                      r"cannot open|syntax error|invalid option|unknown option|usage:|not found\s*$|connection refused|"
                      r"^\s*(ERROR|FATAL)[: ]|^SP2-\d+|ORA-01017|ORA-00942|psql: error|ERROR \d{4} \(|"
                      r"내부 또는 외부 명령|액세스가 거부|권한 거부|찾을 수 없습니다)")
MAX_INTERPRET = 64 * 1024


def load_metrics(codes_dir: Path | None) -> list[dict]:
    """errorcodes/_metrics.yaml — 기계가 충족·미충족을 정해도 되는 (판정, 명령) 짝과 읽을 머리글 칸. 없거나 깨지면 빈 목록(전부 참고 수치)."""
    from .yamlsafe import load as yload
    if not codes_dir:
        return []
    try:
        doc = yload((Path(codes_dir) / "_metrics.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return []
    out = []
    for m in (doc.get("metrics") or []) if isinstance(doc, dict) else []:
        try:
            if str(m.get("agg", "")) not in ("any", "all"):
                continue   # GPT 61차: 여러 대상 줄의 집계 규칙(ANY/ALL)이 적힌 것만 기계 판정
            out.append({"id": str(m["id"]), "title": str(m.get("title", "")), "cmd": re.compile(str(m["cmd"])), "agg": str(m["agg"]),
                        "header": [str(h) for h in m["header"]], "unit": str(m.get("unit", "%")), "op": str(m.get("op", ">=")),
                        "keys": {str(k).upper() for k in m.get("keys") or []},
                        # 8차 ⑨: 판단 기준에 다른 조건(권한·여유 공간 비교 등)이 섞인 판정 — 수치 부분만 결속('수치 조건 충족/미충족')
                        "part_keys": {str(k).upper() for k in m.get("part_keys") or []}})
        except (KeyError, TypeError, re.error):
            continue   # 틀린 항목은 버린다 — 그 판정은 참고 수치로 남는다(오판보다 낫다)
    return out


def metric_for(metrics: list[dict], key: str, cmd: str) -> dict | None:
    k = str(key or "").upper()
    bare = k.split(":", 1)[-1]   # 룰 항목의 키는 '제품:룰ID' — 룰 ID 는 하나뿐이라 맨 ID 로도 찾는다(코드 결속은 제품까지 붙여 적는다)
    def _in(ks: set) -> bool:
        return k in ks or (":" in k and bare in ks and not any(":" in x and x.endswith(":" + bare) for x in ks))

    for m in metrics:
        full, part = _in(m["keys"]), _in(m.get("part_keys") or set())
        if (full or part) and m["cmd"].search(str(cmd or "").strip()):
            # GPT 61차 P0-2: 명령이 대상(경로·장치)을 하나 지정하면 출력의 대상 줄도 하나여야 한다 — 여럿이면 다른 대상이 섞인 것
            args = [t for t in str(cmd).split()[1:] if not t.startswith("-")]
            return {**m, "single": bool(args), "part": part and not full}
    return None


def _read_column(spec: dict, out: str):
    """머리글 칸 하나를 찾아 그 칸의 값들을 읽는다 → ([(값, 줄)], 오류 글)."""
    lines = [l for l in out.splitlines() if l.strip()]
    heads = [(i, l.split()) for i, l in enumerate(lines)
             if any(t.lower() in {h.lower() for h in spec["header"]} for t in l.split())]
    if not heads:
        return None, f"머리글 칸({'/'.join(spec['header'])})이 출력에 없음 — 다른 명령·다른 판의 출력일 수 있음"
    if len(heads) > 1:
        return None, "머리글이 두 번 나옴(표가 둘) — 어느 표를 읽을지 기계로 가리지 않음"
    hi, ht = heads[0]
    col = next(j for j, t in enumerate(ht) if t.lower() in {h.lower() for h in spec["header"]})
    vals, buf = [], []
    for l in lines[hi + 1:]:
        buf += l.split()
        if len(buf) <= col:          # df 가 긴 장치 이름 뒤에서 줄을 접은 경우 — 다음 줄과 이어 읽는다
            continue
        v = buf[col]
        if not v.endswith(spec["unit"]):
            return None, f"'{v}' 는 {spec['unit']} 값이 아님(줄: {l.strip()[:60]}) — 칸이 어긋났을 수 있음"
        try:
            num = float(v[:-len(spec["unit"])] or "x")
        except ValueError:
            return None, f"'{v}' 를 숫자로 읽지 못함"
        if not 0 <= num <= 100:
            return None, f"'{v}' 는 0~100% 범위 밖 — 사용률 칸이 아닐 수 있음"
        vals.append((num, " ".join(buf)[:120]))
        buf = []
    if not vals:
        return None, "머리글 아래에 값 줄이 없음"
    if spec.get("single") and len(vals) > 1:
        return None, f"명령은 대상 하나를 보는데 출력에 대상 줄이 {len(vals)}개 — 다른 파일시스템이 섞였을 수 있음(그 경로로 다시 돌린 출력을 붙이십시오)"
    return vals, ""


def interpret(criterion: str, output: str, spec: dict | None = None) -> dict:
    """붙여 넣은 출력을 판단 기준으로 읽는 **보조** 해석(GPT 56차 반영).
    · 기계로 읽는 것은 'N% 이상' 수치 기준 하나뿐 — 측정값(그 값이 나온 줄)과 기준값을 나눠 보여 준다.
    · '있으면·나오면' 같은 존재 기준은 결과 줄 유무로 판정하지 않는다(머리글·빈 값·오류도 줄이다) → 사람 판단.
    · 명령 실패 출력·% 값이 없는 출력·종료 코드를 알 수 없는 혼합 출력은 판정 불가."""
    crit = (criterion or "").strip()
    out = (output or "").strip()
    if not out:
        return {"verdict": "판정 불가", "why": "결과가 비어 있음"}
    m0 = _CMD_ERR.search(out)
    if m0:   # 명령 자체가 실패한 출력 — 숫자로 읽으면 엉뚱한 '충족'이 나온다
        return {"verdict": "판정 불가", "why": f"명령이 실패한 출력으로 보임({m0.group(0)[:40]}) — 권한·경로·판을 확인"}
    m = re.search(r"(\d+(?:\.\d+)?)\s*%\s*이상", crit)
    if m and spec:   # 7차 아이디어 3: 지표가 고정된 짝만 기계 판정 — 머리글 칸으로만 읽는다
        th = float(m.group(1))
        vals, err = _read_column(spec, out)
        if err:
            return {"verdict": "판정 불가", "why": err, "metric": spec["id"]}
        hit = [v for v in vals if v[0] >= th]
        if spec.get("agg") == "all":
            hit = vals if len(hit) == len(vals) else []
        if spec.get("part"):   # 8차 ⑨: 기준에 다른 조건이 섞인 판정 — 수치 부분만 말하고 나머지는 사람 판단으로 남긴다
            rest = re.sub(r"(사용률\s*)?\d+(?:\.\d+)?\s*%\s*이상(이거나|·|,|이고|또는)?", "", crit).strip(" ·,")
            base = {"metric": spec["id"], "threshold": th, "part": True, "measured": max(v[0] for v in (hit or vals)),
                    "note": f"판단 기준의 나머지 조건({rest[:80] or '수치 밖 조건'})은 사람이 확인 — 출력의 출처·실행 성공은 확인하지 않음, 장애 원인 확정 아님"}
            if hit:
                return {**base, "verdict": "수치 조건 충족",
                        "why": f"수치 부분만 비교: {spec['title']}({'/'.join(spec['header'])} 칸) {len(hit)}줄이 {th:g}% 이상 — 예: {hit[0][1]}"}
            return {**base, "verdict": "수치 조건 미충족",
                    "why": f"수치 부분만 비교: {spec['title']}({'/'.join(spec['header'])} 칸) {len(vals)}줄 모두 {th:g}% 아래 — 다른 조건이면 여전히 해당할 수 있음"}
        if hit:
            return {"verdict": "조건 충족", "metric": spec["id"], "measured": max(v[0] for v in hit), "threshold": th,
                    "why": f"제공된 출력의 조건 비교({'어느 한 줄이라도' if spec.get('agg') == 'any' else '모든 줄이'}): {spec['title']}({'/'.join(spec['header'])} 칸) {len(hit)}줄이 {th:g}% 이상 — 예: {hit[0][1]}"
                           " · 출력의 출처·실행 성공은 확인하지 않음, 장애 원인 확정 아님"}
        return {"verdict": "조건 미충족", "metric": spec["id"], "measured": max(v[0] for v in vals), "threshold": th,
                "why": f"제공된 출력의 조건 비교: {spec['title']}({'/'.join(spec['header'])} 칸) {len(vals)}줄 모두 {th:g}% 아래"
                       f"(최대 {max(v[0] for v in vals):g}%) · 출력의 출처·실행 성공은 확인하지 않음"}
    if m:
        th = float(m.group(1))
        vals = []
        for line in out.splitlines():
            found = [v for v in re.findall(r"(?<![\d.])(\d{1,3}(?:\.\d+)?)\s*%", line) if float(v) <= 100]
            if len(found) > 1:   # GPT 58차: 한 줄에 % 지표가 여럿(sar·iostat 등)이면 어느 것이 기준 지표인지 모른다
                return {"verdict": "판정 불가", "why": f"한 줄에 % 값이 {len(found)}개 — 어느 지표가 기준인지 기계로 가리지 않음(줄: {line.strip()[:80]})"}
            if found:
                vals.append((float(found[0]), line.strip()[:120]))
        if not vals:
            return {"verdict": "판정 불가", "why": "출력에서 % 값을 찾지 못함(형식·단위가 다를 수 있음)"}
        mx, src = max(vals, key=lambda x: x[0])
        # GPT 59차: 한 줄에 % 하나여도 그것이 기준 지표인지 기계는 모른다 — 충족·미충족을 정하지 않고 참고 수치만 보인다
        return {"verdict": "사람 판단",
                "why": (f"참고 수치: 측정값 {mx:g}% (줄: {src}) · 기준 {th:g}% 이상 · % 값 {len(vals)}개 중 최대"
                        f"{' — 기준 이상으로 보임' if mx >= th else ' — 기준 아래로 보임'}. 이 값이 기준 지표가 맞는지는 사람이 확인"),
                "measured": mx, "threshold": th, "above": mx >= th}
    n = sum(1 for l in out.splitlines() if l.strip())
    return {"verdict": "사람 판단", "why": f"판단 기준을 기계로 읽지 않음(결과 {n}줄) — 기준 문구대로 사람이 판단"}


# ── 검증 축(①) ──
def load_verification(codes_dir: Path | None) -> dict:
    """errorcodes/_verification.yaml(교차·문법·실행 결과)과 _evidence.yaml(근거 발췌)을 읽는다. 없으면 빈 값."""
    from .yamlsafe import load as yload
    out = {"gpt": set(), "gpt_reverified": set(), "syntax_fail": set(), "syntax_pass": set(), "exec_pass": set(), "exec_fail": set(),
           "exec_unavailable": {}, "evidence": {}}
    if not codes_dir:
        return out
    try:
        v = yload((Path(codes_dir) / "_verification.yaml").read_text(encoding="utf-8")) or {}
        for k in ("gpt", "gpt_reverified", "syntax_fail", "syntax_pass", "exec_pass", "exec_fail"):
            out[k] = {str(x).upper() for x in (v.get(k) or [])}
        out["exec_unavailable"] = {str(p).lower(): str(r) for p, r in (v.get("exec_unavailable") or {}).items()}
        # 8차 ⑥: 현장 읽기 전용 실행 결과(tools/build/import_field_exec.py) — 판정 키마다 성공·오류 수
        out["field_exec"] = {str(k).upper(): x for k, x in (v.get("field_exec") or {}).items() if isinstance(x, dict)}
    except (OSError, ValueError, AttributeError):
        pass
    try:
        e = yload((Path(codes_dir) / "_evidence.yaml").read_text(encoding="utf-8")) or {}
        for x in e.get("evidence") or []:
            if isinstance(x, dict) and x.get("claim"):
                out["evidence"].setdefault(str(x["claim"]).upper(), []).append(x)
    except (OSError, ValueError, AttributeError):
        pass
    out["evidence_local"] = {}   # 8차 ⑤ 반입 원문 대조(사람이 그 쪽을 열어 확인) — 주장마다 마지막 판정
    try:
        e = yload((Path(codes_dir) / "_evidence_local.yaml").read_text(encoding="utf-8")) or {}
        for x in e.get("evidence") or []:
            if isinstance(x, dict) and x.get("claim") and x.get("verdict") in ("맞음", "틀림"):
                out["evidence_local"][str(x["claim"]).upper()] = x
    except (OSError, ValueError, AttributeError):
        pass
    return out


def axes(key: str, *, ref: str = "", source: str = "", verify_note: str = "", ver: dict | None = None, field: dict | None = None,
         product: str = "") -> dict:
    """key = '제품:ID'(대문자). 각 축은 독립 — 화면은 축마다 따로 보여 준다."""
    ver = ver or {}
    k = key.upper()
    ident = k.split(":", 1)[-1]
    loc = (ver.get("evidence_local") or {}).get(k)
    src = ("반입 원문과 다름 — 고칠 대상" if loc and loc.get("verdict") == "틀림" else
           "공식 근거 보관" if k in ver.get("evidence", {}) else
           "반입 원문 대조" if loc else
           ("제조사 문서 대조" if ref or "대조" in (source or "") or "공식 문서" in (source or "") else "분석기 지식"))
    f = field or {}
    fx = (ver.get("field_exec") or {}).get(k)
    pg = "실패" if k in ver.get("exec_fail", set()) else ("통과" if k in ver.get("exec_pass", set()) else "")
    if not pg and fx and (int(fx.get("ok", 0)) or int(fx.get("error", 0))):   # 시험 PG 결과가 없을 때만 현장 근거로 채운다
        # GPT 64차: 사람이 남긴 보고다 — '현장 실행 검증'이 아니라 '현장 보고'로 부른다(진단 정확성과도 다름)
        ex = f"현장 보고 성공 {int(fx.get('ok', 0))}" + (f" · 오류 {int(fx.get('error', 0))}" if int(fx.get("error", 0)) else "")
    else:
        ex = pg or ("시험 환경 없음" if (product or (k.split(":", 1)[0] if ":" in k else "")).lower() in ver.get("exec_unavailable", {}) else "미실행")
    return {
        "source": src,
        "unverified": bool(verify_note),
        # 7차 아이디어 2: 표본에서 고친 뒤 다시 교차 검증을 통과한 것은 한 단계 위로 따로 표시
        "cross": ("수정 후 재확인" if (k in ver.get("gpt_reverified", set()) or ident in ver.get("gpt_reverified", set()))
                  else "GPT 표본 실검증" if (k in ver.get("gpt", set()) or ident in ver.get("gpt", set())) else ""),
        "syntax": "실패" if k in ver.get("syntax_fail", set()) else ("통과" if k in ver.get("syntax_pass", set()) else "미실행"),
        # 7차 아이디어 4: 시험 환경이 없는 제품은 '미실행'과 구분 — 언제든 돌릴 수 있는데 안 한 것이 아니다 · 8차 ⑥ 현장 실행 결과
        "exec": ex,
        "field_ok": int(f.get("ok", 0)), "field_fail": int(f.get("fail", 0)), "field_version": int(f.get("version", 0)),
    }


# ── 지식 지문(⑩) ──
KNOW_DIRS = ("rules", "errorcodes", "manuals")
_HCACHE: dict = {}


def file_hashes(base: Path) -> dict:
    out = {}
    for sub in KNOW_DIRS:
        d = Path(base) / sub
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*")):
            if not f.is_file() or "__pycache__" in f.parts or f.suffix.lower() not in (".yaml", ".yml", ".json", ".txt", ".md"):
                continue
            st = f.stat()
            key = (str(f), st.st_mtime_ns, st.st_size)
            h = _HCACHE.get(key)
            if h is None:
                h = _HCACHE[key] = hashlib.sha256(f.read_bytes()).hexdigest()
            out[f.relative_to(base).as_posix()] = h
    return out


def fingerprint(hashes: dict) -> str:
    return hashlib.sha256(json.dumps(sorted(hashes.items())).encode("utf-8")).hexdigest()[:16]


def compare_manifest(base: Path) -> dict | None:
    """설치 매니페스트(knowledge-manifest.json 의 files)와 지금 파일을 대조 — 매니페스트가 없으면 None."""
    p = Path(base) / "knowledge-manifest.json"
    try:
        mf = json.loads(p.read_text(encoding="utf-8")).get("files") or {}
    except (OSError, ValueError, AttributeError):
        return None
    if not mf:
        return None
    now = file_hashes(base)
    scope = {k for k in mf if k.split("/", 1)[0] in KNOW_DIRS}
    return {"added": sorted(set(now) - scope), "deleted": sorted(scope - set(now)),
            "changed": sorted(k for k in scope & set(now) if mf[k] != now[k]), "fingerprint": fingerprint(now)}


def write_manifest(base: Path, extra: dict | None = None) -> None:
    """룰팩 적용 등 정당한 지식 변경 뒤 매니페스트를 새로 쓴다(그렇지 않으면 '바뀐 지식' 거짓 경보)."""
    p = Path(base) / "knowledge-manifest.json"
    try:
        old = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        old = {}
    old.update(extra or {})
    old["files"] = {**{k: v for k, v in (old.get("files") or {}).items() if k.split("/", 1)[0] not in KNOW_DIRS}, **file_hashes(base)}
    p.write_text(json.dumps(old, ensure_ascii=False, indent=1), encoding="utf-8")
