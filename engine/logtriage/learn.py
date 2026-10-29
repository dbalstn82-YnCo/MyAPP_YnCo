"""룰 학습(2026-10-13, 마스터 결정 '로컬 학습 + 화면 검토').

분석할 때 **룰에도 벤더 코드 사전에도 걸리지 않은** 오류·경고 메시지를 모아, 값(숫자·주소·경로·따옴표 안 문자열 등)을
자리표로 바꾼 '문구 틀'로 묶는다. 틀마다 룰 초안을 만들고 기계 검증을 거쳐 **담당자가 화면에서 승인한 것만**
rules-learned/ 에 넣는다(즉시 반영). 인터넷망에서는 기존 룰 + 승인한 학습 룰을 서명 룰팩(.rpk)으로 묶어 폐쇄망에 반입한다.

지키는 것
- 외부로 아무것도 보내지 않는다. 모은 예문은 개인정보 마스킹(mask_pii) 뒤 값까지 자리표로 바꾼 것만 남긴다.
- 자동으로 판정에 넣지 않는다 — 승인 전 후보는 분석 결과에 영향이 없다.
- 승인한 룰은 rules/ 가 아니라 rules-learned/ — 룰팩을 적용해도 지워지지 않는다(룰팩에는 rules/learned/ 로 들어간다).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path

import yaml

LEARN_DIR = ("data", "learn")
STORE = "candidates.json"
LEARNED_DIR = "rules-learned"
LEARNED_FILE = "learned.yaml"
MAX_ITEMS = 2000            # 보관 상한(오래 안 보인 것부터 정리 — 승인·무시한 것은 남긴다)
MAX_TEMPLATES_PER_RUN = 300
MAX_LEARNED = 300           # 승인 학습 룰 상한 — 학습 룰 100개에 이벤트 5만 줄이면 분석이 약 1.8초 늘었다(실증 ⑪, 500개면 11.6초)
MAX_EVENTS_PER_RUN = 50_000
_LOCK = threading.Lock()

# ── 문구 틀 만들기 ───────────────────────────────────────────
_SUBS = [
    (re.compile(r"(?i)\b([\w-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|credential|cookie|session(?:id)?|sig(?:nature)?))(\s*(?:[=:]|%3[Dd]|%3[Aa]|\\x3[dD]|\\u003[dD])\s*)(?:\"[^\"]*\"|'[^']*'|[^\s;,&]+)"), r"\1\2<SECRET>"),
    (re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}"), "<SECRET>"),
    (re.compile(r"(?i)\b(Set-Cookie:\s*)[^=\s;]+=[^;\s]+"), r"\1<SECRET>"),
    (re.compile(r"\S*(?:%[0-9A-Fa-f]{2}\S*){3,}"), "<URL>"),
    (re.compile(r"(?<!\S)(-{1,2}(?:P|p|password|pass|pwd|token|secret))\s+\S+"), r"\1 <SECRET>"),
    (re.compile(r"(?i)\b(Bearer|Basic|Negotiate)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 <SECRET>"),
    (re.compile(r"(?i)\bjdbc:[a-z0-9]+:\S+"), "<URL>"),
    (re.compile(r"\b(CN|OU|DC|UID|O|L|ST)=[^,()=]+(?=,|\)|$)"), r"\1=<NAME>"),
    (re.compile(r"\\\\[^\s\\]+\\\S*"), "<PATH>"),
    (re.compile(r"\b[A-Z][A-Z0-9-]{1,15}\\[\w.$-]+"), "<NAME>"),
    (re.compile(r"(?<!\S)(-{1,2}(?:S|U|H|h|u|server|user|host|username|login|database|db))\s+(?!-)\S+"), r"\1 <NAME>"),
    (re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://\S+"), "<URL>"),
    (re.compile(r"\b\d{4}[-/.]\d{1,2}[-/.]\d{1,2}([ T])\d{1,2}:\d{2}(?::\d{2})?(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), r"<TIME>\1<TIME>"),
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TIME>"),
    (re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), "<EMAIL>"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "<ID>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<IP>"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){3,7}[0-9a-fA-F]{1,4}\b"), "<IP>"),
    (re.compile(r"\b0x[0-9a-fA-F]+\b"), "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{12,}\b"), "<HEX>"),
    (re.compile(r"(?:[A-Za-z]:)?[\\/](?:[\w.$~-]+[\\/])+[\w.$~-]*"), "<PATH>"),
    (re.compile(r"'[^'\n]{1,200}'"), "'<STR>'"),
    (re.compile(r'"[^"\n]{1,200}"'), '"<STR>"'),
    (re.compile(r"(?<![A-Za-z])-?\d+(?:[.,]\d+)*(?![A-Za-z])"), "<N>"),
]
_PH = {"<TIME>": r"\S+(?: \S+)?", "<EMAIL>": r"\S+", "<ID>": r"[0-9a-fA-F-]+", "<IP>": r"[0-9a-fA-F:.]+",
       "<HEX>": r"(?:0x)?[0-9a-fA-F]+", "<PATH>": r"\S+", "<STR>": r"[^'\"]{0,200}", "<NAME>": r"[^\s,;()\[\]'\"<>]+", "<TOK>": r"[0-9A-Za-z_]+", "<SECRET>": r"\S+", "<URL>": r"\S+", "<N>": r"-?\d+(?:[.,]\d+)?(?:[.,]\d+)?(?:[.,]\d+)?(?:[.,]\d+)?"}   # 반복 안의 반복을 만들지 않는다(nested_repeat)
_PH_RE = re.compile("|".join(re.escape(k) for k in _PH))
# 오류 코드 모양(ORA-00060·TBR-12345·BEA-000337·WFLYCTL0013·IJ000453)은 숫자 자리표로 바꾸지 않는다 — 코드가 다르면 다른 오류다
_GLUED = re.compile(r"(?:[0-9A-Za-z_]*<(?:N|HEX|ID)>)+[0-9A-Za-z_]*")
_GLUE_IN = re.compile(r"<(?:N|HEX|ID)>(?:[0-9a-fA-F_]|<)|[0-9A-Za-z_]<(?:N|HEX|ID)>")
_CODE_TOK = re.compile(r"\b(?:[A-Z][A-Z0-9]{1,11}-\d{2,7}|[A-Z]{2,8}\d{3,7})\b")
# 계정·호스트·스키마 이름은 따옴표 없이도 값 — 승인하면 정규식에 들어가 룰팩으로 반출되므로 글자 그대로 두지 않는다
_KV_ID = re.compile(r"(?i)\b([A-Za-z][\w.-]{0,40}?)(\s*=\s*)(\"[^\"]*\"|'[^']*'|[^\s,;()\[\]<>]+)")
_ID_KEY = re.compile(r"(?i)(?:^|[_.-])(?:pg)?(user(?:name|id)?|uid|login|account|owner|host(?:name)?|server|database|db(?:name)?|schema|catalog|"
                     r"service(?:_?name)?|sid|instance|principal|realm|namespace|pod|node|cluster|tenant|bucket|queue|topic|domain|spn|keytab|"
                     r"client(?:_?id)?|data\s?source|initial\s?catalog)$")


def _kv_id(m) -> str:
    key = m.group(1)
    k = key.lower()
    if _ID_KEY.search(k) or _ID_KEY.search("_" + k):
        return f"{key}{m.group(2)}<NAME>"
    return m.group(0)


_NAMED = re.compile(r"(?i)(\b(?:for|to|by|of|from|on|with|at)\s+)?\b(user(?:name)?|login|account|host(?:name)?|server|owner|client|schema|table|database|db|relation|view|index|sequence|column|constraint|trigger|procedure|function|package|queue|topic|bucket|namespace|pod|principal)(\s*[=:]\s*|\s+)(?!<)([^\s,;()\[\]'\"<>]{2,64})")


def _named(m) -> str:
    """'user=kim'·'for user kim'·'host web-02'·'table EMP_SAL' 처럼 값으로 보일 때만 <NAME> — 'Login failed' 의 failed 는 그대로."""
    pre, kw, sep, val = m.group(1) or "", m.group(2), m.group(3), m.group(4)
    if kw.lower() in ("relation", "view", "index", "sequence", "column", "constraint", "trigger", "procedure", "function", "package",
                      "queue", "topic", "bucket", "namespace", "pod", "principal") and not val.islower():
        return f"{pre}{kw}{sep}<NAME>"
    if sep.strip() or pre or re.search(r"[\d_.@-]", val) or (val.isupper() and len(val) > 2):
        return f"{pre}{kw}{sep}<NAME>"
    return m.group(0)


def template(message: str) -> str:
    """메시지 첫 줄 → 문구 틀(개인정보·값 제거). 같은 종류의 오류는 같은 틀이 된다."""
    from .parsers import mask_pii
    line = (message or "").splitlines()[0] if message else ""
    line = mask_pii(line)[:400]
    keep: list[str] = []

    def _hold(m):                       # 자리 표시는 숫자·글자가 아닌 사용자 정의 문자(U+E000~) — 뒤의 치환이 건드리지 못한다
        keep.append(m.group(0))
        return chr(0xE000 + len(keep) - 1)
    line = _CODE_TOK.sub(_hold, line)
    line = _KV_ID.sub(_kv_id, line)
    line = _NAMED.sub(_named, line)
    for rx, ph in _SUBS:
        line = rx.sub(ph, line)
    line = re.sub("[\uE000-\uF8FF]", lambda m: keep[ord(m.group(0)) - 0xE000] if ord(m.group(0)) - 0xE000 < len(keep) else "", line)
    # 값 자리표가 숫자·16진 글자·다른 자리표에 바로 붙으면(예: <N>8bf0a1b) 토큰 통째로 하나의 값 — 경계가 없으면 정규식이 어디서 끊을지 여러 갈래가 된다
    line = _GLUED.sub(lambda m: "<TOK>" if _GLUE_IN.search(m.group(0)) else m.group(0), line)
    # 자리표 둘 이상이 맞붙으면(예: HKLM\SOFTWARE… → <NAME><PATH>) 경계가 없으니 하나의 값으로
    line = re.sub(r"<[A-Z]+>(?:<[A-Z]+>)+", "<PATH>", line)
    # SQL 본문(예: CUBRID 이벤트 로그 'sql: update [acct] set [acct].[pw]= …')은 테이블·칼럼 이름이 남는다 — 내부 스키마라 반출하면 안 되고
    # 질의마다 달라 판정 신호도 아니다 → 'sql:' 뒤는 통째로 하나의 값(룰 학습 5차, GPT 15차 민감정보 확인)
    line = re.sub(r"(\bsql:\s*)\S.*$", r"\1<STR>", line, flags=re.I)
    line = re.sub(r"\s+", " ", line).strip()
    return line[:240]


_FILL = {"<TIME>": "00:00:00", "<EMAIL>": "user@example.com", "<ID>": "00000000-0000-0000-0000-000000000000",
         "<IP>": "10.0.0.1", "<HEX>": "0x1f", "<PATH>": "/var/x/y.log", "<STR>": "x", "<N>": "1", "<NAME>": "name1", "<TOK>": "tok1", "<SECRET>": "secret1", "<URL>": "url1"}


def example_of(tpl: str) -> str:
    """문구 틀의 자리표를 가짜 값으로 채운 검증용 예문 — 실제 값은 남기지 않는다."""
    return _PH_RE.sub(lambda m: _FILL[m.group(0)], tpl)


def key_of(product: str, layer: str, tpl: str) -> str:
    return hashlib.sha1(f"{product}|{layer}|{tpl}".encode("utf-8")).hexdigest()[:12]


def collect(events, skip_ids: set) -> list[dict]:
    """분석 한 건에서 룰·코드 어디에도 안 걸린 오류·경고 이벤트를 문구 틀로 묶는다(service 가 부른다)."""
    agg: dict[str, dict] = {}
    seen_msg: dict[str, str] = {}
    n = 0
    for e in events:
        if id(e) in skip_ids or e.severity not in ("critical", "error", "warn"):
            continue
        n += 1
        if n > MAX_EVENTS_PER_RUN:
            break
        first = (e.message or "").splitlines()[0][:400] if e.message else ""
        if not first.strip():
            continue
        tpl = seen_msg.get(first)
        if tpl is None:
            tpl = template(first)
            seen_msg[first] = tpl
        if len(re.sub(r"<[A-Z]+>|[^A-Za-z가-힣]", "", tpl)) < 6:   # 글자가 거의 없는 틀은 룰 근거가 못 된다
            continue
        k = key_of(e.product, e.layer, tpl)
        a = agg.get(k)
        if a is None:
            if len(agg) >= MAX_TEMPLATES_PER_RUN:
                continue
            a = agg[k] = {"key": k, "product": e.product, "layer": e.layer, "severity": e.severity,
                          "template": tpl, "example": example_of(tpl), "count": 0, "code": e.code or ""}
        a["count"] += 1
        if _SEV_RANK[e.severity] > _SEV_RANK[a["severity"]]:
            a["severity"] = e.severity
    return sorted(agg.values(), key=lambda x: -x["count"])


_SEV_RANK = {"info": 0, "warn": 1, "error": 2, "critical": 3}


# ── 후보 보관 ────────────────────────────────────────────────
class LearnStore:
    def __init__(self, base: Path):
        self.base = Path(base)
        self.dir = self.base.joinpath(*LEARN_DIR)
        self.path = self.dir / STORE

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"items": {}}
        except Exception:                       # 망가진 파일은 지우지 않고 옆에 보관한 뒤 새로 시작(조용히 덮어쓰지 않는다)
            try:
                self.path.replace(self.path.with_name(f"{STORE}.broken-{datetime.now():%Y%m%d-%H%M%S}"))
            except OSError:
                pass
            return {"items": {}}

    def _save(self, doc: dict):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.new")
        tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=0), encoding="utf-8")
        os.replace(tmp, self.path)

    def record(self, items: list[dict], analysis_id: str = "") -> int:
        if not items:
            return 0
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with _LOCK:
            doc = self._load()
            its = doc.setdefault("items", {})
            for x in items:
                cur = its.get(x["key"])
                if cur is None:
                    cur = its[x["key"]] = dict(x, first_seen=now, last_seen=now, analyses=[], status="new", hits=0)
                    cur["count"] = 0
                cur["count"] += x["count"]
                cur["hits"] += 1
                cur["last_seen"] = now
                if _SEV_RANK.get(x["severity"], 0) > _SEV_RANK.get(cur["severity"], 0):
                    cur["severity"] = x["severity"]
                if analysis_id and analysis_id not in cur["analyses"]:
                    cur["analyses"] = (cur["analyses"] + [analysis_id])[-10:]
            if len(its) > MAX_ITEMS:
                live = sorted((k for k, v in its.items() if v.get("status") == "new"), key=lambda k: its[k]["last_seen"])
                for k in live[:len(its) - MAX_ITEMS]:
                    its.pop(k, None)
            self._save(doc)
        return len(items)

    def items(self, status: str = "", product: str = "") -> list[dict]:
        its = list(self._load().get("items", {}).values())
        if status:
            its = [x for x in its if x.get("status") == status]
        if product:
            its = [x for x in its if x.get("product") == product]
        return sorted(its, key=lambda x: (-_SEV_RANK.get(x["severity"], 0), -x["count"]))

    def get(self, key: str) -> dict | None:
        return self._load().get("items", {}).get(key)

    def set_status(self, key: str, status: str, **extra) -> dict | None:
        with _LOCK:
            doc = self._load()
            cur = doc.get("items", {}).get(key)
            if not cur:
                return None
            cur["status"] = status
            cur["status_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.update(extra)
            self._save(doc)
            return cur


# ── 룰 초안·검증 ─────────────────────────────────────────────
_CAT_HINTS = [
    ("security", r"auth|login|denied|permission|forbidden|unauthori|password|certificate|ssl|tls|인증|권한"),
    ("memory", r"memory|heap|outofmemory|\boom\b|metaspace|swap|메모리"),
    ("disk", r"no space|disk|file ?system full|quota|디스크"),
    ("storage", r"tablespace|datafile|segment|archive|redo|extent|file not found|cannot open file"),
    ("lock", r"deadlock|lock wait|lock timeout|\block\b|잠금"),
    ("thread", r"thread|worker|executor|pool exhausted|stuck|hung|스레드"),
    ("connection", r"connect|refused|reset by peer|broken pipe|socket|listener|network|unreachable|연결"),
    ("upstream", r"upstream|backend|proxy|gateway|remote server|연계"),
    ("capacity", r"limit|exceed|too many|maximum|max\w*|full|queue|overflow|초과|한도"),
    ("performance", r"slow|timeout|timed out|latency|took \d|elapsed|지연|시간 초과"),
    ("hardware", r"hardware|i/o error|device|sector|controller|fan|power|temperature|ecc"),
]


def guess_category(tpl: str) -> str:
    t = tpl.lower()
    for cat, rx in _CAT_HINTS:
        if re.search(rx, t):
            return cat
    return "internal"


def _cls_esc(ch: str) -> str:
    return "\\" + ch if ch in "\\]^-[" else ch


def _ph_pat(ph: str, nxt: str) -> str:
    """자리표 → 값 패턴. 바로 뒤에 오는 글자(nxt)는 값 패턴에서 빼서, 반복이 어디서 멈출지 하나로 정해지게 한다(unsafe_regex 결정성)."""
    ex = _cls_esc(nxt) if nxt and not nxt.isspace() else ""
    if ph in ("<PATH>", "<EMAIL>", "<SECRET>", "<URL>"):
        return rf"[^\s{ex}]+"
    if ph == "<NAME>":
        return rf"[^\s,;()\[\]'" + '"' + rf"<>{ex}]+"
    if ph == "<TIME>":
        return rf"[^\s{ex}]+"
    if ph == "<IP>":
        return "[" + "".join(x for x in ("0-9", "a-f", "A-F", ":", ".") if x != nxt) + "]+"
    if ph == "<ID>":
        return "[0-9a-fA-F-]+" if nxt != "-" else "[0-9a-fA-F]+"
    if ph == "<HEX>":
        return "[0-9a-fA-Fx]+"
    if ph == "<N>":
        return r"-?\d+" if (nxt in ".," or nxt.isdigit()) else r"-?\d[\d.,]*"
    if ph == "<TOK>":
        return r"[0-9A-Za-z_]+"
    if ph == "<STR>":
        return rf"[^'" + '"' + rf"{ex}]{{0,200}}"
    return _PH[ph]


def regex_of(tpl: str) -> str:
    r"""문구 틀 → 정규식. 글자는 그대로(escape), 자리표는 값 패턴(뒤 글자를 뺀), 공백은 \s+.
    앞쪽의 값 자리표(줄머리 시각·스레드 번호 등)는 뺀다 — 고정 글자부터 시작해야 앵커 사전 필터가 듣는다."""
    t = tpl.strip()
    # 첫 '진짜 낱말'(글자 3자 이상)부터 — 줄머리의 기호·시각·스레드 번호를 빼야 고정 글자로 시작한다(unsafe_regex 의 시작 조건)
    for m in re.finditer(r"<[A-Z]+>|[A-Za-z가-힣][A-Za-z가-힣0-9_]{2,}", t):
        if not m.group(0).startswith("<"):
            t = t[m.start():]
            break
    out, pos = [], 0
    for m in _PH_RE.finditer(t):
        out.append(re.escape(t[pos:m.start()]))
        out.append(_ph_pat(m.group(0), t[m.end()] if m.end() < len(t) else ""))
        pos = m.end()
    out.append(re.escape(t[pos:]))
    rx = re.sub(r"(?:\\ )+", r"\\s+", "".join(out))
    return rx[:600]


def suggest(item: dict) -> dict:
    tpl = item["template"]
    prod = item["product"]
    words = re.sub(r"<[A-Z]+>|'<STR>'|\"<STR>\"", "…", tpl)
    return {
        "id": f"LRN-{re.sub(r'[^A-Z0-9]', '', prod.upper())[:10]}-{item['key'][:10].upper()}",
        "layer": item["layer"], "product": prod,
        "regex": regex_of(tpl), "exclude": "",
        "severity": item["severity"] if item["severity"] in ("critical", "error", "warn") else "warn",
        "category": guess_category(tpl),
        "verdict": f"{prod} 학습 룰: {words[:100]}",
        "immediate": ["같은 시각 앞뒤 로그에서 첫 오류(원인)를 확인"],
        "short": ["반복 여부·영향 범위 확인 후 담당 엔지니어에게 전달"],
        "key": item["key"],
    }


# ── 글자 집합(유니코드 전 범위 구간) — 결정성 검사의 겹침을 표본이 아니라 정확히 판정한다(GPT 5차 반례: \w 와 구자라트 문자 범위) ──
_MAXCP = 0x10FFFF
_IV_CACHE: dict = {}


def _iv_norm(ivs):
    out = []
    for lo, hi in sorted(ivs):
        if out and lo <= out[-1][1] + 1:
            if hi > out[-1][1]:
                out[-1] = (out[-1][0], hi)
        else:
            out.append((lo, hi))
    return out


def _iv_not(ivs):
    out, cur = [], 0
    for lo, hi in _iv_norm(ivs):
        if lo > cur:
            out.append((cur, lo - 1))
        cur = max(cur, hi + 1)
    if cur <= _MAXCP:
        out.append((cur, _MAXCP))
    return out


def _iv_all():
    return [(0, _MAXCP)]


def _iv_meet(a, b) -> bool:
    i = j = 0
    while i < len(a) and j < len(b):
        if a[i][1] < b[j][0]:
            i += 1
        elif b[j][1] < a[i][0]:
            j += 1
        else:
            return True
    return False


def _iv_from(pred):
    out, run = [], None
    for cp in range(_MAXCP + 1):
        if pred(chr(cp)):
            if run is None:
                run = cp
        elif run is not None:
            out.append((run, cp - 1))
            run = None
    if run is not None:
        out.append((run, _MAXCP))
    return out


def _iv_cat(name: str):
    r"""파이썬 re(str 패턴) 의미 그대로: \d = 유니코드 10진 숫자(Nd), \s = str.isspace, \w = str.isalnum 또는 '_'."""
    if name not in _IV_CACHE:
        pred = {"digit": str.isdecimal, "space": str.isspace, "word": lambda c: c.isalnum() or c == "_"}[name]
        _IV_CACHE[name] = _iv_from(pred)
    return _IV_CACHE[name]


def _case_rev():
    """IGNORECASE 에서 서로 같은 글자로 보는 짝 — **파이썬 정규식 엔진(sre)의 규칙 그대로**(GPT 6차: 'İ' 는 str.lower() 로는 두 글자지만
    sre 의 단순 소문자 변환으로는 'i' 라서 re.I 에서 i 와 일치한다).
    · sre: 글자마다 _sre.unicode_tolower 가 같으면 같은 글자, 거기에 re._casefix._EXTRA_CASES(예: i↔ı, s↔ſ, µ↔μ) 특례
    · 덤으로 str.lower/upper/casefold 가 한 글자인 짝도 넣는다(넓게 — 넓을수록 '겹침 → 거부' 쪽이라 안전)"""
    if "rev" not in _IV_CACHE:
        import _sre
        try:
            from re._casefix import _EXTRA_CASES as extra
        except Exception:                       # pragma: no cover
            extra = {}
        groups: dict = {}
        for cp in range(_MAXCP + 1):
            lo = _sre.unicode_tolower(cp)
            if lo != cp:
                groups.setdefault(lo, {lo}).add(cp)
        for lo, others in extra.items():
            g = groups.setdefault(lo, {lo})
            for o in others:
                g |= groups.get(o, {o})
        rev: dict = {}
        for g in groups.values():
            for cp in g:
                rev.setdefault(cp, set()).update(g - {cp})
        for cp in range(_MAXCP + 1):             # str 변환 짝(한 글자)도 양방향
            c = chr(cp)
            for v in (c.lower(), c.upper(), c.casefold()):
                if len(v) == 1 and v != c:
                    rev.setdefault(cp, set()).add(ord(v))
                    rev.setdefault(ord(v), set()).add(cp)
        _IV_CACHE["rev"] = rev
        _IV_CACHE["rev_keys"] = sorted(rev)
    return _IV_CACHE["rev"]


def _iv_case(ivs):
    """구간의 글자 + IGNORECASE 짝. 짝이 있는 글자(대소문자 있는 글자, 수천 개)만 훑으므로 범위가 커도 정확하다
    (전에는 20만 자 넘는 범위를 '모든 글자'로 봤는데, 부정 [^…] 에서 그게 빈 집합이 되어 겹침을 놓쳤다 — GPT 6차)."""
    import bisect
    rev = _case_rev()
    keys = _IV_CACHE["rev_keys"]
    extra = []
    for lo, hi in ivs:
        for i in range(bisect.bisect_left(keys, lo), bisect.bisect_right(keys, hi)):
            for v in rev[keys[i]]:
                extra.append((v, v))
    return _iv_norm(list(ivs) + extra)


def unsafe_regex(pattern: str) -> str:
    """학습 룰이 쓸 수 있는 정규식은 안전한 부분 집합만 — 어기면 이유를 돌려준다(빈 문자열이면 통과).

    파이썬 정규식은 실행 중에 멈출 수 없다. 그래서 끝나지 않을 수 있는 구조를 **돌리기 전에** 막는다(GPT P0-02):
    반복 안의 반복((a+)+), 반복 안의 대안((a|aa)+ — 겹치는 대안), 역참조(\\1), 앞뒤 보기((?=…)·(?<=…)), 600자 초과.
    이 셋을 빼면 백트래킹이 지수로 터지지 않는다(입력 3,000자에서 다항 시간 — 시간 측정이 한 번 더 거른다)."""
    if len(pattern or "") > 600:
        return "정규식이 너무 깁니다(600자 이하)"
    try:
        import re._parser as sp          # 3.11+
    except ImportError:                  # pragma: no cover
        import sre_parse as sp
    try:
        tree = sp.parse(pattern or "")
    except Exception as e:
        return f"정규식 오류: {e}"
    REP = {sp.MAX_REPEAT, sp.MIN_REPEAT} | ({sp.POSSESSIVE_REPEAT} if hasattr(sp, "POSSESSIVE_REPEAT") else set())
    # 깃발은 (?i) 만 — 아래 글자 집합 계산은 '. 은 줄바꿈을 안 먹는다'·'\w 는 유니코드' 를 전제로 한다.
    # (?s) 면 . 이 줄바꿈까지 먹어 (?s)….*\n.*\n… 가 겹침 없이 통과하고 실제로는 다항 폭발(GPT 9차 가설 → 실측, 줄바꿈 1,000자에 수 분)
    FLAG_MSG = "정규식 깃발은 (?i) 만 씁니다 — (?s)·(?m)·(?x)·(?a) 는 글자 판단을 바꿉니다(예: (?s) 면 . 이 줄바꿈까지 먹음)"
    if tree.state.flags & ~(re.IGNORECASE | re.UNICODE):
        return FLAG_MSG

    def shape(items, depth):
        """괄호 겹·반복 횟수·묶음 깃발 — 검사기 자신과 매칭 모두 자원이 한정되게(GPT 9차: 깊은 괄호·극단 반복)."""
        if depth > 8:
            return "괄호가 8겹을 넘습니다 — 학습 룰은 얕게 씁니다"
        for op, av in items:
            subs = ()
            if op in REP:
                lo, hi, sub = av
                if lo > 1000 or (hi is not sp.MAXREPEAT and hi > 1000):
                    return "반복 횟수는 1,000 이하만 씁니다(학습 룰은 줄 앞 1,000자만 봅니다)"
                subs = (sub,)
            elif op is sp.SUBPATTERN:
                if (av[1] | av[2]) & ~re.IGNORECASE:
                    return FLAG_MSG
                subs = (av[-1],)
            elif op is sp.BRANCH:
                subs = av[1]
            for s in subs:
                r = shape(s, depth + 1)
                if r:
                    return r
        return ""
    bad = shape(tree, 0)
    if bad:
        return bad
    why: list[str] = []
    CAT = {sp.CATEGORY_DIGIT: ("digit", False), sp.CATEGORY_NOT_DIGIT: ("digit", True),
           sp.CATEGORY_SPACE: ("space", False), sp.CATEGORY_NOT_SPACE: ("space", True),
           sp.CATEGORY_WORD: ("word", False), sp.CATEGORY_NOT_WORD: ("word", True)}

    def one(op, av):
        """한 글자짜리 항목이면 그 글자 집합(유니코드 전 범위의 구간 목록 — 정확한 집합), 아니면 None.
        룰은 IGNORECASE 로 돌므로 대·소문자 짝(켈빈 기호 K 처럼 소문자가 같은 글자 포함)까지 넣는다."""
        if op is sp.LITERAL:
            return _iv_case([(av, av)])
        if op is sp.NOT_LITERAL:
            return _iv_not(_iv_case([(av, av)]))
        if op is sp.ANY:
            return _iv_not([(10, 10)])
        if op is sp.IN:
            neg = any(o is sp.NEGATE for o, _ in av)
            parts = []
            for o, a in av:
                if o is sp.LITERAL:
                    parts += _iv_case([(a, a)])
                elif o is sp.RANGE:
                    parts += _iv_case([(a[0], a[1])])
                elif o is sp.CATEGORY:
                    nm, inv = CAT.get(a, (None, False))
                    if nm is None:
                        return _iv_all()                  # 모르는 범주 — 모든 글자로 본다(겹친다고 판정 → 거부 쪽)
                    c = _iv_cat(nm)
                    parts += _iv_not(c) if inv else c
                elif o is not sp.NEGATE:
                    return _iv_all()
            u = _iv_norm(parts)
            return _iv_not(u) if neg else u
        return None

    def first(items, i, follow):
        """items[i:] 다음에 올 수 있는 첫 글자 집합들(끝까지 비워질 수 있으면 follow 포함)."""
        out = []
        while i < len(items):
            op, av = items[i]
            f = one(op, av)
            if f is not None:
                return out + [f]
            if op in REP:
                # 뒤 이어짐(rest)을 한 번만 계산해 그대로 돌려준다 — 전에는 선택 항목(lo=0)마다 rest 를 구하고 또 다음 칸으로
                # 넘어가 같은 계산을 되풀이해, a?×24 같은 정규식에서 검사기 자신이 2^24 번 돌았다(실증 ⑪: 첫 로드 130초)
                lo, hi, sub = av
                rest = first(items, i + 1, follow)
                return out + first(list(sub), 0, rest) + (rest if lo == 0 else [])
            elif op is sp.SUBPATTERN:
                rest = first(items, i + 1, follow)
                return out + first(list(av[-1]), 0, rest)
            elif op is sp.BRANCH:
                rest = first(items, i + 1, follow)
                for b in av[1]:
                    out += first(list(b), 0, rest)
                return out
            # AT(^ $ \b) 같은 폭 없는 항목은 건너뛴다
            i += 1
        return out + list(follow)

    def overlap(a, b) -> bool:
        """두 글자 집합 묶음이 한 글자라도 함께 갖는가 — 표본이 아니라 유니코드 전 범위 구간으로 정확히(GPT 5차)."""
        return _iv_meet(_iv_norm([x for iv in a for x in iv]), _iv_norm([x for iv in b for x in iv]))

    def determ(items, follow):
        """갈림길마다 '다음 한 글자'로 어느 길인지 정해져야 한다(LL(1)) — 그렇지 않으면 길 수가 곱으로 늘어 느려진다(GPT 2·3차 반례).
        · 반복(최대>1): 단위는 한 글자 종류, 그 뒤 첫 글자와 겹치지 않을 것(a+a+, .*foo)
        · 선택(?·{0,1}): 넣을 때 첫 글자와 뺄 때 첫 글자가 겹치지 않을 것(a?a?…)
        · 대안(|): 갈래들의 첫 글자가 서로 겹치지 않을 것((a|aa)(a|aa)…)"""
        items = list(items)
        for i, (op, av) in enumerate(items):
            after = first(items, i + 1, follow)
            if op in REP:
                lo, hi, sub = av
                sub = list(sub)
                if hi is sp.MAXREPEAT or hi > 1:
                    unit = one(*sub[0]) if len(sub) == 1 else None
                    if lo == hi:                      # 고정 횟수 {n}: 길이는 정해져 있지만 단위는 한 글자 종류만(회차 사이 갈림길 차단)
                        if unit is None:
                            why.append("반복 단위는 한 글자 종류만 씁니다 — 고정 횟수 반복({n})도 마찬가지입니다(예: (a?){24}, (a|aa){24})")
                            return
                        continue
                    if unit is None:
                        why.append("반복 단위는 한 글자 종류만 씁니다(예: \\d+, [^,]+) — 여러 글자 묶음을 반복하지 않습니다")
                        return
                    if overlap([unit], after):
                        why.append("반복 바로 뒤에 그 반복도 먹을 수 있는 글자가 옵니다(예: a+a+, .*foo, \\w+_) — 끝을 고정 글자로 나누십시오")
                        return
                else:
                    if lo != hi and overlap(first(sub, 0, after), after):
                        why.append("있어도 되고 없어도 되는 부분(?)의 첫 글자가 그 뒤와 겹칩니다(예: a?a?) — 고정 글자로 나누십시오")
                        return
                    determ(sub, after)
            elif op is sp.SUBPATTERN:
                determ(av[-1], after)
            elif op is sp.BRANCH:
                firsts = [first(list(b), 0, after) for b in av[1]]
                for x in range(len(firsts)):
                    for y in range(x + 1, len(firsts)):
                        if overlap(firsts[x], firsts[y]):
                            why.append("대안(|)들의 첫 글자가 겹칩니다(예: (a|aa), (refused|reset)) — 공통 앞부분을 밖으로 빼십시오")
                            return
                for b in av[1]:
                    determ(b, after)

    def walk(items, inside: bool):
        for op, av in items:
            if op in REP:
                lo, hi, sub = av
                many = hi is sp.MAXREPEAT or hi > 1
                if inside and many:
                    why.append("반복 안에 반복이 있습니다(예: (a+)+)")
                walk(sub, inside or many)
            elif op is sp.SUBPATTERN:
                walk(av[-1], inside)
            elif op is sp.BRANCH:
                if inside:
                    why.append("반복 안에 대안(|)이 있습니다(예: (a|aa)+)")
                for b in av[1]:
                    walk(b, inside)
            elif op in (sp.ASSERT, sp.ASSERT_NOT):
                why.append("앞뒤 보기((?=…)·(?!…)·(?<=…))는 쓰지 않습니다")
            elif op in (sp.GROUPREF, getattr(sp, "GROUPREF_EXISTS", None)):
                why.append("역참조(\\1 등)는 쓰지 않습니다")
    walk(tree, False)
    if not why:
        determ(list(tree), [])
    if not why:
        lead = []
        for op, av in list(tree):
            if op is sp.LITERAL:
                lead.append(av)
            else:
                break
        if len(lead) < 3:
            why.append("고정 글자 3자 이상으로 시작해야 합니다(예: 'Batch settlement…') — 값·반복으로 시작하면 줄마다 모든 자리에서 다시 찾아 느려집니다")
    return why[0] if why else ""


# 알려진 반례(GPT 교차검증 2~6차·실증)와 정상 예 — 안전 검사가 파이썬 내부(re._parser·_sre·re._casefix)에 기대므로
# 파이썬 판이 바뀌어 검사가 틀어지면 학습 룰을 아예 읽지 않는다(실패하면 닫힌 쪽 — 사고 공식 실증 ⑫)
_SELF_BAD = (r"ERR(a+)+$x", r"ERR(a|aa)+", r"Critical failure|a+a+a+a+a+Z", r"^" + "a?" * 24 + r"a{24}$",
             r"ERROR (a|aa){24}Z", "ERROR \\w+\u0416Z", "ERROR \\w+[\u0A81-\u0ABC]Z", "ERROR (?i:[i]+\u0130Z)",
             "ERROR \\w+[^\U00040000-\U00071000]Z", r"\S+\s+\S+", r"(?s)ERROR .*\n.*\nZ", r"ERROR a{2147483647}Z")
_SELF_OK = (r"ledger snapshot \d+ rejected", r"connection re(?:fused|set) by peer", r"ERROR \S+ Z", r"ERROR a{24}Z")


def self_test() -> str:
    """빈 문자열이면 정상. 결과는 프로세스 안에 기억한다."""
    if "self" not in _IV_CACHE:
        bad = [r for r in _SELF_BAD if not unsafe_regex(r)] + [r for r in _SELF_OK if unsafe_regex(r)]
        _IV_CACHE["self"] = ("안전 검사 자기 점검 실패(파이썬 판이 바뀌었을 수 있음): " + ", ".join(b[:30] for b in bad[:3])) if bad else ""
    return _IV_CACHE["self"]


def nested_repeat(pattern: str) -> bool:
    r"""반복 안에 또 반복((a+)+, (\w*)*, (x+|y)+ 같은 것)이 있으면 True — 입력에 따라 끝나지 않는 정규식이 된다.
    파이썬 정규식은 실행 중에 멈출 수 없으므로 **돌려 보기 전에** 구조로 거른다."""
    try:
        import re._parser as sp          # 3.11+
    except ImportError:                  # pragma: no cover
        import sre_parse as sp
    try:
        tree = sp.parse(pattern)
    except Exception:
        return False
    REP = {sp.MAX_REPEAT, sp.MIN_REPEAT}
    POSS = getattr(sp, "POSSESSIVE_REPEAT", None)

    def walk(items, inside: bool) -> bool:
        for op, av in items:
            if op in REP or (POSS is not None and op == POSS):
                lo, hi, sub = av
                many = hi is sp.MAXREPEAT or hi > 1
                if inside and many:
                    return True
                if walk(sub, inside or many):
                    return True
            elif op is sp.SUBPATTERN:
                if walk(av[-1], inside):
                    return True
            elif op is sp.BRANCH:
                if any(walk(b, inside) for b in av[1]):
                    return True
            elif op in (sp.ASSERT, sp.ASSERT_NOT):
                if walk(av[1], inside):
                    return True
        return False
    return walk(tree, False)


def _evil_ok(rx: re.Pattern) -> float:
    t0 = time.perf_counter()
    for evil in ("a" * 3000, "[" * 3000, " " * 3000, "0" * 3000, ("x: " * 1000)[:3000]):
        rx.search(evil)
    return (time.perf_counter() - t0) * 1000


def check(spec: dict, base: Path, rules=None, codedb=None, aliases=None) -> dict:
    """승인 전 기계 검증: 정규식·속도·자기 예문 적중·기존 판정과 중복·지나치게 넓은지·ID 충돌."""
    from . import codes as C
    from .rules import load_rules
    errs, warns = [], []
    try:
        rx = re.compile(spec.get("regex") or "", re.IGNORECASE)
        ex = re.compile(spec["exclude"], re.IGNORECASE) if spec.get("exclude") else None
    except re.error as e:
        return {"ok": False, "errors": [f"정규식 오류: {e}"], "warnings": []}
    for part in ("regex", "exclude"):
        why = unsafe_regex(spec.get(part) or "") if (part == "regex" or spec.get(part)) else ""
        if why:
            return {"ok": False, "errors": [("제외 정규식: " if part == "exclude" else "") + why + " — 입력에 따라 끝나지 않을 수 있어 받지 않습니다"],
                    "warnings": []}
    if not spec.get("regex") or len(spec["regex"]) < 8:
        errs.append("정규식이 너무 짧습니다(8자 이상)")
    if not (spec.get("verdict") or "").strip():
        errs.append("판정 제목이 비었습니다")
    if spec.get("severity") not in ("critical", "error", "warn", "info"):
        errs.append("심각도는 critical·error·warn·info 중 하나")
    ms = _evil_ok(rx)
    if ms > 200:
        errs.append(f"정규식이 느립니다({ms:.0f}ms) — 되돌아가기(backtracking)가 큰 패턴")
    if rx.search("") or rx.search("hello world"):
        errs.append("아무 문장에나 걸리는 정규식입니다")
    store = LearnStore(base)
    own = store.get(spec.get("key", "")) if spec.get("key") else None
    examples = [example_of(own["template"])] if own else []
    for s in examples:
        if not (rx.search(s) and not (ex and ex.search(s))):
            errs.append("근거 예문에 걸리지 않습니다")
    # 다른 후보 예문에 얼마나 걸리나(넓이)
    others = [x for x in store.items() if x["key"] != spec.get("key")]
    oex = [(x, example_of(x["template"])) for x in others]
    wide = [x["template"][:80] for x, e in oex if rx.search(e) and not (ex and ex.search(e))]
    same_prod = [x for x, e in oex if x["product"] == spec.get("product") and rx.search(e)]
    if len(wide) > 5:
        errs.append(f"다른 후보 {len(wide)}개 문구에도 걸립니다 — 너무 넓은 룰입니다(고정 글자를 더 넣어 좁히십시오)")
    elif wide:
        warns.append(f"다른 후보 {len(wide)}개 문구에도 걸립니다 — 같은 장애로 묶을 것인지 확인")
    # 기존 판정과 중복
    rules = rules if rules is not None else load_rules(base / "rules", base / "rules-local")
    ids = {r.id for r in rules}
    if spec.get("id") in ids:
        errs.append(f"같은 ID 의 룰이 이미 있습니다: {spec['id']}")
    dup = []
    for s in examples:
        for r in rules:
            if (spec.get("product") in r.products or "*" in r.products) and r.applies_layer(spec.get("layer", r.layer)) \
                    and r.pattern.search(s[:r.scan]) and not (r.exclude and r.exclude.search(s)):
                dup.append(f"룰 {r.id}")
        codedb = codedb if codedb is not None else C.load_codes(base / "errorcodes")
        aliases = aliases if aliases is not None else C.load_aliases(base / "errorcodes")
        code = (own or {}).get("code") or C.alias_code(aliases, spec.get("product", ""), s)
        ent = C.lookup(codedb, spec.get("product", ""), code) if code else None
        if ent:
            dup.append(f"코드 {ent.code}")
    if dup:
        warns.append("이미 판정되는 문구입니다: " + ", ".join(sorted(set(dup))[:5]) + " — 새 룰이 필요한지 확인")
    return {"ok": not errs, "errors": errs, "warnings": warns, "regex_ms": round(ms, 1),
            "also_matches": len(wide), "also_matches_same_product": len(same_prod), "samples": wide[:5]}


# ── 반출 검사: 승인한 룰은 룰팩으로 폐쇄망에 들어간다 — 사람·장비를 가리키는 값이 남으면 안 된다(GPT P0-04) ──
_LEAKS = [
    ("이메일 주소", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("IP 주소", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    ("주민등록번호 모양", re.compile(r"\d{6}\s*-\s*[1-8]\d{6}")),
    ("전화번호 모양", re.compile(r"01[016789]-?\d{3,4}-?\d{4}")),
    ("8자리 이상 숫자", re.compile(r"(?<![\\\w])\d{8,}")),
    ("URL", re.compile(r"(?i)\b(?:https?|ftp|jdbc:\w+)://\S+")),
    ("비밀값 모양", re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|bearer|api[_-]?key)\b\s*[=:]?\s*[^\s\\<>]{4,}")),
]


# 정규식 안에 계정·호스트 이름을 글자 그대로 적은 것(user=hansol) — 틀은 이 값을 자리표로 바꾸므로 사람이 적은 것뿐이다
_ID_LITERAL = re.compile(r"(?i)(?<![A-Za-z0-9_])(?:user(?:name)?|uid|login|account|owner|host(?:name)?|server|principal|client_?id|"
                         r"database|db|schema|sid|service_?name|instance)\s*[=:]['\"]?[A-Za-z0-9._\\-]{3,}")   # 값은 구분자에 붙은 것만(자리표 뒤 낱말 오인 방지)
_VIEWS_CAP = 4096


def _regex_views(pattern: str) -> list[str] | None:
    """정규식이 실제로 맞추는 고정 글자를 펼친 문자열들(갈래마다 하나) — p[a]ssword · pass(?:w)ord · pas{2}word · \\x2e 처럼
    표기만 바꿔 반출 검사를 비켜 가지 못하게(GPT 9차 가설 → 실측 우회 확인). 한 글자 집합([s]·[Pp])은 그 글자,
    여러 글자 집합·범주·. 은 빈칸, 대안·선택은 갈래마다. 갈래가 너무 많으면 None(검사할 수 없음 → 거부 쪽).
    값 자리(고정 글자 없는 [^"]{0,200}·\\S* 같은 선택)는 갈래로 나누지 않고 두 벌로 본다 — 빈칸으로(gap=' ') 한 벌,
    없는 것으로(gap='', pass[^a]*word → password) 한 벌. 자동 초안의 값 자리마다 갈래가 곱으로 늘지 않게."""
    try:
        import re._parser as sp          # 3.11+
    except ImportError:                  # pragma: no cover
        import sre_parse as sp
    try:
        tree = sp.parse(pattern or "")
    except Exception:
        return []
    REP = {sp.MAX_REPEAT, sp.MIN_REPEAT} | ({sp.POSSESSIVE_REPEAT} if hasattr(sp, "POSSESSIVE_REPEAT") else set())

    def letter(av):
        if any(o is sp.NEGATE for o, _ in av):
            return None
        cs = set()
        for o, a in av:
            if o is sp.LITERAL:
                cs.add(chr(a).lower())
            elif o is sp.RANGE and a[0] == a[1]:
                cs.add(chr(a[0]).lower())
            else:
                return None
        return cs.pop() if len(cs) == 1 else None

    def seq(items, gap):
        outs = [""]
        for op, av in items:
            if op is sp.LITERAL:
                alts = [chr(av)]
            elif op is sp.IN:
                c = letter(av)
                alts = [" " if c is None else c]
            elif op is sp.SUBPATTERN:
                alts = seq(av[-1], gap)
            elif op is sp.BRANCH:
                alts = [x for b in av[1] for x in seq(b, gap)]
            elif op in REP:
                lo, hi, sub = av
                inner = seq(sub, gap)
                if lo == 0 and all(not x.strip() for x in inner):
                    alts = [gap]                          # 값 자리 선택 — 갈래로 나누지 않음
                else:
                    alts = [x * min(max(lo, 1), 64) for x in inner] + ([""] if lo == 0 else [])
            elif op is sp.AT:
                alts = [""]
            else:
                alts = [" "]
            outs = list(dict.fromkeys(re.sub("  +", " ", o + a) for o in outs for a in alts))   # 빈칸 연속은 하나로(같은 갈래 합치기)
            if len(outs) > _VIEWS_CAP:
                raise OverflowError
        return outs
    try:
        return list(dict.fromkeys(seq(list(tree), " ") + seq(list(tree), "")))
    except (OverflowError, RecursionError):
        return None


def export_check(rule: dict) -> list[str]:
    """룰의 글자들(정규식·제외·판정 제목·조치) 안에 개인정보·장비 식별값·비밀값 모양이 있으면 그 목록.
    정규식·제외는 글자 그대로(집합 지우고 이스케이프 풀어)와 '실제로 맞추는 글자를 펼친 것' 둘 다 본다."""
    rxs = [str(rule.get("regex") or (rule.get("match") or {}).get("regex") or ""), str(rule.get("exclude") or "")]
    texts = [str(rule.get("verdict") or "")] + [str(x) for x in (rule.get("immediate") or []) + (rule.get("short") or [])]
    texts = [re.sub(r"\\(.)", r"\1", re.sub(r"\[(?:\\.|[^\]\\])*\][+*?]?(?:\{\d*,?\d*\})?", "", t)) for t in rxs] + texts
    out = []
    views = []
    for t in rxs:
        v = _regex_views(t)
        if v is None:
            out.append("정규식 갈래가 너무 많아 반출 검사를 끝낼 수 없습니다 — 선택(?)·대안(|)을 줄이십시오")
        else:
            views += v
    for name, rx in _LEAKS:
        for t in texts + views:
            m = rx.search(t)
            if m:
                out.append(f"{name}: {m.group(0)[:40]}")
                break
    for t in views + texts[:2]:
        m = _ID_LITERAL.search(t)
        if m:
            out.append(f"계정·호스트 이름 값: {m.group(0)[:40]}")
            break
    return out


# ── 승인한 학습 룰 ───────────────────────────────────────────
def learned_path(base: Path) -> Path:
    return Path(base) / LEARNED_DIR / LEARNED_FILE


def learned_rules(base: Path) -> list[dict]:
    p = learned_path(base)
    try:
        return (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("rules", []) or []
    except Exception:
        return []


def _write_learned(base: Path, rules: list[dict]):
    p = learned_path(base)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".yaml.new")
    tmp.write_text("# 학습 룰 — 화면에서 승인한 것만(LogTriage 룰 학습). 룰팩을 만들면 rules/learned/ 로 들어간다\n" +
                   yaml.safe_dump({"rules": rules}, allow_unicode=True, sort_keys=False, width=1000), encoding="utf-8")
    os.replace(tmp, p)


def approve(spec: dict, base: Path, who: str = "", rules=None, codedb=None) -> dict:
    rep = check(spec, base, rules=rules, codedb=codedb)          # 서버가 받은 최종 값으로 다시 검증(화면 검증을 믿지 않는다)
    leaks = export_check(spec)
    if leaks:
        rep["ok"] = False
        rep["errors"] = rep.get("errors", []) + ["반출하면 안 되는 값이 있습니다 — " + ", ".join(leaks) + " (일반화하거나 지우십시오)"]
    if not rep["ok"]:
        return {"error": "; ".join(rep["errors"]), "check": rep}
    rule = {"id": spec["id"], "layer": spec.get("layer") or "sw", "product": [spec.get("product") or "*"],
            "match": {"regex": spec["regex"]}, "severity": spec["severity"],
            "category": spec.get("category") or "internal", "verdict": spec["verdict"].strip()[:140],
            "immediate": [x for x in (spec.get("immediate") or []) if str(x).strip()][:5],
            "short": [x for x in (spec.get("short") or []) if str(x).strip()][:3], "mid": [], "long": [],
            "versions": ["학습 룰 — 판 범위 미확인"],
            "version_note": f"룰 학습 승인 {datetime.now():%Y-%m-%d %H:%M}" + (f" · {who}" if who else "") + f" · 근거 틀 {spec.get('key', '')}"}
    from .rules import check_rule_fields
    try:
        check_rule_fields(rule)
    except ValueError as e:
        return {"error": str(e), "check": rep}
    if spec.get("exclude"):
        rule["exclude"] = spec["exclude"]
    with _LOCK:
        rules = [r for r in learned_rules(base) if r.get("id") != rule["id"]]
        if len(rules) >= MAX_LEARNED:
            return {"error": f"학습 룰이 {MAX_LEARNED}개에 이르렀습니다 — 쓰지 않는 학습 룰을 지운 뒤 승인하십시오(분석 시간 상한)"}
        rules.append(rule)
        _write_learned(base, rules)
    if spec.get("key"):
        LearnStore(base).set_status(spec["key"], "approved", rule_id=rule["id"])
    return {"id": rule["id"], "check": rep, "learned": len(rules)}


def remove_learned(base: Path, rule_id: str) -> dict:
    with _LOCK:
        rules = learned_rules(base)
        keep = [r for r in rules if r.get("id") != rule_id]
        if len(keep) == len(rules):
            return {"error": "해당 학습 룰이 없습니다"}
        _write_learned(base, keep)
    st = LearnStore(base)
    for x in st.items(status="approved"):
        if x.get("rule_id") == rule_id:
            st.set_status(x["key"], "new", rule_id="")
    return {"removed": rule_id, "learned": len(keep)}


# ── 룰팩 만들기(인터넷망) ────────────────────────────────────
def build_pack(base: Path, signer, out_dir: Path, version: str | None = None) -> dict:
    """기존 rules/ + 승인한 학습 룰(rules/learned/)을 서명 룰팩으로. 에러코드·매뉴얼도 함께(폐쇄망 지식 일치).
    signer = Ed25519 개인키(rulepack.load_signing_key) — 폐쇄망은 미리 등록한 공개키로만 검증한다."""
    bad = {r.get("id"): export_check(r) for r in learned_rules(base)}
    bad = {k: v for k, v in bad.items() if v}
    if bad:
        raise ValueError("반출 검사 실패 — " + "; ".join(f"{k}: {', '.join(v)}" for k, v in bad.items()))
    import shutil
    import tempfile
    from . import rulepack
    from .rules import load_rules
    base = Path(base)
    version = version or datetime.now().strftime("%Y.%m.%d.%H%M")
    with tempfile.TemporaryDirectory(prefix="ltpack_") as td:
        tmp_rules = Path(td) / "rules"
        shutil.copytree(base / "rules", tmp_rules)
        lr = learned_rules(base)
        if lr:
            (tmp_rules / "learned").mkdir(exist_ok=True)
            shutil.copy2(learned_path(base), tmp_rules / "learned" / LEARNED_FILE)
        n = len(load_rules(tmp_rules))           # 묶기 전에 전체가 읽히는지 확인(정규식 오류가 있으면 여기서 멈춘다)
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"rulepack-{version}.rpk"
        rulepack.build(tmp_rules, out, None, version=version,
                       changelog=yaml.safe_dump({"version": version, "learned_rules": [r["id"] for r in lr]}, allow_unicode=True),
                       codes_dir=base / "errorcodes", manuals_dir=base / "manuals", signer=signer)
        pub = rulepack.public_bytes(signer)
        rulepack.verify(out, pub)                # 만든 것을 바로 공개키로 검증
    pub_file = out_dir / "rulepack-signing.pub"  # 폐쇄망에 한 번 등록할 공개키(비밀 아님)
    pub_file.write_bytes(pub)
    sha = hashlib.sha256(out.read_bytes()).hexdigest()
    return {"file": str(out), "name": out.name, "version": version, "rules": n, "learned": len(lr), "sha256": sha,
            "pub_file": pub_file.name, "signer_fp": rulepack.fingerprint(pub)}
