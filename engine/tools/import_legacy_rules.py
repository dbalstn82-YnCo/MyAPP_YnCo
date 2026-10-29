"""기존 'AI 로그분석기 v2.2' 내장 룰(JSON, patterns/negative_patterns/immediate_actions/root_actions …)을
LogTriage YAML 룰로 변환해 rules/legacy/ 에 반입한다. 현재 룰과 코드가 겹치는 항목은 제외(중복 방지).

사용: python tools/import_legacy_rules.py <legacy rules/base 디렉터리> [--dry]
결과: rules/legacy/legacy_<파일명>.yaml  (source 표기 legacy-analyzer-v2.2), 요약 출력
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E))
from logtriage.rules import load_rules  # noqa: E402

PRODUCT_MAP = {
    "aix": ("os", "aix"), "rhel": ("os", "linux"), "common": ("os", "*"),
    "general-hw": ("os", "*"), "server-hw": ("os", "*"), "network": ("os", "*"),
    "storage": ("os", "*"), "virtualization": ("os", "*"),
    "apache": ("web", "apache"), "webtob": ("web", "webtob"),
    "oracle": ("db", "oracle"), "tibero": ("db", "tibero"), "altibase": ("db", "altibase"),
    "jeus": ("was", "jeus"), "jboss": ("was", "jboss"),
    "mesim-apig": ("sw", "mesim-apig"), "mesim-esb": ("sw", "mesim-esb"), "indigo-esb": ("sw", "indigo-esb"),
}
CAT_MAP = {"dbms": "db", "was": "was", "web": "web", "os": "os", "hw": "os", "sw": "sw"}
SEV = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warn", "LOW": "info"}
CATEGORY_RULES = [
    ("lock", r"데드락|잠금|lock|latch"), ("memory", r"메모리|OOM|heap|Metaspace|PermGen|swap|스왑"),
    ("undo", r"undo|언두|snapshot too old"), ("disk", r"디스크|용량 부족|space|파일시스템|filesystem|inode"),
    ("storage", r"스토리지|tablespace|테이블스페이스|redo|archive|아카이브|RAID|디스크 장애"),
    ("thread", r"스레드|thread|STUCK"), ("security", r"인증|권한|KEY|certificate|인증서|보안|암호|SSL|TLS|로그인"),
    ("hardware", r"하드웨어|DIMM|ECC|온도|팬|전원|PSU|링크|포트.*다운|HA|VM|ESXi|vCenter|CPU 오류|커널 패닉|panic|NIC"),
    ("capacity", r"한도|초과|큐 포화|Rate|적체|세션 수|프로세스 수|max"),
    ("upstream", r"백엔드|연계|라우팅|타임아웃|timeout|Provider|채널|원격"),
    ("connection", r"연결|커넥션|refused|connect|리스너|listener|접속"),
    ("performance", r"지연|성능|slow|응답"),
]
GENERIC = re.compile(r"^(?:[A-Za-z]{3,8}|[A-Z]{2,4}-|[A-Z]{2,4}-\\d\+|\w{1,5})$")


def infer_category(text: str) -> str:
    for cat, rx in CATEGORY_RULES:
        if re.search(rx, text, re.I):
            return cat
    return "internal"


def good_pattern(p: str) -> bool:
    if not p or len(p.strip()) < 4:
        return False
    if GENERIC.match(p.strip()):
        return False
    if len(p) < 8 and not re.search(r"[\\\[\]().*+?{}|^$\d]", p):
        return False
    try:
        re.compile(p)
    except re.error:
        return False
    return True


def convert(legacy_dir: Path, dry: bool = False) -> dict:
    existing = load_rules(E / "rules", E / "rules-local")
    ex_regex = " || ".join(r.pattern.pattern for r in existing).lower()
    ex_ids = {r.id for r in existing}
    ex_codes = set(re.findall(r"\b[A-Z]{2,6}-\d{3,6}\b", ex_regex.upper()))
    out_dir = E / "rules" / "legacy"
    stats = Counter()
    written = {}
    for f in sorted(legacy_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except Exception as e:
            stats["file_error"] += 1
            print(f"  ! {f.name}: {e}")
            continue
        rules_out = []
        for r in data:
            stats["total"] += 1
            prod_raw = str(r.get("product", "")).lower()
            layer, product = PRODUCT_MAP.get(prod_raw, (CAT_MAP.get(str(r.get("category", "")).lower(), ""), "*"))
            if not layer:
                stats["skip_unknown_product"] += 1
                continue
            pats = [p for p in r.get("patterns", []) if good_pattern(p)]
            if not pats:
                stats["skip_no_pattern"] += 1
                continue
            code = str(r.get("error_code", "")).upper()
            if re.fullmatch(r"[A-Z]{2,6}-\d{3,6}", code) and code in ex_codes:
                stats["skip_dup_code"] += 1
                continue
            if any(p.lower() in ex_regex for p in pats if len(p) >= 10):
                stats["skip_dup_pattern"] += 1
                continue
            rid = "LEG-" + re.sub(r"[^A-Z0-9]+", "-", str(r.get("rule_id", code)).upper()).strip("-")
            if rid in ex_ids:
                stats["skip_dup_id"] += 1
                continue
            ex_ids.add(rid)
            fault = str(r.get("fault_type") or r.get("description") or code).strip()
            cause = str(r.get("cause") or r.get("root_cause") or "").strip()
            impact = str(r.get("impact") or r.get("impact_scope") or "").strip()
            verdict = fault
            if cause and len(fault) + len(cause) < 110:
                verdict = f"{fault} — {cause.rstrip('.')}"
            immediate = [a for a in r.get("immediate_actions", []) if a] or ([str(r["action"])] if r.get("action") and r["action"] != "로그 상세 확인 후 조치" else [])
            mid = [a for a in r.get("root_actions", []) if a]
            neg = [p for p in r.get("negative_patterns", []) if good_pattern(p)]
            rule = {
                "id": rid, "layer": layer, "product": [product],
                "match": {"regex": "|".join(f"(?:{p})" for p in pats)},
                "severity": SEV.get(str(r.get("severity", "MEDIUM")).upper(), "warn"),
                "category": infer_category(" ".join([fault, cause, str(r.get("description", ""))])),
                "verdict": verdict[:140],
                "immediate": immediate[:5], "short": ([f"영향: {impact}"] if impact else [])[:1],
                "mid": mid[:4], "long": [],
                "source_note": f"legacy-analyzer-v2.2 {f.name} {r.get('rule_id', '')} (원 출처: {r.get('source', '')})",
            }
            if neg:
                rule["exclude"] = "|".join(f"(?:{p})" for p in neg)
            rules_out.append(rule)
            stats["converted"] += 1
        if rules_out:
            written[f"legacy_{f.stem}.yaml"] = rules_out
    if not dry:
        out_dir.mkdir(parents=True, exist_ok=True)
        for old in out_dir.glob("legacy_*.yaml"):
            old.unlink()
        for name, rules_out in written.items():
            head = ("# 기존 'AI 로그분석기 v2.2' 내장 룰에서 변환 반입(tools/import_legacy_rules.py) — 중복(코드·패턴) 제외\n"
                    "# 심각도 CRITICAL→critical HIGH→error MEDIUM→warn LOW→info · immediate_actions→즉시 · root_actions→중기 · negative_patterns→exclude\n")
            (out_dir / name).write_text(head + yaml.safe_dump({"rules": rules_out}, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    stats["files"] = len(written)
    return dict(stats)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    st = convert(Path(sys.argv[1]), dry="--dry" in sys.argv)
    print(json.dumps(st, ensure_ascii=False))
