"""GPT 수집 Java 예외(';;' 형식) → errorcodes/claude_sw_java.yaml (product java, 코드 = 예외 FQCN).
같은 FQCN 의 변형([Java heap space] 등)은 한 코드로 합친다. 등급 A/B 는 vendor_*(공식 문서) 로, 그 외는 출처만 표기.
소스(코드) 결함 계열은 category app 으로 보정(WAS/WEB 문제와 구분).

사용: python tools/import_java_exceptions.py collect/verify/resp_java_exceptions_2026-09-10.txt
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

E = Path(__file__).resolve().parents[1]
APP_DEFECT = {  # 소스 결함 가능성 → app
    "java.lang.NullPointerException", "java.lang.IllegalStateException", "java.lang.NumberFormatException",
    "java.util.ConcurrentModificationException", "java.lang.StackOverflowError", "java.lang.ClassNotFoundException",
    "java.lang.NoClassDefFoundError", "org.springframework.jdbc.BadSqlGrammarException",
    "org.apache.ibatis.binding.BindingException", "com.fasterxml.jackson.core.JsonParseException",
}
SEV_OK = {"critical", "error", "warn", "info"}


def main(src: Path):
    merged: dict[str, dict] = {}
    for line in src.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("TOTAL"):
            continue
        parts = [x.strip() for x in line.split(";;")]
        if len(parts) < 10:
            continue
        key, layer, sev, cat, meaning, cause, action, escalate, grade, url = parts[:10]
        if key.startswith("JEUS "):
            continue  # SESSION-2512 는 JEUS 코드 사전에 별도 등재
        m = re.match(r"([\w.$]+)(?:\[(.+)\])?", key)
        fq, variant = m.group(1), m.group(2)
        e = merged.setdefault(fq, {"code": fq, "layer": layer, "severity": sev if sev in SEV_OK else "error",
                                   "category": "app" if fq in APP_DEFECT else cat, "titles": [], "causes": [], "actions": [],
                                   "escalates": [], "grades": [], "urls": []})
        e["titles"].append(f"{meaning}" + (f"({variant})" if variant else ""))
        e["causes"].append((f"[{variant}] " if variant else "") + cause)
        e["actions"].append(action)
        e["escalates"].append(escalate)
        e["grades"].append(grade)
        if url and url != "-":
            e["urls"].append(url)
        if sev == "critical":
            e["severity"] = "critical"
    codes = []
    for fq, e in merged.items():
        title = e["titles"][0] if len(e["titles"]) == 1 else " / ".join(t.split("(")[0] for t in e["titles"])
        if fq in APP_DEFECT:
            title = f"{title} — 소스(애플리케이션) 결함 가능성, WAS/WEB 장애 아님"
        best = min(e["grades"], key=lambda g: "ABCD".find(g) if g in "ABCD" else 9)
        item = {
            "code": fq, "severity": e["severity"], "category": e["category"], "title": title[:140],
            "immediate": [a for a in dict.fromkeys(e["actions"]) if a][:3],
            "short": [f"2차 이관 기준: {x}" for x in dict.fromkeys(e["escalates"]) if x][:2],
            "mid": [], "long": [],
            "source": (f"GPT 수집·공식 문서 대조(등급 {best}) " + ", ".join(list(dict.fromkeys(e["urls"]))[:2])) if e["urls"] else "GPT 수집(출처 미확인 D)",
        }
        if best in ("A", "B") and e["urls"]:
            item["vendor_cause"] = " / ".join(dict.fromkeys(e["causes"]))[:400]
            item["vendor_action"] = e["actions"][0][:300]
            item["vendor_url"] = e["urls"][0]
        codes.append(item)
    out = E / "errorcodes" / "claude_sw_java.yaml"
    doc = {"product": "java", "layer": "sw",
           "note": "Java/Spring/JDBC/LDAP 예외 클래스(FQCN) 코드 — 파서가 벤더 코드 없는 예외 이벤트에 대표 예외 FQCN 을 코드로 부여. 실로그 JeusServer.log(2025-07) 검증. category app = 소스 결함 가능성",
           "codes": codes}
    out.write_text("# Java 예외 코드 사전 — GPT 수집(공식 Javadoc/Spring/MyBatis/Jedis 문서, 2026-09-10) + Claude 검수. 소스 결함(app) 과 인프라(connection/upstream/…) 구분\n" +
                   yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=200), encoding="utf-8")
    print(f"written {out} codes={len(codes)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
