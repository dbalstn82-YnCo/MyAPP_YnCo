"""로그 제품 자동 판별 — 사용자가 제품을 고르게 하지 않는 것이 원칙.

1단계: 파일명·내용 시그니처 힌트 (제품 고유 흔적)
2단계: 등록된 모든 파서로 앞부분 샘플을 실제 파싱해 가장 많은 줄을
        인식한 파서의 제품을 채택 (파서 스코어링)
둘 다 실패한 경우에만 빈 문자열을 반환하고 UI가 수동 선택을 요청한다.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path

_SAMPLE_LINES = 400

# (정규식, 제품) — 위에서부터 우선 적용. 제품 고유 문자열만 사용한다.
_HINTS: list[tuple[re.Pattern, str]] = [(re.compile(p, re.M), prod) for p, prod in [
    (r"^type=\w+ +msg=audit\(\d+\.\d+:\d+\)", "auditd"),
    (r"TimeCreated.*(LevelDisplayName|ProviderName)", "windows"),
    (r"^####<", "weblogic"),
    (r"^\[(?:\d{1,2}/\d{1,2}/\d{2,4}|\d{2,4}\. ?\d{1,2}\. ?\d{1,2}\.?) \d{1,2}:\d{2}:\d{2}[:.]\d{1,3} ?[^\]]*\] [0-9a-fA-F]{8} \S+\s+[FEWAICDORZ] ", "websphere"),  # tWAS SystemOut.log
    (r"\borg\.jboss\b|\bWFLY[A-Z]+\d{4}\b|\bJBAS\d{6}\b", "jboss"),
    (r"^\[\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\]\[\d\]\[\w+\] \[\w+-\d+\]", "jeus"),  # JEUS 6 서버 로그(컨테이너 로그에 webtob 문자열이 섞임)
    (r"^\d{8} \d{2}:\d{2}:\d{2}\.\d{3} \[[^\]]+\]", "java"),  # logback 앱 로그(스레드명에 webtob 가 섞여도 앱 로그)
    (r"WebtoB|webtob|WEBTOB|\[HTH\d*\]|\bwsm\b|\bHTH\d{4}:|\bJSV: ", "webtob"),
    (r"com\.tmax\.esb\.adapter|^\[#\|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\|", "bizmaster-adapter"),
    (r"com\.tmax\.giss|^\[\d{2}:\d{2}:\d{2}\]\[(?:INFO |ERROR|DEBUG|WARN )\]\(", "bizmaster-app"),
    (r"com\.uis\.ddims|\[ DDIMS \]|CAI4dDIMS|InformationPackage", "java"),
    (r"\bJEUS\b|jeus\.server|^\[\d{4}\.\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\]\[\d\]\[", "jeus"),
    (r"\* establish \*|\* service_update \*|TNSLSNR for|written to .*listener", "oracle-listener"),
    (r"^# Query_time: ", "mysql-slow"),
    (r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \S+,[^,]*,[^,]*,\d+,", "postgresql-csv"),
    (r"#Software: Microsoft HTTP API", "iis-httperr"),
    (r"^[0-9A-F]{8}\s+\d{10}\s+[TPIU]\s+[HSOU]\s+\S+|^IDENTIFIER:\s+[0-9A-F]{8}|IDENTIFIER TIMESTAMP", "aix-errpt"),
    (r"\bORA-\d{5}\b|Starting ORACLE instance", "oracle"),
    (r"\bAltibase\b|ALTIBASE|\bERR-[0-9A-Fa-f]{5}\b", "altibase"),
    (r"\bTBR-\d+\b|\btibero\b", "tibero"),
    (r"\bspid\d+\b.*(Error:|SQL Server)|SQL Server \(", "mssql"),
    (r"\[MY-\d{6}\]|mysqld|InnoDB", "mysql"),
    (r"\[\d+\] (LOG|ERROR|FATAL|PANIC|WARNING):|PostgreSQL", "postgresql"),
    (r"\[(?:crit|error|warn)\] \d+#\d+|nginx", "nginx"),
    (r"\bAH\d{5}\b|\[pid \d+[:\]]|Apache/\d", "apache"),
    (r"#Software: Microsoft Internet Information", "iis"),
    (r'^\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*\] "', "accesslog"),
    (r"MESIM.?EAI|mesim.?eai|Indigo.?EAI|indigo.?eai", "mesim-eai"),
    (r"MESIM.?APIG|mesim.?apig", "mesim-apig"),
    (r"MESIM|metabuild|com\.metabuild", "mesim-esb"),
    (r"org\.apache\.catalina|HikariPool|catalina", "tomcat"),
    (r"\bSunOS\b|\bgenunix\b", "solaris"),
    (r"\berrpt\b", "aix-errpt"),
    (r"vmunix", "hpux"),
    (r" kernel: | systemd\[| sshd\[", "linux"),
]]

# 파서 스코어링 후보 — 형식이 겹칠 때 더 특이적인 파서가 먼저 오도록 정렬
_SCORE_ORDER = ["auditd", "windows", "aix-errpt", "postgresql-csv", "iis-httperr",
                "oracle-listener", "mysql-slow", "weblogic", "websphere", "jeus", "mssql", "mysql",
                "postgresql", "oracle", "altibase", "apache", "nginx", "iis",
                "tomcat", "jboss", "bizmaster-adapter", "bizmaster-app", "java", "webtob", "accesslog",
                "tibero", "linux", "mesim-eai"]


def _read_sample(path: Path) -> str:
    from .parsers import open_text
    out = []
    try:
        with open_text(path) as f:
            for i, line in enumerate(f):
                if i >= _SAMPLE_LINES:
                    break
                out.append(line)
    except OSError:
        return ""
    return "".join(out)


def _hint(name: str, sample: str) -> str:
    # 파일명 힌트
    if name.endswith(".gz"):
        name = name[:-3]
    if name.startswith("err.out") or name.startswith("adt_") or name.startswith("eai.log"):
        return "bizmaster-app" if name.startswith(("err.out", "eai.log")) else "bizmaster-adapter"
    if "catalina" in name:
        return "tomcat"
    if "nginx" in name:
        return "nginx"
    if "listener" in name and name.endswith(".log"):
        return "oracle-listener"
    if "slow" in name and ("mysql" in name or name.endswith("-slow.log") or "slow.log" in name):
        return "mysql-slow"
    if "httperr" in name:
        return "iis-httperr"
    if "errpt" in name:
        return "aix-errpt"
    if "alert_" in name or name.startswith("alert"):
        return "oracle"
    if "altibase" in name:
        return "altibase"
    if "tibero" in name:
        return "tibero"
    if "errorlog" in name and "sql" in name:
        return "mssql"
    # 내용 힌트
    for pat, prod in _HINTS:
        if pat.search(sample):
            return prod
    return ""


def _score(path: Path, sample: str) -> str:
    from .parsers import get_parser
    if not sample.strip():
        return ""
    suffix = path.suffix or ".log"
    if suffix.lower() == ".gz":
        suffix = ".log"
    with tempfile.NamedTemporaryFile("w", suffix=suffix,
                                     encoding="utf-8", delete=False) as tf:
        tf.write(sample)
        tmp = Path(tf.name)
    best, best_n = "", 0
    try:
        for prod in _SCORE_ORDER:
            try:
                _, parser = get_parser(prod)
                n = len(parser(tmp, "probe"))
            except Exception:
                n = 0
            if n > best_n:  # 동점이면 앞선(더 특이적인) 파서 유지
                best, best_n = prod, n
    finally:
        tmp.unlink(missing_ok=True)
    return best if best_n >= 2 else ""


def detect_product(path: Path) -> str:
    sample = _read_sample(path)
    return _hint(path.name.lower(), sample) or _score(path, sample)
