"""반출용 로컬 설치형 zip 재생성 — dist(검증 사건·DB·업로드·보고서 제외) + 룰팩 + WebView2 런타임."""
import zipfile
from pathlib import Path
ROOT = Path(r"C:\Users\dbals\Desktop\로그수집기")
DIST = ROOT / "engine/deploy/local/dist"
DATE = __import__("os").environ.get("LT_DATE") or __import__("time").strftime("%Y.%m.%d")
OUT = ROOT / f"반출/LogTriage-로컬설치형-{DATE}.zip"
import sys as _sys; _sys.path.insert(0, str(Path(__file__).resolve().parent))
import _buildstamp as _bs
BUILD_ID = _bs.build_id(ROOT / "engine")
SKIP_DIRS = {"incidents", "data", "reports", "uploads", "__pycache__", "custom", "backups", "restore-rollback", "conf"}
# custom = 사용자 등록 서식(이 PC 전용), conf = 이 PC 의 실제 설정·서버 키(conf-examples 만 배포한다)
SKIP_FILES = {"incidents.json", "incidents.json.migrated", "logtriage_gui.log", "logtriage_server.log", "server.pid", "instance.json", "settings.json", "report_profile.json", ".automation-worker.lock", ".rpk-apply.lock"}
# hwp 차단: 사내 양식(기관명 포함)이 dist 에 남아 있으면 중단
ALLOWED_FORMS = {"form_status.hwpx", "form_postmortem.hwpx"}  # 공식 서식(기관명·인명 없음) — 유일하게 허용되는 HWP 파일
# 실제로 묶일 파일만 검사(SKIP 폴더·앱 임시 백업은 묶지 않으므로 제외) — 묶이는 곳에 허용 서식 아닌 HWP 가 있으면 멈춘다
_SKIP_HWP = lambda p: "custom" in p.parts or any(x in ("reports", "uploads", "incidents", "data", "backups") or x.startswith(".backup-") for x in p.relative_to(DIST).parts)
bad = [p for p in DIST.rglob("*") if not _SKIP_HWP(p) and (p.suffix.lower().startswith(".hwp") and p.name not in ALLOWED_FORMS)
       or p.name.startswith("master") and p.suffix.lower().startswith(".hwp")
       or (p.name.startswith("layout") and p.suffix == ".json" and "report-template" in p.parts)]
for f in ALLOWED_FORMS:  # 허용 서식도 기관명 칸이 비어 있는지 확인
    fp = DIST / "report-template" / f
    if fp.exists():
        import zipfile as _z; sec = _z.ZipFile(fp).read("Contents/section0.xml").decode("utf-8")
        import re as _re
        if _re.search(r"기관명\s*[:：]\s*[^\s<)]", sec):
            raise SystemExit(f"반출 중단 — 서식에 기관명이 채워져 있음: {f}")
if bad:
    raise SystemExit("반출 중단 — HWP/양식 레이아웃 파일 존재: " + ", ".join(str(b) for b in bad))
# 이 PC 의 비밀 파일이 섞이면 중단 — 서버 키가 유출되면 저장된 비밀번호 검증값을 풀 수 있다
SECRET_NAMES = {"secret.key", "auth.json", "hub.json", "rulepack.key", "rulepack_signing.pem", "server.conf", "settings.json"}   # rulepack_signing.pem = 룰팩 서명 개인키(인터넷망 전용, 2026-10-15)
leak = [p for p in DIST.rglob("*") if p.is_file() and p.name in SECRET_NAMES and "conf-examples" not in p.parts]
if leak:
    raise SystemExit("반출 중단 - 설정/키 파일이 dist 에 남아 있습니다(삭제 후 다시): " + ", ".join(str(x.relative_to(DIST)) for x in leak))
n = 0
with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
    for p in sorted(DIST.rglob("*")):
        rel = p.relative_to(DIST)
        if any(part in SKIP_DIRS or part.startswith(".backup-") for part in rel.parts) or p.name in SKIP_FILES or p.suffix in (".jsonl", ".db", ".db-wal", ".db-shm"):
            continue
        if p.is_file():
            if p.name == "재설치-안내.txt":   # 사람이 그대로 열어 보는 안내문 — 빌드 표시를 이번 판으로 맞춘다
                body, hit = _bs.retag(p.read_text(encoding="utf-8"), BUILD_ID)
                if hit == 0:
                    raise RuntimeError(f"{p.name} 에 빌드 표시가 없습니다 — 안내문을 확인하십시오")
                z.writestr(f"LogTriage/{rel.as_posix()}", body.encode("utf-8")); n += 1
                continue
            z.write(p, f"LogTriage/{rel.as_posix()}"); n += 1
    z.writestr("LogTriage/incidents.json", "[]")
    z.write(ROOT / f"반출/rulepack-{DATE}.rpk", f"룰팩/rulepack-{DATE}.rpk")
    z.writestr("룰팩/README.txt", "rulepack.key 는 별도 안전 경로로 전달(zip 미포함).\n")
    wv = ROOT / "반출/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
    if wv.exists():
        z.write(wv, "필수-WebView2런타임(오프라인설치)/MicrosoftEdgeWebView2RuntimeInstallerX64.exe")
    else:
        z.writestr("필수-WebView2런타임(오프라인설치)/README-설치파일없음.txt", "MicrosoftEdgeWebView2RuntimeInstallerX64.exe 가 반출 폴더에 없어 이 zip 에 포함하지 못했습니다.\nWindows 11 은 WebView2 런타임이 기본 포함이라 대부분 그대로 실행됩니다. 없는 PC 는 Microsoft 'WebView2 Runtime Evergreen Standalone Installer(x64)' 를 받아 설치하십시오.\n")
        print("주의: WebView2 설치 파일 없음 — 안내 파일로 대체")
_bs.audit_zip(OUT, BUILD_ID)
print(OUT, OUT.stat().st_size // 1024 // 1024, "MB", n, "files")
