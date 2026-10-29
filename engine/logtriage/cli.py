"""CLI — 로그 파일을 넣으면 장애 시간·유형·조치 방안을 제시한다.

사용 예 (장애 시각을 몰라도 됨 — 자동 탐지):
    python -m logtriage samples/catalina.out --product tomcat
여러 파일:
    python -m logtriage --input samples/catalina.out:tomcat:was01 \
        --input samples/alert_orcl.log:oracle:db01
장애 시각을 아는 경우 시간창 분석:
    python -m logtriage 파일 --product tomcat --incident-time "2026-09-02 14:05"
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from . import __version__
from .parsers import supported_products
from .service import run_analysis

# exe(PyInstaller)로 빌드된 경우 룰은 실행파일 옆 rules/ 폴더 사용 — 룰팩 교체 가능해야 함
if getattr(sys, "frozen", False):
    ENGINE_DIR = Path(sys.executable).resolve().parent
else:
    ENGINE_DIR = Path(__file__).resolve().parent.parent


def parse_args(argv):
    ap = argparse.ArgumentParser(prog="logtriage",
                                 description="장애 로그 1차 대응 분석기")
    ap.add_argument("file", nargs="?", help="단일 로그 파일 경로")
    ap.add_argument("--product", help=f"단일 파일의 제품 ({', '.join(supported_products())})")
    ap.add_argument("--host", default="unknown", help="단일 파일의 호스트명")
    ap.add_argument("--input", action="append", default=[],
                    metavar="파일:제품[:호스트]", help="복수 입력 (반복 지정)")
    ap.add_argument("--incident-time", metavar='"YYYY-MM-DD HH:MM"',
                    help="장애 인지 시각 (생략 시 전체 로그에서 자동 탐지)")
    ap.add_argument("--before", type=int, default=30, help="시간창 시작 T−N분 (기본 30)")
    ap.add_argument("--after", type=int, default=10, help="시간창 끝 T+N분 (기본 10)")
    ap.add_argument("--rules", default=str(ENGINE_DIR / "rules"), help="룰 디렉터리")
    ap.add_argument("--rules-local", default=str(ENGINE_DIR / "rules-local"),
                    help="로컬 룰 디렉터리")
    ap.add_argument("--codes", default=str(ENGINE_DIR / "errorcodes"),
                    help="벤더 에러코드 사전 디렉터리")
    ap.add_argument("--search", metavar='"검색어"',
                    help="지식베이스 검색 (룰·에러코드·매뉴얼, 오프라인)")
    ap.add_argument("--solution", metavar="제품:코드",
                    help="에러코드 해법(OS 별 명령 포함) — 로그 없이. 예: --solution oracle:ORA-00018 --os aix")
    ap.add_argument("--os", default="", help="--solution 과 함께: linux · aix · hpux · solaris · windows (생략 시 제품의 첫 지원 OS)")
    ap.add_argument("--version", action="version", version=f"logtriage {__version__}")
    return ap.parse_args(argv)


def _ask(prompt: str, default: str = "") -> str:
    val = input(prompt).replace("﻿", "").replace("\x00", "").strip().strip('"')
    return val or default


def interactive_argv(prefill_files: list[str]) -> list[str]:
    """더블클릭·드래그&드롭 실행용 대화형 입력 → CLI 인자 구성."""
    print("=" * 56)
    print(f"LogTriage 장애 로그 1차 대응 분석기 {__version__}")
    print("=" * 56)
    files = list(prefill_files)
    if files:
        print("투입된 로그 파일:")
        for f in files:
            print(f"  - {f}")
    while not files:
        p = _ask("로그 파일 경로 (창에 파일을 드래그해도 됩니다): ")
        if p and Path(p).exists():
            files.append(p)
        else:
            print("  ! 파일을 찾을 수 없습니다. 다시 입력하세요.")
    from .detect import detect_product
    argv: list[str] = []
    products = ", ".join(supported_products())
    for f in files:
        guess = detect_product(Path(f))
        if guess:
            prod = _ask(f"'{Path(f).name}' 제품 자동 판별: {guess} (엔터=확정, 다르면 입력): ",
                        guess).lower()
        else:
            prod = ""
        while prod not in supported_products():
            prod = _ask(f"'{Path(f).name}' 의 제품 ({products}): ").lower()
            if prod not in supported_products():
                print(f"  ! 지원 제품: {products}")
        host = _ask("  호스트명 (엔터=unknown): ", "unknown")
        argv += ["--input", f"{f}:{prod}:{host}"]
    t = _ask('장애 인지 시각 [YYYY-MM-DD HH:MM] (엔터=자동 탐지): ')
    if t:
        try:
            datetime.strptime(t, "%Y-%m-%d %H:%M")
            argv += ["--incident-time", t]
        except ValueError:
            print("  ! 형식 오류 — 자동 탐지 모드로 진행합니다.")
    print()
    return argv


def text_report(r: dict) -> str:
    lines: list[str] = []
    w = lines.append
    w("=" * 66)
    w("LogTriage 분석 리포트")
    w(f"분석 범위: {r['window']}  ·  이벤트 {r['events_window']:,}건"
      f"  ·  룰 매칭 {r['match_count']}건")
    w("=" * 66)

    if not r["first"]:
        w("")
        w("판정: 전 계층 CLEAR — 알려진 장애 패턴이 없습니다.")
        w("      로그 외 원인(네트워크·인프라·외부 연동)을 의심하십시오.")
        return "\n".join(lines)

    f = r["first"]
    w("")
    w(f"① 장애 시간{'(자동 탐지)' if r['auto_detected'] else ''}: {r['incident_time']}")
    w(f"② 장애 유형: {f['category_ko']} — {f['verdict']} [{f['rule_id']}]")
    w(f"   최초 이상 계층(추정): {f['layer_ko']}")

    w("")
    w("── 타임라인 (판정 근거) " + "─" * 41)
    for tvt in r["timeline"]:
        w(f"{tvt['ts']}  [{tvt['layer_ko']:>4}] {tvt['severity'].upper():8} "
          f"{tvt['verdict']} [{tvt['rule_id']}]")
        w(f"          {tvt['message'][:90]}")
        w(f"          원본: {tvt['raw_ref']}")

    w("")
    w("③ 장애 유형별 조치 방안 " + "─" * 41)
    tiers = [("immediate", "▶ 즉시 조치 (장애 중)"), ("short", "▷ 단기 조치 (일~주)"),
             ("mid", "▷ 중기 조치 (주~월)"), ("long", "▷ 장기 조치 (구조 개선)")]
    for c in r["checklist"]:
        w(f"[{c['rule_id']}] ({c['category_ko']}) {c['verdict']}")
        for key, label in tiers:
            if c.get(key):
                w(f"  {label}:")
                for a in c[key]:
                    w(f"    - {a}")
    plan = r.get("plan")
    if plan:
        w("")
        w("④ 단계별 대응 계획 " + "─" * 45)
        w("■ 1. 로그 분석 내용")
        for x in plan["analysis"].get("summary", []):
            w(f"  - {x}")
        for c in plan["analysis"].get("codes", []):
            w(f"    · {c['code']} ({c['severity']}) {c['count']}회 {c['first_ts']}~{c['last_ts']} — {c['verdict']}")
        for x in plan["analysis"].get("observations", []):
            w(f"  - {x}")
        if plan["analysis"].get("vendor"):
            w("  ▶ 제조사 제공 원인·조치 (공식 문서 요약)")
            for v in plan["analysis"]["vendor"]:
                w(f"    [{v['code']}] {v['verdict']} ({v['count']}회)")
                w(f"      원인: {v.get('cause') or '-'}")
                w(f"      조치{'(' + v['action_type_ko'] + ')' if v.get('action_type_ko') else ''}: {v.get('action') or '-'}")
                if v.get("url"):
                    w(f"      문서: {v['url']}")
        t1 = plan["tier1"]
        w(f"■ 2. 1차 선 대응 — {t1.get('role', '유지보수(관리) 담당자')}")
        w("  ▶ 지금 상황(쉬운 설명)")
        for x in t1.get("situation", []):
            w(f"  - {x}")
        w("  ▶ 순서대로 할 일")
        for st in t1.get("steps", []):
            if isinstance(st, dict):
                w(f"  {st['n']}) {st['do']}")
                w(f"       방법: {st['how']}")
                w(f"       확인: {st['check']}")
            else:
                w(f"  - {st}")
        if t1.get("dont"):
            w("  ▶ 1차 대응 금지 사항")
            for x in t1["dont"]:
                w(f"  - {x}")
        if t1.get("note"):
            w(f"  ※ {t1['note']}")
        if t1.get("detail"):
            w("  ▶ 판정별 세부 조치(가능한 범위에서)")
            for x in t1["detail"]:
                w(f"  - {x}")
        if t1.get("deferred"):
            w("  ▶ 1차에서 하지 않는 조치(2차 수행·승인 필요)")
            for x in t1["deferred"]:
                w(f"  - {x}")
        esc = t1.get("escalate", {})
        if esc:
            w("  ▶ 2차(엔지니어)로 넘기는 기준: " + " / ".join(esc.get("when", [])))
            w("  ▶ 넘길 때 전달할 것: " + " / ".join(esc.get("hand", [])))
        for c in t1.get("commands", []):
            w(f"    [{c['product']}] {c['title']}: {c['body']}")
        w("■ 3. 2차 조치 — 유지보수 엔지니어")
        w("  ▶ 확인 내용")
        for x in plan["tier2"].get("checks", []):
            w(f"  - {x}")
        w("  ▶ 전달 내용")
        for x in plan["tier2"].get("handover", []):
            w(f"  - {x}")
        w("  ▶ 로그 캡처")
        for c in plan["tier2"].get("captures", []):
            w(f"  [{c['code']}] {c['verdict']} — {c['file']}:{c['range']} ({c['ts']})")
            for ln in c.get("lines", []):
                w(f"    {'>>' if ln['hit'] else '  '} {ln['n']:>6} | {ln['text']}")
        w("■ 4. 3차 조치 — 제조사 상세 분석 의뢰")
        for x in plan["tier3"].get("summary", []):
            w(f"  - {x}")
        w("  ▶ 수집·첨부 자료")
        for x in plan["tier3"].get("collect", []):
            w(f"  - {x}")
        w("  ▶ 중·장기 과제")
        for x in plan["tier3"].get("mid_long", []):
            w(f"  - {x}")
        if plan["tier3"].get("contact"):
            w(f"  ▶ 문의: {plan['tier3']['contact']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    # 한국어 Windows 콘솔(CP949)에서도 리포트가 깨지지 않도록 UTF-8 출력 강제
    for stream in (sys.stdout, sys.stderr, sys.stdin):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    argv = list(sys.argv[1:]) if argv is None else list(argv)
    # 더블클릭(인자 없음) 또는 exe에 파일만 드래그&드롭한 경우 → 대화형 모드
    tty = os.environ.get("LOGTRIAGE_INTERACTIVE") == "1" or (
        sys.stdin is not None and sys.stdin.isatty())
    interactive = tty and (not argv or all(
        not a.startswith("-") and Path(a).exists() for a in argv))
    if interactive:
        try:
            argv = interactive_argv(argv)
        except (KeyboardInterrupt, EOFError):
            return 130

    if getattr(sys, "frozen", False):   # 10차: 단독 exe 하나만 옮겨도 — 옆에 판정 지식이 없으면 exe 안 내장 지식을 펼친다
        from .knowledge_seed import seed
        sr = seed(ENGINE_DIR)
        if sr.get("seeded"):
            print(f"[LogTriage] 내장 지식을 펼쳤습니다: {', '.join(sr['seeded'])} → {ENGINE_DIR}", file=sys.stderr)
        if sr.get("error"):
            print("[LogTriage] " + sr["error"], file=sys.stderr)
    try:
        rc = _run(argv)
    except Exception as e:  # 대화형 창이 오류와 함께 사라지지 않도록
        print(f"\n오류: {e}", file=sys.stderr)
        rc = 1
    if interactive:
        try:
            input("\nEnter 키를 누르면 종료합니다...")
        except EOFError:
            pass
    return rc


def _solution(args) -> int:
    """12차: 에러코드 × OS 해법을 텍스트로(로그 없이)."""
    from .codes import load_codes
    from .os_solution import applicable_os, load_matrix, solution, solution_text
    from .procedures import load_procedures
    if ":" not in args.solution:
        print("형식: --solution 제품:코드 (예: oracle:ORA-00018)", file=sys.stderr)
        return 2
    product, code = args.solution.split(":", 1)
    codes = load_codes(Path(args.codes))
    e = codes.get(f"{product.lower()}:{code}") or codes.get(f"{product.lower()}:{code.upper()}")
    if e is None:
        print(f"코드를 찾지 못했습니다: {args.solution}", file=sys.stderr)
        return 1
    manuals = Path(args.codes).parent / "manuals"
    m = load_matrix(manuals)
    oses = applicable_os(m, e.product)
    os_name = (args.os or (oses[0] if oses else "")).lower()
    sol = solution(e, os_name, manuals, load_procedures(manuals))
    print(solution_text(sol))
    return 1 if sol.get("error") else 0


def _kb_search(args) -> int:
    from .codes import load_codes
    from .kb import load_manuals, search_kb
    from .rules import load_rules
    r = search_kb(args.search,
                  load_rules(Path(args.rules), Path(args.rules_local)),
                  load_codes(Path(args.codes)),
                  load_manuals(ENGINE_DIR / "manuals"))
    print(f"지식베이스 검색: \"{args.search}\" — "
          f"룰 {len(r['rules'])} · 에러코드 {len(r['codes'])} · 매뉴얼 {len(r['manuals'])}")
    for x in r["rules"]:
        print(f"\n[룰 {x['id']}] ({x['layer']}/{','.join(x['products'])}) {x['verdict']}")
        for key, label in (("immediate", "즉시"), ("short", "단기"),
                           ("mid", "중기"), ("long", "장기")):
            for a in x[key]:
                print(f"  {label}: {a}")
    for x in r["codes"]:
        print(f"\n[코드 {x['code']}] ({x['product']}) {x['title']}")
        for a in x["immediate"]:
            print(f"  즉시: {a}")
    for x in r["manuals"]:
        print(f"\n[매뉴얼] {x['title']}")
        for s in x["sections"]:
            print(f"  ■ {s['heading']}: {s['body'][:160]}")
    return 0


def _run(argv) -> int:
    args = parse_args(argv)
    if args.search:
        return _kb_search(args)
    if args.solution:
        return _solution(args)
    from .detect import detect_product
    inputs: list[dict] = []
    if args.file:
        inputs.append({"path": args.file,
                       "product": (args.product or "").lower(), "host": args.host})
    import re as _re
    for spec in args.input:
        drive = ""
        if _re.match(r"^[A-Za-z]:[\\/]", spec):  # Windows 드라이브 콜론 보호
            drive, spec = spec[:2], spec[2:]
        parts = spec.split(":")
        inputs.append({"path": drive + parts[0],
                       "product": parts[1].lower() if len(parts) > 1 else "",
                       "host": parts[2] if len(parts) > 2 else "unknown"})
    for item in inputs:  # 제품 미지정 시 로그 내용으로 자동 판별
        if not item["product"]:
            item["product"] = detect_product(Path(item["path"]))
            if item["product"]:
                print(f"  [판별] {Path(item['path']).name} → {item['product']}")
            else:
                print(f"오류: 제품 자동 판별 실패 — {item['path']} "
                      "( --product 또는 파일:제품 형식으로 지정 )", file=sys.stderr)
                return 2
    if not inputs:
        print("오류: 분석할 입력이 없습니다.", file=sys.stderr)
        return 2

    mode = f"T={args.incident_time}" if args.incident_time else "장애 시간 자동 탐지"
    print(f"logtriage {__version__} — {mode}")
    result = run_analysis(inputs, args.incident_time, args.before, args.after,
                          Path(args.rules), Path(args.rules_local), Path(args.codes))
    for f in result["files"]:
        print(f"  [수집] {f['name']} ({f['product']}) — 이벤트 {f['events']:,}건")
    print(f"  [분석] 시그니처 룰 {result['rule_count']}건 + "
          f"벤더 에러코드 {result['code_count']}건 대조")
    print()
    print(text_report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
