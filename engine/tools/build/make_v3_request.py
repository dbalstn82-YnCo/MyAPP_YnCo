# -*- coding: utf-8 -*-
"""AhnLab V3 예외 등록 신청서 만들기 — 배포 폴더의 실제 exe 해시로(2026-10-15 마스터 지시 "V3 예외 신청 작성").

빌드할 때마다 해시가 바뀌므로 손으로 고치지 않고 이 스크립트로 다시 만든다.
사용: python tools/build/make_v3_request.py [--dist deploy/local/dist] [--out deploy/local/V3예외신청]
산출: LogTriage-<버전>_V3예외신청.md / .docx (신청자·부서·연락처 칸은 비워 둔다 — 신청하는 사람이 채운다)
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ENGINE))
from logtriage import __version__  # noqa: E402

# (표에 쓸 이름, deploy/local 기준 경로). 되돌리기용은 HMAC 틈을 닫은 3차 — 2차는 옛 HMAC 룰팩을 받아 지식을 덮어쓸 수 있어 되돌리기 금지(GPT 16차)
FILES = (("LogTriage.exe (배포본)", "dist/LogTriage.exe"),
         ("logtriage-cli.exe (배포본)", "dist/logtriage-cli.exe"),
         ("LogTriage.exe.이전판 (되돌리기용 직전 판)", "dist/LogTriage.exe.이전판"))


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def signer(p: Path) -> dict:
    """코드 서명 읽기(바꾸지 않음) — build_ledger 와 같은 방법."""
    sys.path.insert(0, str(Path(__file__).parent))
    from build_ledger import signature
    return signature(p)


def build_md(dist: Path) -> str:
    sig = signer(dist / "LogTriage.exe") if (dist / "LogTriage.exe").exists() else {"status": "없음"}
    from build_ledger import signer_ok
    signed = signer_ok(sig)   # 등록한 발행자 지문과 같을 때만 발행자 기준 예외(GPT 37차)
    rows = []
    for n, rel in FILES:
        p = dist / Path(rel).relative_to("dist")   # 12차: --dist 를 빌드 폴더(설치 대기판)로 줘도 그 폴더의 exe 를 읽는다
        if p.exists():
            rows.append(f"| {n} | {p.stat().st_size:,} | `{sha256(p)}` |")
    v = __version__
    return f"""# LogTriage {v} — AhnLab V3 실행 차단 예외 등록 신청서

## 1. 신청 개요

| 항목 | 내용 |
|---|---|
| 신청 대상 | 사내 개발 프로그램 LogTriage(장애 로그 1차 분석기) {v} |
| 신청 내용 | AhnLab V3 행위·평판 기반 실행 차단(ASD)에서 아래 실행 파일을 **파일 해시 기준**으로 예외 등록 |
| 신청자 / 부서 / 연락처 | (작성) |
| 적용 PC | 개발 PC 및 운영 현장 배포 PC(목록 첨부) |
| 유효 기간 | 이 판(아래 해시)에 한함 — 새 판을 배포할 때 새 해시로 다시 신청 |

## 2. 현상

- 새로 복사하거나 새로 빌드한 `LogTriage.exe` 를 실행하면 Windows 가 **"액세스가 거부되었습니다"(CreateProcess 실패)** 로 실행을 막는다.
- 같은 바이트(같은 해시)라도 이미 실행이 허용된 파일은 실행되고 새 복사본만 막히는 경우가 있다. 파일을 이동하면 허용이 유지되기도 했지만,
  **나중에는 이동한 파일까지 같은 해시 전체가 막혔다**(2026-10-15, 이전 배포본 SHA-256 509B26EB… — 실행 이력이 쌓인 뒤 차단). 개발 쪽에서 우회할 방법이 없다.
- 실행 중인 보안 서비스: AhnLab Smart Defense(ASDSvc), V3UI. 파일은 격리·삭제되지 않았고 내용·권한(ACL)도 정상이다.
- 2026-09-30 빌드에서도 같은 현상이 있었다(재빌드로 우회). 서명이 없는 PyInstaller 단일 실행 파일이라 평판 판정에서 '알 수 없는 프로그램'으로 분류되는 것으로 보인다.
- V3 로그는 암호화되어 있어 개발 쪽에서는 **탐지명·차단 사유를 확인할 수 없다.**

## 2-1. 요청 사항(보안 담당)

1. V3 관리 콘솔·로그에서 위 파일의 **탐지명과 차단 사유** 확인(평판 미확인인지, 행위 탐지인지)
2. 아래 해시 3개에만 **예외 등록** — 경로·폴더 전체 예외나 실시간 감시 해제는 요청하지 않는다. 재빌드로 해시가 바뀌면 다시 승인
3. 탐지가 오진이면 **AhnLab 오진 신고** 접수(파일 제출) — 근본 해결 전까지 2번으로 운영
4. 다음 판부터는 사내 코드 서명 인증서 발급 가능 여부 검토(발행자 기준 예외로 전환)

## 3. 예외 대상 파일

| 파일 | 크기(바이트) | SHA-256 |
|---|---:|---|
{chr(10).join(rows)}

{(f"- **코드 서명 확인됨** — 발행자: {sig.get('subject', '')} / 인증서 지문 `{sig.get('thumbprint', '')}`. "
    "해시가 아니라 **이 발행자(인증서) 기준 예외**를 요청한다 — 새 판마다 다시 신청하지 않아도 된다(서명이 깨진 파일은 예외 대상 아님).")
   if signed else "- 코드 서명: 없음 — 아래 해시 기준 예외를 요청한다(사내 코드 서명 인증서 발급 시 발행자 기준으로 전환)."}
- 설치 위치(예): `…\\LogTriage\\LogTriage.exe` (설치 폴더는 PC마다 다를 수 있어 **경로가 아니라 해시 기준** 예외를 요청한다)
- 판 확인: 위 해시는 신청서 생성 시점 배포 폴더의 실제 파일에서 계산했다.

## 4. 프로그램 동작(보안 검토용)

| 구분 | 동작 |
|---|---|
| 용도 | 서버·WAS·DB·OS 장애 로그를 읽어 원인 후보와 1차 조치를 보여 주는 사내 도구 |
| 실행 방식 | PyInstaller 단일 실행 파일 — 실행 시 사용자 임시 폴더(`%TEMP%\\_MEI…`)에 런타임을 풀고 실행, 화면은 Microsoft Edge WebView2 |
| 네트워크(기본) | 이 PC 안(127.0.0.1)에서만 화면 서버를 연다. **인터넷 접속 없음.** |
| 네트워크(설정했을 때만) | 사내 서버 모드 수신(지정 포트), 사내 통합 로그인(OIDC), 본사 통합 현황 전송, 등록한 사내 장비 감시(SNMP·ICMP) |
| 파일 쓰기 | 설치 폴더 아래 `data`·`reports`·`incidents`·`uploads`·`conf` 만 |
| 시스템 변경 | 서비스 등록·레지스트리 시작 항목·드라이버 설치 없음 |
| 무결성 | 탐지 규칙 묶음(룰팩)은 Ed25519 전자서명이 맞아야만 반입(옛 방식 거부) |

## 5. 위험 통제

- 해시 기준 예외라 파일이 한 바이트라도 바뀌면 예외가 적용되지 않는다(변조본 차단 유지).
- 배포본은 개발 PC에서 빌드 → 기능 점검(자동 시험 약 1,000건·화면 점검)을 통과한 파일만 배포한다.
- 근본 대책: 사내 코드 서명 인증서로 실행 파일 서명(발급 시 해시 예외 대신 발행자 기준 예외로 전환 요청 예정).

## 6. 첨부

- 차단 화면/로그(필요 시): V3 로그는 암호화되어 있어 보안 담당 확인 필요
- 배포 PC 목록: (작성)
"""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dist", default=str(ENGINE / "deploy" / "local" / "dist"))
    ap.add_argument("--out", default=str(ENGINE / "deploy" / "local" / "V3예외신청"))
    a = ap.parse_args(argv)
    dist, out = Path(a.dist), Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    md = out / f"LogTriage-{__version__}_V3예외신청.md"
    md.write_text(build_md(dist), encoding="utf-8")
    docx = md.with_suffix(".docx")
    r = subprocess.run([sys.executable, str(Path(__file__).with_name("md2docx.py")), str(md), str(docx)], capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(md)
    print(docx if r.returncode == 0 else f"docx 변환 실패: {r.stderr[-300:]}")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
