"""룰팩 빌드·검증·적용 CLI (인터넷망: build / 폐쇄망: verify·apply) — 공개키 서명(Ed25519)만.

2026-10-15 마스터 결정 "틈 닫고 새로운 도장 받기": 옛 방식(HMAC 공유 비밀키 dist.key·rulepack.key) 룰팩은 만들지도 받지도 않는다.

사용 예:
    # 인터넷망: 서명 개인키가 없으면 만든다 → 공개키(.pub)와 지문을 함께 출력
    python tools/rulepack_cli.py build  --sign-key conf/rulepack_signing.pem --out rulepack-2026.10.15.rpk
    # 폐쇄망: 공개키 + (처음 한 번) 인터넷망 화면·출력의 지문 32자리
    python tools/rulepack_cli.py verify --pub rulepack-signing.pub rulepack-2026.10.15.rpk
    python tools/rulepack_cli.py apply  --pub rulepack-signing.pub --confirm-fp XXXX-XXXX-... rulepack-2026.10.15.rpk
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from logtriage import rulepack  # noqa: E402

ENGINE = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser(description="LogTriage 룰팩 도구 (공개키 서명 Ed25519 전용)")
    ap.add_argument("cmd", choices=["build", "verify", "apply"])
    ap.add_argument("rpk", nargs="?", help="룰팩 파일 (verify/apply)")
    ap.add_argument("--sign-key", default=str(ENGINE / "conf" / "rulepack_signing.pem"),
                    help="build: 서명 개인키(PEM, 인터넷망에만 둔다). 없으면 만든다")
    ap.add_argument("--pub", help="verify/apply: 서명 공개키(rulepack-signing.pub)")
    ap.add_argument("--confirm-fp", default="", help="apply: 처음 등록할 때 인터넷망에서 확인한 지문(32자리)")
    ap.add_argument("--key-file", help=argparse.SUPPRESS)   # 옛 HMAC 옵션 — 쓰면 이유를 알리고 멈춘다
    ap.add_argument("--rules", default=str(ENGINE / "rules"))
    ap.add_argument("--codes", default=str(ENGINE / "errorcodes"))
    ap.add_argument("--manuals", default=str(ENGINE / "manuals"))
    ap.add_argument("--out", help="build 출력 파일명")
    ap.add_argument("--version", help="build 버전 (기본: 오늘 날짜)")
    ap.add_argument("--link-hosts", help="build: 화면 링크로 열어 줄 제조사 문서 도메인을 더할 때 — 한 줄에 하나인 글 파일")
    args = ap.parse_args()

    if args.key_file:
        print("오류: --key-file(옛 방식 HMAC 배포 키)은 더 쓰지 않습니다 — build 는 --sign-key, verify/apply 는 --pub 를 쓰십시오",
              file=sys.stderr)
        return 2
    if args.cmd == "build":
        key_path = Path(args.sign_key)
        new = not key_path.exists()
        signer = rulepack.load_signing_key(key_path, create=True)
        pub = rulepack.public_bytes(signer)
        out = Path(args.out or f"rulepack-{args.version or ''}.rpk".replace("-.", "-"))
        made = rulepack.build(Path(args.rules), out, None, args.version, codes_dir=Path(args.codes),
                              manuals_dir=Path(args.manuals), signer=signer,
                              link_hosts=[x.strip() for x in Path(args.link_hosts).read_text(encoding="utf-8").splitlines()
                                          if x.strip() and not x.startswith("#")] if args.link_hosts else None)
        pub_path = out.with_name("rulepack-signing.pub")
        pub_path.write_bytes(pub)
        if new:
            print(f"[서명 키 생성] {key_path} — 인터넷망 PC 에만 두십시오(반출 금지)")
        print(f"[빌드 완료] {made} + 공개키 {pub_path}")
        print(f"[지문] {rulepack.fingerprint(pub)} — 폐쇄망에서 처음 적용할 때 이 32자리를 입력합니다(같은 USB 의 파일만 믿지 않기 위해)")
        return 0
    if not args.rpk or not args.pub:
        print("오류: 룰팩 파일과 --pub(서명 공개키)가 필요합니다", file=sys.stderr)
        return 2
    pub = Path(args.pub).read_bytes()
    if args.cmd == "verify":
        m = rulepack.verify(Path(args.rpk), pub)
        print(f"[검증 통과] 버전 {m['version']} · 룰 파일 {m['rule_count']}개 · 생성 {m['created']} · 서명 키 지문 {rulepack.fingerprint(pub)}")
        return 0
    try:
        m = rulepack.apply(Path(args.rpk), Path(args.rules), pub, Path(args.codes), Path(args.manuals),
                           confirm_fp=args.confirm_fp or None)
    except rulepack.TrustNeeded as e:
        print(f"[지문 확인 필요] {e}\n  → 인터넷망 출력의 지문과 같으면 --confirm-fp {e.fp} 를 붙여 다시 실행하십시오", file=sys.stderr)
        return 3
    print(f"[적용 완료] 버전 {m['version']} — 룰·에러코드·매뉴얼 교체됨(이전본은 .rpk-transactions 에 보관)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
