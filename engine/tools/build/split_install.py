# -*- coding: utf-8 -*-
"""설치판 zip 을 28MB 조각으로 분할하고 MERGE-README.txt(SHA256 포함)를 쓴다.
사용: python tools/build/split_install.py [YYYY.MM.DD] [설명 한 줄]"""
import hashlib, sys, time
from pathlib import Path
R = Path(r"C:\Users\dbals\Desktop\로그수집기\반출"); DATE = sys.argv[1] if len(sys.argv) > 1 else time.strftime("%Y.%m.%d")
NOTE = sys.argv[2] if len(sys.argv) > 2 else ""
Z = R / f"LogTriage-Linux-Install-{DATE}.zip"; D = R / "분할"; D.mkdir(exist_ok=True)
for old in D.glob("LogTriage-Linux-Install-*.zip.0*"):
    old.unlink()
data = Z.read_bytes(); sha = hashlib.sha256(data).hexdigest(); part = 28 * 1024 * 1024; n = 0
for i in range(0, len(data), part):
    n += 1; (D / f"{Z.name}.{n:03d}").write_bytes(data[i:i + part])
patch = R / f"logtriage-linux-patch-{DATE}-py311.zip"
psha = hashlib.sha256(patch.read_bytes()).hexdigest() if patch.exists() else "(없음)"
(D / "MERGE-README.txt").write_text(f"""{Z.name} 분할본 합치기 ({n}조각) — {DATE} {NOTE}

Linux 서버에서(조각 {n}개를 한 폴더에 둔 뒤):
  cat {Z.name}.00* > {Z.name}
  sha256sum {Z.name}        # 아래 값과 같아야 함
  unzip -t {Z.name} | tail -1   # No errors detected

SHA256: {sha}
크기: {len(data)} bytes

새 설치: unzip -o {Z.name} && mv LogTriage-Linux-{DATE} log_svr && cd log_svr && bash run.sh        # 기본 포트 8088
기존 서버 갱신(패치): unzip -o {patch.name} && bash logtriage-linux-patch/apply_patch.sh /home/yms/log_svr   # 기본 포트 8088
패치 zip SHA256: {psha}
""", encoding="utf-8")
print("parts", n, "install", sha, "patch", psha)
