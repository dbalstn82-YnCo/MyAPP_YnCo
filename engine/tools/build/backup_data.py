"""설치본 자료를 일관된 사본으로 보관 — 다음 차수 첫 기동 전에 되돌릴 때 쓸 DB(GPT 68차 P0). 원본은 읽기 전용으로 연다.
(12차: 그동안 임시 폴더에 두던 bk*.py 가 임시 폴더 정리로 사라져 도구 폴더로 옮김)
사용: python tools/build/backup_data.py <이름>   예) 지식11차-12차첫기동전  → deploy/local/backup/data.<이름>"""
import shutil
import sqlite3
import sys
from pathlib import Path

L = Path(__file__).resolve().parents[2] / "deploy" / "local"
src, dst = L / "dist", L / "backup" / f"data.{sys.argv[1]}"
if dst.exists():
    sys.exit(f"{dst} 가 이미 있습니다 — 다른 이름을 주십시오")
n = s = 0
for p in sorted((src / "data").rglob("*")) + [src / "conf" / x for x in ("auth.json",) if (src / "conf" / x).exists()]:
    if not p.is_file() or p.name.endswith(("-wal", "-shm")):
        continue
    d = dst / p.relative_to(src)
    d.parent.mkdir(parents=True, exist_ok=True)
    if p.read_bytes()[:16] == b"SQLite format 3\x00":
        a = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
        b = sqlite3.connect(str(d))
        a.backup(b)
        b.close()
        a.close()
        s += 1
    else:
        shutil.copy2(p, d)
    n += 1
print(f"보관: 파일 {n}개(SQLite {s}개 backup API) → {dst}")
