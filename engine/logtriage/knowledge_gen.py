"""지식 세대 기록(9차 ⑦ · GPT 70·71차) — 배포 폴더 루트의 knowledge-gen.json 하나에 세 지식 폴더(rules·errorcodes·manuals)의
내용 지문을 함께 적는다. 지식 출시(tools/build/knowledge_release.py)와 룰팩 적용(rulepack.apply)이 **둘 다 이 파일을 통째로 바꿔치기**한다.

기동 때(server.release_leftover): 기록이 있으면 세 폴더의 지금 지문과 대조 —
  · 셋 다 같음 → 정상   · 하나라도 다름 → 기동 거부(GPT 72차 P0-01: 처음엔 '셋 다 다름'은 띠로만 알렸으나, 한 폴더는 신판·한 폴더는 손으로
    바꾼 상태도 셋 다 다름이 되어 통과했다. 제품 안에서 세 폴더를 바꾸는 길은 출시·룰팩뿐이고 둘 다 기록을 갱신하므로 어긋남은 모두 바깥 변경)
  · 복구는 룰팩 재적용 또는 개발 PC 의 knowledge_release 뿐 — 현장에서 손으로 고친 지식을 '봉인'해 인정하는 명령은 일부러 두지 않는다
  · 기록 없음 → 옛 설치 방식 → 통과(단 매니페스트에 gen_era 가 있으면 = 기록이 사라짐 → 거부, GPT 71차)
폴더별 표식 파일을 두지 않는 까닭: 룰팩은 포함된 폴더만 통째로 바꾸므로 폴더 안 표식은 현장 룰팩 적용 때 일부만 사라져 거짓 '섞임'이 된다(10-19 설계 중 발견).
실수·중단 감지용이지 보안 경계가 아니다(배포 폴더 쓰기 권한자는 기록도 바꿀 수 있다).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

FILE = "knowledge-gen.json"
DIRS = ("rules", "errorcodes", "manuals")
SUFFIX = (".yaml", ".yml", ".json", ".txt", ".md")


def dir_hash(d: Path) -> str:
    h = hashlib.sha256()
    if d.is_dir():
        for f in sorted(d.rglob("*")):
            if f.is_file() and "__pycache__" not in f.parts and f.suffix.lower() in SUFFIX:
                h.update(f.relative_to(d).as_posix().encode() + b"\0" + hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()


def write_gen(base: Path, source: str) -> dict:
    base = Path(base)
    rec = {"at": time.strftime("%Y-%m-%d %H:%M:%S"), "source": source, "dirs": {d: dir_hash(base / d) for d in DIRS}}
    tmp = base / (FILE + ".lt-new")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False, indent=1))
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, base / FILE)
    return rec


def check_gen(base: Path) -> str:
    p = Path(base) / FILE
    if not p.exists():
        try:   # GPT 71차: 출시가 세대 기록을 남긴 설치(매니페스트 gen_era)인데 기록이 없다 = 지워졌거나 덮였다 — 옛 설치로 오인하지 않는다
            era = json.loads((Path(base) / "knowledge-manifest.json").read_text(encoding="utf-8")).get("gen_era")
        except (OSError, ValueError, AttributeError):
            era = False
        if era:
            return ("지식 세대 기록(knowledge-gen.json)이 없습니다 — 이 설치는 세대 기록을 남기는 출시로 깔렸는데 기록이 사라져 "
                    "판정 지식이 섞였는지 알 수 없어 띄우지 않습니다.\n개발 PC 에서 knowledge_release 로 다시 내보내거나 룰팩을 다시 적용하십시오")
        return ""
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
        want = rec["dirs"]
    except (OSError, ValueError, KeyError, TypeError):
        return "지식 세대 기록(knowledge-gen.json)이 깨져 읽을 수 없습니다 — 판정 지식이 섞였는지 알 수 없어 띄우지 않습니다"
    diff = [d for d in DIRS if dir_hash(Path(base) / d) != want.get(d)]
    if diff:
        return (f"지식 폴더 {', '.join(diff)} 이(가) 세대 기록({rec.get('source', '')}, {rec.get('at', '')})과 다릅니다 — 출시·룰팩 밖에서 바뀌어 "
                "판정 지식이 섞였을 수 있어 띄우지 않습니다.\n개발 PC 에서 knowledge_release 로 다시 내보내거나 룰팩을 다시 적용하십시오")
    return ""
