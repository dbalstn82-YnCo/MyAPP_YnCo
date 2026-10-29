"""룰·코드 YAML 을 안전하게 빨리 읽는다(2026-10-14).

- 빠르게: LibYAML C 안전 파서(CSafeLoader). 없으면 파이썬 안전 파서. 둘 다 임의 객체를 만들지 않는다.
- 안전하게: C 파서는 아주 깊게 중첩된 문서(예: '[' 5,000개)에서 예외 대신 **프로세스가 통째로 죽는다**
  (스택 넘침 — 파이썬 파서는 RecursionError). 그래서 실제로 읽기 전에 재귀 없는 이벤트 단계로
  깊이·별칭 수·크기를 먼저 센다. 실제 룰·코드 파일의 최대 깊이는 4, 별칭은 거의 없다.
- 이 함수가 거부하거나 형식이 틀린 파일은 부르는 쪽이 그 파일만 건너뛴다(파일 하나가 분석 전체를 멈추지 않게).
"""
from __future__ import annotations

import yaml

LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
MAX_ALIASES = 200


class YamlRejected(ValueError):
    """크기·깊이·별칭 한도를 넘은 YAML."""


def load(text: str):
    if len(text) > MAX_BYTES:
        raise YamlRejected(f"파일이 너무 큽니다({len(text):,}자 > {MAX_BYTES:,})")
    depth = aliases = 0
    for ev in yaml.parse(text, Loader=LOADER):
        if isinstance(ev, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
            depth += 1
            if depth > MAX_DEPTH:
                raise YamlRejected(f"중첩이 {MAX_DEPTH}단을 넘습니다")
        elif isinstance(ev, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
            depth -= 1
        elif isinstance(ev, yaml.AliasEvent):
            aliases += 1
            if aliases > MAX_ALIASES:
                raise YamlRejected(f"별칭(*)이 {MAX_ALIASES}개를 넘습니다")
    return yaml.load(text, Loader=LOADER)
