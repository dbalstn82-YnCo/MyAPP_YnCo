"""시그니처 룰 로더·매처.

룰은 YAML 파일로 관리한다 (설계서 05장). rules/ 는 룰팩 대상(읽기 전용),
rules-local/ 은 사이트 커스텀 룰로 ID 충돌 시 로컬 룰이 우선한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# YAML 읽기는 yamlsafe.load — C 안전 파서(약 8배 빠름) + 깊이·별칭·크기 한도(C 파서는 깊은 중첩에서 프로세스가 죽는다)

from .rules_anchor import anchor_hit, anchors
from .schema import Event


MATCH_MAX = 3000  # 룰 정규식은 메시지 앞 3,000자(스택트레이스 상단 포함)만 검사 — 대용량 스택트레이스 성능 보호
LEGACY_SCAN = 600  # 기존 도구 변환 룰(단일 라인 설계)은 메시지 앞 600자만
LEARNED_SCAN = 1000  # 학습 룰(현장에서 승인한 정규식)은 앞 1,000자만 — 줄마다 드는 비용에 상한(GPT 3차)


@dataclass
class Rule:
    id: str
    layer: str
    products: list[str]
    pattern: re.Pattern
    severity: str
    category: str
    verdict: str
    immediate: list[str] = field(default_factory=list)   # 즉시 조치 (장애 중)
    short: list[str] = field(default_factory=list)       # 단기 조치 (일~주)
    mid: list[str] = field(default_factory=list)         # 중기 조치 (주~월)
    long: list[str] = field(default_factory=list)        # 장기 조치 (구조 개선)
    correlate: list[dict] = field(default_factory=list)
    source: str = "rulepack"  # rulepack | local
    exclude: re.Pattern | None = None  # 제외 정규식(negative pattern) — 일치하면 판정하지 않음
    anchors: tuple = ()  # 정규식 실행 전 substring 사전 필터(소문자)
    scan: int = MATCH_MAX  # 이 룰이 검사할 메시지 길이
    layers: tuple = ()  # 다중 계층 룰(layer: [sw, was]) — 비어 있으면 layer 하나
    versions: list = field(default_factory=list)  # 적용 버전(확인된 범위)
    version_note: str = ""  # 버전별 메시지 차이·검증 메모
    defer_to_code: bool = False  # 이벤트 코드가 사전에 있으면 물러난다(일반 룰이 구체적 벤더 원인을 가리지 않게 — 룰 학습 3차)
    auxiliary: bool = False  # 보조 판정 — 걸려도 그 줄의 주 판정(사전 조회)을 막지 않는다(예: IIS 30초 이상 5xx 성능)

    def applies_layer(self, layer: str) -> bool:
        return layer in self.layers if self.layers else layer == self.layer

    def matches(self, ev: Event) -> bool:
        if not self.applies_layer(ev.layer):
            return False
        if self.products and ev.product not in self.products and "*" not in self.products:
            return False
        text = ev.message[:MATCH_MAX]
        if not self.pattern.search(text):
            return False
        return not (self.exclude and self.exclude.search(text))


@dataclass
class Match:
    rule: Rule
    event: Event


import threading as _threading
SKIPPED = _threading.local()   # 이 스레드의 마지막 load_rules 가 건너뛴 파일(분석 결과에 '판정 범위 제한'으로 남긴다)


def _load_file(path: Path, source: str) -> list[Rule]:
    """파일 하나가 깨져도(형식 오류·한도 초과·항목 누락) 그 파일만 건너뛴다 — 전에는 하나가 룰 전체 읽기를 멈춰 분석이 안 됐다."""
    try:
        return _load_file_strict(path, source)
    except Exception as e:
        import sys
        sys.stderr.write(f"[rules] {path.name} 건너뜀 — {type(e).__name__}: {str(e)[:160]}\n")
        try:
            SKIPPED.files.append(f"{path.parent.name}/{path.name}")
        except AttributeError:
            SKIPPED.files = [f"{path.parent.name}/{path.name}"]
        return []


def unreadable_files(*dirs) -> list[dict]:
    """읽지 못해 건너뛰는 룰 파일(이름·사유) — 화면에 알리기용."""
    out = []
    for d in dirs:
        if not d or not Path(d).exists():
            continue
        for f in sorted(Path(d).rglob("*.yaml")):
            try:
                _load_file_strict(f, "check")
            except Exception as e:
                out.append({"file": str(f.relative_to(Path(d).parent)), "why": f"{type(e).__name__}: {str(e)[:120]}"})
    return out


RULE_LAYERS = frozenset(("os", "web", "was", "db", "sw"))
RULE_SEVERITIES = frozenset(("critical", "error", "warn", "info"))


def check_rule_fields(e: dict) -> None:
    """계층·심각도·분류는 정해진 값만 — 화면이 이 값을 표 제목·꼬리표로 그리고 분석이 사전 열쇠로 쓴다.
    아무 글이나 받으면 지역 룰 하나로 코드 조회 화면에 스크립트가 들어가고(저장형 XSS) 분석이 KeyError 로 멈춘다(2026-10-15 전수 점검)."""
    from .service import CATEGORY_KO
    lay = e.get("layer")
    lays = lay if isinstance(lay, list) else [lay]
    if not lays or any(not isinstance(x, str) or x not in RULE_LAYERS for x in lays):
        raise ValueError(f"허용되지 않는 계층 — {sorted(RULE_LAYERS)} 중 하나")
    if e.get("severity", "error") not in RULE_SEVERITIES:
        raise ValueError(f"허용되지 않는 심각도 — {sorted(RULE_SEVERITIES)} 중 하나")
    if e.get("category", "etc") not in CATEGORY_KO:
        raise ValueError("허용되지 않는 분류")


def _load_file_strict(path: Path, source: str) -> list[Rule]:
    from .yamlsafe import load as _yload
    rules: list[Rule] = []
    docs = _yload(path.read_text(encoding="utf-8"))
    if docs is None:
        return rules
    # 파일 하나에 rule 단일 또는 rules 리스트 허용
    entries = docs.get("rules") if isinstance(docs, dict) and "rules" in docs else [docs.get("rule", docs)]
    for e in entries:
        check_rule_fields(e)
        lay = e["layer"]
        layers = tuple(lay) if isinstance(lay, list) else ()
        rules.append(Rule(
            id=e["id"],
            layer=lay[0] if isinstance(lay, list) else lay,
            layers=layers,
            products=[p.lower() for p in e.get("product", ["*"])],
            pattern=re.compile(e["match"]["regex"], re.IGNORECASE),
            severity=e.get("severity", "error"),
            category=e.get("category", "etc"),
            verdict=e.get("verdict", e["id"]),
            immediate=e.get("immediate", []),
            short=e.get("short", e.get("actions", [])),  # 구버전 actions는 단기로
            mid=e.get("mid", []),
            long=e.get("long", []),
            correlate=e.get("correlate", []),
            source=source,
            exclude=re.compile(e["exclude"], re.IGNORECASE) if e.get("exclude") else None,
            anchors=anchors(e["match"]["regex"]),
            scan=LEGACY_SCAN if source == "legacy" else LEARNED_SCAN if source == "learned" else MATCH_MAX,
            versions=[str(v) for v in (e.get("versions") or [])],
            version_note=str(e.get("version_note", "") or ""),
            defer_to_code=bool(e.get("defer_to_code", False)),
            auxiliary=bool(e.get("auxiliary", False)),
        ))
    return rules


def _learned_ok(r: Rule, f: Path) -> bool:
    """학습 룰은 안전한 정규식 부분 집합만(learn.unsafe_regex) — 어기면 읽지 않는다(분석기가 멈추지 않게, GPT P0-02)."""
    from .learn import self_test, unsafe_regex
    why = self_test() or unsafe_regex(r.pattern.pattern) or (unsafe_regex(r.exclude.pattern) if r.exclude else "")
    if why:
        import sys
        sys.stderr.write(f"[rules] 학습 룰 {r.id} 건너뜀({f.name}): {why}\n")
    return not why


def _id_clash(by_id: dict, r: Rule, f: Path) -> bool:
    """학습 룰이 이미 읽은 다른 출처의 룰과 ID 가 같으면 읽지 않는다(공식 룰을 학습 룰이 덮지 않게)."""
    old = by_id.get(r.id)
    if old is not None and old.source != "learned":
        import sys
        sys.stderr.write(f"[rules] 학습 룰 {r.id} 건너뜀({f.name}): 같은 ID 의 {old.source} 룰이 있음\n")
        return True
    return False


def _learned_full(n: int, f: Path) -> bool:
    """학습 룰은 읽는 쪽에서도 상한(learn.MAX_LEARNED) — 승인 화면만 막으면 손으로 고친 YAML·룰팩으로 넘칠 수 있다(GPT 9차)."""
    from .learn import MAX_LEARNED
    if n >= MAX_LEARNED:
        import sys
        sys.stderr.write(f"[rules] 학습 룰 상한 {MAX_LEARNED}개를 넘어 {f.name} 의 나머지는 읽지 않음\n")
        return True
    return False


def load_rules(rules_dir: Path, local_dir: Path | None = None) -> list[Rule]:
    SKIPPED.files = []
    by_id: dict[str, Rule] = {}
    n_learned = 0
    for f in sorted(rules_dir.rglob("*.yaml")):
        src = "legacy" if "legacy" in f.parts else "learned" if "learned" in f.relative_to(rules_dir).parts else "rulepack"
        for r in _load_file(f, src):
            if src == "learned":
                if _learned_full(n_learned, f):
                    break
                if not _learned_ok(r, f) or _id_clash(by_id, r, f):
                    continue
                n_learned += 1
            by_id[r.id] = r
    # 학습 룰(화면에서 승인한 것) — 사이트 룰 폴더 옆 rules-learned/. 룰팩을 적용해도 지워지지 않는다(learn.py)
    learned_dir = local_dir.parent / "rules-learned" if local_dir else None
    if learned_dir and learned_dir.exists():
        for f in sorted(learned_dir.rglob("*.yaml")):
            for r in _load_file(f, "learned"):
                if _learned_full(n_learned, f):
                    break
                if _learned_ok(r, f) and not _id_clash(by_id, r, f):
                    by_id[r.id] = r
                    n_learned += 1
    if local_dir and local_dir.exists():
        for f in sorted(local_dir.rglob("*.yaml")):
            for r in _load_file(f, "local"):
                by_id[r.id] = r  # 로컬 룰 우선
    return list(by_id.values())


def candidates(rules: list[Rule], layer: str, product: str) -> list[Rule]:
    return [r for r in rules if r.applies_layer(layer)
            and (not r.products or product in r.products or "*" in r.products)]


def trie_regex(words) -> str:
    """리터럴 목록을 앞부분이 같은 것끼리 묶은 정규식으로(12차 성능) — 파이썬 정규식은 나열 대안을 위치마다 하나씩 시도해
    리터럴 86개 관문이 20만 줄에 1.8초였다. 묶으면 같은 결과로 약 4.7배 빠르다(무작위 대조 시험)."""
    t: dict = {}
    for w in words:
        d = t
        for ch in w:
            d = d.setdefault(ch, {})
        d[""] = True

    def emit(d) -> str:
        if "" in d and len(d) == 1:
            return ""
        opt = "" in d
        alts = [re.escape(ch) + emit(d[ch]) for ch in sorted(k for k in d if k)]
        if len(alts) == 1 and not opt:
            return alts[0]
        body = "(?:" + "|".join(alts) + ")"
        return body + "?" if opt else body
    return emit(t)


def build_prefilter(cand: list[Rule]):
    """(계층, 제품) 후보 룰에 대해 '어느 룰이든 걸릴 가능성' 을 싸게 판정하는 함수를 만든다.
    앵커가 있는 룰은 소문자 substring 검사, 앵커가 없는 룰만 통합 정규식으로 검사한다."""
    anchored = [r.anchors for r in cand if r.anchors]
    loose = [r for r in cand if not r.anchors]
    # 12차 성능 ②: 관문 — 대안마다 '반드시 들어가야 하는' 리터럴 중 가장 긴 것 하나씩을 한 정규식으로.
    # 관문에 아무것도 안 걸리면 어떤 대안도 리터럴을 다 갖출 수 없으므로 앵커 룰은 하나도 걸릴 수 없다(안전한 방향 — 거짓 음성 없음).
    # 정상 줄 대부분이 C 수준 검색 한 번으로 끝난다(전에는 줄마다 룰 수만큼 앵커 검사 — 100MB 에서 3,260만 번).
    gate = None
    lits = {max(br, key=len) for a in anchored for br in a if br}
    if anchored and all(br for a in anchored for br in a):
        try:
            gate = re.compile(trie_regex(lits))
        except re.error:
            gate = None
    master = None
    if loose:
        try:
            master = re.compile("|".join(f"(?:{r.pattern.pattern})" for r in loose), re.IGNORECASE)
        except re.error:
            return lambda text, tl: True  # 통합 정규식 실패 시 안전하게 전부 통과

    def hit(text: str, tl: str) -> bool:
        if gate is None or gate.search(tl):
            for a in anchored:
                if anchor_hit(a, tl):
                    return True
        return master is not None and bool(master.search(text))
    return hit


def match_events(rules: list[Rule], events: list[Event]) -> list[Match]:
    """대용량 대응: (계층, 제품)별 후보 룰 목록을 캐시하고, 룰마다 앵커(필수 리터럴) substring 검사를 통과할 때만
    정규식을 실행한다. 앵커가 없는 룰은 정규식을 그대로 실행한다."""
    out: list[Match] = []
    cache: dict[tuple[str, str], list[Rule]] = {}
    for ev in events:
        key = (ev.layer, ev.product)
        cand = cache.get(key)
        if cand is None:
            cand = cache[key] = candidates(rules, ev.layer, ev.product)
        if not cand:
            continue
        text = ev.message if len(ev.message) <= MATCH_MAX else ev.message[:MATCH_MAX]
        tl = text.lower()
        for r in cand:
            if r.scan >= len(text):
                sub, subl = text, tl
            else:
                sub, subl = text[:r.scan], tl[:r.scan]
            if r.anchors and not anchor_hit(r.anchors, subl):
                continue
            if r.pattern.search(sub) and not (r.exclude and r.exclude.search(sub)):
                ev.tags.append(r.category)
                out.append(Match(rule=r, event=ev))
    return out
