"""화면 값 출처 시험(2026-10-15 아이디어 3) — 화면 대본의 ${…} 중 가장 안쪽 값 하나하나가
  ① esc()/jsa()/da()/linkOrText() 등 이스케이프 함수로 감싸였거나 ② 숫자·고정 글이 분명하거나
  ③ 사람이 출처를 따져 '안전'으로 적어 둔 목록(tests/ui_interp_reviewed.txt)에 있어야 한다.
새 화면 값이 이 셋 어디에도 없으면 실패 — 지난 전수 점검(에이전트가 사람처럼 읽음)을 기계로 굳힌다.
목록에 새로 넣을 때는 값이 어디서 오는지(로그·업로드·다른 사용자·장비면 안 됨) 확인한 뒤에만.
"""
import re
import unittest
from collections import Counter
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
REVIEWED = Path(__file__).with_name("ui_interp_reviewed.txt")
INNER = re.compile(r"\$\{([^{}`]*)\}")
SAFE = re.compile(r"""^\s*(
      (esc|jsa|da|linkOrText|encodeURIComponent|Number|String\(Number|Math\.\w+|fmt\w*|pct|num|sevPill0?|sevChip|catPill|kindPill|pill|sev|stPill|fmtB|ago|fmtAt)\(.*\)(\|\|-?\d+)?
    | -?\d+(\.\d+)?
    | "[^"]*" | '[^']*'
    | [\w.]+\.(length|toFixed\(\d\)|toLocaleString\(\))
)\s*$""", re.X)


def scan() -> Counter:
    c = Counter()
    for p in sorted(GUI.glob("*.html")):
        for m in INNER.finditer(p.read_text(encoding="utf-8")):
            e = " ".join(m.group(1).split())
            if not SAFE.match(e):
                c[(p.name, e)] += 1
    return c


def load_reviewed() -> set:
    out = set()
    if REVIEWED.exists():
        for line in REVIEWED.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                f, e = line.split("\t")[:2]
                out.add((f, e))
    return out


TAGS = ("num", "cond", "local", "const", "server")


class InterpReview(unittest.TestCase):
    def test_every_bare_value_is_reviewed(self):
        new = sorted(k for k in scan() if k not in load_reviewed())
        self.assertEqual(new, [], "출처를 따지지 않은 화면 값 — esc() 로 감싸거나, 안전함을 확인한 뒤 ui_interp_reviewed.txt 에 넣으십시오:\n"
                         + "\n".join(f"{f}\t{e}" for f, e in new[:40]))

    def test_review_list_has_no_dead_entries(self):
        live = set(scan())
        dead = sorted(k for k in load_reviewed() if k not in live)
        self.assertEqual(dead, [], "더는 화면에 없는 검토 항목 — 목록에서 지우십시오(목록이 낡으면 검토가 뜻을 잃는다)")

    def test_every_entry_has_a_source_tag(self):
        """3차 아이디어 3: 줄마다 출처 태그 — 왜 안전한지 적어 둔다(num·cond·local·const·server)."""
        bad = [ln[:80] for ln in REVIEWED.read_text(encoding="utf-8").splitlines()
               if ln.strip() and not ln.startswith("#") and (len(ln.split("\t")) != 3 or ln.split("\t")[2] not in TAGS)]
        self.assertEqual(bad, [], "출처 태그가 없거나 틀린 줄")

    def test_known_dangerous_values_are_not_listed(self):
        """2026-10-15 전수 점검에서 실제 XSS 였던 값은 목록에 들어갈 수 없다."""
        for f, e in load_reviewed():
            self.assertNotRegex(e, r"LY\[[a-z]\.layer\]", f"{f}: {e}")   # 계층 이름은 반드시 esc(…)


if __name__ == "__main__":
    unittest.main()
