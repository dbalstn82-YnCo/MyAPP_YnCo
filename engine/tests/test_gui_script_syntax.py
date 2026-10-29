# -*- coding: utf-8 -*-
"""화면 대본에 **끊긴 글자열**이 없는지 본다 (2026-10-01)

왜 생겼나. 화면 코드를 고치면서 줄바꿈 표기(역슬래시 n)가 **진짜 줄바꿈**이 되어
글자열 안으로 들어갔다.

    const want=prompt('새 사이트 ID 를 적으십시오.
    '
      +'지금 신원: '+now

브라우저는 "Uncaught SyntaxError: Invalid or unexpected token" 을 내고 그 화면의 대본이
**통째로 죽었다** — [통합 현황] 이 '연결 확인 중' 에서 멈췄다.

그런데 시험 789건이 전부 통과했다. 화면 시험이 **HTML 에 글자가 있는지만** 봤기 때문이다.
글자는 다 있었다. 깨진 것은 문법이었다.

[이 시험이 하지 않는 것]
자바스크립트를 해석하지 않는다. 처음엔 따옴표를 세어 보려 했는데 정규식 리터럴 안의
따옴표까지 세느라 멀쩡한 파일을 전부 잘못 잡았다. **엉뚱하게 우는 검사는 곧 꺼진다.**
그래서 **실제로 났던 꼴 하나만** 좁혀서 본다 — 어떤 줄이 따옴표를 홀수 번 두어 열린 채
끝나고, **바로 다음 줄이 같은 따옴표로 시작**하는 자리. 멀쩡한 코드에서는 거의 나오지
않고, 이 결함에서는 반드시 나온다.
"""
import re
import unittest
from pathlib import Path

GUI = Path(__file__).resolve().parents[1] / "logtriage" / "gui"
SCRIPT = re.compile(r"<script\b[^>]*>(.*?)</script>", re.S | re.I)
QUOTES = ("'", chr(34))


def split_strings(js: str):
    """줄 가운데서 끊긴 글자열 — (줄 번호, 줄) 목록."""
    lines = js.splitlines()
    bad = []
    for n, line in enumerate(lines):
        if n + 1 >= len(lines):
            break
        nxt = lines[n + 1].lstrip()
        if not nxt or nxt[0] not in QUOTES:
            continue
        q = nxt[0]
        cnt, i = 0, 0
        while i < len(line):          # 앞에 역슬래시가 붙은 따옴표는 세지 않는다
            if line[i] == chr(92):
                i += 2
                continue
            if line[i] == q:
                cnt += 1
            i += 1
        if cnt % 2 == 1:              # 열린 채 줄이 끝났다
            bad.append((n + 1, line.strip()[:90]))
    return bad


class GuiScriptTests(unittest.TestCase):

    def test_no_string_is_split_across_lines(self):
        files = sorted(GUI.glob("*.html"))
        self.assertTrue(files, "화면 파일을 못 찾았습니다")
        for f in files:
            with self.subTest(file=f.name):
                for js in SCRIPT.findall(f.read_text(encoding="utf-8")):
                    bad = split_strings(js)
                    self.assertFalse(
                        bad, f"{f.name}: 글자열이 줄 가운데서 끊겼습니다 — "
                             + "; ".join(f"{n}행 {t}" for n, t in bad[:3]))

    def test_the_check_catches_the_real_defect(self):
        """막는 시험은 **일부러 깨뜨려 봐야** 믿을 수 있다 — 실제로 났던 꼴 그대로 넣는다."""
        broken = chr(10).join([
            "  const want=prompt('새 사이트 ID 를 적으십시오.",
            "'",
            "    +'지금 신원: '+now);",
        ])
        self.assertTrue(split_strings(broken), "진짜 결함을 못 잡습니다")

    def test_it_does_not_cry_over_normal_code(self):
        """엉뚱하게 우는 검사는 곧 꺼진다 — 멀쩡한 꼴을 모아 본다."""
        ok = chr(10).join([
            "const a = 'hello';",
            "const esc = s => s.replace(/[&<>" + chr(34) + "']/g, c => M[c]);",
            "const h = `여러 줄",
            "  템플릿은 괜찮다`;",
            "const j = 'a'",
            "  + 'b';",
            "const k = {x: 'y'};",
        ])
        self.assertEqual(split_strings(ok), [])


if __name__ == "__main__":
    unittest.main()
