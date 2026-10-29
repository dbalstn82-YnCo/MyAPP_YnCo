# -*- coding: utf-8 -*-
"""화면에 값을 넣을 때의 이스케이프 검사 (2026-09-22)

이 제품은 로그 문자열·호스트명·장비명처럼 **바깥에서 들어온 글자**를 화면에 그대로 뿌린다.
한 군데라도 이스케이프가 빠지면 저장형 XSS 가 된다. 사람이 매번 확인할 수 없으니 기계로 잡는다.

  · 화면 대본의 on… 속성(onclick 등) 안에 이스케이프 없는 값이 들어가면 안 된다
  · esc() 는 따옴표까지 막아야 한다(속성이 작은따옴표인 자리가 있다)
  · 서버가 만드는 HTML(로그인·안내 화면)도 같은 규칙
"""
import re
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

# 값이 아니라 반복 번호·내부에서 만든 식별자라 안전한 것들
# jsa() = 속성 안 JS 문자열(2026-10-15): esc 만으로는 &#39; 가 속성 해석 때 ' 로 돌아와 JS 문자열을 빠져나간다 —
# '${esc(x)}' 꼴 자체는 test_ui_api_list.AttrJsStrings 가 막는다. encodeURIComponent 는 ' 를 그대로 두어 뺐다.
SAFE_EXPR = re.compile(r"""^(
      jsa\(.*\) | esc\(.*\)
    | [ij]        | HISTSEL | idx | n
    | \w*[Ii]d    | cid | wrapId | gid
    | JSON\.stringify\(.*\)
    | \d+
)$""", re.X)

HANDLER = re.compile(r'\bon[a-z]+\s*=\s*(["\'])((?:(?!\1).)*)\1')
INTERP = re.compile(r"\$\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}")


class InlineHandlerTests(unittest.TestCase):
    def test_no_unescaped_value_in_event_handlers(self):
        bad = []
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            for m in HANDLER.finditer(src):
                for e in INTERP.finditer(m.group(2)):
                    expr = e.group(1).strip()
                    if SAFE_EXPR.match(expr):
                        continue
                    bad.append(f"{f.name}:{src.count(chr(10), 0, m.start()) + 1}  {expr[:70]}")
        self.assertEqual(bad, [], "이벤트 속성에 이스케이프 없는 값:\n  " + "\n  ".join(bad))

    def test_json_stringify_into_attribute_is_escaped(self):
        """JSON.stringify 는 따옴표를 그대로 뱉는다 — 속성 안에 넣으면 속성이 끊겨 단추가 죽는다."""
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            for m in HANDLER.finditer(src):
                if "JSON.stringify(" in m.group(2):
                    with self.subTest(page=f.name):
                        self.assertIn("esc(JSON.stringify(", m.group(2),
                                      f"{f.name}: JSON.stringify 를 이스케이프 없이 속성에 넣었습니다")


class EscapeHelperTests(unittest.TestCase):
    def test_every_page_escapes_both_quotes(self):
        for f in sorted(GUI.glob("*.html")):
            src = f.read_text(encoding="utf-8")
            # '&amp;' 안에도 ; 가 있어 구분자로 자르면 안 된다 — 정의가 있는 줄 전체를 본다
            for body in [l for l in src.splitlines() if "const esc=" in l]:
                with self.subTest(page=f.name):
                    self.assertIn("&quot;", body, f"{f.name}: esc 가 큰따옴표를 막지 않습니다")
                    self.assertIn("&#39;", body, f"{f.name}: esc 가 작은따옴표를 막지 않습니다")
                    self.assertIn("&lt;", body)
                    self.assertIn("&amp;", body)


class ServerRenderTests(unittest.TestCase):
    """서버가 만드는 HTML — 로그인·안내 화면에 들어가는 값도 이스케이프해야 한다."""

    def test_login_page_escapes_message(self):
        import logtriage.server as S
        src = Path(S.__file__).read_text(encoding="utf-8")
        # 안내문은 html_escape 를 거친다
        self.assertIn("def _notice_html", src)
        blk = src.split("def _notice_html", 1)[1].split("def ", 1)[0]
        self.assertEqual(blk.count("html_escape("), 2, "안내 화면의 제목·본문이 모두 이스케이프돼야 합니다")

    def test_masked_value_is_plain(self):
        """가림 표시(**)가 HTML 로 해석되지 않는 평범한 글자인지."""
        from logtriage.privacy import MASK
        self.assertNotIn("<", MASK)
        self.assertNotIn("&", MASK)


class StoredLogRenderTests(unittest.TestCase):
    """로그 본문이 화면에 들어가는 자리 — 텍스트로만 넣거나 이스케이프해야 한다."""

    def test_log_lines_are_not_written_as_html(self):
        src = (GUI / "ui.html").read_text(encoding="utf-8")
        # 로그 줄(l.text)은 텍스트 목록(L.push)으로만 쓰이고 innerHTML 로 직접 들어가지 않는다
        for m in re.finditer(r"innerHTML\s*=\s*`([^`]*)`", src, re.S):
            self.assertNotIn("${l.text}", m.group(1))
            self.assertNotIn("${c.body}", m.group(1))


if __name__ == "__main__":
    unittest.main()
