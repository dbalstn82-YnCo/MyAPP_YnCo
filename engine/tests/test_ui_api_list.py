"""화면이 부르는 API 이름이 화면의 위임 목록(api())에 다 있는지 — 2026-10-15 27차 반영 때 [지문 등록] 버튼이
목록에 없는 custom_form_pin 을 불러 조용히 아무 일도 안 했다(화면·서버 어긋남 유형). 목록의 이름은 앱(Api)·서버(API_NAMES)에도 있어야 한다."""
import re
import sys
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))

UI = (ENGINE / "logtriage" / "gui" / "ui.html").read_text(encoding="utf-8")
# 데스크톱 창에서만 쓰는 것(파일 고르기·폴더 열기 등) — 서버형은 브라우저 내려받기·업로드로 대신한다
DESKTOP_ONLY = {"pick_logs", "pick_report_dir", "pick_form_file", "pick_style_source", "open_folder", "save_html", "apply_rulepack"}


def ui_list() -> set:
    m = re.search(r"const api=\(\)=>\(\{.*?Object\.fromEntries\(\[(.*?)\]\.map", UI, re.S)
    return set(re.findall(r'"(\w+)"', m.group(1)))


class UiApiList(unittest.TestCase):
    def test_every_call_is_listed(self):
        called = set(re.findall(r"api\(\)\.(\w+)\(", UI))
        self.assertFalse(called - ui_list(), f"화면이 부르지만 api() 목록에 없는 이름: {sorted(called - ui_list())}")

    def test_listed_names_exist_in_app_and_server(self):
        from logtriage.gui.app import Api
        from logtriage.server import API_NAMES, ServerApi
        names = ui_list()
        self.assertFalse({n for n in names if not hasattr(Api, n) and not hasattr(ServerApi, n)}, "앱·서버 어디에도 없는 이름")
        missing = {n for n in names - DESKTOP_ONLY if n not in API_NAMES}
        self.assertFalse(missing, f"서버 API 목록에 없는 이름: {sorted(missing)}")


class AttrJsStrings(unittest.TestCase):
    """onclick 같은 속성 안에 JS 문자열을 '${esc(x)}' 로 넣으면 &#39; 가 속성 해석 때 ' 로 돌아와 이름·로그 글의 따옴표로
    스크립트가 끼어든다(2026-10-15 발견: 로그 검색어·서식 이름). 속성 안 JS 문자열은 jsa() 로만 넣는다."""

    def test_no_quoted_esc_in_gui_pages(self):
        import html
        import json
        for p in (ENGINE / "logtriage" / "gui").glob("*.html"):
            s = p.read_text(encoding="utf-8")
            self.assertNotRegex(s, r"'\$\{esc\(", f"{p.name}: 속성 안 JS 문자열에 esc 를 쓰고 있습니다 — jsa() 로")
        # jsa 가 만드는 값: 속성 해석(html.unescape) 뒤 JSON 문자열 하나 — 원래 글과 같고 따옴표로 빠져나가지 못한다
        for v in ("a');window.__pwn=1;('", 'x"y\\z', "</script><b>", "줄\n바꿈"):
            enc = json.dumps(v, ensure_ascii=False)
            enc = "".join({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}.get(c, c) for c in enc)
            self.assertEqual(json.loads(html.unescape(enc)), v)


class LinkGuard(unittest.TestCase):
    """data-href 를 따라가는 처리기는 모두 공통 검사 LT_OKHREF 를 거친다 — 같은 출처는 정규화된 주소로, 바깥은
    https 이면서 승인된 제조사·공식 문서 도메인(links.LINK_HOSTS)일 때만. javascript:·data:·'/\\evil'·계정 붙은 주소는 막는다
    (GPT 29·30·31차, 아이디어 1). 검사 결과로 받은 '정규화된 주소'로 이동한다."""

    def _run(self, cases):
        import json
        import shutil
        import subprocess
        from logtriage.links import okhref_js
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        js = ("var window={};var document={currentScript:null,createElement:function(){return {}}};"
              "var location={href:'http://127.0.0.1:8897/x',origin:'http://127.0.0.1:8897'};" + okhref_js() +
              "var c=" + json.dumps(list(cases)) + ";console.log(JSON.stringify(c.map(function(x){return window.LT_OKHREF(x)})))")
        out = subprocess.run([node, "-e", js], capture_output=True, text=True, timeout=30)
        return dict(zip(cases, json.loads(out.stdout)))

    def test_guard_behaviour_in_node(self):
        cases = {"/nms": "http://127.0.0.1:8897/nms", "#forms": "http://127.0.0.1:8897/x#forms", "?inc=1": "http://127.0.0.1:8897/x?inc=1",
                 "https://docs.oracle.com/x": "https://docs.oracle.com/x", "https://DOCS.Oracle.com/y": "https://docs.oracle.com/y",
                 "https://sub.docs.oracle.com/z": "https://sub.docs.oracle.com/z",
                 "https://evil-docs.oracle.com.evil.example/": "", "https://notdocs.oracle.com.example/": "",
                 "https://evil.example/": "", "http://docs.oracle.com/x": "", "https://user:pw@docs.oracle.com/": "",
                 "https://github.com/x": "", "//evil.example/p": "", "/\\evil.example": "", "\\\\evil.example": "",
                 "http:\\\\evil.example": "", " javascript:alert(1)": "", "java\tscript:alert(1)": "", "\x01javascript:alert(1)": "",
                 "data:text/html,<b>": "", "JaVaScRiPt:1": "", "vbscript:1": "", "": ""}
        got = self._run(cases)
        for k, want in cases.items():
            with self.subTest(url=repr(k)):
                self.assertEqual(got[k], want)

    def test_every_handler_is_guarded(self):
        from logtriage.server import NAV_JS
        srcs = {p.name: p.read_text(encoding="utf-8") for p in (ENGINE / "logtriage" / "gui").glob("*.html")}
        srcs["_palette.js"] = (ENGINE / "logtriage" / "gui" / "_palette.js").read_text(encoding="utf-8")
        srcs["NAV_JS"] = NAV_JS
        self.assertIn("window.LT_OKHREF=function", NAV_JS)
        for name, s in srcs.items():
            # 검사 전 원래 주소로 바로 가는 꼴 금지(검사 결과의 정규화된 주소로만 이동)
            raw = re.findall(r"location\.href=(a\.dataset\.href|e\.target\.dataset\.href)\b|window\.open\(a\.dataset\.href\b", s)
            self.assertEqual(raw, [], f"{name}: 검사 전 주소로 바로 이동합니다")
            if re.search(r"location\.href=h\b|window\.open\(h\b", s) and re.search(r"getAttribute\(['\"]data-href['\"]\)", s):
                self.assertIn("(h=(window.LT_OKHREF", s, f"{name}: h 를 검사 결과로 바꾸지 않고 이동합니다")
            if re.search(r"closest\(['\"]a\[data-href\]|getAttribute\(['\"]data-href['\"]\)|function goHref", s):
                with self.subTest(page=name):
                    self.assertIn("LT_OKHREF", s, f"{name}: data-href 처리기에 공통 링크 검사가 없습니다")


class NoInlineHandlers(unittest.TestCase):
    """아이디어 2(2026-10-15): 인라인 이벤트(onclick= 등)는 엄격한 CSP 에서 돌지 않는다 — data-click/change/input + ACT 위임만.
    쓰인 동작 이름은 그 화면의 ACT 에 모두 있어야 한다(없으면 단추가 조용히 아무 일도 안 한다)."""

    def test_no_inline_event_attributes(self):
        from logtriage.server import NAV_JS, SHIM
        for p in (ENGINE / "logtriage" / "gui").glob("*.html"):
            s = p.read_text(encoding="utf-8")
            with self.subTest(page=p.name):
                self.assertNotRegex(s, r"<[a-zA-Z][^<>]*\son[a-z]+\s*=", f"{p.name}: 인라인 이벤트 속성")
        for name, s in (("NAV_JS", NAV_JS), ("SHIM", SHIM)):
            self.assertNotRegex(s, r"<[a-zA-Z][^<>]*\son[a-z]+\s*=", name)

    def test_every_action_name_is_defined(self):
        for p in (ENGINE / "logtriage" / "gui").glob("*.html"):
            s = p.read_text(encoding="utf-8")
            used = set(re.findall(r'data-(?:click|change|input)="(\w+)"', s))
            if not used:
                continue
            m = re.search(r"const ACT=\{(.*?)\};", s, re.S)
            self.assertIsNotNone(m, p.name)
            keys = set(re.findall(r"(?:^|[,{\s])(\w+):", m.group(1)))
            with self.subTest(page=p.name):
                self.assertFalse(used - keys, f"{p.name}: ACT 에 없는 동작 {sorted(used - keys)}")


class TrustedTypesPolicy(unittest.TestCase):
    """3차 아이디어 2: Trusted Types 기본 정책 — HTML 대입이 지나는 정화 함수(Node 로 실제 실행)."""

    def test_clean(self):
        import json
        import shutil
        import subprocess
        from logtriage.links import TT_JS
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        self.assertFalse(any(ord(c) < 32 for c in TT_JS), "정규식에 제어 문자(\\b·\\2 깨짐)")
        cases = {'<b onclick="x()">a</b>': "<b>a</b>", "<img src=x onerror=alert(1)>": '<img src="x">',
                 "<script>alert(1)</script>ok": "alert(1)ok", '<a href="javascript:alert(1)">j</a>': "<a>j</a>",
                 '<a href="&#106;avascript:alert(1)">e</a>': "<a>e</a>", '<a href="jav&#x09;ascript:alert(1)">e</a>': "<a>e</a>",
                 '<a href=" &#14;javascript:alert(1)">e</a>': "<a>e</a>", '<a href="javascript&colon;alert(1)">e</a>': "<a>e</a>",
                 "<IMG SRC=JaVaScRiPt:alert(1)>": "<IMG>", "<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>": "<svg></svg>",
                 '<svg><a xlink:href="javascript:alert(1)"><text>x</text></a></svg>': "<svg><a><text>x</text></a></svg>",
                 '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;"></iframe>': "", "<IFRAME SRC=x></iframe>": "", "<base href=//e>": "",
                 "<button formaction=javascript:alert(1)>b</button>": "<button>b</button>",
                 "<details open ontoggle=alert(1)>d</details>": "<details open>d</details>",
                 '<div style="background:url(javascript:alert(1))">s</div>': "<div>s</div>", '<a href="data:text/html,<b>">d</a>': "<a>d</a>",
                 "<!-- <img src=x onerror=alert(1)> -->ok": "ok", "<img src=x onerror\x0c=alert(1)>": '<img src="x">',
                 '<img src="data:image/svg+xml;base64,AA">': '<img src="data:image/svg+xml;base64,AA">',   # 아이콘은 그대로
                 '<span class="pill" style="color:red" data-click="go" data-args="[&quot;x&quot;]" title="a>b">한글 &lt;b&gt;</span>':
                     '<span class="pill" style="color:red" data-click="go" data-args="[&quot;x&quot;]" title="a&gt;b">한글 &lt;b&gt;</span>',
                 '<svg viewBox="0 0 24 24"><path d="M3 11.5 12 4"/></svg>': '<svg viewBox="0 0 24 24"><path d="M3 11.5 12 4"/></svg>',
                 '<tr><td class="num">1</td></tr><br/><input type="checkbox" checked>': '<tr><td class="num">1</td></tr><br/><input type="checkbox" checked>',
                 # GPT 38차: 허용 목록·DOM Clobbering·바깥 CSS url·네임스페이스·원문 요소 mXSS
                 '<img name="cookie" src="a.png">': '<img src="a.png">', '<img id="getElementById">': "<img>",
                 '<a id="LT_OKHREF" href="/x">l</a>': '<a href="/x">l</a>', '<input name="submit" value="1">': '<input value="1">',
                 '<a id="toString">t</a>': "<a>t</a>", '<div id="existing" class="c">e</div>': '<div id="existing" class="c">e</div>',
                 '<input type="radio" name="kind" value="a">': '<input type="radio" name="kind" value="a">',
                 '<div style="background:url(https://evil.example/x.png)">c</div>': "<div>c</div>",
                 '<div style="background:u\\72l(https://e/x)">c</div>': "<div>c</div>", "<div style=\"@import 'x'\">c</div>": "<div>c</div>",
                 '<rect fill="url(#g_dash)" rx="8"/>': '<rect fill="url(#g_dash)" rx="8"/>', '<rect fill="url(https://e/x#a)"/>': "<rect/>",
                 "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>": '&lt;mtext&gt;<table>&lt;mglyph&gt;<img src="x">',
                 "<svg><foreignObject><iframe src=javascript:alert(1)></iframe></foreignObject></svg>": "<svg></svg>",
                 '<svg xmlns="http://www.w3.org/1999/xhtml"><use href="https://e/x.svg#a"/></svg>': "<svg></svg>",
                 '<svg xmlns="http://www.w3.org/2000/svg"></svg>': '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
                 '<textarea><img title="</textarea><img src=x onerror=alert(1)>"></textarea>':
                     '<textarea><img title="&lt;/textarea&gt;&lt;img src=x onerror=alert(1)&gt;"></textarea>',
                 '<noscript><p title="</noscript><img src=x onerror=alert(1)>">':
                     '<p title="&lt;/noscript&gt;&lt;img src=x onerror=alert(1)&gt;">',
                 '<img alt="x onerror=alert(1)>': '&lt;img alt="x onerror=alert(1)&gt;', "원인 <IP> 확인": "원인 &lt;IP&gt; 확인",
                 '<b onclick=x>a</b onclick=y>': "<b>a</b>", "<svg><![CDATA[><img src=x onerror=alert(1)>]]></svg>": '<svg>&lt;![CDATA[&gt;<img src="x">]]&gt;</svg>'}
        js = ("function Element(){};function HTMLCollection(){};function HTMLFormElement(){};HTMLFormElement.prototype={submit:1,action:1,method:1};"
              "var document={cookie:'',title:'',getElementById:function(){}};"
              "var created;var window={trustedTypes:{createPolicy:function(n,p){created=p;return p}},LT_OKHREF:function(){},existing:new Element(),name:''};"
              "var trustedTypes=window.trustedTypes;"
              "var location={href:'http://h/x'};" + TT_JS + ";var f=created.createHTML;console.log(JSON.stringify(" + json.dumps(list(cases))
              + ".map(function(x){var a=f(x);return [a,f(a)]})))")
        got = dict(zip(cases, json.loads(subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8", timeout=30).stdout)))
        for k, want in cases.items():
            with self.subTest(html=k):
                self.assertEqual(got[k][0], want)
                self.assertEqual(got[k][1], got[k][0], "두 번 소독하면 결과가 달라진다(GPT 39차 — 멱등)")

    def test_policy_is_first_and_enforced(self):
        from logtriage.server import Handler
        self.assertIn("require-trusted-types-for 'script'", Handler._CSP)
        self.assertIn("trusted-types default", Handler._CSP)


class NoControlChars(unittest.TestCase):
    """소스·시험에 백스페이스 같은 제어 문자가 섞이면 정규식 \\b 가 깨져 시험이 아무것도 못 찾고 그냥 통과한다
    (2026-10-15 발견: 시험 3곳이 이렇게 비어 있었다)."""

    def test_no_backspace_or_stray_controls(self):
        bad = []
        for root in ("logtriage", "tests", "tools"):
            for p in (ENGINE / root).rglob("*"):
                if p.suffix in (".py", ".html", ".js", ".css", ".yaml", ".yml", ".json") and "__pycache__" not in p.parts:
                    t = p.read_text(encoding="utf-8", errors="replace")
                    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", t):
                        bad.append(str(p.relative_to(ENGINE)))
        self.assertEqual(bad, [], "제어 문자가 든 파일")


if __name__ == "__main__":
    unittest.main()
