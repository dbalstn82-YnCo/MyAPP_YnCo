# -*- coding: utf-8 -*-
"""홈 단추와 메뉴 설명 말풍선 (2026-09-28)

사용자 지시
  · 로그인 뒤 첫 화면이 대시보드인데 왼쪽 메뉴가 다 펼쳐져 있어 조잡하다 → 기본은 접힘
  · 대시보드를 첫 화면으로 정했으면 **홈으로 돌아가는 단추**가 있어야 한다
  · 마우스를 가져다 대면 그 메뉴가 무엇인지 설명이 떠야 한다

여기서 지키는 것
  ① 홈은 묶음 '밖' 맨 위에 있어야 한다 — 묶음은 머리글 다음 항목만 접으므로,
     묶음 안에 있으면 다 접었을 때 홈까지 사라져 돌아갈 길이 없어진다.
  ② 설명 글은 한 곳(NAV_JS)에만 둔다. 화면마다 복사하면 또 한 곳이 빠진다(게시판 먹통).
  ③ 말풍선이 어디선가 터져도 메뉴는 그대로 쓸 수 있어야 한다.
"""
import re
import sys
import unittest
from pathlib import Path

ENG = Path(__file__).resolve().parents[1]
GUI = ENG / "logtriage" / "gui"
sys.path.insert(0, str(ENG))

import logtriage.server as S  # noqa: E402

ITEM = re.compile(r'<(a|button)\b([^>]*)>(.*?)</\1>', re.S)


def nav_of(name):
    src = (GUI / name).read_text(encoding="utf-8")
    m = re.search(r'<nav class="nav"[^>]*>(.*?)</nav>', src, re.S)
    return m.group(1) if m else None


def pages():
    for f in sorted(GUI.glob("*.html")):
        if nav_of(f.name):
            yield f.name


def label(inner):
    return re.sub(r"<[^>]+>", "", re.sub(r"<svg.*?</svg>", "", inner, flags=re.S)).strip()


def tip_table():
    """NAV_JS 안의 설명 표를 읽어 온다 — 시험이 표를 따로 베껴 두면 같이 썩는다."""
    m = re.search(r"var TIP=\{(.*?)\};var THREF=\{(.*?)\};", S.NAV_JS, re.S)
    assert m, "NAV_JS 에 설명 표(TIP/THREF)가 없습니다"
    tips = dict(re.findall(r"(\w+):'([^']+)'", m.group(1)))
    href = dict(re.findall(r"'([^']+)':'(\w+)'", m.group(2)))
    return tips, href


class HomeButtonTests(unittest.TestCase):
    def test_every_page_has_exactly_one_home(self):
        for name in pages():
            with self.subTest(page=name):
                homes = re.findall(r'<(?:a|button)[^>]*class="home\b[^"]*"', nav_of(name))
                self.assertEqual(len(homes), 1, f"{name}: 홈 단추가 {len(homes)}개입니다")

    def test_home_sits_above_every_group_so_folding_cannot_hide_it(self):
        """묶음을 모두 접어도 홈은 남아야 한다 — 묶음은 머리글 '다음' 항목만 접는다."""
        for name in pages():
            nav = nav_of(name)
            with self.subTest(page=name):
                i = nav.index('class="home')
                j = nav.index('class="grp')
                self.assertLess(i, j, f"{name}: 홈이 묶음 머리글 아래에 있습니다 — 접으면 사라집니다")

    def test_home_goes_to_the_home_screen(self):
        """2026-09-29 포털 개편 — 홈은 '내가 할 일' 화면이고, 예전 대시보드는 [전체 현황] 이다."""
        for name in pages():
            nav = nav_of(name)
            tag = re.search(r'<(?:a|button)[^>]*class="home[^"]*"[^>]*>', nav).group(0)
            with self.subTest(page=name):
                if name == "ui.html":        # 한 화면 안에서 탭을 옮기는 화면
                    self.assertIn('data-go="home"', tag)
                else:
                    self.assertIn('href="/"', tag, f"{name}: 홈이 첫 화면을 가리키지 않습니다")
                    self.assertIn('data-href="/"', tag)

    def test_home_says_it_is_home(self):
        for name in pages():
            nav = nav_of(name)
            m = re.search(r'<(a|button)[^>]*class="home[^"]*"[^>]*>(.*?)</\1>', nav, re.S)
            with self.subTest(page=name):
                self.assertIn("홈", label(m.group(2)), f"{name}: 홈 단추에 '홈' 이 없습니다")

    def test_overall_view_is_listed_once_and_not_confused_with_home(self):
        """홈(내 일)과 전체 현황(지표판)은 다른 화면이다 — 각각 한 번씩만 있어야 한다."""
        for name in pages():
            nav = nav_of(name)
            with self.subTest(page=name):
                n = len([1 for m in ITEM.finditer(nav) if label(m.group(3)) == "전체 현황"])
                self.assertEqual(n, 1, f"{name}: 전체 현황 항목이 {n}개입니다")
                h = len([1 for m in ITEM.finditer(nav) if label(m.group(3)) == "홈"])
                self.assertEqual(h, 1, f"{name}: 홈 항목이 {h}개입니다")

    def test_overall_view_sits_in_the_analysis_group(self):
        for name in pages():
            nav = nav_of(name)
            with self.subTest(page=name):
                i = nav.index("전체 현황")
                j = nav.index('data-grp="analysis"')
                k = nav.index('data-grp="knowledge"')
                self.assertTrue(j < i < k, f"{name}: 전체 현황이 분석 묶음 안에 없습니다")


class FoldDefaultTests(unittest.TestCase):
    """기본은 접힘 — 처음 보는 사람에게 메뉴 열넷을 한꺼번에 들이대지 않는다."""

    def test_unset_means_folded(self):
        self.assertIn("return v===null?true:v==='1'", S.NAV_JS,
                      "저장된 값이 없을 때 펼친 채로 시작합니다(기본은 접힘이어야 합니다)")

    def test_storage_failure_also_starts_folded(self):
        blk = S.NAV_JS[S.NAV_JS.index("function rd(g){"):]
        self.assertTrue(blk.startswith("function rd(g){try{var v=localStorage.getItem(key(g));"
                                       "return v===null?true:v==='1'}catch(e){return true}}"),
                        "localStorage 를 못 쓰는 환경에서 기본값이 다릅니다")

    def test_last_version_memory_cannot_keep_the_menu_open(self):
        """지난 판은 기본이 '펼침' 이었다 — 그때 머리글을 한 번이라도 눌러 본 브라우저에는
        '펼침' 이 저장돼 있어, 기본값만 바꾸면 그 사람 화면은 여전히 다 펼쳐져 보인다.
        (사용자가 실제로 겪은 일: "또 메뉴 전체가 펼쳐져 있네")

        지우지 않고 **저장 이름표를 바꾼다**(GPT 교차 검토). 지우다 하나라도 실패하면
        그 묶음만 펼쳐진 채 '끝났다' 고 표시돼, 고치려던 증상이 그대로 다시 난다."""
        js = S.NAV_JS
        self.assertIn("var FOLD_SCHEMA='2';", js, "저장 형식 번호가 없습니다")
        self.assertIn("return 'lt.fold.'+FOLD_SCHEMA+'.'+", js,
                      "저장 이름표에 형식 번호가 들어가지 않습니다 — 옛 값을 그대로 읽습니다")
        self.assertNotIn("localStorage.removeItem", js,
                         "사용자가 고른 것을 지우고 있습니다 — 이름표만 바꾸면 됩니다")

    def test_fold_schema_is_not_tied_to_the_build(self):
        """이 번호를 빌드마다 올리면 판을 올릴 때마다 사용자의 사이드바 선택이 날아간다.

        접힘 정책을 다시 강제로 재정렬하거나 묶음 이름표 체계가 바뀔 때만 올린다."""
        import logtriage
        self.assertNotIn(logtriage.BUILD, S.NAV_JS,
                         "저장 형식 번호가 빌드 번호와 이어져 있습니다")

    def test_a_folded_group_is_still_openable(self):
        """접힌 채로 시작하니, 펴는 손잡이가 반드시 달려 있어야 한다(아니면 조용한 먹통)."""
        self.assertIn("g.h.addEventListener('click',t)", S.NAV_JS)
        self.assertIn("aria-expanded", S.NAV_JS)

    def test_current_screen_group_is_opened_anyway(self):
        self.assertIn("if(g.f&&g.it.some(cur_))g.f=false", S.NAV_JS,
                      "지금 보고 있는 화면이 든 묶음은 펴 줘야 합니다")


class SidebarScrollTests(unittest.TestCase):
    """묶음을 다 펼치면 화면보다 길어진다 — 그때 아래 항목이 잘려 보이지 않았다.

    .app 이 height:100vh · overflow:hidden 이라 사이드바에는 스크롤이 없었다
    (사용자 지시 2026-09-28: "메뉴를 전부다 펼쳤을때 아래 메뉴가 안보인다").
    """

    def test_menu_list_scrolls(self):
        for bit in ("flex:1 1 auto", "min-height:0", "overflow-y:auto"):
            with self.subTest(bit=bit):
                self.assertIn(bit, S.NAV_JS, f"메뉴 목록이 스크롤되지 않습니다: {bit}")
        self.assertIn(".side .nav{flex:1 1 auto;min-height:0;overflow-y:auto", S.NAV_JS)

    def test_only_the_list_scrolls_not_the_whole_sidebar(self):
        """로고와 아래쪽 사용자 카드·꼬리말은 제자리에 있어야 한다."""
        self.assertIn(".side{overflow:hidden}", S.NAV_JS)

    def test_narrow_window_keeps_its_own_layout(self):
        """좁은 창에서는 사이드바가 가로줄이 된다 — 세로 스크롤 규칙을 걸면 안 된다."""
        i = S.NAV_JS.index(".side .nav{flex:1 1 auto")
        head = S.NAV_JS[:i]
        j = head.rindex("@media(")          # 이 규칙을 감싸는 가장 가까운 미디어 질의
        self.assertTrue(head[j:].startswith("@media(min-width:761px){"),
                        f"스크롤 규칙이 넓은 창에만 걸려 있지 않습니다: {head[j:j+40]}")
        self.assertNotIn("}", head[j + len("@media(min-width:761px){"):].replace(
            ".side{overflow:hidden}", "").replace(
            ".side .logo,.side .lt-me,.side .foot{flex-shrink:0}", ""),
            "스크롤 규칙 앞에서 미디어 질의가 닫혔습니다")

    def test_home_stays_put_while_the_list_scrolls(self):
        """목록이 스크롤되면 홈도 같이 밀려 올라간다 — '어디서든 한 번에 홈' 이 깨진다."""
        self.assertIn(".side .nav .home{position:sticky;top:0", S.NAV_JS,
                      "홈 단추가 스크롤에 같이 밀려 올라갑니다")
        self.assertIn("var(--side-bg,#14212B)", S.NAV_JS,
                      "붙여 둔 홈 뒤로 항목이 비쳐 보입니다")

    def test_current_screen_is_pulled_into_view(self):
        """스크롤이 생기면 지금 보고 있는 항목이 화면 밖에 있을 수 있다.

        GPT 교차 검토: scrollIntoView 는 '보이게 하려고 스크롤 가능한 조상을 모두' 움직인다.
        여기서 움직여야 할 것은 메뉴 목록 하나뿐이므로 .nav 의 scrollTop 만 손댄다."""
        blk = S.NAV_JS[S.NAV_JS.index("function fold("):S.NAV_JS.index("function tips(")]
        self.assertNotIn("scrollIntoView", blk,
                         "문서까지 흔들 수 있는 방식으로 스크롤합니다")
        self.assertIn("n.scrollTop-=(top-er.top)", blk, "현재 항목을 끌어 오지 않습니다")
        self.assertIn("n.scrollTop+=(er.bottom-nr.bottom)", blk)
        self.assertIn("try{if(!n.dataset.ltSeen)", blk, "실패하면 메뉴까지 멈춥니다")

    def test_pulling_into_view_happens_once_and_only_on_wide_windows(self):
        """접기·펼치기를 할 때마다 끌어 오면, 머리글을 만지는 사람을 엉뚱한 자리로 데려간다.
        좁은 창에는 이 스크롤 자체가 없으므로 JS 도 같이 막는다(CSS 만 막으면 비대칭)."""
        blk = S.NAV_JS[S.NAV_JS.index("function fold("):S.NAV_JS.index("function tips(")]
        self.assertIn("n.dataset.ltSeen='1'", blk, "처음 한 번만 하는 표시가 없습니다")
        self.assertIn("window.matchMedia('(min-width:761px)').matches", blk,
                      "좁은 창에서도 스크롤을 건드립니다")

    def test_fixed_areas_do_not_get_squeezed(self):
        """화면이 아주 낮으면 로고·사용자 카드·꼬리말이 눌리거나 잘린다(GPT 지적)."""
        self.assertIn(".side .logo,.side .lt-me,.side .foot{flex-shrink:0}", S.NAV_JS)

    def test_sticky_home_does_not_cover_what_we_scrolled_to(self):
        self.assertIn("scroll-padding-top:52px", S.NAV_JS,
                      "끌어 온 항목이 붙여 둔 홈 아래로 숨습니다")

    def test_scrolling_the_list_closes_the_tooltip(self):
        self.assertIn("on_(n,'scroll',hide,{passive:true})", S.NAV_JS)


class TooltipTests(unittest.TestCase):
    def test_tips_live_in_nav_js_only(self):
        self.assertIn("function tips(", S.NAV_JS, "말풍선이 공용 대본에 없습니다")
        for name in pages():
            with self.subTest(page=name):
                self.assertNotIn("lt-tip", (GUI / name).read_text(encoding="utf-8"),
                                 f"{name}: 말풍선이 화면에 복사돼 있습니다 — 한 곳에만 둡니다")

    def test_tips_are_wired_to_boot(self):
        self.assertIn("nav();fold();tips()", S.NAV_JS, "말풍선을 붙이는 호출이 없습니다")
        self.assertEqual(S.NAV_JS.count("nav();fold();tips()"), 2,
                         "권한 반영 뒤(늦은 호출) 말풍선을 다시 붙이지 않습니다")

    def test_every_menu_item_has_an_explanation(self):
        tips, href = tip_table()
        for name in pages():
            nav = nav_of(name)
            for m in ITEM.finditer(nav):
                at, inner = m.group(2), m.group(3)
                if 'class="grp' in at:
                    continue
                ic = re.search(r'data-icon="([^"]+)"', inner)
                go = re.search(r'data-go="([^"]+)"', at)
                dh = re.search(r'data-href="([^"]*)"', at)
                key = (ic.group(1) if ic else
                       go.group(1) if go else
                       href.get(dh.group(1) if dh else "", ""))
                with self.subTest(page=name, item=label(inner)[:14]):
                    self.assertIn(key, tips,
                                  f"{name}: '{label(inner)}' 에 설명이 없습니다(표 이름 {key!r})")
                    self.assertGreater(len(tips[key]), 12, "설명이 이름만 되풀이하는 수준입니다")

    def test_href_table_covers_every_sidebar_address(self):
        tips, href = tip_table()
        for name in pages():
            for dh in re.findall(r'data-href="([^"]+)"', nav_of(name)):
                with self.subTest(page=name, href=dh):
                    self.assertIn(dh, href, f"{name}: {dh} 가 설명 표에 없습니다")

    def test_group_heading_tells_what_it_is_for(self):
        """큰 항목(묶음)에 마우스를 대면 '무엇을 하는 곳인지' 가 먼저 나와야 한다.

        항목 이름만 늘어놓으면 처음 보는 사람에게는 설명이 아니다(사용자 지시 2026-09-28)."""
        m = re.search(r"var GRP=\{(.*?)\};", S.NAV_JS, re.S)
        self.assertIsNotNone(m, "묶음 안내문 표(GRP)가 없습니다")
        grp = dict(re.findall(r"(\w+):'([^']+)'", m.group(1)))
        ids = set()
        for name in pages():
            ids |= set(re.findall(r'data-grp="([a-z]+)"', nav_of(name)))
        for i in sorted(ids):
            with self.subTest(grp=i):
                self.assertIn(i, grp, f"묶음 '{i}' 에 안내문이 없습니다")
                self.assertGreater(len(grp[i]), 10, f"묶음 '{i}' 안내문이 너무 짧습니다")
        self.assertIn("head.setAttribute('data-tip',GRP[", S.NAV_JS)

    def test_group_heading_also_lists_what_is_inside(self):
        """접혀 있을 때 안에 무엇이 있는지도 둘째 줄로 알려 준다."""
        self.assertIn("'담긴 항목: '", S.NAV_JS)
        self.assertIn("' · 눌러서 접기·펼치기'", S.NAV_JS)
        self.assertIn("list.push(ttxt(el))", S.NAV_JS, "담긴 항목 이름을 모으지 않습니다")
        self.assertIn("(t2?'<i>'+esc(t2)+'</i>':'')", S.NAV_JS, "둘째 줄을 그리지 않습니다")
        self.assertIn(".lt-tip i{", S.NAV_JS, "둘째 줄 모양이 없습니다")

    def test_shows_on_hover_and_on_keyboard_focus(self):
        for ev in ("mouseover", "mouseleave", "focusin", "focusout"):
            with self.subTest(ev=ev):
                self.assertIn("on_(n,'%s'" % ev, S.NAV_JS,
                              f"말풍선이 {ev} 을 받지 않습니다")

    def test_native_title_is_removed_so_it_does_not_show_twice(self):
        self.assertIn("el.removeAttribute('title')", S.NAV_JS,
                      "브라우저 기본 말풍선과 두 겹으로 뜹니다")

    def test_tooltip_never_swallows_a_click(self):
        self.assertIn("pointer-events:none", S.NAV_JS,
                      "말풍선이 마우스를 먹으면 그 아래 메뉴를 누를 수 없습니다")

    def test_escape_and_scroll_hide_it(self):
        self.assertIn("e.key==='Escape'", S.NAV_JS)
        self.assertIn("on_(window,'scroll',hide,true)", S.NAV_JS)

    def test_failure_is_not_fatal(self):
        blk = S.NAV_JS[S.NAV_JS.index("function tips("):]
        # tips() 다음에는 상단 바(GST/gnb) 가 이어진다 — 거기까지 끊어서 본다
        blk = blk[:blk.index("var GST=") if "var GST=" in blk else blk.index("function boot(")]
        self.assertIn("catch(e){", blk, "말풍선이 터지면 메뉴까지 멈춥니다")
        # throw 는 딱 한 곳 — 손잡이를 도로 뗀 뒤 바깥 catch 로 넘기는 자리뿐이고,
        # 바깥은 경고만 찍고 삼킨다. 밖으로 새어 나가면 화면 대본 전체가 멈춘다.
        self.assertEqual(blk.count("throw"), 1, "예외가 여러 갈래로 새 나갑니다")
        self.assertTrue(blk.rstrip().endswith(
            "console.warn('LogTriage: 메뉴 설명 말풍선 실패 — 메뉴는 그대로 씁니다',e)}}"),
            "마지막에 삼키는 자리가 없습니다 — 예외가 밖으로 나갑니다")

    def test_it_closes_when_the_window_or_screen_changes(self):
        """GPT 교차 검토(2026-09-28): 1280px 에서 띄운 말풍선이 480px 로 줄였다 늘리면
        옛 자리에 되살아난다. 화면이 바뀌는 모든 길목에서 닫는다."""
        for ev in ("resize", "hashchange", "popstate", "pagehide"):
            with self.subTest(ev=ev):
                self.assertIn("on_(window,'%s',hide)" % ev, S.NAV_JS,
                              f"{ev} 에서 말풍선을 닫지 않습니다")
        self.assertIn("visibilitychange", S.NAV_JS)

    def test_it_does_not_point_at_a_vanished_item(self):
        """0.11초 기다리는 사이에 항목이 사라질 수 있다(권한 반영으로 지워진다)."""
        self.assertIn("if(el.isConnected===false||!n.contains(el)){hide();return}", S.NAV_JS)

    def test_assistive_tech_learns_which_menu_it_describes(self):
        self.assertIn("el.setAttribute('aria-describedby','lt-tip')", S.NAV_JS)
        self.assertIn("cur.removeAttribute('aria-describedby')", S.NAV_JS,
                      "설명 연결을 떼지 않으면 사라진 말풍선을 계속 가리킵니다")

    def test_half_wired_state_cannot_set_in(self):
        """손잡이를 반쯤 달고 예외가 나면 '다 달았다' 표시만 남아 영영 반쪽으로 굳는다.

        표시는 맨 끝에 세우고, 실패하면 단 것을 도로 뗀다 — 그래야 다시 불러도 두 벌이 안 된다."""
        js = S.NAV_JS
        i = js.index("function on_(t,ev,fn,cap)")
        blk = js[i:js.index("function boot(")]
        self.assertLess(blk.index("on_(n,'mouseover'"), blk.index("n.dataset.ltTip='1'"),
                        "완료 표시를 손잡이보다 먼저 세우고 있습니다")
        self.assertIn("removeEventListener(a[1],a[2],a[3])", blk,
                      "실패했을 때 단 손잡이를 도로 떼지 않습니다")

    def test_moving_between_items_drops_the_previous_link(self):
        """A→B 로 옮길 때 A 의 aria-describedby 가 남으면 안 된다."""
        self.assertIn("if(el===cur)return;hide();cur=el;", S.NAV_JS)

    def test_narrow_window_has_no_tooltip(self):
        """좁은 창에서는 손가락으로 만지므로 말풍선이 걸리적거린다."""
        self.assertIn("@media(max-width:760px){.lt-tip{display:none}}", S.NAV_JS)


class HomeStyleTests(unittest.TestCase):
    def test_home_is_visually_marked_in_one_place(self):
        self.assertIn(".nav .home{", S.NAV_JS, "홈 단추 모양이 공용 CSS 에 없습니다")
        self.assertIn(".nav .home.on{", S.NAV_JS,
                      "대시보드에 있을 때 홈이 활성으로 보이지 않습니다")


if __name__ == "__main__":
    unittest.main()
