"""18차(2026-10-23):
 ① 로그인 대문 혹평 — '글이 너무 많고, 그림으로 기능이 연상되지 않는다' → GPT 시안 115 · 그림 116, 클로드 상호 검증
 ② 마스터 아이디어 — '가입한 인원의 부서가 같으면 그룹화' → [사용자 · 권한] · [이메일 계정] 표 부서별 묶기"""
from __future__ import annotations

import base64
import hashlib
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
sys.path.insert(0, str(ENGINE))

ART_SHA = "a29f63fdab322b9b2c4f055be17c6a8ef426ffa0a9fb8710c8e7b481f983e68d"   # GPT 116 흐름 그림(base64 글 그대로의 지문)


def gui(name):
    return (GUI / name).read_text(encoding="utf-8")


def visible_text(h: str) -> str:
    b = h.split("<body", 1)[1]
    b = re.sub(r"<(style|script|svg)[\s\S]*?</\1>", "", b)
    t = re.sub(r"<[^>]+>", " ", b)
    return re.sub(r"%[A-Z_]+%", "", t)


class LoginLanding(unittest.TestCase):
    def test_one_line_pitch_and_four_keys(self):
        h = gui("login.html")
        self.assertIn("<h1><em>로그</em>를 넣으면, 원인부터 보고서까지</h1>", h)
        self.assertNotRegex(h, r'<div class="pitch">[\s\S]{0,400}<p[ >]')          # 제목 아래 설명 문단 없음
        keys = re.search(r'<ul class="keys" aria-label="주요 기능">([\s\S]*?)</ul>', h).group(1)
        self.assertEqual(re.findall(r"<span>([^<]+)</span>", keys), ["장애 판정", "실시간 관제", "보고서 자동 작성", "부서 공유"])
        self.assertEqual(len(re.findall(r'<i class="k[1-4]"><svg', keys)), 4)

    def test_text_budget(self):
        """대문(서버가 끼우는 로그인 칸 제외)의 보이는 글은 120자 이하 — 혹평의 핵심이 '글이 너무 많다'였다."""
        n = len(re.sub(r"\s+", "", visible_text(gui("login.html"))))
        self.assertLessEqual(n, 120, n)

    def test_seal_one_line_detail_in_tooltip(self):
        h = gui("login.html")
        self.assertIn('<div class="seal" title="서버 키로 한 번 섞고(HMAC-SHA256)', h)
        self.assertIn("비밀번호는 암호화해 저장합니다</div>", h)

    def test_flow_art_embedded_and_key_art_kept(self):
        h = gui("login.html")
        m = re.search(r'<img class="art" alt="" src="data:image/jpeg;base64,([^"]+)">', h)
        self.assertTrue(m)
        self.assertEqual(hashlib.sha256(m.group(1).encode()).hexdigest(), ART_SHA)
        raw = base64.b64decode(m.group(1))
        self.assertTrue(raw.startswith(b"\xff\xd8") and raw.endswith(b"\xff\xd9"))   # 잘리지 않은 JPEG
        self.assertIn('<img class="art art2" alt="" src="data:image/jpeg;base64,', h)   # 비밀번호 화면 열쇠 그림은 그대로
        self.assertIn("radial-gradient(closest-side,#000 72%,rgba(0,0,0,0) 100%)", h)  # 그림 네 변에서 0 — 네모 경계 없음

    def test_mobile_fixes(self):
        h = gui("login.html")
        self.assertIn(".stage{grid-template-columns:minmax(0,1fr);", h)          # 375 화면 오른쪽 잘림(1fr→글 최소 폭 400)
        self.assertIn(".art2{display:none}body.key .art{display:none}", h)       # 좁은 화면에서 그림 두 장 겹침
        self.assertIn("body.key .art2{display:block;flex:none;width:58%;max-width:250px;margin:6px auto 2px}", h)
        self.assertIn(".art{flex:none;width:100%;max-width:260px;margin:6px auto 0;display:block}", h)   # GPT 117 P2-02

    def test_login_form_note_moved_to_tooltip(self):
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        form = src[src.index("def _email_form"):src.index("def _join_form")]
        self.assertNotIn('<p class="note">', form)
        self.assertIn('title="{a["max_fails"]}회 틀리면 {a["lock_minutes"]}분간 잠깁니다"', form)


class DeptGroups(unittest.TestCase):
    def test_wired_on_both_tables(self):
        h = gui("admin.html")
        for want in ('<input type="checkbox" id="ug"> 부서별 묶기', '<input type="checkbox" id="ag"> 부서별 묶기',
                     "dgPaint($('users'),list,9,userRow,'u',!!q,", "dgPaint($('accts'),list,7,acctRow,'a',!!q,",
                     "$('usub').textContent=`${list.length} / ${U.users.length}명`+dgCount(list);",
                     "if(!DG[tag]){tb.innerHTML=list.map(rowFn).join('');return}"):          # 끄면 17차 표 그대로
            self.assertIn(want, h)

    def test_group_key_matches_server_share_rule(self):
        """화면 묶음 = 실제 공유 묶음: 서버 _same_dept 는 앞뒤 공백만 떼고 글자 그대로 비교, 확인 전(dept_self)·빈 부서는 공유 안 함."""
        h = gui("admin.html")
        self.assertIn("function dgKey(r){return String(r.dept||'').trim()}", h)
        src = (ENGINE / "logtriage" / "server.py").read_text(encoding="utf-8")
        body = src[src.index("def _same_dept"):src.index("def _other_owner")]
        self.assertIn('mine = str((self._u or {}).get("dept") or "").strip()', body)
        self.assertIn('cache[owner] = "" if u.get("dept_self") else str(u.get("dept") or "").strip()', body)
        self.assertIn("return bool(cache[owner]) and cache[owner] == mine", body)
        self.assertIn("share=k?rs.filter(r=>!r.dept_self&&!r.disabled).length:0", h)   # 확인 전·중지는 공유 수에서 뺀다(GPT 117 P1-01)
        self.assertIn("pill('중지 '+off+'명','mute')", h)
        self.assertIn("부서가 없으면 분석을 공유하지 않습니다", h)

    def test_escaping_and_storage_guard(self):
        h = gui("admin.html")
        block = h[h.index("function dgPaint("):h.index("function renderUsers(){")]
        for m in re.finditer(r"\+\s*(k|x|r\.\w+)\s*\+", block):                  # 부서 이름을 날것으로 붙이지 않는다
            self.fail("이스케이프 없이 붙인 값: " + m.group(0))
        self.assertIn("esc(k||'부서 미지정')", block)
        self.assertIn("sim.map(esc).join(', ')", block)
        self.assertIn("try{DG.u=localStorage.getItem('lt.admin.dg.u')!=='0'", h)   # 저장소 막힌 창에서도 그려진다

    def test_group_logic_in_node(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        h = gui("admin.html")
        fns = "\n".join(re.search(r"^function %s\(.*$" % n, h, re.M).group(0) for n in ("dgKey", "dgNorm", "dgCount"))
        js = fns + r"""
const out=[dgKey({dept:'  운영1팀 '}), dgKey({}), dgNorm('운영 1팀')===dgNorm('운영1팀'), dgNorm('Infra Team')===dgNorm('infrateam'),
  dgNorm('운영1팀')===dgNorm('운영2팀'), dgCount([{dept:'가'},{dept:' 가'},{dept:'나'},{dept:''}]), dgCount([{dept:''}])];
console.log(JSON.stringify(out));"""
        r = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        import json
        self.assertEqual(json.loads(r.stdout), ["운영1팀", "", True, True, False, " · 부서 2곳", ""])


    def test_counter_example_in_node(self):
        """GPT 117 반례: 같은 부서에 확인·사용 1 / 중지 1 / 확인 전 1 → 등록 3명, 공유 0(혼자라 '서로' 아님), 미지정은 맨 끝.
        또 부서 이름의 꺾쇠는 머리 줄에 글자로만 나온다."""
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        h = gui("admin.html")
        pick = lambda rx: re.search(rx, h, re.M).group(0)
        src = "\n".join([pick(r"^const esc=.*$"), pick(r"^const ROLE=.*$"), pick(r"^const pill=.*$"),
                         "const DG={u:true,a:true,closed:{}};function dgSave(){}",
                         pick(r"^function dgKey\(.*$"), pick(r"^function dgNorm\(.*$"), pick(r"^function dgCount\(.*$"),
                         h[h.index("function dgPaint("):h.index("function renderUsers(){")]])
        js = src + r"""
const users=[{login:'a',dept:'운영1팀',role:'operator'},{login:'b',dept:'운영1팀',role:'viewer',disabled:1},
  {login:'c',dept:'운영1팀',role:'viewer',dept_self:true},{login:'d',dept:'',role:'viewer'},{login:'e',dept:'<b>x',role:'admin'},
  {login:'f',dept:'개발2팀',role:'viewer'},{login:'g',dept:'개발2팀',role:'operator'}];
var U={users},A=null;const tb={innerHTML:'',querySelectorAll:()=>[]};
dgPaint(tb,users,9,r=>'<tr data-l="'+r.login+'"><td>'+r.login+'</td></tr>','u',false,'');
const heads=tb.innerHTML.split('<tr class="dgrp">').slice(1).map(s=>s.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim());
console.log(JSON.stringify(heads));"""
        r = subprocess.run([node, "-e", js], capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        import json
        heads = json.loads(r.stdout)
        self.assertEqual(len(heads), 4)
        self.assertTrue(heads[0].startswith("&lt;b&gt;x 1명"), heads[0])          # 꺾쇠는 이스케이프
        self.assertTrue(heads[1].startswith("개발2팀 2명") and "이 2명은 서로 분석" in heads[1], heads[1])
        self.assertTrue(heads[2].startswith("운영1팀 3명"), heads[2])
        self.assertIn("신청 부서·확인 전 1명", heads[2])
        self.assertIn("중지 1명", heads[2])
        self.assertIn("함께 공유되는 사람이 아직 없습니다", heads[2])
        self.assertNotIn("서로 분석", heads[2])
        self.assertTrue(heads[3].startswith("부서 미지정 1명") and "부서가 없으면 분석을 공유하지 않습니다" in heads[3], heads[3])


if __name__ == "__main__":
    unittest.main()
