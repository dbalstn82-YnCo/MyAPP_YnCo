"""16차(2026-10-22 현장 사용자 피드백 + GPT 106차):
 ① 자산 관리 '미리 점검' 문구     ② 모니터링 포트 노출(목록·상세·응답)   ③ 자산 보기 수량(번호 열 기준)
 ④ 예약 작업 등록일시            ⑤ 관리 화면 시연 자료 탭 삭제          ⑥ 예약·자동화 안내 그림 크기
 ⑦ [1장 요약 복사] → 무엇이 복사됐는지 보여 줌   ⑧ 저장 경로 — 업로드 원본 정리(관리자)
 GPT 106: 스스로 적은 부서는 공유 기준 아님 · 근거 묶음 대표=가장 심각 · 업로드 2xx 확인 · 이퀄라이저 임계치 비율 정렬"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
GUI = ENGINE / "logtriage" / "gui"
sys.path.insert(0, str(ENGINE))


def gui(name):
    return (GUI / name).read_text(encoding="utf-8")


class Screens(unittest.TestCase):
    def test_1_asset_preview_wording(self):
        h = gui("inventory.html")
        for gone in ("우리 기준으로 읽어 보기", "읽은 자리에서 지웁니다</b>", "알아 두실 것 — ", "항목 id 는 바뀌지 않습니다"):
            self.assertNotIn(gone, h)
        for want in ("자산 목록 파일 미리 점검", "미리보기 · 저장 안 됨", "채워진 항목과 빠진 항목을 먼저 보여 드립니다",
                     "비밀번호는 표에 적지 마십시오", "점검 항목 설정", "if(sc) sc.title='칸 이름(비밀번호·인증키·토큰 등)을 보고"):
            self.assertIn(want, h)

    def test_2_port_hidden_on_screen(self):
        h = gui("nms.html")
        self.assertNotIn("'TCP : '+t.port", h)
        self.assertNotIn("'TCP 포트 '+t.port", h)
        self.assertIn("${t.method==='tcp'?'TCP':'ICMP'} · ${t.interval}초마다", h)
        for want in ('id="pmask">●●●●●', 'id="pshow" aria-pressed="false">보기', "(자산 권한 필요)", "PSHOW===t.id",
                     "if(id!==selected) PSHOW=null"):
            self.assertIn(want, h)

    def test_3_sheet_counts_by_number_column(self):
        h = gui("inventory_view.html")
        for want in ("function numCol(s)", "function sheetStat(s)", "번호 없는 줄만 보기", "${sheetStat(s).rec.toLocaleString()}",
                     "표 전체 ${DOC.total_rows.toLocaleString()}줄(제목·합계·빈 줄 포함)", "class=\"nonumtag\">번호 없음"):
            self.assertIn(want, h)
        self.assertNotIn("${(s.rows.length-s.header_rows).toLocaleString()}", h)
        # GPT 107 P1-02: 번호 붙은 합계 줄은 자산 아님 · 번호 중복·빠진 번호 표시
        for want in ("const SUMROW=/^(합\\s*계|소\\s*계|총\\s*계)$/;", "noNum=x=>NC&&!isRec(x[2],NC);", "const nn=NC&&!isRec(vals,NC);",
                     "번호 중복 ${f(ST.dup)}", "빠진 번호 ${f(ST.gap)}"):
            self.assertIn(want, h)

    def test_4_job_registered_column(self):
        h = gui("automation.html")
        self.assertEqual(h.count("<th>상태</th><th>등록일시</th><th></th>"), 2)
        self.assertIn("j.created?esc(regAt(j.created))", h)
        self.assertIn('colspan="6" class="empty">예약 작업이 없습니다', h)

    def test_6_intro_image_bounded(self):
        h = gui("automation.html")
        self.assertIn(".introbd img{width:100%;max-width:300px;max-height:220px", h)
        self.assertIn(".introbd>.flow{grid-column:1 / -1}", h)
        self.assertIn('<dialog id="pgdlg"', h)              # 삭제 확인은 제품 안 확인 창(시안 ③)
        self.assertNotIn("if(!confirm(what+", h)

    def test_7_summary_copy_shows_what_was_copied(self):
        h = gui("ui.html")
        self.assertIn("📋 요약 글 복사", h)
        self.assertNotIn(">1장 요약 복사<", h)
        g = h[h.index("async function copyOnePage(){"):h.index("/* ── 분석 진행 패널")]
        for want in ('m.querySelector(".cbt").textContent=txt', "Ctrl</kbd>+<kbd>V", "파일은 만들지 않습니다", 'data-click="copyClose"'):
            self.assertIn(want, g)
        self.assertIn('data-href="/automation#out"', h)
        self.assertIn("${autoLink()}", h)

    def test_8_purge_control_admin_only(self):
        h = gui("automation.html")
        self.assertIn("p.key==='uploads'&&S.can_admin&&p.count>0?PURGE_HTML:''", h)
        import logtriage.server as S
        src = Path(S.__file__).read_text(encoding="utf-8")
        self.assertIn('"/api/automation/purge_uploads"):\n            return "admin"', src)

    def test_gpt106_evidence_and_upload_and_eq(self):
        ui = gui("ui.html")
        self.assertIn("if((SEVRANK[SEVK[t.severity]]??9)<(SEVRANK[SEVK[x.t.severity]]??9)) x.t=t;", ui)
        self.assertIn('<tr data-ref="${esc(x.t.raw_ref||"")}" data-eid="${esc(x.t.eid||"")}" tabindex="0"', ui)
        self.assertIn('class="repfail" role="alert"', ui)
        import logtriage.server as S
        src = Path(S.__file__).read_text(encoding="utf-8")
        self.assertIn("if((x.status<200||x.status>299)&&!(j&&j.error))", src)
        self.assertIn("p.setAttribute('aria-busy','true')", src)
        live = gui("nms_live.html")
        self.assertIn(".sort((a,b)=>risk(b)-risk(a));", live)


class Contrast(unittest.TestCase):
    """GPT 106 P2: 이번에 새로 쓴 작은 글자색이 흰·연한 바탕에서 4.5:1 을 넘는지(WCAG AA) 실제 계산."""

    @staticmethod
    def ratio(a, b):
        def lum(h):
            c = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
            return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]
        l1, l2 = sorted((lum(a), lum(b)), reverse=True)
        return (l1 + 0.05) / (l2 + 0.05)

    def test_new_text_colors_contrast(self):
        for fg, bg in (("#4B5563", "#EEF1F5"), ("#6B7280", "#FFFFFF"), ("#6B7280", "#F7F9FC"), ("#8A4B00", "#F7F9FC"),
                       ("#8A5A00", "#FDEBB8"), ("#1A5FD0", "#F2F7FF"), ("#B42318", "#FFFFFF"), ("#1F5FCB", "#F4F8FF")):
            with self.subTest(fg=fg, bg=bg):
                self.assertGreaterEqual(self.ratio(fg, bg), 4.5)
        css = gui("_ds.css") + gui("inventory_view.html") + gui("automation.html") + gui("ui.html")
        for used in ("#1A5FD0", "#4B5563", "#6B7280", "#8A4B00", "#8A5A00", "#B42318", "#1F5FCB"):
            self.assertIn(used, css)


class ScriptSyntax(unittest.TestCase):
    """16차: 파이썬 치환에서 '\\n' 이 실제 줄바꿈으로 들어가 예약·자동화 화면 스크립트 전체가 멈춘 일이 있었다(화면에서 발견).
    문자열 검사만으로는 못 잡는다 → 모든 화면의 <script> 를 실제 JS 해석기(node)로 문법 검사한다."""

    def test_all_page_scripts_parse(self):
        import shutil
        import subprocess
        node = shutil.which("node")
        if not node:
            self.skipTest("node 없음")
        js = ("const fs=require('fs');let bad=[];for(const f of process.argv.slice(1)){const h=fs.readFileSync(f,'utf8');"
              "[...h.matchAll(/<script[^>]*>([\\s\\S]*?)<\\/script>/g)].forEach((x,i)=>{try{new Function(x[1])}catch(e){bad.push(f+'#'+i+' '+e.message)}})}"
              "console.log(JSON.stringify(bad))")
        files = [str(p) for p in sorted(GUI.glob("*.html"))]
        out = subprocess.run([node, "-e", js, *files], capture_output=True, text=True, encoding="utf-8", timeout=60)
        self.assertEqual(json.loads(out.stdout.strip() or "[]"), [], out.stderr[:500])


class PortMask(unittest.TestCase):
    def test_mask_assets_drops_port_without_asset_permission(self):
        from logtriage import server as S

        class H:
            _u = {"role": "viewer", "asset_sites": []}

            def _local_site(self):
                return "LOCAL"
        data = {"targets": [{"address": "10.0.0.5", "port": 10022, "snmp_port": 161, "method": "tcp", "interval": 30}]}
        out = S.Handler._mask_assets(H(), data)["targets"][0]
        self.assertIsNone(out["port"])
        self.assertIsNone(out["snmp_port"])
        self.assertEqual(out["address"], "(자산 권한 필요)")
        self.assertEqual(out["interval"], 30)


class DeptSelfDeclared(unittest.TestCase):
    """GPT 106 P0 조건부: 직접 가입 때 적은 부서로 그 부서 분석 원본을 보면 안 된다 — 관리자 승인·편집 뒤에만 공유."""

    def test_signup_dept_not_trusted_until_admin(self):
        from logtriage import accounts as A
        from logtriage import auth as AU
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            store = AU.AuthStore(base / "data" / "auth" / "auth.sqlite3")
            acc = A.Accounts(store, base, {"mode": "local", "local": {"domain": "solideos.com", "signup": "approve", "scrypt_n": 12}})
            acc.signup("new.e@solideos.com", "Lt-Zq8!mK3pW9xR", "새사람", "운영1팀")
            u = store.get_user("new.e@solideos.com")
            self.assertTrue(u.get("dept_self"))
            self.assertEqual(u.get("dept"), "운영1팀")
            E = "new.e@solideos.com"
            acc.approve(E, actor="admin")                      # GPT 107 P0-01: 가입 승인 ≠ 부서 확인
            self.assertTrue(store.get_user(E).get("dept_self"))
            store.update_user(E, {"name": "새사람2", "dept": "운영1팀", "role": "operator"}, "admin")   # 이름·권한만 고쳐 저장
            self.assertTrue(store.get_user(E).get("dept_self"))
            store.update_user(E, {"dept_confirm": True}, "admin")                                     # 명시적 [부서 확인]
            self.assertFalse(store.get_user(E).get("dept_self"))
            self.assertEqual(store.get_user(E).get("dept"), "운영1팀")
            acc.signup("new.g@solideos.com", "Lt-Zq8!mK3pW9xQ", "다른", "운영1팀")
            store.update_user("new.g@solideos.com", {"dept": "개발2팀"}, "admin")                     # 관리자가 부서를 직접 정함 = 확인
            self.assertFalse(store.get_user("new.g@solideos.com").get("dept_self"))
            with self.assertRaises(ValueError):
                store.update_user(E, {"dept_confirm": "yes"}, "admin")
            acc.create("pre.f@solideos.com", None, "viewer", [], [], "미리", "운영1팀", actor="admin")
            self.assertFalse(store.get_user("pre.f@solideos.com").get("dept_self"))     # 관리자가 만든 계정은 확인된 부서


class SameDeptGate(unittest.TestCase):
    """서버 판단 함수 자체: 보는 사람·소유자 어느 쪽이든 신청 부서(확인 전)면 공유하지 않는다."""

    def _h(self, me, users):
        from logtriage import server as S

        class Auth:
            def get_user(self, login):
                return users.get(login)

        class H:
            pass
        h = H()
        h._u = me
        h.api = type("Api", (), {"auth": Auth()})()
        return lambda owner: S.Handler._same_dept(h, owner)

    def test_dept_self_never_shares(self):
        users = {"a": {"dept": "운영1팀"}, "s": {"dept": "운영1팀", "dept_self": True}}
        self.assertTrue(self._h({"dept": "운영1팀"}, users)("a"))
        self.assertFalse(self._h({"dept": "운영1팀", "dept_self": True}, users)("a"))   # 보는 사람이 확인 전
        self.assertFalse(self._h({"dept": "운영1팀"}, users)("s"))                      # 소유자가 확인 전
        self.assertFalse(self._h({"dept": ""}, users)("a"))


class AutomationR16(unittest.TestCase):
    def setUp(self):
        from logtriage.server import ServerApi
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.api = ServerApi(self.base, [])
        self.w = self.api.automation

    def tearDown(self):
        self.tmp.cleanup()

    def test_created_kept_on_edit_and_migration(self):
        r = self.w.save({"name": "백업 시험", "kind": "backup", "schedule": {"mode": "daily", "time": "03:00"}, "params": {"keep": 3}})
        j = next(x for x in self.w.status()["jobs"] if x["id"] == r["id"])
        self.assertAlmostEqual(j["created"], time.time(), delta=60)
        time.sleep(0.05)
        self.w.save({"id": r["id"], "name": "백업 시험 2", "kind": "backup", "schedule": {"mode": "daily", "time": "04:00"}, "params": {"keep": 3}})
        j2 = next(x for x in self.w.status()["jobs"] if x["id"] == r["id"])
        self.assertEqual(j2["created"], j["created"])        # 편집해도 등록 시각은 그대로
        # 옛 판 DB(created 칸 없음) → 새 판이 열면 칸을 더하고 옛 작업은 비워 둔다(지어내지 않음)
        from logtriage.automation import migrate_jobs
        db = sqlite3.connect(self.base / "old.sqlite3")
        db.execute("CREATE TABLE jobs(id TEXT PRIMARY KEY, name TEXT, kind TEXT, schedule TEXT, params TEXT, enabled INTEGER, "
                   "next_due REAL, state TEXT DEFAULT 'idle', attempts INTEGER DEFAULT 0)")
        db.execute("INSERT INTO jobs VALUES('a','옛 작업','backup','{}','{}',1,0,'idle',0)")
        migrate_jobs(db); migrate_jobs(db)                 # 두 번 열어도 안전
        row = db.execute("SELECT created FROM jobs WHERE id='a'").fetchone()
        db.close()
        self.assertIsNone(row[0])

    def test_purge_uploads(self):
        up = self.base / "uploads"
        (up / "inbox").mkdir(parents=True, exist_ok=True)
        old, new = up / "20260101_old.log", up / "20261022_new.log"
        old.write_text("x" * 100); new.write_text("y" * 50)
        (up / "inbox" / "keep.log").write_text("z")
        t = time.time() - 10 * 86400
        os.utime(old, (t, t))
        r = self.w.command("purge_uploads", {"older_days": 7})
        self.assertEqual((r["removed"], r["bytes"], r["kept"]), (1, 100, 1))
        self.assertFalse(old.exists()); self.assertTrue(new.exists()); self.assertTrue((up / "inbox" / "keep.log").exists())
        with self.w.guard.shared():                         # 분석 중이면 거절(읽는 파일을 지우지 않게)
            with self.assertRaises(ValueError):
                self.w.command("purge_uploads", {"older_days": 0})
        self.assertTrue(new.exists())
        r = self.w.command("purge_uploads", {"older_days": 0})   # GPT 107 P1-01: 1분 안에 바뀐(올리는 중일 수 있는) 파일은 '전부'여도 남김
        self.assertEqual((r["removed"], r["kept"]), (0, 1))
        t2 = time.time() - 120
        os.utime(new, (t2, t2))
        r = self.w.command("purge_uploads", {"older_days": 0})
        self.assertEqual(r["removed"], 1)
        self.assertTrue((up / "inbox" / "keep.log").exists())
        with self.assertRaises(ValueError):
            self.w.command("purge_uploads", {"older_days": -1})

    def test_purge_refuses_linked_upload_folder(self):
        """GPT 107 P0-02: uploads 가 바깥 폴더를 가리키는 바로가기면 거절하고 바깥 파일은 그대로."""
        import shutil
        import subprocess
        outside = self.base / "outside"; outside.mkdir()
        victim = outside / "important.txt"; victim.write_text("keep")
        t = time.time() - 30 * 86400
        os.utime(victim, (t, t))
        up = self.base / "uploads"
        shutil.rmtree(up, ignore_errors=True)
        try:
            os.symlink(outside, up, target_is_directory=True)
        except (OSError, NotImplementedError):
            if os.name != "nt":
                self.skipTest("심볼릭 링크를 만들 수 없음")
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(up), str(outside)], capture_output=True)   # 권한 없이 되는 연결 지점
            if r.returncode != 0:
                self.skipTest("연결 지점을 만들 수 없음")
        with self.assertRaises(ValueError):
            self.w.command("purge_uploads", {"older_days": 0})
        self.assertTrue(victim.exists())


if __name__ == "__main__":
    unittest.main()
