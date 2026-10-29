# -*- coding: utf-8 -*-
"""예약·자동화 r4: 정기 상태 점검(알림은 변화 시에만), 산출물 형식(HTML·PDF·HWPX), 저장 경로·추가 사본·보관 기간 설정 검증,
산출물 내려받기 권한(운영/관리자·경로 조작 차단), ops_report 출력 형식 검사."""
import json
import os
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from logtriage import auth as A  # noqa: E402
from logtriage import ops_report as R  # noqa: E402
from logtriage.automation_actions import health_check, report  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_enterprise import LINK_SECRET, Srv, cookie_of, prep_base  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TPL = ROOT / "report-template" / "form_status.hwpx"


class OpsReportTests(unittest.TestCase):
    DOC = {"title": "정기 상태 점검 결과", "subtitle": "테스트 · 기준", "site": "본사", "meta": [("생성", "2026-09-18")],
           "kpis": [("감시 장비", "3대", "mute"), ("장애", "1대", "crit")],
           "sections": [{"title": "장애 장비", "cols": [("장비", 3, "L"), ("상태", 1, "C"), ("CPU", 1, "R")],
                         "rows": [["<script>x</script>", "장애", "95%"]], "tones": ["crit"]},
                        {"title": "빈 절", "cols": [("a", 1, "L")], "rows": [], "empty": "없음"}], "footer": "끝"}

    def test_html_escapes(self):
        h = R.render_html(self.DOC)
        self.assertIn("&lt;script&gt;", h); self.assertNotIn("<script>x", h)

    def test_pdf_structure(self):
        b = R.render_pdf(self.DOC)
        self.assertTrue(b.startswith(b"%PDF-1.4") and b.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"/UniKS-UCS2-H", b); self.assertIn(b"/Ordering (Korea1)", b)
        xref = int(b[b.rindex(b"startxref") + 9:].split()[0])
        self.assertEqual(b[xref:xref + 4], b"xref")   # xref 오프셋이 정확해야 PDF 보기 프로그램이 복구 없이 연다

    @unittest.skipUnless(TPL.exists(), "양식 없음")
    def test_hwpx_valid_zip_and_xml(self):
        from lxml import etree
        data = R.render_hwpx(self.DOC, TPL)
        z = zipfile.ZipFile(__import__("io").BytesIO(data))
        self.assertEqual(z.infolist()[0].filename, "mimetype")
        self.assertEqual(z.infolist()[0].compress_type, zipfile.ZIP_STORED)
        sec = etree.fromstring(z.read("Contents/section0.xml"))
        text = "".join(sec.itertext())
        self.assertIn("정기 상태 점검 결과", text); self.assertIn("<script>x</script>", text)
        head = etree.fromstring(z.read("Contents/header.xml"))
        ns = {"hh": "http://www.hancom.co.kr/hwpml/2011/head"}
        for tag in ("charPr", "paraPr", "borderFill"):   # itemCnt 가 실제 개수와 같아야 한글이 연다
            el = head.find(f".//hh:{tag}", ns).getparent()
            self.assertEqual(int(el.get("itemCnt")), len(el.findall(f"hh:{tag}", ns)), tag)
        ids = {e.get("id") for e in head.iter("{%s}paraPr" % ns["hh"])}
        for p in sec.iter("{http://www.hancom.co.kr/hwpml/2011/paragraph}p"):
            self.assertIn(p.get("paraPrIDRef"), ids)

    def test_write_outputs_partial_failure(self):
        with tempfile.TemporaryDirectory() as td:
            made, errors = R.write_outputs(self.DOC, Path(td), "x", ["html", "pdf", "hwpx"], Path(td) / "none.hwpx")
            self.assertEqual({m.suffix for m in made}, {".html", ".pdf"})
            self.assertTrue(errors and errors[0].startswith("HWPX"))
            self.assertFalse(list(Path(td).glob("*.partial")))


class AutomationR4Tests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        auth = {"mode": "portal", "default_role": "viewer", "default_sites": [], "portal": {"method": "link", "link": {"secret": LINK_SECRET}}}
        prep_base(self.base, auth=auth)
        (self.base / "report-template").mkdir()
        if TPL.exists():
            (self.base / "report-template" / "form_status.hwpx").write_bytes(TPL.read_bytes())
        st = A.AuthStore(self.base / "data" / "auth" / "auth.sqlite3")
        conf = A.load_conf(self.base)
        for login, role in (("op", "operator"), ("vw", "viewer"), ("ad", "admin")):
            st.portal_user(login, conf)
            st.update_user(login, {"role": role, "sites": ["*"]} if login != "ad" else {"role": role}, actor="x")
        self.s = Srv(self.base)
        self.w = self.s.api.automation

    def tearDown(self):
        self.s.close(); self.td.cleanup()

    def login(self, user):
        ts, n = int(time.time()), "n" + str(time.time_ns())
        q = "&".join(f"{k}={v}" for k, v in {"u": user, "t": ts, "n": n, "sig": A.link_sign(LINK_SECRET, user, ts, n)}.items())
        return cookie_of(self.s.req("GET", "/sso/link?" + q)[0])

    def test_health_check_notifies_only_on_change_and_saves_formats(self):
        nms = self.s.api.nms
        nms.save({"name": "down1", "address": "10.255.255.9", "kind": "server", "method": "icmp", "interval": 30})
        tid = nms.snapshot()["targets"][0]["id"]
        with nms.db() as db:
            db.execute("UPDATE targets SET status='down', last_check=? WHERE id=?", (time.time(), tid))
        job = {"id": "hc1", "name": "점검", "run_id": "r1", "params": {"save": True, "notify": True, "formats": ["html", "pdf"]}}
        r1 = health_check(self.w, job)
        self.assertEqual((r1["down"], sorted(Path(f).suffix for f in r1["files"])), (1, [".html", ".pdf"]))
        health_check(self.w, dict(job, run_id="r2"))   # 같은 상태 → 알림 추가 없음
        with self.w.db() as db:
            notes = [r["message"] for r in db.execute("SELECT message FROM notices WHERE message LIKE '정기 상태 점검%'")]
        self.assertEqual(len(notes), 1); self.assertIn("down1", notes[0])
        with nms.db() as db:
            db.execute("UPDATE targets SET status='up' WHERE id=?", (tid,))
        health_check(self.w, dict(job, run_id="r3", params={"save": False, "notify": True}))
        with self.w.db() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM notices WHERE category='recovery' AND message LIKE '정기 상태 점검%'").fetchone()[0], 1)

    def test_report_formats_and_self_run_excluded(self):
        with self.w.db() as db:
            db.execute("INSERT INTO runs(id,job_id,name,started,state) VALUES('me','j','매일 운영 보고서',?,'running')", (time.time(),))
        r = report(self.w, {"id": "j", "name": "매일 운영 보고서", "run_id": "me", "params": {"days": 1, "formats": ["html", "pdf", "hwpx"]}})
        exts = sorted(Path(f).suffix for f in r["files"])
        self.assertEqual(exts, [".html", ".hwpx", ".json", ".pdf"] if TPL.exists() else [".html", ".json", ".pdf"])
        html = (self.w.output_dir() / r["html"]).read_text(encoding="utf-8")
        self.assertIn("정기 운영 보고서", html); self.assertNotIn("실행 중", html)   # 자기 자신(실행 중)은 결과표에 넣지 않음

    def test_outputs_validation_copy_and_prune(self):
        with self.assertRaises(ValueError):
            self.w.set_outputs({"dir": "relative/path"})
        with self.assertRaises(ValueError):
            self.w.set_outputs({"formats": ["docx"]})
        with self.assertRaises(ValueError):
            self.w.set_outputs({"copy_dirs": ["/a"] * 6})
        out, cp = self.base / "outx", self.base / "copyx"
        self.w.set_outputs({"dir": str(out), "copy_dirs": [str(cp)], "formats": ["html"], "keep_days": 7})
        with self.assertRaises(ValueError):
            self.w.set_outputs({"dir": str(out), "copy_dirs": [str(out)]})
        r = health_check(self.w, {"id": "h", "name": "점검", "run_id": "r", "params": {"save": True, "notify": False}})
        self.assertEqual(r["copies"], 1)
        self.assertTrue((out / r["files"][0]).exists() and (cp / r["files"][0]).exists())
        old = out / "check-20000101-000000.html"; old.write_text("x"); os.utime(old, (1, 1))
        keep = out / "my-note.html"; keep.write_text("x"); os.utime(keep, (1, 1))
        self.w.prune_outputs()
        self.assertFalse(old.exists()); self.assertTrue(keep.exists())   # 자동 산출물 이름만 정리

    def test_download_permissions_and_traversal(self):
        r = health_check(self.w, {"id": "h", "name": "점검", "run_id": "r", "params": {"save": True, "notify": False, "formats": ["pdf"]}})
        name = r["files"][0]
        (self.base / "backups").mkdir(exist_ok=True)
        (self.base / "backups" / "backup-1.zip").write_bytes(b"PK")
        op, vw = self.login("op"), self.login("vw")
        self.assertEqual(self.s.req("GET", f"/api/automation/download?area=out&name={name}", cookie=vw)[0].status, 403)
        self.assertEqual(self.s.req("GET", f"/api/automation/download?area=out&name={name}", cookie=op)[0].status, 403)   # 자산 권한 없음
        st_ = self.s.api.auth
        for u in ("op", "ad"):
            st_.update_user(u, {"asset_sites": ["LOCAL"]}, actor="x")
        op, ad = self.login("op"), self.login("ad")
        r_, body = self.s.req("GET", f"/api/automation/download?area=out&name={name}", cookie=op)
        self.assertEqual(r_.status, 200); self.assertTrue(body.startswith(b"%PDF"))
        r_, _ = self.s.req("GET", f"/api/automation/download?area=out&name={name}&inline=1", cookie=op)
        self.assertIn("inline", r_.getheader("Content-Disposition")); self.assertIn("default-src 'none'", r_.getheader("Content-Security-Policy"))
        self.assertEqual(self.s.req("GET", "/api/automation/download?area=backups&name=backup-1.zip", cookie=op)[0].status, 403)
        self.assertEqual(self.s.req("GET", "/api/automation/download?area=backups&name=backup-1.zip", cookie=ad)[0].status, 200)
        for bad in ("../conf/auth.json", "..%2F..%2Fconf%2Fauth.json", "x/../../conf/auth.json"):
            self.assertEqual(self.s.req("GET", f"/api/automation/download?area=out&name={bad}", cookie=ad)[0].status, 404, bad)
        self.assertEqual(self.s.req("GET", "/api/automation/download?area=etc&name=passwd", cookie=ad)[0].status, 404)
        self.assertEqual(self.s.req("POST", "/api/automation/set_outputs", {"dir": ""}, cookie=op)[0].status, 403)
        st = json.loads(self.s.req("GET", "/api/automation/status", cookie=op)[1])
        self.assertFalse(st["can_admin"]); self.assertTrue(any(f["name"] == name for f in st["products"]))
        self.assertTrue({"inbox", "out", "backups"} <= {p["key"] for p in st["paths"]})

    def test_asset_permission_required_even_for_admin(self):
        ad = self.login("ad")
        r_, b = self.s.req("GET", "/api/inventory/docs", cookie=ad)
        self.assertEqual(r_.status, 403); self.assertIn("담당자만", json.loads(b)["error"])
        self.assertEqual(self.s.req("GET", "/resources", cookie=ad)[0].status, 403)
        me = json.loads(self.s.req("GET", "/api/me", cookie=ad)[1]); self.assertFalse(me["can_assets"])
        r_, b = self.s.req("POST", "/api/admin/user_update", {"login": "op", "asset_sites": ["*"]}, cookie=ad)
        self.assertEqual(r_.status, 400)   # 전체(*) 자산 권한 불가
        self.assertEqual(self.s.req("POST", "/api/admin/user_update", {"login": "op", "asset_sites": ["LOCAL"]}, cookie=ad)[0].status, 200)
        op = self.login("op")
        self.assertEqual(self.s.req("GET", "/api/inventory/docs", cookie=op)[0].status, 200)
        r_, b = self.s.req("GET", "/api/admin/audit?action=denied.asset", cookie=ad)
        self.assertTrue(json.loads(b)["rows"])
        r_, b = self.s.req("POST", "/api/automation/save", {"name": "x", "kind": "asset_sync", "schedule": {"mode": "interval", "seconds": 60}, "params": {}}, cookie=self.login("vw"))
        self.assertEqual(r_.status, 403)


if __name__ == "__main__":
    unittest.main()
