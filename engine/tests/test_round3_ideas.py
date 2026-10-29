"""2026-10-16 3차 아이디어 시험 — 4 서명 룰팩 링크 도메인 · 11 격리 폴더 보관 기간 · 12 문장 끝 변경 공개·끄기.
(1·2 CSP·Trusted Types 는 test_security_headers/test_ui_api_list, 3 출처 태그는 test_ui_interp_review, 8 칸 넘침은 test_render_layout,
 10 서명 관문은 test_build_ledger 에.) 실보고서는 쓰지 않는다."""
import json
import shutil
import sys
import tempfile
import time
import types
import unittest
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
from logtriage import links, rulepack, report, safe_backup  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parent)); import _privtmp  # noqa: E402,E702

RULE = 'rules:\n- id: TEST-LH-1\n  layer: was\n  product: [tomcat]\n  match: {regex: "OutOfMemoryError"}\n  verdict: Memory failure\n'
TPL = ENGINE / "report-template"
S = ENGINE / "samples"



def _register_qz(base, d, at):
    """7차(GPT 60차): 앱이 격리한 폴더는 폴더 밖 신뢰 기록(conf/tmp_quarantine.json)에 시각·내용 지문이 있어야 지울 수 있다.
    예전 시험들이 만들던 '표식(.qz)만 있는 격리 폴더'는 이제 앱이 지우지 않는다 — 앱이 격리한 것과 같은 상태로 기록을 남긴다."""
    reg = safe_backup._qreg(base)
    reg[d.name] = {"at": at, "from": d.name, "sha": safe_backup.content_digest(d)}
    safe_backup._qreg_write(base, reg)

class SignedLinkHosts(unittest.TestCase):
    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        self.src = self.td / "src"
        self.src.mkdir()
        (self.src / "r.yaml").write_text(RULE, encoding="utf-8")
        self.sig = rulepack.load_signing_key(self.td / "sign.pem", create=True)
        self.pub = rulepack.public_bytes(self.sig)
        self.fp = rulepack.fingerprint(self.pub)
        self.base = self.td / "closed"
        (self.base / "rules").mkdir(parents=True)
        (self.base / "rules" / "base.yaml").write_text(RULE.replace("TEST-LH-1", "KEEP"), encoding="utf-8")

    def test_round_trip_and_tamper(self):
        pk = self.td / "p.rpk"
        rulepack.build(self.src, pk, None, version="2026.10.16", signer=self.sig, link_hosts=["Docs.Vendor-A.co.kr"])
        rulepack.apply(pk, self.base / "rules", self.pub, confirm_fp=self.fp)
        self.assertEqual(links.extra_hosts(self.base), ["docs.vendor-a.co.kr"])
        # 기록 한 곳만 고치면 두 곳이 달라 아무것도 더하지 않는다
        pol = self.base / "conf" / "rulepack_policy.json"
        d = json.loads(pol.read_text(encoding="utf-8"))
        d["link_hosts"].append("evil.example.com")
        pol.write_text(json.dumps(d), encoding="utf-8")
        self.assertEqual(links.extra_hosts(self.base), [])

    def test_bad_host_rejects_whole_pack(self):
        with self.assertRaises(ValueError):
            rulepack.build(self.src, self.td / "x.rpk", None, signer=self.sig, link_hosts=["*.evil.com"])
        # 서명된 manifest 를 직접 고치면 서명이 깨진다(서명 범위 안)
        pk = self.td / "p2.rpk"
        rulepack.build(self.src, pk, None, version="2026.10.16", signer=self.sig, link_hosts=["kb.example.com"])
        bad = self.td / "bad.rpk"
        with zipfile.ZipFile(pk) as zi, zipfile.ZipFile(bad, "w") as zo:
            for n in zi.namelist():
                b = zi.read(n)
                if n == rulepack.MANIFEST:
                    b = b.replace(b"kb.example.com", b"evil.example.com")
                zo.writestr(n, b)
        with self.assertRaises(ValueError):
            rulepack.apply(bad, self.base / "rules", self.pub, confirm_fp=self.fp)
        self.assertEqual(links.extra_hosts(self.base), [])

    def test_no_link_hosts_means_none(self):
        pk = self.td / "p3.rpk"
        rulepack.build(self.src, pk, None, version="2026.10.16", signer=self.sig)
        rulepack.apply(pk, self.base / "rules", self.pub, confirm_fp=self.fp)
        self.assertEqual(links.extra_hosts(self.base), [])


class Retention(unittest.TestCase):
    def test_purge_only_old_quarantined(self):
        from logtriage.automation import Automation
        base = Path(_privtmp.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        a = Automation(types.SimpleNamespace(_base=base))
        self.assertEqual(a.tmp_retention(), 0)                                   # 기본 = 사용 안 함

        def qz(name, age_days):
            d = base / name
            (d / "stage").mkdir(parents=True)
            (d / "stage" / "x").write_text("x", encoding="utf-8")
            t = time.time() - 3 * 86400
            import os
            for p in sorted(d.rglob("*"), reverse=True) + [d]:
                os.utime(p, (t, t))
            (d / safe_backup.QZ_MARK).write_text(json.dumps({"at": time.time() - age_days * 86400}), encoding="utf-8")
            _register_qz(base, d, time.time() - age_days * 86400)
            return d
        old, young = qz(".backup-QZ_old", 10), qz(".backup-QZ_young", 1)
        forged = base / ".backup-QZ_forged"   # 표식만 꾸민 오래된 격리 폴더 — 신뢰 기록이 없으니 보관 기간이 지나도 지우지 않는다
        (forged / "stage").mkdir(parents=True)
        (forged / safe_backup.QZ_MARK).write_text(json.dumps({"at": time.time() - 30 * 86400}), encoding="utf-8")
        un = base / ".backup-unowned"
        (un / "stage").mkdir(parents=True)
        self.assertEqual(a.purge_quarantined(), 0)                               # 기본은 아무것도 지우지 않는다
        self.assertTrue(old.exists())
        a.set_tmp_retention(7)
        self.assertEqual(a.purge_quarantined(), 1)
        self.assertFalse(old.exists())
        self.assertTrue(young.exists() and un.exists())                           # 기간 안·표식 없는 폴더는 그대로
        self.assertTrue(forged.exists())                                           # 신뢰 기록 없는 격리 폴더도 그대로
        for bad in (-1, 366, "x"):
            with self.assertRaises((ValueError, TypeError)):
                a.set_tmp_retention(bad)

    def test_purge_never_follows_junction(self):
        """GPT 37차: 격리 폴더 안에 정션이 있으면 자동 삭제는 그 폴더를 건드리지 않고, 바깥 파일은 그대로."""
        import os
        import subprocess
        from logtriage.automation import Automation
        base = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "keep.txt").write_text("k", encoding="utf-8")
        a = Automation(types.SimpleNamespace(_base=base))
        a.set_tmp_retention(1)
        d = base / ".backup-QZ_j"
        (d / "stage").mkdir(parents=True)
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(d / "stage" / "j"), str(outside)], capture_output=True)
        else:
            os.symlink(outside, d / "stage" / "j")
        self.assertTrue((d / "stage" / "j").exists(), "정션을 못 만들면 시험이 뜻이 없다")
        t = time.time() - 3 * 86400
        for p in [d / "stage", d]:
            os.utime(p, (t, t))
        (d / safe_backup.QZ_MARK).write_text(json.dumps({"at": time.time() - 9 * 86400}), encoding="utf-8")
        os.utime(d / safe_backup.QZ_MARK, (t, t))
        self.assertEqual(a.purge_quarantined(), 0)
        self.assertTrue((outside / "keep.txt").exists())
        self.assertTrue(any(base.glob(".backup-QZ_j*")))


class SafeDeleteBoundary(unittest.TestCase):
    """GPT 38차: 검사 뒤 바꿔치기(TOCTOU) — 지우는 도중 하위 폴더가 정션으로 바뀌어도 바깥을 지우지 않고,
    넓은 집단이 쓸 수 있는 자료 폴더에서는 아예 지우지 않는다."""

    @staticmethod
    def _junction(link, target):
        import os
        import subprocess
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True)
        else:
            os.symlink(target, link)

    def test_swap_during_delete_is_not_followed(self):
        import os
        from unittest import mock
        root = Path(tempfile.mkdtemp())
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        self.addCleanup(shutil.rmtree, outside, True)
        (outside / "keep.txt").write_text("k", encoding="utf-8")
        (root / "s").mkdir()
        (root / "s" / "a.txt").write_text("x", encoding="utf-8")
        (root / "f.txt").write_text("x", encoding="utf-8")
        real = os.scandir
        swapped = []

        def evil(path):   # 검사(_has_link)는 끝났고, 지우기가 폴더를 여는 순간 누군가 s 를 바깥 정션으로 바꾼다
            if Path(path) == root and not swapped:
                shutil.rmtree(root / "s")
                self._junction(root / "s", outside)
                swapped.append(1)
            return real(path)
        with mock.patch.object(safe_backup.os, "scandir", side_effect=evil):
            safe_backup._rm_nofollow(root)
        self.assertTrue(swapped and not root.exists())
        self.assertTrue((outside / "keep.txt").exists(), "정션을 따라가 바깥 파일을 지웠다")

    def test_sddl_untrusted_write(self):
        """GPT 39차: 넓은 집단 목록이 아니라 믿는 주체 허용 목록 — 그 밖의 어떤 SID 의 쓰기·믿지 않는 소유자도 공유로 본다."""
        w = safe_backup.sddl_untrusted_write
        me = "S-1-5-21-1-2-3-1001"
        self.assertFalse(w("O:" + me + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)", me))      # mkdtemp 모양
        self.assertFalse(w("O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;FA;;;" + me + ")", me))  # Users 읽기만
        self.assertTrue(w("O:BAD:PAI(A;OICI;FA;;;BA)(A;OICIIO;SDGXGWGR;;;AU)", me))     # 상속 전용이라도 새 하위 폴더에 붙는다
        self.assertTrue(w("O:BAD:(A;OICI;0x1301bf;;;WD)", me))                           # Everyone 수정
        self.assertTrue(w("O:BAD:(A;OICI;0x1301bf;;;S-1-5-21-9-9-9-3807388439)", me))    # 목록에 없는 다른 사용자·그룹(GPT 39차)
        self.assertTrue(w("O:BAD:(A;OICI;0x1301bf;;;S-1-5-21-9-9-9-513)", me))           # 도메인 그룹
        self.assertTrue(w("O:S-1-5-21-9-9-9-1500D:(A;OICI;FA;;;SY)", me))                  # 소유자가 남 — 언제든 권한을 바꾼다
        self.assertTrue(w("O:BAD:(A;;ZZ;;;S-1-5-21-9-9-9-1)", me))                       # 모르는 권한 글자 = 쓰기
        self.assertTrue(w("", me))                                                        # 못 읽으면 공유
        self.assertFalse(w("O:BAD:(A;OICI;FA;;;SY)(D;OICI;FA;;;WD)(A;OICI;0x1200a9;;;S-1-5-21-9-9-9-1)", me))  # 거부 ACE·읽기만

    def test_chain_rules(self):
        """GPT 40차: 위 경로는 '이미 있는 성분을 지우거나 바꿀 수 있는 권한'만 본다 — 하위 지우기·지우기·권한/소유자 변경·전체."""
        w = safe_backup.sddl_untrusted_write
        me, other = "S-1-5-21-1-2-3-1001", "S-1-5-21-9-9-9-1500"
        chain = dict(mask=safe_backup._SWAP_BITS, self_only=True)
        self.assertTrue(w(f"O:SYD:(A;;0x40;;;{other})", me, **chain))                   # 하위 지우기(FILE_DELETE_CHILD)
        self.assertTrue(w(f"O:SYD:(A;OICI;0x1301bf;;;{other})", me, **chain))           # 수정 = 지우기 포함 → 이름 바꿔치기
        self.assertTrue(w(f"O:SYD:(A;;WD;;;{other})", me, **chain))                     # 권한 변경
        self.assertTrue(w(f"O:{other}D:(A;;FA;;;SY)", me, **chain))                      # 남이 소유자
        self.assertFalse(w("O:SYD:(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)", me, **chain))  # C:\ 모양 — 새 폴더 만들기·상속 전용만
        self.assertFalse(w(f"O:SYD:(A;;0x1200a9;;;{other})", me, **chain))               # 읽기·실행만

    def test_untrusted_subdir_stops_delete(self):
        from unittest import mock
        root = Path(_privtmp.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "s" / "t").mkdir(parents=True)
        (root / "s" / "t" / "a.txt").write_text("x", encoding="utf-8")
        real = safe_backup._one_untrusted
        with mock.patch.object(safe_backup, "_one_untrusted", side_effect=lambda p, me, chain=False: Path(p).name == "t" or real(p, me, chain)):
            with self.assertRaises(PermissionError):
                safe_backup._rm_nofollow(root)
        self.assertTrue((root / "s" / "t" / "a.txt").exists())                           # 믿지 않는 하위 폴더 안은 건드리지 않음

    def test_partial_delete_is_reported(self):
        """GPT 41차 권고: 일부만 지웠으면 '지움'이 아니다 — 지운 수·남은 수·까닭을 돌려주고(감사 기록) 폴더는 남는다."""
        import os
        from unittest import mock
        base = Path(_privtmp.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        d = base / ".backup-QZ_pt"
        (d / "stage" / "t").mkdir(parents=True)
        (d / "stage" / "t" / "a.txt").write_text("x", encoding="utf-8")
        (d / "stage" / "b.txt").write_text("x", encoding="utf-8")
        t = time.time() - 3 * 86400
        (d / safe_backup.QZ_MARK).write_text(json.dumps({"at": t}), encoding="utf-8")
        for p in [d / "stage" / "t" / "a.txt", d / "stage" / "t", d / "stage" / "b.txt", d / "stage", d / safe_backup.QZ_MARK, d]:
            os.utime(p, (t, t))
        _register_qz(base, d, t)
        real = safe_backup._one_untrusted
        with mock.patch.object(safe_backup, "_one_untrusted", side_effect=lambda p, me, chain=False: Path(p).name == "t" or real(p, me, chain)):
            r = safe_backup.delete_backup(base, d.name)
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("partial"))
        self.assertGreaterEqual(r["left"], 1)
        self.assertIn("일부만 지웠습니다", r["error"])
        self.assertTrue(any(base.glob(".backup-QZ_pt*")))

    def test_real_acl(self):
        import os
        if os.name != "nt":
            self.skipTest("Windows ACL")
        base = Path(_privtmp.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        self.assertTrue(safe_backup._my_sid().startswith("S-1-5-"))
        self.assertFalse(safe_backup._shared_writable(base))                             # 사용자 폴더 아래 = 나·SYSTEM·관리자만
        self.assertTrue(safe_backup._shared_writable(Path(os.environ.get("SystemDrive", "C:") + "\\")))   # C:\ = 인증된 사용자 쓰기

    def test_shared_folder_refuses_delete(self):
        import os
        base = Path(_privtmp.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        self.assertFalse(safe_backup._shared_writable(base), "개인 임시 폴더는 넓은 쓰기 권한이 없어야 한다(권한을 못 읽었나?)")
        d = base / ".backup-QZ_sh"
        (d / "stage").mkdir(parents=True)
        (d / "stage" / "a.txt").write_text("x", encoding="utf-8")
        t = time.time() - 3 * 86400
        (d / safe_backup.QZ_MARK).write_text(json.dumps({"at": t}), encoding="utf-8")
        for p in [d / "stage" / "a.txt", d / "stage", d / safe_backup.QZ_MARK, d]:
            os.utime(p, (t, t))
        _register_qz(base, d, t)
        from unittest import mock
        with mock.patch.object(safe_backup, "_shared_writable", return_value=True):
            r = safe_backup.delete_backup(base, d.name)
        self.assertFalse(r["ok"])
        self.assertIn("쓸 수 있는 사용자·그룹이 있어", r["error"])
        self.assertTrue(any(base.glob(".backup-QZ_sh*")))
        r = safe_backup.delete_backup(base, d.name)                                   # 권한이 좁으면 지운다
        self.assertTrue(r["ok"], r)
        self.assertFalse(any(base.glob(".backup-QZ_sh*")))


class FitLog(unittest.TestCase):
    def test_log_and_off_switch(self):
        from logtriage.report_forms import StyleProfile, option_on
        sp = StyleProfile({"fields": {"장애원인": {"ending": {"noun": 9}}}})
        sp.for_form("status").fit_endings("장애원인", ["원인 분석 결과 커넥션 풀이 고갈되어 서비스를 재기동하십시오.", "정상"])
        self.assertEqual(len(sp.log), 1)
        self.assertNotIn("원인 분석", json.dumps(sp.log, ensure_ascii=False))    # 끝 몇 글자만
        sp.fit_endings("장애원인", ["계정 hong@corp.com 확인하십시오."])
        self.assertNotIn("hong@", json.dumps(sp.log, ensure_ascii=False))          # 끝 글자 속 민감정보는 가림(GPT 37차)
        off = StyleProfile({"fields": {"장애원인": {"ending": {"noun": 9}}}})
        off.fit_on = option_on({"fit_endings": "끔"}, "fit_endings", True)
        self.assertEqual(off.fit_endings("장애원인", ["재기동하십시오."]), ["재기동하십시오."])
        self.assertTrue(option_on({}, "fit_endings", True))
        self.assertFalse(option_on({}, "evidence_index", False))

    def test_report_result_carries_log(self):
        inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "h"}], None,
                           rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            shutil.copyfile(TPL / f, td / f)
        r = report.generate(td / "template.yaml", inc, td / "o")
        self.assertIn("fitted", r)
        if r["fitted"]:
            self.assertIn("자동으로 다듬은 줄", Path(r["todo_file"]).read_text(encoding="utf-8"))


class OneValueAllForms(unittest.TestCase):
    """3차 아이디어 5(누름틀 대신): 확인 목록에서 한 번 넣은 값이 같은 이름 자리 모두(두 서식)에 들어간다."""

    @classmethod
    def setUpClass(cls):
        cls.inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                                {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                               rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.td, True)
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            shutil.copyfile(TPL / f, self.td / f)

    def _text(self, r):
        return "".join(zipfile.ZipFile(f).read("Contents/section0.xml").decode("utf-8") for f in r["hwpx_all"])

    def test_values_fill_every_spot(self):
        r0 = report.generate(self.td / "template.yaml", self.inc, self.td / "a")
        before = {g["item"]: g["count"] for g in r0["todo_summary"]}
        r1 = report.generate(self.td / "template.yaml", self.inc, self.td / "b", {"복구 시각": "14:20", "시각 · 조치1": "14:05"})
        self.assertFalse(r1.get("forms_error"))
        after = {g["item"]: g["count"] for g in r1["todo_summary"]}
        self.assertNotIn("복구 시각", after)
        self.assertNotIn("시각 · 조치1", after)
        self.assertEqual(r1["todo_count"], r0["todo_count"] - before["복구 시각"] - before["시각 · 조치1"])
        self.assertEqual(after.get("수행 여부·일시 · 조치1"), before.get("수행 여부·일시 · 조치1"))   # 조치 번호는 그대로
        t = self._text(r1)
        self.assertGreaterEqual(t.count("14:20"), before["복구 시각"])
        self.assertIn("14:05", t)
        self.assertEqual(sorted(r1["values_used"]), ["복구 시각", "시각 · 조치1"])

    def test_bad_values_refused_and_context_clean(self):
        from logtriage.report_forms import _VALUES, clean_values, mark
        for bad in ({"복구 시각": "x" * 101}, {"복구 시각": "[기재: 다시]"}, {"복구 시각": "a\x01b"}):
            with self.assertRaises(ValueError):
                clean_values(bad)
        self.assertEqual(clean_values({"": "x", "a": "  "}), {})
        r = report.generate(self.td / "template.yaml", self.inc, self.td / "c", {"복구 시각": "x" * 101})
        self.assertIn("100자", r.get("forms_error", "") + r.get("error", ""))
        self.assertIsNone(_VALUES.get())                                          # 다음 보고서에 값이 새지 않는다
        self.assertTrue(mark("복구 시각").startswith("[기재"))


class EvidenceIndex(OneValueAllForms):
    """3차 아이디어 13: '근거 색인 쪽 붙이기 = 켬'일 때만 사후관리 보고서 끝에 근거 ID 색인."""

    def _paras(self, r, kind):
        from logtriage import report_style as rs
        f = [x for x in r["hwpx_all"] if kind in Path(x).name][0]
        return [p.text for p in rs.parse_hwpx(Path(f).read_bytes()) if p.text]

    def test_off_by_default_on_when_asked(self):
        r = report.generate(self.td / "template.yaml", self.inc, self.td / "a")
        self.assertFalse(any("근거 색인" in t for t in self._paras(r, "사후")))
        (self.td / "report_profile.json").write_text(json.dumps({"evidence_index": "켬"}, ensure_ascii=False), encoding="utf-8")
        r = report.generate(self.td / "template.yaml", self.inc, self.td / "b")
        tx = self._paras(r, "사후")
        i = next(k for k, t in enumerate(tx) if "근거 색인" in t)
        eids = [k["eid"] for k in self.inc["timeline_key"] if k.get("eid")]
        self.assertTrue(all(any(e in t for t in tx[i:]) for e in eids))
        self.assertIn("분석요약_", tx[-1])
        self.assertFalse(any("근거 색인" in t for t in self._paras(r, "상황")))      # 상황관리 보고서는 그대로


class HubFormLedger(unittest.TestCase):
    """3차 아이디어 6: 사이트가 보낸 서식 원장(이름·지문만)을 본사가 사이트별로 갈아 끼워 저장 — 형식 틀린 줄은 버린다."""

    def test_ingest_and_overview(self):
        from logtriage.hub import HubStore
        base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, base, True)
        hs = HubStore(base)
        hs.add_site("S1", "사이트1")
        good = {"kind": "builtin", "name": "장애 사후관리 보고서", "sha256": "a" * 64}
        p = {"site": {"version": "1.0.0"}, "stream": "f" * 16, "seq": 1,
             "forms": [good, {"kind": "custom", "name": "<script>", "sha256": "../x"}, {"name": "", "sha256": "b" * 64}, 7, "x"]}
        r = hs.ingest("S1", p)
        self.assertEqual(r["received"].get("forms_rejected"), 1)                    # 한 줄이라도 틀리면 통째로 거부(GPT 37차)
        self.assertEqual(hs.overview()["forms"], [])
        r = hs.ingest("S1", dict(p, seq=2, forms=[good]))
        self.assertEqual(r["received"]["forms"], 1)
        ov = hs.overview()
        self.assertEqual([(f["site_id"], f["name"], f["sha256"]) for f in ov["forms"]], [("S1", good["name"], "a" * 64)])
        hs.ingest("S1", dict(p, seq=3, forms=[good] * 201))                         # 200줄 초과도 거부 — 예전 원장 유지
        self.assertEqual(len(hs.overview()["forms"]), 1)
        from logtriage.hub import ReplayError
        with self.assertRaises(ReplayError):                                         # 같은 순번 재전송은 거부
            hs.ingest("S1", dict(p, seq=3, forms=[dict(good, sha256="d" * 64)]))
        p2 = dict(p, seq=4, forms=[dict(good, sha256="c" * 64)])               # 다음 전송이 통째로 바꾼다
        hs.ingest("S1", p2)
        self.assertEqual([f["sha256"] for f in hs.overview()["forms"]], ["c" * 64])
        self.assertEqual(hs.overview(allowed=["S2"])["forms"], [])                  # 볼 수 있는 사이트만

    def test_site_payload_has_only_names_and_hashes(self):
        from logtriage.report_custom import ledger_export
        d = ledger_export(TPL)
        for f in d["forms"]:
            self.assertEqual(set({k: f.get(k) for k in ("kind", "name", "sha256")}), {"kind", "name", "sha256"})


class SandboxConfig(unittest.TestCase):
    """3차 아이디어 9(준비만): .wsb 는 엔진·파이썬 읽기 전용, 결과 폴더만 쓰기, 네트워크·클립보드 끔."""

    def test_wsb(self):
        import xml.etree.ElementTree as ET
        sys.path.insert(0, str(ENGINE / "tools" / "build"))
        import rollback_compat_sandbox as sb
        td = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, td, True)
        root = ET.parse(sb.make_wsb(td)).getroot()
        self.assertEqual(root.findtext("Networking"), "Disable")
        self.assertEqual(root.findtext("ClipboardRedirection"), "Disable")
        ro = {m.findtext("SandboxFolder"): m.findtext("ReadOnly") for m in root.iter("MappedFolder")}
        self.assertEqual(ro, {r"C:\lt\engine": "true", r"C:\lt\python": "true", r"C:\lt\out": "false"})


if __name__ == "__main__":
    unittest.main()
