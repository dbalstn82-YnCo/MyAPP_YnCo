"""2026-10-15 아이디어 반영 시험 — 현장 서식 시험 묶음(아이디어 5)과 함께 묶었다.

1 자동 적합도(자동·담당자 확인·모호해서 비움)  2 서식별 학습 분리  4 확인 목록 묶음 요약  6 근거 ID
7 서식 원본 지문  10 문장 끝 통계  9 임시 백업 관리(관리자 화면 백엔드)
현장 서식 변형: 칸 이름 바꿈 · 모호한 이름 · 안내 문단 없앰 · 전각 쌍점 — 매 빌드 회귀 시험에서 돈다.
실보고서는 쓰지 않는다 — 공식 서식 + 합성 샘플 로그 + 생성물만.
"""
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ENGINE))
sys.path.insert(0, str(Path(__file__).resolve().parent)); import _privtmp  # noqa: E402,E702
from logtriage import report, report_custom as rc, report_forms as rf, report_style as rs, safe_backup  # noqa: E402
from logtriage.service import run_analysis  # noqa: E402

TPL = ENGINE / "report-template"
S = ENGINE / "samples"
PROFILE = {"org": "가상기관", "system": "가상업무시스템", "service": "가상 민원 서비스", "dept": "정보화팀", "person": "홍길동",
           "rank": "주무관", "phone": "000-0000-0000", "location": "본관 전산실", "operator": "가상운영팀"}

# 현장 서식 변형 — (원본 서식, [(바꿀 글, 새 글)], {칸 이름: 기대 값 키 또는 basis})
VARIANTS = [
    ("form_status.hwpx", [("○ 장애시간", "○ 장애 발생 일시"), ("○ 장애원인", "○ 발생 원인"), (">소속<", ">부서<"), (">담당자<", ">작성자<")],
     {"부서": "dept", "장애 발생 일시": "incident_period", "발생 원인": "cause"}),
    ("form_status.hwpx", [(">붙 임<", ">비고<")], {"비고": "ambiguous"}),
    ("form_status.hwpx", [("※ 서버위치", "＊ 서버위치")], {}),     # 안내 문단이 안내로 안 보이게 — 자리가 하나 줄고 깨지지 않는다
    ("form_postmortem.hwpx", [(">시스템명<", ">시스템 이름<"), (">제조사<", ">제조 회사<")], {"제조 회사": "blank"}),
]


def make_variant(src: Path, subs: list, out: Path) -> int:
    n = 0
    zi = zipfile.ZipFile(src)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zo:
        for name in zi.namelist():
            b = zi.read(name)
            if re.match(r"Contents/section\d+\.xml", name):
                t = b.decode("utf-8")
                for x, y in subs:
                    n += t.count(x)
                    t = t.replace(x, y)
                b = t.encode("utf-8")
            zo.writestr(zi.getinfo(name), b)
    return n


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inc = run_analysis([{"path": str(S / "alert_orcl.log"), "product": "oracle", "host": "db-a"},
                                {"path": str(S / "catalina.out"), "product": "tomcat", "host": "was-b"}], None,
                               rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")

    def setUp(self):
        self.td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.td, ignore_errors=True))
        self.tdir = self.td / "tdir"
        self.tdir.mkdir()
        for f in ("form_status.hwpx", "form_postmortem.hwpx", "style_profile.json"):
            if (TPL / f).exists():
                shutil.copyfile(TPL / f, self.tdir / f)


class FieldFixtures(Base):
    """아이디어 5: 현장 서식 변형 묶음 — 분석·자동 판단·저장·채우기가 깨지지 않는다."""

    def test_variants(self):
        for i, (src, subs, want) in enumerate(VARIANTS):
            with self.subTest(i=i):
                v = self.td / f"variant{i}.hwpx"
                self.assertGreater(make_variant(TPL / src, subs, v), 0, "변형이 실제로 들어가야 시험이 의미가 있다")
                a = rc.analyze_form(v)
                fit = a["fit"]
                self.assertEqual(sum(fit.values()), len(a["fields"]))                       # 아이디어 1: 모든 자리가 셋 중 하나
                got = {rc.norm(f["label"]).lstrip(rc._LEAD): f for f in a["fields"]}
                for lab, exp in want.items():
                    self.assertIn(lab, got)
                    if exp in ("ambiguous", "confirm"):
                        self.assertEqual(got[lab]["basis"], exp)
                        self.assertEqual(got[lab]["field"], "blank")
                    else:
                        self.assertEqual(got[lab]["field"], exp)
                saved = rc.save_template(self.tdir, v, f"변형{i}", a["fields"])
                t = rc.load_template(self.tdir, saved["id"])
                self.assertEqual(t["form_state"], "ok")
                r = rc.fill_template(Path(t["form"]), t["fields"], self.inc, PROFILE, self.td / f"out{i}.hwpx")
                self.assertGreater(r["filled"], 0)
                self.assertTrue(zipfile.is_zipfile(r["hwpx"]))

    def test_ambiguous_with_bullet(self):
        self.assertEqual(rc.basis("▹비고", "blank"), "ambiguous")
        self.assertEqual(rc.suggest("▹비고"), "blank")
        self.assertEqual(rc.basis("대국민 안내", "blank"), "confirm")
        self.assertEqual(rc.basis("장애내용", "content"), "auto")


class FormFingerprint(Base):
    """아이디어 7: 등록 뒤 서식 파일이 바뀌면 채우지 않고 알린다. 다시 저장하면 지문이 새로 생긴다."""

    def test_changed_form_is_not_filled(self):
        v = self.td / "v.hwpx"
        make_variant(TPL / "form_status.hwpx", [(">소속<", ">부서<")], v)
        saved = rc.save_template(self.tdir, v, "지문", rc.analyze_form(v)["fields"])
        d = rc.custom_dir(self.tdir) / saved["id"]
        self.assertTrue(json.loads((d / "mapping.json").read_text(encoding="utf-8")).get("form_sha256"))
        out = rc.generate_custom(self.tdir, self.inc, PROFILE, self.td / "o1")
        self.assertFalse(out[0].get("error"))
        make_variant(TPL / "form_status.hwpx", [(">소속<", ">팀<")], d / "form.hwpx")    # 등록 뒤 누군가 파일을 바꿈
        self.assertEqual(rc.load_template(self.tdir, saved["id"])["form_state"], "changed")
        self.assertEqual([x["form_state"] for x in rc.list_templates(self.tdir)], ["changed"])
        out = rc.generate_custom(self.tdir, self.inc, PROFILE, self.td / "o2")
        self.assertIn("원본 지문 불일치", out[0].get("error", ""))
        self.assertFalse(list((self.td / "o2").glob("*.hwpx")))
        # 보고서 만들기 결과에도 실패가 실린다(예전엔 사용자 서식 실패가 화면에 안 나왔다)
        r = report.generate(self.tdir / "template.yaml", self.inc, self.td / "o3")
        self.assertTrue(any("원본 지문" in e for e in r.get("custom_errors", [])))
        # 매핑 편집에서 다시 저장 → 지문 갱신
        a = rc.analyze_form(d / "form.hwpx")
        rc.save_template(self.tdir, d / "form.hwpx", "지문", a["fields"], tpl_id=saved["id"])
        self.assertEqual(rc.load_template(self.tdir, saved["id"])["form_state"], "ok")

    def test_old_template_without_fingerprint_is_blocked_until_pinned(self):
        v = self.td / "v.hwpx"
        make_variant(TPL / "form_status.hwpx", [(">소속<", ">부서<")], v)
        saved = rc.save_template(self.tdir, v, "옛", rc.analyze_form(v)["fields"])
        mp = rc.custom_dir(self.tdir) / saved["id"] / "mapping.json"
        m = json.loads(mp.read_text(encoding="utf-8"))
        m.pop("form_sha256")
        mp.write_text(json.dumps(m, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(rc.load_template(self.tdir, saved["id"])["form_state"], "none")
        out = rc.generate_custom(self.tdir, self.inc, PROFILE, self.td / "o")
        self.assertIn("원본 지문이 없는", out[0].get("error", ""))                       # 기준값 없으면 채우지 않는다(GPT 27차)
        self.assertFalse(list((self.td / "o").glob("*.hwpx")))
        self.assertTrue(rc.pin_form(self.tdir, saved["id"])["ok"])                      # 담당자 확인 뒤 지문 등록
        self.assertFalse(rc.generate_custom(self.tdir, self.inc, PROFILE, self.td / "o2")[0].get("error"))
        with self.assertRaises(ValueError):
            rc.pin_form(self.tdir, saved["id"])                                          # 이미 있으면 덮지 않는다
        with self.assertRaises(ValueError):
            rc.pin_form(self.tdir, "../x")


class TodoAndEvidence(Base):
    """아이디어 4·6: 확인 목록 묶음 요약(텍스트·HTML·결과) · 판정 요점과 분석요약 줄이 같은 근거 ID 로 이어진다."""

    def test_todo_summary_and_eids(self):
        r = report.generate(self.tdir / "template.yaml", self.inc, self.td / "o")
        summ = r.get("todo_summary") or []
        self.assertTrue(summ)
        self.assertEqual(sum(g["count"] for g in summ), r["todo_count"])              # 묶어도 빠지는 자리 없음
        same = [g for g in summ if g["count"] > 1 and not g["each"]]
        self.assertEqual(summ[:len(same)], same)                                        # 같은 값으로 여러 곳 → 먼저
        by = {g["item"]: g for g in summ}
        self.assertFalse(by["복구 시각"]["each"])                                       # 여러 곳에 같은 값
        self.assertTrue(by["현황·조치"]["each"])                                        # 같은 서식·같은 자리 반복 = 줄마다 다른 값(GPT 27차)
        self.assertFalse(by["시각 · 조치1"]["each"])                                     # 조치 번호로 두 보고서의 같은 조치를 짝지음(2차 아이디어 5)
        txt = Path(r["todo_file"]).read_text(encoding="utf-8")
        self.assertIn("같은 이름으로 묶은 항목", txt)
        self.assertIn("시각 · 조치1 — 2곳", txt)
        self.assertIn("줄마다 다른 값", txt)
        html = Path(r["html"]).read_text(encoding="utf-8")
        self.assertIn("제출 전 확인 목록", html)
        key = self.inc["timeline_key"]
        self.assertTrue(key and all(k.get("eid") for k in key))
        tl_eids = {t.get("eid") for t in self.inc["timeline"]}
        for k in key:
            self.assertIn(k["eid"], tl_eids)                                            # 요점의 ID 가 근거 줄에 실제로 있다
            self.assertIn(k["eid"], html)

    def test_key_eid_beyond_cap_is_kept(self):
        """요점이 가리키는 근거가 3,000줄 상한 밖이어도 timeline·분석요약에 남는다(GPT 27차)."""
        log = self.td / "many.log"
        lines = [f"12-Oct-2026 09:{i // 60:02d}:{i % 60:02d}.000 SEVERE [http-nio-8080-exec-1] o.a.c.c.C.[Tomcat].[localhost] java.lang.OutOfMemoryError: Java heap space"
                 for i in range(3100)]
        lines.append("12-Oct-2026 10:30:00.000 SEVERE [main] org.apache.catalina.core.StandardService.startInternal Failed to start connector [Connector[HTTP/1.1-8080]] java.net.BindException: Address already in use")
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        inc = run_analysis([{"path": str(log), "product": "tomcat", "host": "h"}], None,
                           rules_dir=ENGINE / "rules", local_dir=ENGINE / "rules-local", codes_dir=ENGINE / "errorcodes")
        if inc.get("timeline_total", 0) <= 3000:
            self.skipTest("표본이 상한을 넘지 않음")
        tl_eids = {t["eid"] for t in inc["timeline"]}
        late = [k for k in inc["timeline_key"] if k.get("eid") and k["ts"] >= "10:30"]
        self.assertTrue(late, "상한 밖에서 처음 나온 판정이 요점에 있어야 시험이 의미가 있다")
        for k in inc["timeline_key"]:
            if k.get("eid"):
                self.assertIn(k["eid"], tl_eids)
        self.assertLessEqual(len(inc["timeline"]), 3000 + len(inc["timeline_key"]))

    def test_other_obs_line_carries_eids(self):
        inc = dict(self.inc)
        many = [dict(self.inc["timeline_key"][0], eid=f"E-TEST{i:04d}", ts=f"2026-10-12 09:{i:02d}:00", verdict=f"판정{i}") for i in range(30)]
        inc["timeline_key"] = many
        F = rf.Facts(inc, PROFILE, None, rf.StyleProfile())
        lines = F.timeline_lines("조치내용", 3)
        other = [x for x in lines if "그 밖의 관측" in x]
        self.assertTrue(other, "판정이 줄 수보다 많으면 '그 밖의 관측' 줄이 생긴다")
        self.assertIn("E-TEST", other[0])                                               # 분석요약에서 같은 줄을 찾을 ID


class PerFormStyle(unittest.TestCase):
    """아이디어 2: 서식별 통계가 있으면 먼저, 표본이 모자란 값은 전체 통계."""

    def test_merge(self):
        d = {"fields": {"장애내용": {"lines": {"n": 20, "median": 2, "p75": 3}, "char": {"n": 20, "share": 0.9, "size": 11, "face": "A"}}},
             "by_form": {"status": {"fields": {"장애내용": {"lines": {"n": 5, "median": 1, "p75": 1},
                                                          "char": {"n": 2, "share": 1.0, "size": 15, "face": "B"}}}}}}
        sp = rf.StyleProfile(d)
        self.assertEqual(sp.lines_limit("장애내용", 9), 3)
        st = sp.for_form("status")
        self.assertEqual(st.form, "status")
        self.assertEqual(st.lines_limit("장애내용", 9), 1)                    # 서식별 표본 5 → 서식별
        self.assertEqual(st.field_style("장애내용")["face"], "A")             # 서식별 모양 표본 2 → 전체
        self.assertEqual(st.field_style("장애내용")["size"], 11.0)            # 글꼴·크기·자간·장평은 한 묶음 — 섞이지 않는다(GPT 27차)
        d["by_form"]["status"]["fields"]["장애내용"]["char"] = {"n": 9, "share": 0.9, "size": 15, "face": "B", "spacing": -5, "ratio": 95,
                                                                "sr_share": 0.9, "sr_margin": 0.8}
        d["fields"]["장애내용"]["char"].update(spacing=0, ratio=100, sr_share=1.0, sr_margin=1.0)
        cs = rf.StyleProfile(d).for_form("status").field_style("장애내용")
        self.assertEqual((cs["face"], cs["size"], cs["spacing"], cs["ratio"]), ("B", 15.0, -5, 95))   # 모두 서식별 한 묶음에서
        self.assertEqual(sp.for_form("postmortem").lines_limit("장애내용", 9), 3)   # 서식별 통계 없음 → 전체
        self.assertEqual(sp.for_form("").form, "")

    def test_learn_writes_by_form_only_with_enough_docs(self):
        td = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(td, ignore_errors=True))
        src = td / "src"
        src.mkdir()
        for i in range(rs.BY_FORM_MIN_DOCS):
            shutil.copyfile(TPL / "form_status.hwpx", src / f"s{i}.hwpx")
        shutil.copyfile(TPL / "form_postmortem.hwpx", src / "p.hwpx")
        r = rs.learn(src, TPL, td / "prof.json")
        self.assertEqual(r["by_form"], {"status": rs.BY_FORM_MIN_DOCS})       # 사후관리 1건은 나누지 않는다
        prof = json.loads((td / "prof.json").read_text(encoding="utf-8"))
        self.assertFalse(rs._forbidden_check(prof, rs.form_labels(TPL)))


class Endings(unittest.TestCase):
    """아이디어 10: 문장 끝 유형 — 유형 이름과 건수만."""

    def test_classes(self):
        e = rs.ending_class
        self.assertEqual(e("DB 커넥션 풀 고갈 발생 (최초 이상) (2회, ~14:02)"), "noun")
        self.assertEqual(e("서비스 재기동함."), "eum")
        self.assertEqual(e("원인을 확인하였다."), "da")
        self.assertEqual(e("14:03"), "other")
        self.assertEqual(e("[기재: 소요]"), "")
        self.assertEqual(e(""), "")

    def test_profile_has_only_class_names(self):
        a = rs.Agg()
        labels = rs.form_labels(TPL)
        paras = rs.parse_hwpx((TPL / "form_status.hwpx").read_bytes())
        rs.learn_doc(paras, "status", labels, a)
        prof = rs.summarize(a, labels)
        for sec in ("fields", "cells"):
            for v in prof[sec].values():
                self.assertTrue(set(v.get("ending", {})) <= {"da", "eum", "noun", "other"})


class StaleBackupAdmin(unittest.TestCase):
    """아이디어 9: 관리자 화면의 임시 백업 목록·삭제 — 주인이 살아 있거나 링크면 지우지 않는다."""

    def setUp(self):
        self.base = Path(_privtmp.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.base, ignore_errors=True))

    def _mk(self, name, owner=None):
        d = self.base / name
        (d / "stage").mkdir(parents=True)
        (d / "stage" / "x.txt").write_text("x", encoding="utf-8")
        if owner is not None:
            (d / safe_backup.OWNER).write_text(json.dumps({"pid": owner}), encoding="utf-8")
        return d

    @staticmethod
    def _age(d, sec=3600):
        import time
        t = time.time() - sec
        for p in sorted(d.rglob("*"), reverse=True) + [d]:
            os.utime(p, (t, t))

    def _qz_age(self, name, sec=3600):
        d = self.base / name
        m = json.loads((d / safe_backup.QZ_MARK).read_text(encoding="utf-8"))
        m["at"] -= sec
        (d / safe_backup.QZ_MARK).write_text(json.dumps(m), encoding="utf-8")
        reg = safe_backup._qreg(self.base)   # 7차: 지우기 판단은 conf 의 신뢰 기록 시각 — 같이 당긴다
        if name in reg:
            reg[name]["at"] -= sec
            safe_backup._qreg_write(self.base, reg)

    def test_list_and_two_step_delete(self):
        un = self._mk(".backup-unowned")
        live = self._mk(".backup-live", owner=os.getpid())
        names = {i["name"]: i for i in safe_backup.list_backups(self.base)}
        self.assertEqual(names[".backup-unowned"]["state"], "unowned")
        self.assertEqual(names[".backup-live"]["state"], "in_use")
        self.assertGreater(names[".backup-unowned"]["bytes"], 0)
        self.assertIsNone(names[".backup-unowned"]["action"])                 # 방금 바뀐 파일 → 아무것도 못 함
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-live").get("ok"))
        self.assertTrue(live.exists())
        for bad in ("..", "../x", ".backup-../../x", "stage", "C:\\Windows", ".backup-unowned/stage", ".backup-QZ_../x"):
            self.assertFalse(safe_backup.delete_backup(self.base, bad).get("ok"), bad)
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-unowned").get("ok"))
        self._age(un)
        self.assertEqual({i["name"]: i for i in safe_backup.list_backups(self.base)}[".backup-unowned"]["action"], "quarantine")
        r = safe_backup.delete_backup(self.base, ".backup-unowned")          # 1단계: 격리(이름 바꾸기)만
        self.assertTrue(r.get("ok") and r.get("quarantined"), r)
        self.assertFalse(un.exists())
        qz = self.base / r["name"]
        self.assertTrue(qz.is_dir() and (qz / "stage" / "x.txt").exists())   # 자료는 아직 그대로
        item = {i["name"]: i for i in safe_backup.list_backups(self.base)}[r["name"]]
        self.assertEqual((item["state"], item["action"]), ("quarantined", None))
        self.assertFalse(safe_backup.delete_backup(self.base, r["name"]).get("ok"))   # 격리 직후 지우기 거절
        self._qz_age(r["name"])
        self.assertEqual({i["name"]: i for i in safe_backup.list_backups(self.base)}[r["name"]]["action"], "delete")
        self.assertTrue(safe_backup.delete_backup(self.base, r["name"]).get("ok"))   # 2단계: 10분 뒤 지우기
        self.assertFalse(qz.exists())
        self._age(live)
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-live").get("ok"))   # 오래돼도 주인이 살아 있으면 안 지운다

    def test_write_after_quarantine_blocks_delete(self):
        un = self._mk(".backup-w")
        self._age(un)
        r = safe_backup.delete_backup(self.base, ".backup-w")
        self._qz_age(r["name"])
        (self.base / r["name"] / "stage" / "x.txt").write_text("still writing", encoding="utf-8")   # 열린 파일로 계속 쓰는 경우
        self.assertFalse(safe_backup.delete_backup(self.base, r["name"]).get("ok"))
        self.assertTrue((self.base / r["name"]).exists())

    @unittest.skipUnless(os.name == "nt", "Windows 전용 — 열린 파일이 있으면 이름 바꾸기 거절")
    def test_open_file_blocks_quarantine_on_windows(self):
        un = self._mk(".backup-open")
        self._age(un)
        with open(un / "stage" / "x.txt", "rb"):
            r = safe_backup.delete_backup(self.base, ".backup-open")
        self.assertFalse(r.get("ok"), r)
        self.assertTrue(un.exists())

    def test_orphan_and_link(self):
        dead = self._mk(".backup-dead", owner=999999)       # 없는 프로세스
        self._age(dead)
        self.assertEqual({i["name"]: i for i in safe_backup.list_backups(self.base)}[".backup-dead"]["action"], "delete")
        outside = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        (outside / "keep.txt").write_text("k", encoding="utf-8")
        inner = self._mk(".backup-inner", owner=999998)
        import subprocess
        if os.name == "nt":
            subprocess.run(["cmd", "/c", "mklink", "/J", str(inner / "stage" / "j"), str(outside)], capture_output=True)
        else:
            os.symlink(outside, inner / "stage" / "j")
        self._age(inner)
        self.assertTrue((inner / "stage" / "j").exists(), "정션을 못 만들면 시험이 의미가 없다")
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-inner").get("ok"))
        self.assertTrue((outside / "keep.txt").exists())
        self.assertTrue(safe_backup.delete_backup(self.base, ".backup-dead").get("ok"))   # 주인 끝난 폴더는 한 번에
        self.assertFalse(dead.exists())

    def test_unowned_waits_while_zip_is_written(self):
        un = self._mk(".backup-old")
        self._age(un)
        (self.base / "backups").mkdir()
        (self.base / "backups" / "backup-x.zip.partial").write_bytes(b"PK")   # 옛 판이 지금 묶는 중
        self.assertIsNone(safe_backup.list_backups(self.base)[0]["action"])
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-old").get("ok"))
        self._age(self.base / "backups")
        self.assertTrue(safe_backup.delete_backup(self.base, ".backup-old").get("quarantined"))

    def test_fresh_empty_dir_is_not_touched(self):
        d = self.base / ".backup-empty"
        d.mkdir()
        self.assertFalse(safe_backup.delete_backup(self.base, ".backup-empty").get("ok"))
        self.assertTrue(d.exists())


if __name__ == "__main__":
    unittest.main()
