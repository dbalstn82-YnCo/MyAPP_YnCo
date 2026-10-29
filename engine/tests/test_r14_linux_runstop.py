"""14차(2026-10-22 현장 RHEL): bash run.sh 가 healthz·판 지문이 맞는데도 '포트를 쥔 것은 새 프로세스가 아님 — 옛 서버'로 실패,
bash stop.sh 는 '실행 중인 서버가 없습니다' — 원인은 ( cd engine && nohup python … & echo $! ) 의 $! 가 python 이 아닌 하위 셸.
반출/_run.sh·_stop.sh(묶음의 run.sh·stop.sh 원본)가 그 모양으로 돌아가지 않는지와 GPT 100차 반례 막이를 지킨다.
반례 동작 시험은 검증도구/sim_stop_sh.sh(Git Bash /proc + 대역) — bash·/proc 이 있으면 여기서도 돌린다. 묶음 안(반출 없음)에서는 건너뛴다."""
from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path

ENGINE = Path(__file__).resolve().parents[1]
OUT = ENGINE.parent / "반출"
SIM = ENGINE.parent / "검증도구" / "sim_stop_sh.sh"


@unittest.skipUnless((OUT / "_run.sh").is_file() and (OUT / "_stop.sh").is_file(), "반출 원본이 없는 자리(리눅스 묶음 안)")
class RunStop(unittest.TestCase):
    def setUp(self):
        self.run = (OUT / "_run.sh").read_text(encoding="utf-8")
        self.stop = (OUT / "_stop.sh").read_text(encoding="utf-8")

    def test_pid_is_python_not_subshell(self):
        code = [ln for ln in self.run.splitlines() if not ln.lstrip().startswith("#")]
        launch = [ln for ln in code if "nohup" in ln and '"$PY"' in ln]
        self.assertEqual(len(launch), 2, launch)
        for ln in launch:
            self.assertFalse(re.search(r"\(\s*cd\b.*&&.*nohup", ln), ln)        # 하위 셸 안 비동기 && 목록이면 $! 가 셸
            self.assertTrue(ln.rstrip().endswith("9>&- &"), ln)                 # 직접 백그라운드 작업 · 기동 자물쇠 안 물려줌
        self.assertIn('echo $! > "$HERE/server.pid"', self.run)
        self.assertIn("pgrep -P \"$_P\" -f 'logtriage\\.server'", self.run)

    def test_port_cleanup_is_port_owner_only(self):
        """GPT 100차 P0-01: 포트 정리는 그 포트를 실제로 쥔 이 폴더의 서버만."""
        self.assertIn('bash "$HERE/stop.sh" --mine-only --port "$PORT"', self.run)
        self.assertIn('bash "$HERE/stop.sh" --port "$PORT"', self.run)
        self.assertIn('ss -ltnpH "sport = :$PORT"', self.stop)

    def test_mine_checks_uid_cwd_cmdline(self):
        """GPT 100차 P0-03 · P0-02: 다른 사용자(root 포함) 서버 제외, 강제 종료 직전 재확인."""
        m = re.search(r"mine\(\) \{(.*?)\n\}", self.stop, re.S).group(1)
        for part in ('stat -c %u "/proc/$1"', '"$ME"', 'readlink -f "/proc/$1/cwd"', '"$WANT"', "logtriage\\.server"):
            self.assertIn(part, m)
        self.assertIn('for P in $LEFT; do mine "$P" && FORCE="$FORCE $P"; done', self.stop)

    def test_flock_serializes(self):
        self.assertIn('flock -n 9 || fail', self.run)
        self.assertIn("export LT_CTL_LOCKED=1", self.run)
        self.assertIn('if [ -z "${LT_CTL_LOCKED:-}" ] && command -v flock', self.stop)

    def test_build_check_uses_engine_stamp(self):
        """2026-10-22 현장 2차: 패치 뒤 VERSION.txt 만 옛 값이라 새로 뜬 서버를 '판이 다르다'며 내렸다 —
        기준은 이 폴더 엔진의 판 지문(_build_id.json), VERSION.txt 가 다르면 알리고 고친다. 진짜 옛 서버가 응답하면 여전히 막는다."""
        self.assertIn('"$HERE/engine/logtriage/_build_id.json"', self.run)
        self.assertIn('[ "$VER_ID" != "$WANT_ID" ]', self.run)
        self.assertIn('응답한 서버의 판 지문이 다릅니다: ${GOT_ID:-(없음)} (이 폴더 엔진 $WANT_ID)"; BAD=1', self.run)
        i = self.run.index("# 판 지문 대조 — 이 폴더의 엔진과")
        self.assertLess(self.run.index("_build_id.json", i), self.run.index("VERSION.txt", self.run.index("VER_ID=", i)))

    def test_setup_code_shown_on_start(self):
        """2026-10-22 마스터: '기동 시 1회용 코드가 안 나온다 — 파일을 찾아야 하는 건 아니다' — 계정이 없으면 기동 안내에 코드·바로 열 주소."""
        i = self.run.index('SETUP_F="$HERE/data/conf/setup-code.txt"')
        blk = self.run[i:self.run.index("\nfi\n", self.run.index("SCODE=", i)) + 3]
        self.assertIn('1회용 코드 : $SCODE', blk)
        self.assertIn('/setup?t=$SCODE', blk)
        self.assertLess(self.run.index("LogTriage 기동 완료"), i)                 # 기동 완료 바로 아래(눈에 띄는 자리)
        self.assertNotIn("코드: cat", self.run)                                  # '파일을 열어 보라'는 안내는 없앴다
        j = self.run.index('chmod 600 "$HERE/server.log"')                      # GPT 104차 P0: 코드가 찍히는 기록은 이 계정만
        self.assertLess(j, self.run.index('nohup "$PY" "${ARGS[@]}"'))

    def test_lf_only(self):
        for n in ("_stop.sh",):
            self.assertNotIn(b"\r", (OUT / n).read_bytes(), n)

    @unittest.skipUnless(SIM.is_file() and shutil.which("bash") and Path("/proc").exists() or
                         (SIM.is_file() and shutil.which("bash") and subprocess.run(["bash", "-c", "test -d /proc/self"],
                                                                                  capture_output=True).returncode == 0),
                         "bash·/proc 없음")
    def test_counterexamples_sim(self):
        r = subprocess.run(["bash", str(SIM), str(OUT / "_stop.sh")], capture_output=True, timeout=240,
                           encoding="utf-8", errors="replace")
        self.assertIn("실패 0", r.stdout, r.stdout[-2000:] + r.stderr[-1000:])


if __name__ == "__main__":
    unittest.main()
