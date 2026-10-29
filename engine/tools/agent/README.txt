LogTriage 자원 사용률 에이전트 — 설치형(압축 해제 후 실행, root/관리자 권한 불필요)
=====================================================================================

이 폴더 안에서만 동작합니다(설정·로그·pid 파일 모두 이 폴더). /opt, /etc, systemd 등 시스템 영역에는 아무것도 쓰지 않습니다.
일반 사용자 계정으로 실행해도 CPU·메모리·디스크(모든 볼륨)·트래픽 값을 읽을 수 있습니다(Linux 는 /proc 과 df 만 사용).

1. 준비: LogTriage [모니터링] → [+ 감시 항목 등록] 에서 이 서버 IP 를 '자원 사용률 수집: 에이전트'로 등록.
   (화면에서 받은 lt-agent.zip 에는 서버 주소·토큰이 agent.conf 에 이미 들어 있습니다)

2. Linux / Unix (AIX·Solaris·HP-UX·FreeBSD 포함)
     unzip lt-agent.zip && cd lt-agent
     sh lt-agent-ctl.sh test          # 서버 연결·1회 전송 시험
     sh lt-agent-ctl.sh start         # 백그라운드 시작(agent.conf 가 없으면: start http://<서버>:8088 <토큰>)
     sh lt-agent-ctl.sh status        # 상태·마지막 정상 전송·최근 로그
     sh lt-agent-ctl.sh enable-boot   # 재부팅 후 자동 시작(사용자 crontab @reboot) — 선택
     sh lt-agent-ctl.sh stop
   수집기는 자동 선택: python3 → lt-agent.py / Linux+bash → lt-agent.sh / 그 외 → lt-agent-posix.sh(vmstat·df).
   강제 지정은 agent.conf 의 COLLECTOR=python|bash|posix.
   필요한 것: python3 또는 (curl 또는 wget). 대상 서버 → LogTriage 서버 TCP 8088(기본) 아웃바운드 허용.

3. Windows (관리자 권한 불필요)
     압축 해제 → 명령 프롬프트에서 폴더로 이동
     lt-agent.cmd test
     lt-agent.cmd start               # PowerShell 로 숨김 실행
     lt-agent.cmd status
     lt-agent.cmd enable-boot         # 로그온 시 자동 시작(사용자 작업 스케줄러) — 선택
     lt-agent.cmd stop

3-1. 계정별 프로세스 현황: 기본으로 계정별 프로세스 수·CPU·메모리 집계와 상위 20개 프로세스(이름만, 명령행 인자 없음)를 함께 보냅니다.
     Linux/Unix 는 /proc·ps 로 전 계정이 보이고, Windows 는 관리자 권한이 아니면 다른 계정 프로세스가 N/A 로 집계됩니다. 끄려면 agent.conf 의 PROCS=0.

4. 확인: lt-agent.log 마지막 줄에 {"ok": true, ...} 가 보이면 정상. 401 이면 토큰 불일치, 404 이면 이 서버 IP 가 미등록.

5. 재부팅 자동 시작이 꼭 필요한데 cron 사용 권한이 없다면 관리자에게 lt-agent-install.sh(root, systemd 서비스) 실행을 요청하십시오.

제한: POSIX 수집기(vmstat·df)는 트래픽을 보내지 않고, HP-UX 는 메모리를 보내지 않으며, AIX/Solaris 메모리는 파일 캐시를 포함해 높게 보입니다(실장비 미검증 — 이상하면 COLLECTOR=python).

보안: agent.conf 에 토큰이 들어 있습니다(권한 600 으로 유지, lt-agent-ctl.sh 는 토큰을 명령행이 아닌 환경변수로 수집기에 전달). 토큰이 유출되면 LogTriage 서버의 data/nms/agent_token.txt 를 지우고 재기동해 새 토큰을 받으십시오.
