@echo off
rem LogTriage 자원 사용률 에이전트 — Windows 설치형(관리자 권한 불필요). 압축을 푼 폴더에서 실행.
rem   lt-agent.cmd start [서버주소] [토큰] [간격초] [드라이브]   백그라운드 시작(처음 한 번은 주소·토큰 → agent.conf 저장)
rem   lt-agent.cmd stop | status | log | test
rem   lt-agent.cmd enable-boot | disable-boot     로그온 시 자동 시작(사용자 작업 스케줄러 LogTriageAgent) 등록/해제
setlocal EnableDelayedExpansion
set "HERE=%~dp0"
set "CONF=%HERE%agent.conf"
set "PIDF=%HERE%agent.pid"
set "LOG=%HERE%lt-agent.log"
set "CMD=%~1"
if "%CMD%"=="" set "CMD=status"
set "INTERVAL=30"
set "DISK=all"
set "PROCS=1"
if not "%~2"=="" if not "%~3"=="" (
  > "%CONF%" echo # LogTriage 에이전트 설정 - 토큰이 들어 있으므로 다른 사용자와 공유하지 마십시오
  >>"%CONF%" echo URL=%~2
  >>"%CONF%" echo TOKEN=%~3
  if not "%~4"=="" (>>"%CONF%" echo INTERVAL=%~4) else (>>"%CONF%" echo INTERVAL=30)
  if not "%~5"=="" (>>"%CONF%" echo DISK=%~5) else (>>"%CONF%" echo DISK=all)
  echo 설정 저장: %CONF%
)
if exist "%CONF%" for /f "usebackq eol=# tokens=1,* delims==" %%a in ("%CONF%") do set "%%a=%%b"
if /i "%CMD%"=="start" goto start
if /i "%CMD%"=="stop" goto stop
if /i "%CMD%"=="status" goto status
if /i "%CMD%"=="log" goto log
if /i "%CMD%"=="test" goto test
if /i "%CMD%"=="enable-boot" goto enable
if /i "%CMD%"=="disable-boot" goto disable
echo 사용: lt-agent.cmd start ^| stop ^| status ^| log ^| test ^| enable-boot ^| disable-boot
exit /b 2

:need
if "%URL%"=="" (echo 설정이 없습니다. 먼저: lt-agent.cmd start http://^<LogTriage서버^>:8088 ^<토큰^> & exit /b 1)
if "%TOKEN%"=="" (echo agent.conf 에 TOKEN 이 필요합니다 & exit /b 1)
exit /b 0

:running
set "RUNPID="
if exist "%PIDF%" (
  set /p RUNPID=<"%PIDF%"
  tasklist /FI "PID eq !RUNPID!" 2>nul | find "!RUNPID!" >nul || set "RUNPID="
)
exit /b 0

:start
call :need || exit /b 1
call :running
if not "%RUNPID%"=="" (echo 이미 실행 중 ^(pid %RUNPID%^) & exit /b 0)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath 'powershell' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','\"%HERE%lt-agent.ps1\"','-Url','%URL%','-Token','%TOKEN%','-Interval','%INTERVAL%','-Drive','%DISK%','-Procs','%PROCS%' -WindowStyle Hidden -RedirectStandardOutput '%LOG%' -PassThru; Set-Content -Path '%PIDF%' -Value $p.Id"
ping -n 3 127.0.0.1 >nul
call :running
if "%RUNPID%"=="" (echo ! 시작 실패 - 로그 확인: %LOG% & exit /b 1)
echo 시작됨: pid %RUNPID% · 첫 전송은 %INTERVAL%초 뒤 · 로그 %LOG%
echo LogTriage [모니터링]에 이 PC IP 가 '자원 사용률 수집: 에이전트'로 등록돼 있어야 저장됩니다.
exit /b 0

:stop
call :running
if "%RUNPID%"=="" (echo 실행 중이 아닙니다 & del /q "%PIDF%" 2>nul & exit /b 0)
taskkill /PID %RUNPID% /T /F >nul 2>&1
del /q "%PIDF%" 2>nul
echo 중지됨 ^(pid %RUNPID%^)
exit /b 0

:status
call :running
if "%RUNPID%"=="" (echo 중지 상태) else (echo 실행 중: pid %RUNPID%)
if not "%URL%"=="" echo 서버: %URL% · 간격 %INTERVAL%s · 드라이브 %DISK%
if exist "%LOG%" (echo --- 최근 로그 --- & powershell -NoProfile -Command "Get-Content -Path '%LOG%' -Tail 5")
exit /b 0

:log
if exist "%LOG%" (powershell -NoProfile -Command "Get-Content -Path '%LOG%' -Tail 30") else (echo 로그 없음)
exit /b 0

:test
call :need || exit /b 1
echo 1^) 서버 연결: %URL%/healthz
powershell -NoProfile -Command "try{$r=Invoke-RestMethod -Uri '%URL%/healthz' -TimeoutSec 5; if($r.ok){'   OK'}else{'   응답 이상'; exit 1}}catch{'   실패: '+$_.Exception.Message; '   주소·포트(기본 8088)·방화벽 확인'; exit 1}" || exit /b 1
echo 2^) 수집기: PowerShell ^(lt-agent.ps1^) - start 후 로그로 확인하십시오
exit /b 0

:enable
schtasks /Create /F /SC ONLOGON /TN LogTriageAgent /TR "\"%HERE%lt-agent.cmd\" start" /RL LIMITED >nul && echo 등록됨: 로그온 시 자동 시작 ^(작업 스케줄러 LogTriageAgent^) || echo ! 등록 실패 ^(작업 스케줄러 사용 권한 확인^)
exit /b 0

:disable
schtasks /Delete /F /TN LogTriageAgent >nul 2>&1 && echo 자동 시작 해제 || echo 등록된 작업 없음
exit /b 0
