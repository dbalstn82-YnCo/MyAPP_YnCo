# LogTriage 자원 사용률 에이전트(Windows PowerShell) — CPU/메모리/디스크 사용률을 LogTriage 서버에 주기적으로 전송
# 사용: powershell -ExecutionPolicy Bypass -File lt-agent.ps1 -Url http://<LogTriage서버>:8088 -Token <토큰> [-Interval 30] [-Drive all] [-Procs 1]   (all: 모든 고정 드라이브, 또는 C: 처럼 하나 / -Procs 0: 계정별 프로세스 수집 안 함)
# 계정별 프로세스: 관리자 권한이면 전 계정, 일반 사용자면 접근 가능한 프로세스만 계정이 보이고 나머지는 N/A
param([Parameter(Mandatory=$true)][string]$Url,[Parameter(Mandatory=$true)][string]$Token,[int]$Interval=30,[string]$Drive="all",[int]$Procs=1)
$Url=$Url.TrimEnd("/")
if ($Token -eq "-") { $Token = $env:LT_AGENT_TOKEN }
if ($env:LT_PROCS -eq "0") { $Procs = 0 }
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$NCPU = [Environment]::ProcessorCount
$OwnerCache = @{}; $SidCache = @{}; $PrevCpu = @{}; $PrevT = $null
$OwnerApi = $false
if (-not $IsAdmin) {   # 일반 사용자: 프로세스 토큰의 SID 로 계정 조회(빠름). 컴파일 실패 시 WMI GetOwner 폴백
  try {
    Add-Type -Namespace LT -Name Own -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr tok);
[DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr info, int len, out int need);
[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr str);
[DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
[DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
public static string Sid(int pid) {
  IntPtr h = OpenProcess(0x1000, false, pid); if (h == IntPtr.Zero) return null;
  IntPtr tok = IntPtr.Zero; string r = null;
  try {
    if (!OpenProcessToken(h, 0x8, out tok)) return null;
    int need; GetTokenInformation(tok, 1, IntPtr.Zero, 0, out need); if (need <= 0) return null;
    IntPtr buf = System.Runtime.InteropServices.Marshal.AllocHGlobal(need);
    try {
      if (!GetTokenInformation(tok, 1, buf, need, out need)) return null;
      IntPtr sid = System.Runtime.InteropServices.Marshal.ReadIntPtr(buf); IntPtr s;
      if (ConvertSidToStringSidW(sid, out s)) { r = System.Runtime.InteropServices.Marshal.PtrToStringUni(s); LocalFree(s); }
    } finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(buf); }
  } finally { if (tok != IntPtr.Zero) CloseHandle(tok); CloseHandle(h); }
  return r; }
'@ -ErrorAction Stop
    $OwnerApi = $true
  } catch { $OwnerApi = $false }
}
function Get-OwnerApi([int]$ProcId) {   # SID → DOMAIN\user (SID 별 캐시)
  $s = [LT.Own]::Sid($ProcId); if (-not $s) { return "N/A" }
  if ($SidCache.ContainsKey($s)) { return $SidCache[$s] }
  $n = "N/A"; try { $n = (New-Object System.Security.Principal.SecurityIdentifier($s)).Translate([System.Security.Principal.NTAccount]).Value } catch { $n = $s }
  $SidCache[$s] = $n; return $n
}
function Get-Procs {   # 계정별 집계 + 상위 20개 — 관리자: Get-Process -IncludeUserName(전 계정), 일반 사용자: 토큰 SID 조회(접근 가능한 것만, 나머지 N/A)
  $now = Get-Date; $rows = @()
  if ($IsAdmin) { $plist = Get-Process -IncludeUserName -ErrorAction SilentlyContinue } else { $plist = Get-Process -ErrorAction SilentlyContinue }
  if (-not $IsAdmin -and -not $OwnerApi) {   # 폴백: WMI GetOwner(느림) — 새 PID 만 조회해 캐시
    $need = @($plist | Where-Object { -not $OwnerCache.ContainsKey($_.Id) } | Select-Object -ExpandProperty Id)
    if ($need.Count -gt 0) {
      foreach ($w in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        if ($need -contains $w.ProcessId) { $o = Invoke-CimMethod -InputObject $w -MethodName GetOwner -ErrorAction SilentlyContinue
          if ($o -and $o.ReturnValue -eq 0 -and $o.User) { $OwnerCache[[int]$w.ProcessId] = ($(if ($o.Domain) { $o.Domain + "\" } else { "" }) + $o.User) } else { $OwnerCache[[int]$w.ProcessId] = "N/A" } } } }
  }
  $cur = @{}; $el = if ($PrevT) { ($now - $PrevT).TotalSeconds } else { 0 }
  foreach ($pr in $plist) {
    if ($IsAdmin) { $u = $(if ($pr.UserName) { $pr.UserName } else { "N/A" }) }
    elseif ($OwnerApi) { $u = Get-OwnerApi $pr.Id }
    else { $u = $(if ($OwnerCache.ContainsKey($pr.Id)) { $OwnerCache[$pr.Id] } else { "N/A" }) }
    $cs = 0.0; try { $cs = $pr.TotalProcessorTime.TotalSeconds } catch {}
    $st = ""; try { $st = $pr.StartTime.Ticks } catch { $st = $pr.ProcessName }   # 시작 시각(없으면 이름)으로 PID 재사용 구분
    $key = "$($pr.Id)|$st"; $cur[$key] = $cs; $pct = 0.0
    if ($el -gt 0 -and $PrevCpu.ContainsKey($key) -and $cs -ge $PrevCpu[$key]) { $pct = [math]::Round(100.0 * ($cs - $PrevCpu[$key]) / $el / $NCPU, 1) }
    $rows += [pscustomobject]@{ pid = $pr.Id; user = $u; name = $pr.ProcessName; cpu = $pct; mem_mb = [math]::Round($pr.WorkingSet64 / 1MB, 1) }
  }
  $script:PrevCpu = $cur; $script:PrevT = $now
  $users = @(); foreach ($g in ($rows | Group-Object user | Sort-Object Count -Descending | Select-Object -First 40)) {
    $users += @{ user = $g.Name; count = $g.Count; cpu = [math]::Round(($g.Group | Measure-Object cpu -Sum).Sum, 1); mem_mb = [math]::Round(($g.Group | Measure-Object mem_mb -Sum).Sum, 1) } }
  $top = @(); foreach ($r in ($rows | Sort-Object cpu, mem_mb -Descending | Select-Object -First 20)) { $top += @{ pid = $r.pid; user = $r.user; name = $r.name; cpu = $r.cpu; mem_mb = $r.mem_mb } }
  $failed = @($rows | Where-Object { $_.user -eq "N/A" }).Count
  return @{ total = $rows.Count; known = ($rows.Count - $failed); failed = $failed; ncpu = $NCPU; users = $users; top = $top }
}
if ($Procs) { try { $null = Get-Procs } catch { $Procs = 0 } }   # CPU% 기준값
while ($true) {
  Start-Sleep -Seconds $Interval
  $cpu=[math]::Round((Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue,1)
  $os=Get-CimInstance Win32_OperatingSystem
  $mem=[math]::Round(100*($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize,1)
  $ds=@(); $disk=$null
  $list = if ($Drive -eq "all") { Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" } else { Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$Drive'" }
  foreach ($d in $list) { if ($d.Size -gt 0) { $p=[math]::Round(100*($d.Size-$d.FreeSpace)/$d.Size,1); $ds+=@{path=$d.DeviceID;pct=$p;used_gb=[math]::Round(($d.Size-$d.FreeSpace)/1GB,1);total_gb=[math]::Round($d.Size/1GB,1)}; if ($null -eq $disk -or $p -gt $disk) { $disk=$p } } }
  $rx=[math]::Round(((Get-Counter '\\Network Interface(*)\\Bytes Received/sec').CounterSamples | Measure-Object CookedValue -Sum).Sum,1)
  $tx=[math]::Round(((Get-Counter '\\Network Interface(*)\\Bytes Sent/sec').CounterSamples | Measure-Object CookedValue -Sum).Sum,1)
  $bodyObj=@{hostname=$env:COMPUTERNAME;cpu=$cpu;mem=$mem;disk=$disk;rx=$rx;tx=$tx;os="windows";disk_path=$Drive;disks=$ds}
  if ($Procs) { try { $bodyObj.procs = Get-Procs } catch { $bodyObj.procs = $null } }
  $body=$bodyObj|ConvertTo-Json -Compress -Depth 5
  try { $r=Invoke-RestMethod -Method Post -Uri "$Url/api/nms/metrics" -ContentType "application/json" -Headers @{"X-Agent-Token"=$Token} -Body $body -TimeoutSec 5; $msg=($r|ConvertTo-Json -Compress) }
  catch { $msg="전송 실패: $($_.Exception.Message)" }
  Write-Host ("{0} cpu={1} mem={2} disk={3} -> {4}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$cpu,$mem,$disk,$msg)
}
