[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\EnsureFirewall-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5

function Ensure-LogFile {
  $dir = Split-Path -Parent $LogPath
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType File -Force | Out-Null }
}

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  try { Add-Content -Path $LogPath -Value $line -Encoding utf8 } catch {}
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"; $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Now-Timestamp {
  $tz=(Get-Date).ToString('zzz').Replace(':','')
  (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') + $tz
}

function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Test-Admin {
  try { return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
  catch { return $false }
}

function _B($v) { return [bool]$v }
function _S($v) { if ($null -eq $v) { return "" } else { return [string]$v } }

function Ensure-FirewallProfile {
  param([ValidateSet('Domain','Private','Public')][string]$Profile)

  Write-Log "Checking $($Profile) firewall profile..." 'INFO'

  $result = [ordered]@{
    profile        = $Profile
    changes        = @()
    enforced       = $true
    policy_blocked = $false
    errors         = @()
  }

  try { $before = Get-NetFirewallProfile -Profile $Profile -ErrorAction Stop } catch {
    $result.enforced = $false
    $result.errors  += "Get-NetFirewallProfile(before): $($_.Exception.Message)"
    return [pscustomobject]$result
  }

  $isAdmin = Test-Admin
  if (-not $isAdmin) {
    Write-Log "Not running elevated; will not modify settings, only report." 'WARN'
  } else {
    if (-not ($before.Enabled)) {
      try {
        Write-Log "$($Profile) firewall was disabled. Enabling it." 'WARN'
        Set-NetFirewallProfile -Profile $Profile -Enabled True -ErrorAction Stop
        $result.changes += 'enabled'
      } catch {
        $result.errors  += "Set Enabled: $($_.Exception.Message)"
        $result.enforced = $false
      }
    }

    if (-not (_B $before.LogAllowed)) {
      try {
        Write-Log "$($Profile): enabling logging of allowed connections." 'WARN'
        Set-NetFirewallProfile -Profile $Profile -LogAllowed True -ErrorAction Stop
        $result.changes += 'log_allowed'
      } catch {
        $result.errors  += "Set LogAllowed: $($_.Exception.Message)"
        $result.enforced = $false
      }
    }

    if (-not (_B $before.LogBlocked)) {
      try {
        Write-Log "$($Profile): enabling logging of blocked connections." 'WARN'
        Set-NetFirewallProfile -Profile $Profile -LogBlocked True -ErrorAction Stop
        $result.changes += 'log_blocked'
      } catch {
        $result.errors  += "Set LogBlocked: $($_.Exception.Message)"
        $result.enforced = $false
      }
    }

    if ([string]::IsNullOrWhiteSpace( (_S $before.LogFileName) )) {
      try {
        Write-Log "$($Profile): setting default log path." 'WARN'
        Set-NetFirewallProfile -Profile $Profile -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log" -ErrorAction Stop
        $result.changes += 'log_path'
      } catch {
        $result.errors  += "Set LogFileName: $($_.Exception.Message)"
        $result.enforced = $false
      }
    }
  }

  try { $after = Get-NetFirewallProfile -Profile $Profile -ErrorAction Stop } catch { $after = $null; $result.errors += "Get-NetFirewallProfile(after): $($_.Exception.Message)"; $result.enforced = $false }
  try { $afterActive = Get-NetFirewallProfile -Profile $Profile -PolicyStore ActiveStore -ErrorAction Stop } catch { $afterActive = $null; $result.errors += "Get-NetFirewallProfile(ActiveStore): $($_.Exception.Message)" }

  if ($afterActive) {
    if (($result.changes -contains 'log_allowed') -and -not (_B $afterActive.LogAllowed)) { $result.policy_blocked = $true }
    if (($result.changes -contains 'log_blocked') -and -not (_B $afterActive.LogBlocked)) { $result.policy_blocked = $true }
  }

  $result.before = [pscustomobject]@{
    enabled       = _B $before.Enabled
    log_allowed   = _B $before.LogAllowed
    log_blocked   = _B $before.LogBlocked
    log_file_name = _S $before.LogFileName
  }

  if ($after) {
    $result.after = [pscustomobject]@{
      enabled       = _B $after.Enabled
      log_allowed   = _B $after.LogAllowed
      log_blocked   = _B $after.LogBlocked
      log_file_name = _S $after.LogFileName
    }
  }

  if ($afterActive) {
    $result.active_store = [pscustomobject]@{
      enabled       = _B $afterActive.Enabled
      log_allowed   = _B $afterActive.LogAllowed
      log_blocked   = _B $afterActive.LogBlocked
      log_file_name = _S $afterActive.LogFileName
    }
  }

  return [pscustomobject]$result
}

Ensure-LogFile
Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Ensure Firewall Enabled ===" 'INFO'

try {
  $ts = Now-Timestamp
  $lines = @()

  $svc = Get-Service -Name MpsSvc -ErrorAction SilentlyContinue
  $isAdmin = Test-Admin
  $verify = [pscustomobject]@{
    timestamp      = $ts
    host           = $HostName
    action         = 'ensure_firewall_enabled'
    copilot_action = $true
    type           = 'verify_source'
    os_version     = (Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Version)
    ps_version     = $PSVersionTable.PSVersion.ToString()
    admin          = $isAdmin
    service        = @{
      name   = 'MpsSvc'
      status = if ($svc) { $svc.Status } else { 'NotFound' }
    }
    modules        = @('NetSecurity')
  }
  $lines += ($verify | ConvertTo-Json -Compress -Depth 5)

  if ($svc -and $svc.Status -ne 'Running') {
    Write-Log "Windows Firewall service (MpsSvc) is not Running (status=$($svc.Status))." 'WARN'
  }

  $details = New-Object System.Collections.Generic.List[object]
  foreach ($profile in @('Domain','Private','Public')) {
    try {
      $details.Add( (Ensure-FirewallProfile -Profile $profile) )
    } catch {
      Write-Log "Failed on profile ${profile}: $($_.Exception.Message)" 'ERROR'
      $details.Add([pscustomobject]@{
        profile        = $profile
        enforced       = $false
        changes        = @()
        errors         = @("Unhandled: $($_.Exception.Message)")
        policy_blocked = $false
      })
    }
  }

  $changedCount = ($details | Where-Object { $_.changes -and $_.changes.Count -gt 0 }).Count
  $errorsCount  = ($details | Where-Object { $_.enforced -eq $false }).Count
  $policyCount  = ($details | Where-Object { $_.policy_blocked }).Count

  $lines += ([pscustomobject]@{
    timestamp        = $ts
    host             = $HostName
    action           = 'ensure_firewall_enabled'
    copilot_action   = $true
    type             = 'summary'
    profiles_total   = 3
    profiles_changed = $changedCount
    profiles_error   = $errorsCount
    profiles_policy  = $policyCount
    status           = if ($errorsCount -gt 0) { 'partial' } elseif ($changedCount -gt 0) { 'updated' } else { 'ok' }
    duration_s       = [math]::Round(((Get-Date)-$runStart).TotalSeconds,1)
  } | ConvertTo-Json -Compress -Depth 5)

  foreach ($d in $details) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'ensure_firewall_enabled'
      copilot_action = $true
      type           = 'profile'
      profile        = $d.profile
      enforced       = [bool]$d.enforced
      policy_blocked = [bool]$d.policy_blocked
      changes        = $d.changes
      before         = $d.before
      after          = $d.after
      active_store   = $d.active_store
      errors         = $d.errors
    } | ConvertTo-Json -Compress -Depth 7)
  }

  if ($policyCount -gt 0) {
    $lines += ([pscustomobject]@{
      timestamp      = $ts
      host           = $HostName
      action         = 'ensure_firewall_enabled'
      copilot_action = $true
      type           = 'policy_hint'
      hint           = 'Logging settings appear overridden by policy (ActiveStore). Check GPO.'
      registry_paths = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging',
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging',
        'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
      )
    } | ConvertTo-Json -Compress -Depth 4)
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("NDJSON written to {0} ({1} lines)" -f $ARLog,$lines.Count) 'INFO'
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = [pscustomobject]@{
    timestamp      = Now-Timestamp
    host           = $HostName
    action         = 'ensure_firewall_enabled'
    copilot_action = $true
    type           = 'error'
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @(( $err | ConvertTo-Json -Compress -Depth 4 )) -Path $ARLog
  Write-Log "Error NDJSON written" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
