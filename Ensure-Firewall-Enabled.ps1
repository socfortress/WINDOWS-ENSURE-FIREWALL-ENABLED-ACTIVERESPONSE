[CmdletBinding()]
param(
  [string]$LogPath = "$env:TEMP\EnsureFirewall-script.log",
  [string]$ARLog   = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep  = 5

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
  Add-Content -Path $LogPath -Value $line -Encoding utf8
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
  Set-Content -Path $tmp -Value ($JsonLines -join [Environment]::NewLine) -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Ensure-FirewallProfile {
  param([ValidateSet('Domain','Private','Public')][string]$Profile)

  Write-Log "Checking $Profile firewall profile..." 'INFO'

  $before = Get-NetFirewallProfile -Profile $Profile
  $changes = @()

  if (-not $before.Enabled) {
    Write-Log "$Profile firewall was disabled. Enabling it." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -Enabled True
    $changes += 'enabled'
  }

  if (-not $before.LogAllowed) {
    Write-Log "${Profile}: enabling logging of allowed connections." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogAllowed True
    $changes += 'log_allowed'
  }

  if (-not $before.LogBlocked) {
    Write-Log "${Profile}: enabling logging of blocked connections." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogBlocked True
    $changes += 'log_blocked'
  }

  if (-not $before.LogFileName) {
    Write-Log "${Profile}: setting default log path." 'WARN'
    Set-NetFirewallProfile -Profile $Profile -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"
    $changes += 'log_path'
  }

  $after = Get-NetFirewallProfile -Profile $Profile
  $afterActive = Get-NetFirewallProfile -Profile $Profile -PolicyStore ActiveStore

  $policyBlocked = $false
  if ($changes -contains 'log_allowed' -and -not $afterActive.LogAllowed) { $policyBlocked = $true }
  if ($changes -contains 'log_blocked' -and -not $afterActive.LogBlocked) { $policyBlocked = $true }

  [pscustomobject]@{
    profile        = $Profile
    before         = [pscustomobject]@{
      enabled       = [bool]$before.Enabled
      log_allowed   = [bool]$before.LogAllowed
      log_blocked   = [bool]$before.LogBlocked
      log_file_name = [string]$before.LogFileName
    }
    after          = [pscustomobject]@{
      enabled       = [bool]$after.Enabled
      log_allowed   = [bool]$after.LogAllowed
      log_blocked   = [bool]$after.LogBlocked
      log_file_name = [string]$after.LogFileName
    }
    active_store   = [pscustomobject]@{
      enabled       = [bool]$afterActive.Enabled
      log_allowed   = [bool]$afterActive.LogAllowed
      log_blocked   = [bool]$afterActive.LogBlocked
      log_file_name = [string]$afterActive.LogFileName
    }
    changes        = $changes
    enforced       = $true
    policy_blocked = $policyBlocked
  }
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Ensure Firewall Enabled ==="

try {
  $ts = Now-Timestamp
  $details = New-Object System.Collections.Generic.List[object]

  foreach ($profile in @('Domain','Private','Public')) {
    try {
      $details.Add( (Ensure-FirewallProfile -Profile $profile) )
    } catch {
      Write-Log "Failed on profile ${profile}: $($_.Exception.Message)" 'ERROR'
      $details.Add([pscustomobject]@{
        profile        = $profile
        enforced       = $false
        error          = $_.Exception.Message
        policy_blocked = $false
      })
    }
  }

  $changedCount = ($details | Where-Object { $_.changes -and $_.changes.Count -gt 0 }).Count
  $errorsCount  = ($details | Where-Object { $_.enforced -eq $false }).Count
  $policyCount  = ($details | Where-Object { $_.policy_blocked }).Count

  $lines = @()

  # Summary
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

  # Per-profile
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
      error          = $d.error
    } | ConvertTo-Json -Compress -Depth 6)
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
