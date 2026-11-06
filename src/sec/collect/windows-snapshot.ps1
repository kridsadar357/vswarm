# vswarm Windows snapshot: one read-only pass over the places Windows starts programs from, printed as one line
# of JSON. vswarm runs it once per scan; you can run it by hand to see what vswarm sees:
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File windows-snapshot.ps1
# Nothing is changed and nothing is sent anywhere. Each section that fails is named under "errors", so vswarm
# reports a gap instead of a clean result. This file must stay plain ASCII: Windows PowerShell 5.1 reads a file
# without a byte order mark in the ANSI code page.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell 5.1 otherwise writes some lists as {"value":[...],"Count":n} (its type data for System.Array).
Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue
$out = [ordered]@{ v = 1; errors = [ordered]@{} }

function Section([string]$name, [scriptblock]$body) {
  try {
    $out[$name] = @(& $body)
  } catch {
    $out[$name] = @()
    $out.errors[$name] = [string]$_.Exception.Message
  }
}

# Run and RunOnce values: started at every logon (HKCU for this user, HKLM for everyone).
Section 'runKeys' {
  $keys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
  )
  foreach ($k in $keys) {
    if (-not (Test-Path -LiteralPath $k)) { continue }
    $item = Get-Item -LiteralPath $k
    foreach ($n in $item.GetValueNames()) {
      [ordered]@{ hive = $k.Substring(0, 4); key = $k.Substring(6); name = [string]$n; command = [string]$item.GetValue($n) }
    }
  }
}

# Startup folders: shortcuts and files started at logon. Shortcuts are resolved to what they start.
Section 'startup' {
  $shell = New-Object -ComObject WScript.Shell
  $folders = @(
    [ordered]@{ scope = 'user'; dir = [Environment]::GetFolderPath('Startup') },
    [ordered]@{ scope = 'all'; dir = [Environment]::GetFolderPath('CommonStartup') }
  )
  foreach ($s in $folders) {
    if (-not $s.dir -or -not (Test-Path -LiteralPath $s.dir)) { continue }
    foreach ($f in @(Get-ChildItem -LiteralPath $s.dir -File -Force)) {
      if ($f.Name -eq 'desktop.ini') { continue }
      $target = ''
      $arguments = ''
      if ($f.Extension -eq '.lnk') {
        try {
          $l = $shell.CreateShortcut($f.FullName)
          $target = [string]$l.TargetPath
          $arguments = [string]$l.Arguments
        } catch {}
      }
      [ordered]@{ scope = $s.scope; file = $f.Name; path = $f.FullName; target = $target; arguments = $arguments }
    }
  }
}

# Scheduled tasks outside \Microsoft\ (the ones Windows ships live there).
Section 'tasks' {
  # Tasks this user may not read are named as a gap; the rest are still listed.
  $all = @(Get-ScheduledTask -ErrorAction SilentlyContinue -ErrorVariable taskErrors)
  if ($taskErrors) { $out.errors.tasks = 'some tasks could not be read: ' + [string]$taskErrors[0].Exception.Message }
  foreach ($t in @($all | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
    $actions = @()
    foreach ($a in @($t.Actions)) {
      if ($a.Execute) { $actions += ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim() }
      elseif ($a.ClassId) { $actions += 'com-handler ' + [string]$a.ClassId }
    }
    [ordered]@{ path = [string]$t.TaskPath; name = [string]$t.TaskName; state = [string]$t.State; actions = $actions }
  }
}

# Services that start on their own and do not run from the Windows folder. The folders under it that ordinary
# users can write to are kept.
Section 'services' {
  $win = ([string]$env:SystemRoot).TrimEnd('\') + '\'
  $writable = @('Temp\', 'Tasks\', 'Tracing\', 'System32\spool\drivers\color\')
  foreach ($s in @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'")) {
    $p = ([string]$s.PathName).Trim().Trim('"')
    if ($p.StartsWith($win, [StringComparison]::OrdinalIgnoreCase)) {
      $rest = $p.Substring($win.Length)
      if (-not ($writable | Where-Object { $rest.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) })) { continue }
    }
    [ordered]@{ name = [string]$s.Name; displayName = [string]$s.DisplayName; pathName = [string]$s.PathName; startName = [string]$s.StartName; state = [string]$s.State }
  }
}

# WMI permanent event subscriptions: a filter (when), a consumer (what runs) and a binding between them.
try {
  $ns = 'root\subscription'
  $filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter | ForEach-Object {
    [ordered]@{ name = [string]$_.Name; query = [string]$_.Query }
  })
  $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer | ForEach-Object {
    $text = [string]$_.ScriptText
    if ($text.Length -gt 200) { $text = $text.Substring(0, 200) }
    [ordered]@{
      name = [string]$_.Name; class = [string]$_.CimClass.CimClassName
      commandLine = [string]$_.CommandLineTemplate; executable = [string]$_.ExecutablePath
      scriptFile = [string]$_.ScriptFileName; scriptText = $text
    }
  })
  $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | ForEach-Object {
    [ordered]@{ filter = [string]$_.Filter.Name; consumer = [string]$_.Consumer.Name }
  })
  $out.wmi = [ordered]@{ filters = $filters; consumers = $consumers; bindings = $bindings }
} catch {
  $out.errors.wmi = [string]$_.Exception.Message
}

# Processes in this logon session (the ones this user can see the path of), and established TCP connections.
Section 'processes' {
  $session = (Get-Process -Id $PID).SessionId
  foreach ($p in @(Get-CimInstance -ClassName Win32_Process)) {
    [ordered]@{ pid = [int]$p.ProcessId; name = [string]$p.Name; exe = [string]$p.ExecutablePath; mine = ($p.SessionId -eq $session) }
  }
}
Section 'connections' {
  # No established connection at all is an answer, not an error.
  $all = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue -ErrorVariable connErrors)
  $real = @($connErrors | Where-Object { $_.CategoryInfo.Category -ne 'ObjectNotFound' })
  if ($real.Count) { $out.errors.connections = [string]$real[0].Exception.Message }
  foreach ($c in $all) {
    [ordered]@{ pid = [int]$c.OwningProcess; remote = [string]$c.RemoteAddress; port = [int]$c.RemotePort }
  }
}

# Documents may be redirected (OneDrive); PowerShell profiles live under the real one.
try { $out.docs = [Environment]::GetFolderPath('MyDocuments') } catch { $out.errors.docs = [string]$_.Exception.Message }
$out.pshome = [string]$PSHOME

# Pure ASCII on stdout whatever the console code page: everything else becomes a \u escape.
$json = ConvertTo-Json -InputObject $out -Depth 6 -Compress
$json = [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
[Console]::Out.WriteLine($json)
exit 0
