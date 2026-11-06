# vswarm installer for Windows (preview).
#   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.ps1 | iex"
# Installs Bun if missing, puts vswarm in ~\.vswarm\app, then runs `vswarm install` (launcher, your PATH, a first baseline).
# VSWARM_REPO and VSWARM_REF pick another repository or branch. Nothing here needs an administrator.
# In a script block of its own, so none of its variables stay behind in your session.
& {
  # Not 'Stop': Windows PowerShell 5.1 turns any line a native command writes to stderr into a terminating error.
  # Every step that matters checks its own result instead.
  $ErrorActionPreference = 'Continue'

  $Repo = if ($env:VSWARM_REPO) { $env:VSWARM_REPO } else { 'https://github.com/kridsadar357/vswarm.git' }
  $Ref = if ($env:VSWARM_REF) { $env:VSWARM_REF } else { 'main' }
  $Data = if ($env:VSWARM_HOME) { $env:VSWARM_HOME } else { Join-Path $HOME '.vswarm' }
  $App = Join-Path $Data 'app'

  function Say($m) { Write-Host "  v $m" -ForegroundColor Magenta }
  # throw, not exit: under `irm | iex` an exit would close the window you ran it in.
  function Die($m) { Write-Host "  x $m" -ForegroundColor Red; throw 'vswarm was not installed' }
  # git that must succeed. (PowerShell names ignore case: a function called Git would call itself.)
  function Need-Git { & git @args; if ($LASTEXITCODE -ne 0) { Die "git $($args -join ' ') failed" } }

  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die 'git is required: https://git-scm.com/download/win (or: winget install Git.Git)' }

  $Bun = (Get-Command bun -ErrorAction SilentlyContinue).Source
  if (-not $Bun -and (Test-Path (Join-Path $HOME '.bun\bin\bun.exe'))) { $Bun = Join-Path $HOME '.bun\bin\bun.exe' }
  if (-not $Bun) {
    Say 'installing Bun (https://bun.sh)'
    try { & ([scriptblock]::Create((Invoke-RestMethod 'https://bun.sh/install.ps1'))) | Out-Null } catch { Die "Bun did not install: $_" }
    $Bun = Join-Path $HOME '.bun\bin\bun.exe'
    if (-not (Test-Path $Bun)) { Die 'Bun did not install; see https://bun.sh' }
  }

  if (Test-Path (Join-Path $App '.git')) {
    Say "updating $App"
    Need-Git -C $App fetch --quiet --tags --force origin
  } else {
    Say "downloading vswarm into $App"
    New-Item -ItemType Directory -Force -Path $Data | Out-Null
    Need-Git clone --quiet $Repo $App
  }

  # Signed releases: when the repository lists release keys, install the newest release tag, and only if its
  # signature checks out. `vswarm install` then pins those keys; later updates accept nothing else.
  $Tag = (& git -C $App tag -l 'v*' --sort=-v:refname | Select-Object -First 1)
  $Signers = if ($Tag) { (& git -C $App show "${Tag}:trust/allowed_signers" 2>$null) -join "`n" } else { '' }
  if (-not $env:VSWARM_REF -and $Tag -and ($Signers -match '(?m)^[^#\s]')) {
    $File = Join-Path $App '.release-signers'
    [IO.File]::WriteAllText($File, $Signers + "`n")
    & git -C $App -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$File" verify-tag $Tag 2>$null | Out-Null
    $Verified = $LASTEXITCODE -eq 0
    Remove-Item -Force $File
    if (-not $Verified) { Die "release $Tag is not signed by the key it lists; not installing it" }
    Need-Git -C $App checkout --quiet --detach $Tag
    Say "release $Tag, signature checked"
  } else {
    Need-Git -C $App checkout --quiet $Ref
    & git -C $App pull --quiet --ff-only origin $Ref 2>$null | Out-Null
  }

  Push-Location $App
  & $Bun install --production --silent 2>$null | Out-Null
  Pop-Location
  & $Bun (Join-Path $App 'src\cli.ts') install
  if ($LASTEXITCODE -ne 0) { Die "vswarm install stopped (exit $LASTEXITCODE)" }
}
