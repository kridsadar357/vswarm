# vswarm installer for Windows (preview).
#   powershell -ExecutionPolicy Bypass -c "irm https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.ps1 | iex"
# Uses the Bun on your PATH, or installs a pinned Bun release (checked against the SHA-256 below), puts vswarm in
# ~\.vswarm\app, then runs `vswarm install` (launcher, your PATH, a first baseline).
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
    # One Bun release, and the SHA-256 of each zip as published in its SHASUMS256.txt
    # (https://github.com/oven-sh/bun/releases/download/bun-v1.3.14/SHASUMS256.txt). A download that does not match is
    # not unpacked. Moving to another release means changing the version and every hash here and in install.sh.
    $BunVersion = '1.3.14'
    $BunSha256 = @{
      'bun-windows-x64'          = '0a0620930b6675d7ba440e81f4e0e00d3cfbe096c4b140d3fff02205e9e18922'
      'bun-windows-x64-baseline' = '538f9c846355d9e847b2671bc00c47da4229a0befb24df3282b739770f3b475f'
      'bun-windows-aarch64'      = '89841f5a57f2348b67ec0839b718f4bf4ea7d07c371c9ba4b77b6c790f918953'
    }
    # 32-bit PowerShell on 64-bit Windows reports the real CPU in PROCESSOR_ARCHITEW6432.
    $Cpu = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($Cpu -eq 'ARM64') { $Asset = 'bun-windows-aarch64' }
    elseif ($Cpu -eq 'AMD64') {
      # The baseline build for CPUs without AVX2 (PF_AVX2_INSTRUCTIONS_AVAILABLE is 40).
      $Avx2 = $true
      try {
        Add-Type -Namespace VswarmInstall -Name Cpu -MemberDefinition '[DllImport("kernel32.dll")] public static extern bool IsProcessorFeaturePresent(int feature);' -ErrorAction Stop
        $Avx2 = [VswarmInstall.Cpu]::IsProcessorFeaturePresent(40)
      } catch {}
      $Asset = if ($Avx2) { 'bun-windows-x64' } else { 'bun-windows-x64-baseline' }
    } else { Die "no Bun build for a $Cpu CPU; install Bun yourself (https://bun.sh) and run this again" }
    Say "installing Bun $BunVersion ($Asset), checked against its pinned SHA-256"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('vswarm-bun-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $Tmp | Out-Null
    $Zip = Join-Path $Tmp "$Asset.zip"
    try {
      # Windows PowerShell 5.1 redraws a progress bar for every block it downloads, which makes it very slow.
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/oven-sh/bun/releases/download/bun-v$BunVersion/$Asset.zip" -OutFile $Zip -ErrorAction Stop
    } catch { Remove-Item -Recurse -Force $Tmp; Die "could not download $Asset.zip from github.com/oven-sh/bun: $_" }
    $Got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Zip).Hash.ToLowerInvariant()
    if ($Got -ne $BunSha256[$Asset]) { Remove-Item -Recurse -Force $Tmp; Die "$Asset.zip does not match its pinned SHA-256 (got $Got); not installing it" }
    Expand-Archive -LiteralPath $Zip -DestinationPath $Tmp -Force
    $BunDir = Join-Path $HOME '.bun\bin'
    New-Item -ItemType Directory -Force -Path $BunDir | Out-Null
    $Bun = Join-Path $BunDir 'bun.exe'
    Move-Item -Force -LiteralPath (Join-Path $Tmp "$Asset\bun.exe") -Destination $Bun
    Remove-Item -Recurse -Force $Tmp
    & $Bun --version | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'Bun did not start; see https://bun.sh' }
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
  # signature checks out. `vswarm install` then pins those keys; later updates accept nothing else. Until the
  # maintainer publishes a release key, this installs main as it is, unsigned, and says so.
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
    if (-not $env:VSWARM_REF) { Say 'no signed release yet: installed main as it is, without a signature check' }
  }

  Push-Location $App
  & $Bun install --production --silent 2>$null | Out-Null
  Pop-Location
  & $Bun (Join-Path $App 'src\cli.ts') install
  if ($LASTEXITCODE -ne 0) { Die "vswarm install stopped (exit $LASTEXITCODE)" }
}
