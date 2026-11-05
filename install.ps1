# vswarm installer for Windows (PowerShell).
#   irm https://raw.githubusercontent.com/kridsadar357/vswarm/main/install.ps1 | iex
# Installs Bun if missing, puts vswarm in %USERPROFILE%\.vswarm\app, then runs `vswarm install`.
$ErrorActionPreference = 'Stop'
$Repo = if ($env:VSWARM_REPO) { $env:VSWARM_REPO } else { 'https://github.com/kridsadar357/vswarm.git' }
$Ref = if ($env:VSWARM_REF) { $env:VSWARM_REF } else { 'main' }
$Home_ = if ($env:VSWARM_HOME) { $env:VSWARM_HOME } else { Join-Path $env:USERPROFILE '.vswarm' }
$App = Join-Path $Home_ 'app'

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is required: winget install Git.Git' }
$Bun = (Get-Command bun -ErrorAction SilentlyContinue).Source
if (-not $Bun) {
  Write-Host '  installing Bun (https://bun.sh)'
  powershell -NoProfile -Command "irm bun.sh/install.ps1 | iex" | Out-Null
  $Bun = Join-Path $env:USERPROFILE '.bun\bin\bun.exe'
}
if (Test-Path (Join-Path $App '.git')) {
  git -C $App pull --quiet --ff-only origin $Ref
} else {
  New-Item -ItemType Directory -Force -Path $Home_ | Out-Null
  git clone --quiet --depth 1 --branch $Ref $Repo $App
}
Push-Location $App
& $Bun install --production --silent | Out-Null
& $Bun (Join-Path $App 'src\cli.ts') install
Pop-Location
