# Runs the tests one file at a time (CI on Windows). Bun 1.3 on Windows sometimes crashes itself (a segfault, "a bug
# in Bun, not your code") at a different test each run; a file whose run crashed Bun is run again, up to two more
# times. A test that fails is never run again: the step fails as it would under a plain `bun test`.
# PowerShell, not Git Bash: under Git Bash, ssh-add is Git's own, which cannot reach the agent's named pipe.
$ErrorActionPreference = 'Continue'
$failed = @()
foreach ($f in Get-ChildItem test -Filter *.test.ts | Sort-Object Name) {
  for ($try = 1; $try -le 3; $try++) {
    $out = (& bun test ".\test\$($f.Name)" 2>&1 | ForEach-Object { "$_" }) -join "`n"
    $code = $LASTEXITCODE
    Write-Output $out
    if ($code -eq 0) { break }
    $crashed = $out -match 'Bun has crashed'
    $failedTest = $out -match '(?m)^\(fail\)'
    if ($crashed -and -not $failedTest -and $try -lt 3) {
      Write-Output "::warning::Bun crashed running $($f.Name) (try $try); running it again"
      continue
    }
    $failed += $f.Name
    break
  }
}
if ($failed.Count -gt 0) { Write-Output "::error::failed: $($failed -join ', ')"; exit 1 }
exit 0
