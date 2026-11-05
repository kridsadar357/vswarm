@echo off
rem Run vswarm straight from a checkout: vswarm.cmd install
where bun >nul 2>nul || (echo vswarm needs Bun: powershell -c "irm bun.sh/install.ps1 | iex" & exit /b 1)
bun "%~dp0src\cli.ts" %*
