@echo off
REM Convenience wrapper: launches the PowerShell installer with a relaxed
REM execution policy so you can run it from cmd or by double-clicking.
REM Any arguments are forwarded (e.g. install.cmd -Symlink -DryRun).
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
endlocal
