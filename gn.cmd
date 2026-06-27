@echo off
rem GreyIQ `gn` CLI launcher (Windows, dev/source). Runs the torch-free bug-bounty
rem CLI. In a packaged build, call the frozen backend exe directly:
rem   "%LOCALAPPDATA%\Programs\GreyIQ\resources\backend\greyiq-backend.exe" hunt ...
setlocal
set "GN_BACKEND=%~dp0backend\gn_cli.py"
where python >nul 2>nul && (python "%GN_BACKEND%" %* & exit /b %errorlevel%)
where py >nul 2>nul && (py -3 "%GN_BACKEND%" %* & exit /b %errorlevel%)
echo gn: Python was not found on PATH. Install Python 3.11+ or run the packaged greyiq-backend.exe.>&2
exit /b 1
