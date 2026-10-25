@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

set EVENTS=%1
if "%EVENTS%"=="" set EVENTS=4000

echo Running Mini SOC pipeline benchmark with %EVENTS% events ...
".venv\Scripts\python.exe" scripts\benchmark_pipeline.py --events %EVENTS%
set EXITCODE=%errorlevel%

echo.
if not "%EXITCODE%"=="0" (
  echo [ERROR] Benchmark failed. See the output above.
  pause
  exit /b %EXITCODE%
)
echo Report written to logs\benchmark-report.json
pause
