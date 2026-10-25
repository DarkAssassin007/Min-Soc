@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

echo Running Mini SOC end-to-end lab validation ...
echo.
".venv\Scripts\python.exe" scripts\lab_validation.py
set EXITCODE=%errorlevel%

echo.
if not "%EXITCODE%"=="0" (
  echo [FAIL] Validation failed - see logs\validation-report.json for details.
  pause
  exit /b %EXITCODE%
)
echo Report written to logs\validation-report.json
pause
