@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

echo Starting Mini SOC backend on http://127.0.0.1:8000 ...
echo Press Ctrl+C to stop.
echo.
pushd backend
"..\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
popd

if errorlevel 1 (
  echo.
  echo [ERROR] The backend exited with an error. Check logs\mini-soc.log for details.
  pause
)
