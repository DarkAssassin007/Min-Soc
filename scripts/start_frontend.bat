@echo off
setlocal
cd /d "%~dp0.."

if not exist "frontend\node_modules" (
  echo [ERROR] frontend\node_modules not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

echo Starting Mini SOC dashboard on http://127.0.0.1:5173 ...
echo Press Ctrl+C to stop.
echo.
pushd frontend
call npm run dev
popd

if errorlevel 1 (
  echo.
  echo [ERROR] The dashboard dev server exited with an error.
  pause
)
