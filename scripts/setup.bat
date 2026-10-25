@echo off
setlocal
cd /d "%~dp0.."
echo ============================================
echo  Mini SOC - first-time setup
echo ============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found on PATH. Install Python 3.11 or newer.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/4] Creating virtual environment in .venv ...
  python -m venv .venv
  if errorlevel 1 (
    echo [ERROR] Virtual environment creation failed.
    pause
    exit /b 1
  )
) else (
  echo [1/4] Virtual environment already exists.
)

echo [2/4] Installing Python dependencies ...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r backend\requirements.txt -r backend\requirements-dev.txt
if errorlevel 1 (
  echo [ERROR] pip install failed.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q -r ml\requirements.txt
if errorlevel 1 (
  echo [ERROR] ML dependency install failed.
  pause
  exit /b 1
)

if not exist ".env" (
  echo [3/4] Creating .env from .env.example ...
  copy /y ".env.example" ".env" >nul
) else (
  echo [3/4] .env already exists - leaving it untouched.
)

echo [4/4] Installing dashboard dependencies ...
pushd frontend
call npm install
if errorlevel 1 (
  popd
  echo [ERROR] npm install failed. Is Node.js 18+ installed?
  pause
  exit /b 1
)
popd

echo.
echo Setup complete. Next steps:
echo   1. Edit .env and set MINI_SOC_ADMIN_PASSWORD
echo   2. Run scripts\start_all.bat
echo.
pause
