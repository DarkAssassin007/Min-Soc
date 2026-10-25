@echo off
setlocal EnableExtensions
title Mini SOC - launcher
cd /d "%~dp0"

echo ============================================
echo   Mini SOC - one-click launcher
echo ============================================
echo.

rem --- 1. Prerequisites -------------------------------------------------
where python >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Python was not found on PATH. Install Python 3.11 or newer, then retry.
  echo         https://www.python.org/downloads/windows/
  pause
  exit /b 1
)

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js / npm was not found on PATH. Install Node.js 18 or newer, then retry.
  echo         https://nodejs.org/
  pause
  exit /b 1
)

rem --- 2. First-run setup: venv, Python deps, .env, npm install ---------
set NEEDS_SETUP=
if not exist ".venv\Scripts\python.exe" set NEEDS_SETUP=1
if not exist "frontend\node_modules" set NEEDS_SETUP=1

if defined NEEDS_SETUP (
  echo [setup] First run detected - installing dependencies. This can take a few minutes ...
  echo.
  call "scripts\setup.bat"
  if errorlevel 1 (
    echo.
    echo [ERROR] Setup failed. Fix the error shown above and run this file again.
    pause
    exit /b 1
  )
)

if not exist ".env" (
  echo [setup] Creating .env from .env.example ...
  copy /y ".env.example" ".env" >nul
  echo         Open .env and set MINI_SOC_ADMIN_PASSWORD before any production use.
)

rem --- 3. Warn if the ports are already taken ---------------------------
netstat -ano | findstr /r /c:":8000 .*LISTENING" >nul 2>nul
if not errorlevel 1 (
  echo [WARN] Port 8000 is already in use - the backend window may fail to start.
)
netstat -ano | findstr /r /c:":5173 .*LISTENING" >nul 2>nul
if not errorlevel 1 (
  echo [WARN] Port 5173 is already in use - the dashboard window may fail to start.
)

rem --- 4. Start backend + dashboard in their own windows ----------------
echo.
echo Starting Mini SOC backend and dashboard in separate windows ...
start "Mini SOC backend" /d "%~dp0" cmd /k "scripts\start_backend.bat"
rem Let the API bind its port first (ping is used instead of `timeout` because
rem `timeout` can resolve to a GNU binary when launched from Git Bash / MSYS).
ping -n 5 127.0.0.1 >nul 2>nul
start "Mini SOC dashboard" /d "%~dp0" cmd /k "scripts\start_frontend.bat"

echo.
echo ============================================
echo   Mini SOC is starting
echo ============================================
echo   Dashboard : http://127.0.0.1:5173
echo   API docs  : http://127.0.0.1:8000/docs
echo   Health    : http://127.0.0.1:8000/api/v1/system/health
echo   Login     : admin / MiniSOC-Core-2026!  (change it after first sign-in)
echo   Stop      : close the two windows that just opened (or Ctrl+C in them).
echo   Runbook   : RUNBOOK.md  - full procedure and deployment structure.
echo.
pause
