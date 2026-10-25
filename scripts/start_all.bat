@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

echo Launching Mini SOC backend and dashboard in separate windows ...
start "Mini SOC backend" cmd /k "%~dp0start_backend.bat"
timeout /t 3 /nobreak >nul
start "Mini SOC dashboard" cmd /k "%~dp0start_frontend.bat"

echo.
echo Backend API     : http://127.0.0.1:8000/docs
echo SOC dashboard   : http://127.0.0.1:5173
echo Close the two opened windows to stop the services.
pause
