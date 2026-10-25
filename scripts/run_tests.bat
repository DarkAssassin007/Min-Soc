@echo off
setlocal
cd /d "%~dp0.."

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] .venv not found. Run scripts\setup.bat first.
  pause
  exit /b 1
)

set BACKEND_FAILED=
set FRONTEND_FAILED=

echo ============================================
echo  Backend test suite
echo ============================================
pushd backend
"..\.venv\Scripts\python.exe" -m pytest -q
if errorlevel 1 set BACKEND_FAILED=1
popd

echo.
echo ============================================
echo  Dashboard test suite
echo ============================================
pushd frontend
call npm test
if errorlevel 1 set FRONTEND_FAILED=1
popd

echo.
if defined BACKEND_FAILED (
  echo [FAIL] Backend tests failed.
  pause
  exit /b 1
)
if defined FRONTEND_FAILED (
  echo [FAIL] Dashboard tests failed.
  pause
  exit /b 1
)
echo All tests passed.
pause
