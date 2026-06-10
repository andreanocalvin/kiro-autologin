@echo off
setlocal enabledelayedexpansion

echo.
echo   ===========================================
echo     Kiro Auto-Login - Setup
echo   ===========================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [ERR] Python not found!
    echo   Install from: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo   [OK] Python %PYVER%

REM Install dependencies
echo.
echo   Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo   [ERR] pip install failed!
    pause
    exit /b 1
)

REM Install Playwright browser
echo.
echo   Installing Playwright Chromium browser...
playwright install chromium
if %errorlevel% neq 0 (
    echo   [ERR] Playwright install failed!
    pause
    exit /b 1
)

echo.
echo   ===========================================
echo     Setup complete!
echo   ===========================================
echo.
echo   Next steps:
echo     1. Edit accounts.txt with your credentials
echo     2. Double-click run-batch.bat to start
echo.
pause
