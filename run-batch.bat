@echo off
title Kiro Auto-Login - Batch Mode
color 0A

echo ============================================
echo   Kiro Auto-Login - Batch Mode
echo ============================================
echo.

:: Check if accounts.txt exists
if not exist "accounts.txt" (
    echo [ERROR] accounts.txt not found!
    echo Please create accounts.txt with email:password per line.
    pause
    exit /b 1
)

:: Count accounts
set count=0
for /f "usebackq tokens=*" %%a in ("accounts.txt") do (
    set line=%%a
    if not "!line:~0,1!"=="#" (
        if not "!line!"=="" set /a count+=1
    )
)

echo Found accounts in accounts.txt
echo.

:: Ask for mode
echo [1] Headless mode (faster, no browser window)
echo [2] Visible mode (see browser, good for debugging)
echo.
set /p mode="Choose mode (1/2): "

:: Ask for concurrency
set /p concurrent="Concurrent browsers (default 1): "
if "%concurrent%"=="" set concurrent=1

echo.
echo Starting batch login...
echo ============================================
echo.

if "%mode%"=="1" (
    python kiro_autologin.py --batch accounts.txt --headless --concurrent %concurrent%
) else (
    python kiro_autologin.py --batch accounts.txt --concurrent %concurrent%
)

echo.
echo ============================================
echo   Batch complete!
echo ============================================
pause
