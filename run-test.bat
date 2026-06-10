@echo off
title Kiro Auto-Login - Test Mode
color 0E

echo ============================================
echo   Kiro Auto-Login - Test Mode
echo   (No DB save, just test login)
echo ============================================
echo.

set /p creds="Enter email:password (or leave empty to use first line from accounts.txt): "

if "%creds%"=="" (
    :: Read first non-comment, non-empty line from accounts.txt
    if not exist "accounts.txt" (
        echo [ERROR] accounts.txt not found!
        pause
        exit /b 1
    )
    for /f "usebackq tokens=*" %%a in ("accounts.txt") do (
        set line=%%a
        if not "!line:~0,1!"=="#" (
            if not "!line!"=="" (
                set creds=!line!
                goto :found
            )
        )
    )
    :found
)

if "%creds%"=="" (
    echo [ERROR] No credentials provided and accounts.txt is empty.
    pause
    exit /b 1
)

echo.
echo Testing: %creds%
echo.

:: Ask for mode
echo [1] Headless mode
echo [2] Visible mode (see browser)
echo.
set /p mode="Choose mode (1/2): "

echo.
echo Starting test...
echo ============================================
echo.

if "%mode%"=="1" (
    python kiro_autologin.py --test --headless --debug "%creds%"
) else (
    python kiro_autologin.py --test --debug "%creds%"
)

echo.
echo ============================================
echo   Test complete!
echo ============================================
pause
