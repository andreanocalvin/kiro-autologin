@echo off
setlocal
title Kiro Batch Login for 9router
color 0A

echo.
echo  ===================================================
echo     Kiro Auto-Login for 9router - Batch Mode
echo  ===================================================
echo.

python "%~dp0kiro_autologin.py" --batch "%~dp0accounts.txt" --interactive %*

echo.
pause
