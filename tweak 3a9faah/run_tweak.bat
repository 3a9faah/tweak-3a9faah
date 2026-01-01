@echo off
title 3a9faah Ultimate Tweak Tool
color 0B

echo ===============================================================================
echo    ____        ___   __            _     
echo   ^|___ \      / _ \ / _^|          ^| ^|    
echo     __) ^| __ ^| (_) ^| ^|_ __ _  __ _^| ^|__  
echo    ^|__ ^< / _` \__, ^|  _/ _` ^|/ _` ^| '_ \ 
echo    ___) ^| (_^| ^| / /^| ^|^| (_^| ^| (_^| ^| ^| ^| ^|
echo   ^|____/ \__,_^|/_/ ^|_^| \__,_^|\__,_^|_^| ^|_^|
echo.
echo   ULTIMATE WINDOWS TWEAK TOOL v2.0
echo   Copyright (c) 2025 3a9faah
echo   GitHub: https://github.com/3a9faah
echo ===============================================================================
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required.
    echo [*] Restarting with admin rights...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [*] Running 3a9faah Tweak Tool...
echo.

:: Set execution policy and run script
powershell -ExecutionPolicy Bypass -File "%~dp03a9faah_tweak.ps1"

echo.
echo [*] Done! - 3a9faah
pause
