@echo off
title APK Reverse Engineering & Security Audit Engine
cls
echo =====================================================================
echo           ONE-CLICK APK REVERSE ENGINEERING & AUDIT ENGINE
echo =====================================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.8+ and add it to your system PATH.
    pause
    exit /b 1
)

echo [*] Checking dependencies...
pip install -r "%~dp0requirements.txt" --quiet >nul 2>&1

echo [*] Starting Automated Security Audit...
echo.
python "%~dp0run_audit.py" "%~dp0base.apk"

echo.
echo =====================================================================
echo  Audit Completed! Check AUDIT_REPORT.md for full results.
echo =====================================================================
echo.
pause
