@echo off
@chcp 65001 >nul
title OstadRESpy - Universal Reverse Engineering & Threat Analyzer
cls
color 0A
echo ===============================================================================
echo                [OstadRESpy] - Universal Threat Analyzer Engine
echo                   Created by Ostad Rezaul Karim (Director)
echo                            Ostad Red Team Forge
echo ===============================================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] Python 3 is not installed or not added to your system PATH!
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

echo [*] Checking required dependencies...
pip install -r "%~dp0requirements.txt" --quiet >nul 2>&1

:: Check if a target file was dragged and dropped onto the bat file
if "%~1"=="" (
    set TARGET="%~dp0base.apk"
) else (
    set TARGET="%~1"
)

echo [*] Target File: %TARGET%
echo [*] Launching OstadRESpy Security Engine...
echo.
python "%~dp0ostadrespy.py" %TARGET%

echo.
echo ===============================================================================
echo  [+] Audit Finished! Report written to OstadRESpy_AUDIT_REPORT.md
echo ===============================================================================
echo.
pause
