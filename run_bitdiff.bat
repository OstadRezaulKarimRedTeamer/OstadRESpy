@echo off
@chcp 65001 >nul
title OstadBitDiff - Top 1% Binary Diffing & Trojan Hunter
cls
color 0B
echo ===============================================================================
echo                [OstadBitDiff] - Top 1% Binary Diffing Engine
echo                   Created by Ostad Rezaul Karim (Director)
echo                            Ostad Red Team Forge
echo ===============================================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    color 0C
    echo [ERROR] Python 3 is not installed or not added to your system PATH!
    pause
    exit /b 1
)

:: If two files were dragged and dropped
if not "%~2"=="" (
    set FILE1="%~1"
    set FILE2="%~2"
    goto RUN_DIFF
)

:: If no arguments, prompt user
echo Drag and drop TWO files or enter their paths below:
echo.
set /p FILE1="Enter path of File 1 (Original): "
set /p FILE2="Enter path of File 2 (Modified): "

:RUN_DIFF
echo.
echo [*] Comparing:
echo     Target A: %FILE1%
echo     Target B: %FILE2%
echo.
python "%~dp0ostadbitdiff.py" %FILE1% %FILE2%

echo.
echo ===============================================================================
echo  [+] Diff Completed! Report written to OstadBitDiff_REPORT.md
echo ===============================================================================
echo.
pause
