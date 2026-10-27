@echo off
@chcp 65001 >nul
title OstadRESpy Cyberpunk HUD
cd /d "%~dp0"
echo ==============================================================================
echo    ___       _             _ ____  _____ ____             
echo   / _ \  ___| |_ __ _   __| |  _ \| ____/ ___| _ __  _   _ 
echo  | | | |/ __| __/ _` | / _` | |_) |  _| \___ \| '_ \| | | |
echo  | |_| |\__ \ || (_| || (_| |  _ <| |___ ___) | |_) | |_| |
echo   \___/ |___/\__\__,_| \__,_|_| \_\_____|____/| .__/ \__, |
echo                                               |_|    |___/ 
echo       [ All-in-One 10-Layer Defense Engine - Web GUI Engine ]
echo                     Created by: Ostad Rezaul Karim
echo                      Director, Ostad Red Team Forge
echo                     ostadrezaulkarimofficial@gmail.com
echo ==============================================================================
echo [*] Launching OstadRESpy Cyberpunk Web HUD on http://localhost:5050...
python gui_server.py
pause
