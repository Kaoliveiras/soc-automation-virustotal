@echo off
title SOC Automation - VirusTotal Scanner
:start
cls
python main.py
echo.
echo ------------------------------------------
echo Press any key to analyze another IP...
pause > nul
goto start