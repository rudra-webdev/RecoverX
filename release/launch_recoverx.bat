@echo off
title RecoverX - Forensic Data Recovery Engine
echo Starting RecoverX Desktop Application in Offline Mode...
python main.py
if errorlevel 1 (
    echo.
    echo Application exited with an error. Check reports\recoverx.log for details.
    pause
)

