@echo off
title SafeX Threat Defense Launcher
echo ===================================================
echo Starting SafeX Email, URL & File Threat Analyzer...
echo ===================================================
echo Opening web interface at http://127.0.0.1:8000 ...
timeout /t 1 >nul
start http://127.0.0.1:8000
python -m uvicorn safex.web.app:app --host 127.0.0.1 --port 8000
pause
