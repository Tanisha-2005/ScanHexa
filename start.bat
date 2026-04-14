@echo off
echo ===================================================
echo  Cybrexa AI - Launching Monolithic Server
echo ===================================================
echo.
echo Installing dependencies...
call npm run install:all >nul 2>&1


echo.
echo Starting Production Server...
call npm start
pause
