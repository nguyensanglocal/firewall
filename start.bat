@echo off
:: Run app.py with administrator privileges

:: Check for admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Run the Python script
cd /d "%~dp0"
start "" http://localhost:5000/
python ip_dashboard.py
if %errorLevel% neq 0 (
    echo Failed to run app.py. Please check if Python is installed and the script is correct.
)
pause