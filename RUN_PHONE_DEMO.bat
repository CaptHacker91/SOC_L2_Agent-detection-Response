@echo off
rem ============================================================
rem SCRIPT KA PURPOSE: Project ko college demo ke liye start/setup karna.
rem Hinglish note: Ye script virtual environment, dependencies aur Streamlit app ko ready karta hai.
rem ============================================================
setlocal
cd /d "%~dp0"

echo ========================================
echo   SOC L2 Agent - Phone Demo Launcher
echo ========================================

where py >nul 2>nul
if errorlevel 1 (
    echo Python launcher 'py' was not found. Install Python 3.13 first.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    py -3.13 -m venv .venv
    if errorlevel 1 goto :fail
)

call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
if errorlevel 1 goto :fail
python -m pip install -r requirements.txt
if errorlevel 1 goto :fail

if not exist ".env" copy /y ".env.example" ".env" >nul

rem Phone demo ke liye MOCK data force kiya ja raha hai; is command se .env file edit nahi hoti.
set DATA_SOURCE=MOCK

echo.
echo Starting Streamlit on 0.0.0.0 so phones on the same trusted Wi-Fi can connect.
echo Run 'ipconfig' and open http://YOUR-LAPTOP-IP:8501 on the phone.
python -m streamlit run app.py --server.address 0.0.0.0
exit /b %errorlevel%

:fail
echo.
echo Setup failed. Read the error above and use README.md for manual setup.
pause
exit /b 1
