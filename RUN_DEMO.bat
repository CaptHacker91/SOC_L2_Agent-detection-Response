@echo off
rem ============================================================
rem SCRIPT KA PURPOSE: Project ko college demo ke liye start/setup karna.
rem Hinglish note: Ye script virtual environment, dependencies aur Streamlit app ko ready karta hai.
rem ============================================================
setlocal
cd /d "%~dp0"

echo ========================================
echo   SOC L2 Agent - College Demo Launcher
echo ========================================

where py >nul 2>nul
if errorlevel 1 (
    echo Python launcher 'py' was not found. Install Python 3.13 first.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Creating Python 3.13 virtual environment...
    py -3.13 -m venv .venv
    if errorlevel 1 goto :fail
) else (
    echo [1/4] Existing virtual environment found.
)

call ".venv\Scripts\activate.bat"

echo [2/4] Checking project dependencies...
python -m pip install --upgrade pip
if errorlevel 1 goto :fail
python -m pip install -r requirements.txt
if errorlevel 1 goto :fail

if not exist ".env" (
    echo [3/4] Creating .env from .env.example...
    copy /y ".env.example" ".env" >nul
) else (
    echo [3/4] Existing .env preserved.
)

rem College demo ke liye MOCK data force kiya ja raha hai; is command se .env file edit nahi hoti.
set DATA_SOURCE=MOCK

echo [4/4] Starting Streamlit in MOCK mode...
echo Close the browser or press Ctrl+C in this window to stop the app.
python -m streamlit run app.py
exit /b %errorlevel%

:fail
echo.
echo Launcher stopped because a setup command failed.
echo Read the error above, then run the commands from README.md.
pause
exit /b 1
