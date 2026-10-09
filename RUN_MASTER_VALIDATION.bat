@echo off
setlocal
cd /d %~dp0
if not exist .venv\Scripts\python.exe (
  py -3.13 -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python -m unittest discover -s tests -p "test_*.py"
if errorlevel 1 exit /b 1
python scripts\final_validation.py
if errorlevel 1 exit /b 1
python -m compileall -q .
if errorlevel 1 exit /b 1
echo.
echo MASTER VALIDATION PASSED.
pause
