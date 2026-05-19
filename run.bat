@echo off
setlocal
cd /d "%~dp0"

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b
)

:: Check for virtual environment
if not exist ".venv" (
    echo [INFO] Creating virtual environment...
    python -m venv .venv
    call .venv\Scripts\activate
    echo [INFO] Installing dependencies...
    pip install --require-hashes -r requirements.lock
) else (
    call .venv\Scripts\activate
)

:: Run the app
echo [INFO] Starting Paracci...
python run.py
pause
