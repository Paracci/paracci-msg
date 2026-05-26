@echo off
setlocal
cd /d "%~dp0"

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.10+ and try again. >> paracci_startup_error.log
    exit /b 1
)

:: Check for virtual environment
if not exist ".venv" (
    echo [INFO] Creating virtual environment...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        echo [ERROR] Failed to create virtual environment. >> paracci_startup_error.log
        exit /b 1
    )
    call .venv\Scripts\activate
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to activate virtual environment.
        echo [ERROR] Failed to activate virtual environment. >> paracci_startup_error.log
        exit /b 1
    )
    echo [INFO] Installing dependencies...
    pip install --require-hashes -r requirements.lock
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies.
        echo [ERROR] Failed to install dependencies. >> paracci_startup_error.log
        exit /b 1
    )
) else (
    call .venv\Scripts\activate
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to activate virtual environment.
        echo [ERROR] Failed to activate virtual environment. >> paracci_startup_error.log
        exit /b 1
    )
)

:: Run the app
echo [INFO] Starting Paracci...
echo success > paracci_startup_success.tmp
python run.py
if %errorlevel% neq 0 (
    echo [ERROR] Paracci app crashed or exited with error code %errorlevel%.
    echo [ERROR] Paracci app crashed or exited with error code %errorlevel%. >> paracci_startup_error.log
    if exist paracci_startup_success.tmp del /f /q paracci_startup_success.tmp
    exit /b %errorlevel%
)

if exist paracci_startup_success.tmp del /f /q paracci_startup_success.tmp
exit /b 0
