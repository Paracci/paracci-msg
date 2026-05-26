@echo off
setlocal
cd /d "%~dp0"

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    exit /b 1
)

:: Resolve user's local AppData directory for Paracci
set "PARACCI_USER_DIR=%LOCALAPPDATA%\Paracci"
if "%LOCALAPPDATA%"=="" (
    set "PARACCI_USER_DIR=%USERPROFILE%\AppData\Local\Paracci"
)

:: Ensure user directory exists
if not exist "%PARACCI_USER_DIR%" (
    mkdir "%PARACCI_USER_DIR%"
)

:: Check for virtual environment
if not exist "%PARACCI_USER_DIR%\.venv" (
    echo [INFO] Creating virtual environment...
    python -m venv "%PARACCI_USER_DIR%\.venv"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        echo [ERROR] Failed to create virtual environment. >> "%PARACCI_USER_DIR%\paracci_startup_error.log"
        exit /b 1
    )
    call "%PARACCI_USER_DIR%\.venv\Scripts\activate"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to activate virtual environment.
        echo [ERROR] Failed to activate virtual environment. >> "%PARACCI_USER_DIR%\paracci_startup_error.log"
        exit /b 1
    )
    echo [INFO] Installing dependencies...
    pip install --require-hashes -r requirements.lock
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies.
        echo [ERROR] Failed to install dependencies. >> "%PARACCI_USER_DIR%\paracci_startup_error.log"
        exit /b 1
    )
) else (
    call "%PARACCI_USER_DIR%\.venv\Scripts\activate"
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to activate virtual environment.
        echo [ERROR] Failed to activate virtual environment. >> "%PARACCI_USER_DIR%\paracci_startup_error.log"
        exit /b 1
    )
)

:: Run the app
echo [INFO] Starting Paracci...
echo success > "%PARACCI_USER_DIR%\paracci_startup_success.tmp"
python run.py
if %errorlevel% neq 0 (
    echo [ERROR] Paracci app crashed or exited with error code %errorlevel%.
    echo [ERROR] Paracci app crashed or exited with error code %errorlevel%. >> "%PARACCI_USER_DIR%\paracci_startup_error.log"
    if exist "%PARACCI_USER_DIR%\paracci_startup_success.tmp" del /f /q "%PARACCI_USER_DIR%\paracci_startup_success.tmp"
    exit /b %errorlevel%
)

if exist "%PARACCI_USER_DIR%\paracci_startup_success.tmp" del /f /q "%PARACCI_USER_DIR%\paracci_startup_success.tmp"
exit /b 0
