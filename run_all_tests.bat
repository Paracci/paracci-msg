@echo off
setlocal
cd /d "%~dp0"

echo ==============================================
echo [1/2] RUNNING LOCAL WINDOWS TESTS...
echo ==============================================

:: Find and activate virtual environment
set "VENV_PATH="
if exist ".venv\Scripts\activate.bat" (
    set "VENV_PATH=.venv\Scripts\activate.bat"
) else if exist "%LOCALAPPDATA%\Paracci\.venv\Scripts\activate.bat" (
    set "VENV_PATH=%LOCALAPPDATA%\Paracci\.venv\Scripts\activate.bat"
)

if not "%VENV_PATH%"=="" (
    echo [INFO] Activating virtual environment: %VENV_PATH%
    call "%VENV_PATH%"
) else (
    echo [WARNING] No virtual environment found. Running with global python.
)

python -m pytest paracci/tests -q
if %errorlevel% neq 0 (
    echo [ERROR] Windows pytest tests failed.
    exit /b %errorlevel%
)

node --test paracci/tests/test_session_clipboard.mjs
if %errorlevel% neq 0 (
    echo [ERROR] Windows JavaScript clipboard tests failed.
    exit /b %errorlevel%
)

echo.
echo ==============================================
echo [2/2] RUNNING DOCKER LINUX TESTS...
echo ==============================================

:: Build the docker image if not already built (checks if image exists)
docker image inspect paracci-linux-test >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Docker image paracci-linux-test not found. Building...
    docker build -f Dockerfile.test -t paracci-linux-test .
    if %errorlevel% neq 0 (
        echo [ERROR] Docker build failed.
        exit /b %errorlevel%
    )
)

:: Run the container with the workspace directory mounted, preserving container's Linux node_modules
docker run --rm -v "%cd%:/workspace" -v "/workspace/node_modules" paracci-linux-test
if %errorlevel% neq 0 (
    echo [ERROR] Docker Linux tests failed.
    exit /b %errorlevel%
)


echo.
echo ==============================================
echo ALL TESTS COMPLETED SUCCESSFULLY!
echo ==============================================
endlocal
pause
