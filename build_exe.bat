@echo off
setlocal
cd /d "%~dp0"

echo [INFO] Installing native desktop requirements...
pip install --require-hashes -r requirements.lock
pip install --require-hashes -r requirements-dev.lock

echo [INFO] Building Paracci with pyside6-deploy...
python build_exe.py

echo.
echo [INFO] Build process completed.
pause
