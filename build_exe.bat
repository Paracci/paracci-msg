@echo off
setlocal
cd /d "%~dp0"

echo [INFO] Installing native desktop requirements...
pip install -r requirements.txt

echo [INFO] Building Paracci with pyside6-deploy...
python build_exe.py

echo.
echo [INFO] Build process completed.
pause
