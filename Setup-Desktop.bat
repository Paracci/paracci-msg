@echo off
setlocal
cd /d "%~dp0"

echo [INFO] Creating Paracci Desktop Shortcut...

set "SCRIPT_PATH=%~dp0Paracci.vbs"
set "ICON_PATH=%~dp0paracci_icon.ico"
set "SHORTCUT_PATH=%USERPROFILE%\Desktop\Paracci.lnk"

:: Create shortcut using PowerShell
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut('%SHORTCUT_PATH%');$s.TargetPath='%SCRIPT_PATH%';$s.WorkingDirectory='%~dp0';$s.IconLocation='%ICON_PATH%';$s.Save()"

if %errorlevel% equ 0 (
    echo [SUCCESS] Paracci shortcut created on your Desktop!
) else (
    echo [ERROR] Failed to create shortcut.
)

pause
