@echo off
setlocal
cd /d "%~dp0"

rem Use a short path for the virtual environment to avoid Windows long-path install failures.
set "VENV_DIR=%TEMP%\ppgui_venv"
set "PYI_WORK=%TEMP%\ppgui_pyi_work"
set "LOCAL_RELEASE_DIR=%LOCALAPPDATA%\PacketDesk"

where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3.11+ from python.org and enable "Add Python to PATH".
  pause
  exit /b 1
)

if exist "%VENV_DIR%" rmdir /s /q "%VENV_DIR%"
python -m venv "%VENV_DIR%"
if errorlevel 1 exit /b 1
call "%VENV_DIR%\Scripts\activate.bat"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

if exist "%PYI_WORK%" rmdir /s /q "%PYI_WORK%"

if exist dist\PacketDesk.exe (
  taskkill /f /im PacketDesk.exe >nul 2>nul
  del /f /q dist\PacketDesk.exe >nul 2>nul
  if exist dist\PacketDesk.exe (
    echo.
    echo Build cannot continue because dist\PacketDesk.exe is locked.
    echo Close PacketDesk and disable preview/scan locks on the file, then run again.
    pause
    exit /b 1
  )
)

python -m PyInstaller ^
  --noconfirm ^
  --windowed ^
  --onefile ^
  --exclude-module "pyqtgraph.opengl" ^
  --add-data "logo.ico;." ^
  --add-data "logo.png;." ^
  --icon "logo.ico" ^
  --workpath "%PYI_WORK%" ^
  --name PacketDesk ^
  packetdesk_gui.py

if errorlevel 1 (
  echo.
  echo Build failed. PyInstaller returned a non-zero exit code.
  if exist dist\PacketDesk.exe echo Note: dist\PacketDesk.exe exists from a previous or partial build.
  pause
  exit /b 1
)

if exist dist\PacketDesk.exe (
  echo.
  echo Build complete: dist\PacketDesk.exe
  if not exist "%LOCAL_RELEASE_DIR%" mkdir "%LOCAL_RELEASE_DIR%"
  copy /y dist\PacketDesk.exe "%LOCAL_RELEASE_DIR%\PacketDesk.exe" >nul
  if errorlevel 1 (
    echo.
    echo Warning: Could not copy to %LOCAL_RELEASE_DIR%\PacketDesk.exe
    echo Run dist\PacketDesk.exe directly after OneDrive finishes syncing.
  ) else (
    echo Stable local copy: %LOCAL_RELEASE_DIR%\PacketDesk.exe
  )
) else (
  echo.
  echo Build failed. Review the PyInstaller output above.
)
pause
