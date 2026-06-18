@echo off
setlocal
cd /d "%~dp0"

rem Use a short path for the virtual environment to avoid Windows long-path install failures.
set "VENV_DIR=%TEMP%\ppgui_venv"
set "PYI_WORK=%TEMP%\ppgui_pyi_work"
set "LOCAL_RELEASE_DIR=%LOCALAPPDATA%\PacketDesk"
set "PORTABLE_DIST_DIR=dist_portable"
set "PORTABLE_EXE=%PORTABLE_DIST_DIR%\PacketDesk.exe"

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

if exist "%PORTABLE_EXE%" (
  taskkill /f /im PacketDesk.exe >nul 2>nul
  del /f /q "%PORTABLE_EXE%" >nul 2>nul
  if exist "%PORTABLE_EXE%" (
    echo.
    echo Build cannot continue because %PORTABLE_EXE% is locked.
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
  --distpath "%PORTABLE_DIST_DIR%" ^
  --workpath "%PYI_WORK%" ^
  --name PacketDesk ^
  packetdesk_gui.py

if errorlevel 1 (
  echo.
  echo Build failed. PyInstaller returned a non-zero exit code.
  if exist "%PORTABLE_EXE%" echo Note: %PORTABLE_EXE% exists from a previous or partial build.
  pause
  exit /b 1
)

if exist "%PORTABLE_EXE%" (
  echo.
  echo Build complete: %PORTABLE_EXE%
  if not exist "%LOCAL_RELEASE_DIR%" mkdir "%LOCAL_RELEASE_DIR%"
  copy /y "%PORTABLE_EXE%" "%LOCAL_RELEASE_DIR%\PacketDesk.exe" >nul
  if errorlevel 1 (
    echo.
    echo Warning: Could not copy to %LOCAL_RELEASE_DIR%\PacketDesk.exe
    echo Run %PORTABLE_EXE% directly after OneDrive finishes syncing.
  ) else (
    echo Stable local copy: %LOCAL_RELEASE_DIR%\PacketDesk.exe
  )
) else (
  echo.
  echo Build failed. Review the PyInstaller output above.
)
pause
