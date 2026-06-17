@echo off
setlocal EnableExtensions EnableDelayedExpansion
cd /d "%~dp0"

REM ================================================================
REM PacketDesk MSIX build script for Microsoft Store submission
REM ================================================================
REM First run setup:
REM   1. Reserve PacketDesk in Partner Center.
REM   2. Open Product identity / Package identity in Partner Center.
REM   3. Replace STORE_IDENTITY_NAME and STORE_PUBLISHER below with the
REM      exact values from Partner Center.
REM
REM This produces an UNSIGNED .msix for Store upload. Microsoft signs
REM MSIX packages after Store certification. Do not use the optional
REM self-signed local-test package for Partner Center upload.
REM ================================================================

set "APP_NAME=PacketDesk"
set "APP_DISPLAY_NAME=PacketDesk"
set "APP_DESCRIPTION=Windows network diagnostics, route monitoring, DNS tools, and connectivity checks."
set "APP_VERSION=1.0.0.0"
set "APP_ARCH=x64"
set "PY_MAIN=packetdesk_gui.py"

REM REQUIRED: replace these two with the exact Partner Center values.
set "STORE_IDENTITY_NAME=DispatchDataworksLLC.PacketDesk"
set "STORE_PUBLISHER=CN=82273C04-5ACF-4690-9E60-215363B6B47A"

REM This is the friendly publisher name shown in package metadata.
set "PUBLISHER_DISPLAY_NAME=Dispatch Dataworks LLC"

set "MIN_WINDOWS_VERSION=10.0.17763.0"
set "MAX_WINDOWS_VERSION_TESTED=10.0.26100.0"

REM Set to 1 to also create a self-signed local test package copy.
REM Keep this 0 for normal Store-submission builds.
set "CREATE_LOCAL_TEST_SIGNED_COPY=0"

if "%STORE_IDENTITY_NAME%"=="PUT-PARTNER-CENTER-PACKAGE-IDENTITY-NAME-HERE" (
  echo.
  echo ERROR: Edit build_msix_store.bat first.
  echo Set STORE_IDENTITY_NAME to the exact Package/Identity/Name from Partner Center.
  echo.
  pause
  exit /b 1
)

if "%STORE_PUBLISHER%"=="CN=PUT-PARTNER-CENTER-PUBLISHER-ID-HERE" (
  echo.
  echo ERROR: Edit build_msix_store.bat first.
  echo Set STORE_PUBLISHER to the exact Package/Identity/Publisher from Partner Center.
  echo.
  pause
  exit /b 1
)

if not exist "%PY_MAIN%" (
  echo.
  echo ERROR: Could not find %PY_MAIN% in this folder.
  echo Put this batch file in the PacketDesk project root.
  echo.
  pause
  exit /b 1
)

where python >nul 2>nul
if errorlevel 1 (
  echo.
  echo ERROR: Python was not found. Install Python 3.11+ and enable Add Python to PATH.
  echo.
  pause
  exit /b 1
)

set "PF86=%ProgramFiles(x86)%"
if not defined PF86 set "PF86=%ProgramFiles%"

set "MAKEAPPX="
for /f "delims=" %%F in ('where makeappx.exe 2^>nul') do (
  if not defined MAKEAPPX set "MAKEAPPX=%%F"
)
if not defined MAKEAPPX (
  if exist "%PF86%\Windows Kits\10\bin\x64\makeappx.exe" set "MAKEAPPX=%PF86%\Windows Kits\10\bin\x64\makeappx.exe"
)
if not defined MAKEAPPX (
  for /f "delims=" %%D in ('dir /b /ad "%PF86%\Windows Kits\10\bin\10.*" 2^>nul ^| sort /r') do (
    if not defined MAKEAPPX if exist "%PF86%\Windows Kits\10\bin\%%D\x64\makeappx.exe" set "MAKEAPPX=%PF86%\Windows Kits\10\bin\%%D\x64\makeappx.exe"
  )
)
if not defined MAKEAPPX (
  echo.
  echo ERROR: MakeAppx.exe was not found.
  echo Install the Windows 10/11 SDK, then rerun this script.
  echo Typical path: C:\Program Files ^(x86^)\Windows Kits\10\bin\...\x64\makeappx.exe
  echo.
  pause
  exit /b 1
)

echo.
echo Using MakeAppx: %MAKEAPPX%
echo.

set "VENV=.venv"
if not exist "%VENV%\Scripts\python.exe" (
  python -m venv "%VENV%"
  if errorlevel 1 goto :fail
)
set "PY_EXE=%VENV%\Scripts\python.exe"

"%PY_EXE%" -m pip install --upgrade pip
if errorlevel 1 goto :fail
"%PY_EXE%" -m pip install -r requirements.txt
if errorlevel 1 goto :fail

set "ICON_ARG="
if exist "assets\packetdesk.ico" set "ICON_ARG=--icon assets\packetdesk.ico"

rmdir /s /q build 2>nul
rmdir /s /q dist 2>nul
rmdir /s /q msix_stage 2>nul
mkdir msix_out 2>nul

echo.
echo Building PyInstaller onedir package...
echo.
"%PY_EXE%" -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --windowed ^
  --onedir ^
  --name "%APP_NAME%" ^
  --hidden-import pyqtgraph.graphicsItems.DateAxisItem ^
  %ICON_ARG% ^
  "%PY_MAIN%"
if errorlevel 1 goto :fail

if not exist "dist\%APP_NAME%\%APP_NAME%.exe" (
  echo.
  echo ERROR: PyInstaller did not create dist\%APP_NAME%\%APP_NAME%.exe
  echo.
  pause
  exit /b 1
)

set "MSIX_STAGE=msix_stage"
set "APP_STAGE=%MSIX_STAGE%\%APP_NAME%"
mkdir "%APP_STAGE%"
if errorlevel 1 goto :fail

xcopy "dist\%APP_NAME%\*" "%APP_STAGE%\" /E /I /Y >nul
if errorlevel 1 goto :fail

if not exist "tools\prepare_msix_store_package.ps1" (
  echo.
  echo ERROR: tools\prepare_msix_store_package.ps1 is missing.
  echo Re-download the MSIX build files or restore the tools folder.
  echo.
  pause
  exit /b 1
)

echo.
echo Creating MSIX manifest and visual assets...
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "tools\prepare_msix_store_package.ps1" ^
  -StageDir "%MSIX_STAGE%" ^
  -AppName "%APP_NAME%" ^
  -DisplayName "%APP_DISPLAY_NAME%" ^
  -Description "%APP_DESCRIPTION%" ^
  -IdentityName "%STORE_IDENTITY_NAME%" ^
  -Publisher "%STORE_PUBLISHER%" ^
  -PublisherDisplayName "%PUBLISHER_DISPLAY_NAME%" ^
  -Version "%APP_VERSION%" ^
  -MinVersion "%MIN_WINDOWS_VERSION%" ^
  -MaxVersionTested "%MAX_WINDOWS_VERSION_TESTED%"
if errorlevel 1 goto :fail

set "MSIX_FILE=msix_out\%APP_NAME%_%APP_VERSION%_%APP_ARCH%_StoreUpload.msix"
del "%MSIX_FILE%" 2>nul

echo.
echo Packing unsigned MSIX for Store upload...
echo.
"%MAKEAPPX%" pack /d "%MSIX_STAGE%" /p "%MSIX_FILE%" /o /v
if errorlevel 1 goto :fail

if "%CREATE_LOCAL_TEST_SIGNED_COPY%"=="1" call :sign_local_test_copy

echo.
echo Build complete.
echo Store upload package:
echo   %CD%\%MSIX_FILE%
echo.
echo Upload this .msix in Partner Center's Packages step.
echo Do not upload a self-signed local-test copy.
echo.
pause
exit /b 0

:sign_local_test_copy
set "SIGNED_MSIX=msix_out\%APP_NAME%_%APP_VERSION%_%APP_ARCH%_LOCAL_TEST_SIGNED.msix"
copy /Y "%MSIX_FILE%" "%SIGNED_MSIX%" >nul

set "SIGNTOOL="
for /f "delims=" %%F in ('where signtool.exe 2^>nul') do (
  if not defined SIGNTOOL set "SIGNTOOL=%%F"
)
if not defined SIGNTOOL (
  if exist "%PF86%\Windows Kits\10\bin\x64\signtool.exe" set "SIGNTOOL=%PF86%\Windows Kits\10\bin\x64\signtool.exe"
)
if not defined SIGNTOOL (
  for /f "delims=" %%D in ('dir /b /ad "%PF86%\Windows Kits\10\bin\10.*" 2^>nul ^| sort /r') do (
    if not defined SIGNTOOL if exist "%PF86%\Windows Kits\10\bin\%%D\x64\signtool.exe" set "SIGNTOOL=%PF86%\Windows Kits\10\bin\%%D\x64\signtool.exe"
  )
)
if not defined SIGNTOOL (
  echo SignTool was not found. Skipping local test signing.
  exit /b 0
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "if (-not (Test-Path 'cert:\CurrentUser\My')) { exit 1 }; $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq '%STORE_PUBLISHER%' -and $_.EnhancedKeyUsageList.FriendlyName -contains 'Code Signing' } | Select-Object -First 1; if (-not $cert) { New-SelfSignedCertificate -Type CodeSigningCert -Subject '%STORE_PUBLISHER%' -CertStoreLocation Cert:\CurrentUser\My | Out-Null }"
"%SIGNTOOL%" sign /fd SHA256 /a /v "%SIGNED_MSIX%"
if errorlevel 1 (
  echo Local test signing failed. Store upload MSIX was still created.
) else (
  echo Local test signed package:
  echo   %CD%\%SIGNED_MSIX%
)
exit /b 0

:fail
echo.
echo BUILD FAILED. Review the output above.
echo.
pause
exit /b 1
