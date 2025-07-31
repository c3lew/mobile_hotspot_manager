@echo off
:: ==============================================================================
:: Mobile Hotspot Manager - Easy Launcher
:: ==============================================================================
:: This batch file provides an easy way to run the PowerShell script
:: Run this as Administrator for best results
:: ==============================================================================

echo.
echo ==============================================================================
echo                    Mobile Hotspot Manager for Windows 10/11
echo ==============================================================================
echo.

:: Check if PowerShell script exists
if not exist "%~dp0mobile-hotspot-manager.ps1" (
    echo ERROR: mobile-hotspot-manager.ps1 not found in the same directory!
    echo Please make sure both files are in the same folder.
    pause
    exit /b 1
)

:: Show menu
:MENU
echo Please select an action:
echo.
echo 1. Enable Mobile Hotspot
echo 2. Disable Mobile Hotspot  
echo 3. Toggle Hotspot (On/Off)
echo 4. Check Hotspot Status
echo 5. Get WiFi Passwords
echo 6. Show Hotspot Credentials
echo 7. Show Help
echo 8. Exit
echo.
set /p "choice=Enter your choice (1-8): "

:: Process choice
if "%choice%"=="1" goto ENABLE
if "%choice%"=="2" goto DISABLE
if "%choice%"=="3" goto TOGGLE
if "%choice%"=="4" goto STATUS
if "%choice%"=="5" goto GETWIFI
if "%choice%"=="6" goto GETHOTSPOT
if "%choice%"=="7" goto HELP
if "%choice%"=="8" goto EXIT
echo Invalid choice. Please try again.
echo.
goto MENU

:ENABLE
echo.
echo Enabling Mobile Hotspot...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action Enable
goto CONTINUE

:DISABLE
echo.
echo Disabling Mobile Hotspot...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action Disable
goto CONTINUE

:TOGGLE
echo.
echo Toggling Mobile Hotspot...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action Toggle
goto CONTINUE

:STATUS
echo.
echo Checking Hotspot Status...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action Status
goto CONTINUE

:GETWIFI
echo.
echo Retrieving WiFi Passwords...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action GetWiFi
echo.
echo WiFi credentials have been saved to a CSV file in the current directory.
goto CONTINUE

:GETHOTSPOT
echo.
echo Displaying Hotspot Credentials...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action GetHotspot
goto CONTINUE

:HELP
echo.
powershell.exe -ExecutionPolicy Bypass -File "%~dp0mobile-hotspot-manager.ps1" -Action Help
goto CONTINUE

:CONTINUE
echo.
echo ==============================================================================
echo.
set /p "continue=Press Enter to return to menu or type 'exit' to quit: "
if /i "%continue%"=="exit" goto EXIT
echo.
goto MENU

:EXIT
echo.
echo Thank you for using Mobile Hotspot Manager!
echo Check the log files for detailed operation history.
echo.
pause
exit /b 0
