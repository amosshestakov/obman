@echo off
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
    py -3 obman.py
) else (
    python obman.py
)
if errorlevel 1 (
    echo.
    echo Could not start obman. Install Python 3.11+ from python.org
    echo with Tcl/Tk and "Add python.exe to PATH" enabled.
    pause
)
