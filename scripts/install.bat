@echo off
setlocal EnableExtensions
cd /d "%~dp0\.."

where python >nul 2>nul
if errorlevel 1 (
  echo Python not found.
  echo Install Python 3.10+ and CHECK "Add python.exe to PATH".
  echo https://www.python.org/downloads/
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  python -m venv .venv
  if errorlevel 1 (
    echo Failed to create .venv
    pause
    exit /b 1
  )
)

echo Installing dependencies...
".venv\Scripts\python.exe" -m pip install -U pip
if errorlevel 1 (
  echo pip failed
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 (
  echo package install failed
  pause
  exit /b 1
)

if not exist "config.yaml" (
  copy /Y config.example.yaml config.yaml >nul
  echo Created config.yaml
)

echo Starting setup. Choose Y for autostart when asked.
".venv\Scripts\python.exe" -m campus_connect setup
pause
