@echo off
setlocal EnableExtensions
cd /d "%~dp0\.."
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m campus_connect login
) else (
  python -m campus_connect login
)
pause
