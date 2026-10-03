@echo off
REM Thin wrapper so the common case is `run.bat <pattern>` on Windows.
REM Everything lives in run.py; this exists only to keep the command short.
REM See `run.bat --help`.
setlocal
set "HERE=%~dp0"
if not defined PYTHON set "PYTHON=python"
"%PYTHON%" "%HERE%run.py" %*
