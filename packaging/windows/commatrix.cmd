@echo off
rem commatrix launcher for the SCCM package: runs the bundled embedded Python
rem with the package on PYTHONPATH, so no system-wide Python/pip is required.
rem Layout: this .cmd, python\python.exe, lib\commatrix\ live in the same folder.
set "COMMATRIX_HOME=%~dp0"
set "PYTHONPATH=%COMMATRIX_HOME%lib;%PYTHONPATH%"
"%COMMATRIX_HOME%python\python.exe" -m commatrix %*
