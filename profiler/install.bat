@echo off

REM old version
REM for /f "delims=" %%i in ('py.exe -m site --user-site') do set PYMODULE_PATH=%%i
REM robocopy /E .\packages\ %PYMODULE_PATH%\

python3 -m pip install .\packages\fctools
python3 -m pip install .\packages\vmtools
