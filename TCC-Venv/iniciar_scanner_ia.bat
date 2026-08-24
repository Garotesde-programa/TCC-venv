@echo off
setlocal EnableExtensions
title Scanner IA

call "%~dp0_env.bat"
if errorlevel 1 (
    pause
    exit /b 1
)

set SCANNER_SSL_MODE=
set SCANNER_FORCE_HTTPS_REDIRECT=0
set SCANNER_TRUST_PROXY=0

if not exist "%ROOT_DIR%\data" mkdir "%ROOT_DIR%\data"
set "LOG_FILE=%ROOT_DIR%\data\server.log"
set "RUN_BAT=%ROOT_DIR%\data\_run_server.bat"

REM Se a porta 5000 ja estiver em uso, o servidor provavelmente ja esta rodando.
netstat -ano | findstr /c:":5000 " | findstr /i "LISTENING" >nul 2>&1
if not errorlevel 1 (
    echo [INFO] Porta 5000 ja em uso - abrindo navegador.
    start "" "http://127.0.0.1:5000"
    endlocal
    exit /b 0
)

REM Gera um .bat auxiliar com os caminhos ja embutidos - evita o bug classico
REM de aspas duplicadas quebrando "start ... cmd /c ""..."" && ""..."""
REM quando ROOT_DIR/SCRIPTS_DIR tem espaco (ex: "C:\Users\Joao Silva\...").
> "%RUN_BAT%" (
    echo @echo off
    echo cd /d "%SCRIPTS_DIR%"
    echo "%PYTHON_EXE%" app_web.py ^>^> "%LOG_FILE%" 2^>^&1
)
echo ==== %DATE% %TIME% ==== > "%LOG_FILE%"

start /min "Scanner IA" cmd /c call "%RUN_BAT%"

echo [INFO] Aguardando o servidor iniciar...
set "READY=0"
for /l %%i in (1,1,40) do (
    for /f %%R in ('powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:5000/api/health -TimeoutSec 1).StatusCode } catch { 0 }" 2^>nul') do (
        if "%%R"=="200" (
            set "READY=1"
            goto :ready
        )
    )
    timeout /t 1 /nobreak >nul
)
:ready

if "%READY%"=="1" (
    start "" "http://127.0.0.1:5000"
) else (
    echo.
    echo [ERRO] O servidor nao respondeu em 40s. Log:
    echo.
    type "%LOG_FILE%"
    echo.
    echo Log completo em: %LOG_FILE%
    pause
)
endlocal
