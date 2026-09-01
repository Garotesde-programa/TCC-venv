@echo off
setlocal EnableExtensions
title Scanner IA - Testes

call "%~dp0_env.bat"
if errorlevel 1 (
    pause
    exit /b 1
)

"%PYTHON_EXE%" -c "import pytest" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Instalando dependencias de teste ^(requirements-dev.txt^) ...
    "%PYTHON_EXE%" -m pip install -r "%ROOT_DIR%\requirements-dev.txt"
    if errorlevel 1 (
        echo [ERRO] Falha ao instalar requirements-dev.txt
        pause
        exit /b 1
    )
)

echo [INFO] Garantindo o Chromium do Playwright instalado...
"%PYTHON_EXE%" -m playwright install chromium >nul 2>&1

echo.
echo [INFO] Rodando suite de testes...
echo.
"%PYTHON_EXE%" -m pytest "%ROOT_DIR%"
set "TEST_EXIT=%errorlevel%"

echo.
if "%TEST_EXIT%"=="0" (
    echo [OK] Todos os testes passaram.
) else (
    echo [ERRO] Alguns testes falharam. Codigo de saida: %TEST_EXIT%
)
pause
endlocal
exit /b %TEST_EXIT%
