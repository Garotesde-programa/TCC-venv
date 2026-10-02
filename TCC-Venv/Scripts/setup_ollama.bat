@echo off
REM Instala o Ollama (se nao tiver) e baixa o modelo usado pelo agente de IA.
REM Uso: scripts\setup_ollama.bat [modelo]
REM Ex.:  scripts\setup_ollama.bat qwen2.5:14b

setlocal enabledelayedexpansion

set "MODEL=%~1"
if "%MODEL%"=="" set "MODEL=qwen2.5:14b"

where ollama >nul 2>nul
if %errorlevel% neq 0 (
    echo [*] Ollama nao encontrado. Baixando instalador...
    powershell -Command "Invoke-WebRequest -Uri https://ollama.com/download/OllamaSetup.exe -OutFile %TEMP%\OllamaSetup.exe"
    echo [*] Rodando instalador ^(siga o assistente^)...
    start /wait %TEMP%\OllamaSetup.exe
) else (
    echo [*] Ollama ja instalado.
)

echo [*] Garantindo que o servico do Ollama esta rodando...
start /b ollama serve >nul 2>nul
timeout /t 3 /nobreak >nul

echo [*] Baixando modelo: %MODEL% ^(pode demorar - alguns GB^)
ollama pull %MODEL%

echo.
echo [OK] Ollama pronto. Modelo '%MODEL%' disponivel.
echo      Defina SCANNER_AI_BACKEND=ollama no .env e suba o app normalmente.
endlocal
