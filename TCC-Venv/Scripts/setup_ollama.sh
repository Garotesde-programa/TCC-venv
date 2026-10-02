#!/usr/bin/env bash
# Instala o Ollama (se não tiver) e baixa o modelo usado pelo agente de IA.
# Uso: bash scripts/setup_ollama.sh [modelo]
# Ex.:  bash scripts/setup_ollama.sh qwen2.5:14b

set -e

MODEL="${1:-${SCANNER_OLLAMA_MODEL:-qwen2.5:14b}}"

if ! command -v ollama >/dev/null 2>&1; then
    echo "[*] Ollama não encontrado. Instalando..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "[*] Ollama já instalado: $(ollama --version)"
fi

# Garante que o serviço está de pé antes de puxar o modelo
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "[*] Subindo o servidor do Ollama em background..."
    nohup ollama serve > /tmp/ollama_serve.log 2>&1 &
    sleep 3
fi

echo "[*] Baixando modelo: $MODEL (pode demorar - é uma baixa de alguns GB)"
ollama pull "$MODEL"

echo "[OK] Ollama pronto. Modelo '$MODEL' disponível."
echo "     Agora defina SCANNER_AI_BACKEND=ollama no seu .env e suba o app normalmente."
