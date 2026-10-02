#!/usr/bin/env bash
MODEL="${1:-${SCANNER_OLLAMA_MODEL:-qwen2.5:7b}}"
if ! command -v ollama >/dev/null 2>&1; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    nohup ollama serve > /tmp/ollama_serve.log 2>&1 &
    sleep 3
fi
ollama pull "$MODEL"
echo "[OK] Modelo '$MODEL' pronto."
