#!/usr/bin/env bash
# Roda a suite de testes (pytest) reaproveitando o mesmo .venv do
# iniciar_scanner_ia.sh. Cria o venv se ainda não existir.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "[INFO] .venv nao encontrado - criando ..."
    PYTHON_BIN="$(command -v python3 || command -v python || true)"
    if [ -z "$PYTHON_BIN" ]; then
        echo "[ERRO] Python 3.9+ nao encontrado no PATH."
        exit 1
    fi
    "$PYTHON_BIN" -m venv "$VENV_DIR" || {
        echo "[ERRO] Nao foi possivel criar o ambiente virtual em $VENV_DIR"
        echo "Em algumas distros: sudo apt install python3-venv"
        exit 1
    }
    "$VENV_DIR/bin/python3" -m pip install --upgrade pip -q
    "$VENV_DIR/bin/python3" -m pip install -r "$ROOT_DIR/requirements.txt" || {
        echo "[ERRO] Falha ao instalar requirements.txt"
        exit 1
    }
fi
VENV_PYTHON="$VENV_DIR/bin/python3"

if ! "$VENV_PYTHON" -c "import pytest" >/dev/null 2>&1; then
    echo "[INFO] Instalando dependencias de teste (requirements-dev.txt) ..."
    "$VENV_PYTHON" -m pip install -r "$ROOT_DIR/requirements-dev.txt" || {
        echo "[ERRO] Falha ao instalar requirements-dev.txt"
        exit 1
    }
fi

echo "[INFO] Garantindo o Chromium do Playwright instalado..."
"$VENV_PYTHON" -m playwright install chromium >/dev/null 2>&1 || true

echo
echo "[INFO] Rodando suite de testes..."
echo
"$VENV_PYTHON" -m pytest "$ROOT_DIR"
exit $?
