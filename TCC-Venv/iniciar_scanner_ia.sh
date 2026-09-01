#!/usr/bin/env bash
# Launcher portavel do Scanner IA para Linux/macOS.
# Equivalente ao iniciar_scanner_ia.bat: cria .venv, instala deps,
# sobe o servidor, espera health check responder e abre o navegador.
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$ROOT_DIR/Scripts"
VENV_DIR="$ROOT_DIR/.venv"
DATA_DIR="$ROOT_DIR/data"
LOG_FILE="$DATA_DIR/server.log"
PID_FILE="$DATA_DIR/server.pid"
PORT="${SCANNER_PORT:-5000}"
HEALTH_URL="http://127.0.0.1:${PORT}/api/health"

if [ ! -f "$SCRIPTS_DIR/app_web.py" ]; then
    echo "[ERRO] app_web.py nao encontrado em $SCRIPTS_DIR"
    echo "Coloque este projeto intacto e execute o script na raiz."
    exit 1
fi

mkdir -p "$DATA_DIR"

# 1) Python 3.9+
PYTHON_BIN=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
        if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 9) else 1)" >/dev/null 2>&1; then
            PYTHON_BIN="$cand"
            break
        fi
    fi
done
if [ -z "$PYTHON_BIN" ]; then
    echo "[ERRO] Python 3.9+ nao encontrado no PATH."
    echo "Instale com: sudo apt install python3 python3-venv   (ou equivalente da sua distro)"
    exit 1
fi

# 2) .venv portavel (cria na primeira execucao)
if [ ! -x "$VENV_DIR/bin/python3" ]; then
    echo "[INFO] Primeira execucao: criando .venv ..."
    "$PYTHON_BIN" -m venv "$VENV_DIR" || {
        echo "[ERRO] Nao foi possivel criar o ambiente virtual em $VENV_DIR"
        echo "Em algumas distros: sudo apt install python3-venv"
        exit 1
    }
fi
VENV_PYTHON="$VENV_DIR/bin/python3"

# 3) Dependencias (instala se faltar flask)
if ! "$VENV_PYTHON" -c "import flask" >/dev/null 2>&1; then
    echo "[INFO] Instalando dependencias em .venv ..."
    "$VENV_PYTHON" -m pip install --upgrade pip -q
    "$VENV_PYTHON" -m pip install -r "$ROOT_DIR/requirements.txt" || {
        echo "[ERRO] Falha ao instalar requirements.txt"
        exit 1
    }
fi

export SCANNER_SSL_MODE="${SCANNER_SSL_MODE:-}"
export SCANNER_FORCE_HTTPS_REDIRECT="${SCANNER_FORCE_HTTPS_REDIRECT:-0}"
export SCANNER_TRUST_PROXY="${SCANNER_TRUST_PROXY:-0}"

# 4) Se a porta ja estiver em uso, assume que o servidor ja esta rodando.
port_in_use() {
    if command -v curl >/dev/null 2>&1; then
        curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${PORT}/" && return 0
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null && { exec 3>&-; return 0; }
    return 1
}

if port_in_use; then
    echo "[INFO] Porta ${PORT} ja em uso - abrindo navegador."
else
    echo "[INFO] Iniciando servidor... (log em $LOG_FILE)"
    echo "==== $(date) ====" > "$LOG_FILE"
    ( cd "$SCRIPTS_DIR" && exec "$VENV_PYTHON" app_web.py >> "$LOG_FILE" 2>&1 ) &
    echo $! > "$PID_FILE"
fi

echo "[INFO] Aguardando o servidor iniciar..."
READY=0
for _ in $(seq 1 40); do
    if command -v curl >/dev/null 2>&1; then
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 "$HEALTH_URL" 2>/dev/null || echo 000)"
        if [ "$code" = "200" ]; then
            READY=1
            break
        fi
    fi
    sleep 1
done

if [ "$READY" = "1" ]; then
    URL="http://127.0.0.1:${PORT}"
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$URL" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then
        open "$URL" >/dev/null 2>&1 &
    else
        echo "[INFO] Acesse manualmente: $URL"
    fi
else
    echo
    echo "[ERRO] O servidor nao respondeu em 40s. Log:"
    echo
    tail -n 60 "$LOG_FILE" 2>/dev/null
    echo
    echo "Log completo em: $LOG_FILE"
    exit 1
fi
