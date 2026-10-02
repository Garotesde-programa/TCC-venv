# Imagem da aplicação web do scanner (não inclui o Ollama - isso é
# um serviço separado no docker-compose.yml, pra poder trocar de
# GPU/host sem rebuildar a app).
FROM python:3.11-slim

WORKDIR /app

# Dependências do sistema mínimas (nada de compilador pesado - o projeto
# usa só urllib/flask na base; playwright é opcional e não entra aqui).
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY Scripts/ ./Scripts/
COPY data/ ./data/

WORKDIR /app/Scripts

EXPOSE 5000

# Healthcheck simples - bate na própria página inicial
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/ || exit 1

CMD ["python3", "app_web.py"]
