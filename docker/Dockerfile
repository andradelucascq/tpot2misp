FROM python:3.9-slim

WORKDIR /app

# Copiar requirements.txt primeiro para aproveitar o cache do Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o código do projeto
COPY main.py .
COPY collectors/ ./collectors/
COPY config/ ./config/
COPY processors/ ./processors/
COPY utils/ ./utils/

# Criar diretórios para volumes
RUN mkdir -p /app/data /app/logs

# Configuração para volumes
VOLUME ["/app/data", "/app/logs"]

# Comando para executar o aplicativo
CMD ["python", "main.py"]