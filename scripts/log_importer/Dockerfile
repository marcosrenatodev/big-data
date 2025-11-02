FROM python:3.11-slim

# Evita cache e mensagens desnecessárias
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Instala dependências do script
RUN python -m pip install psycopg2-binary

# Copia o script para dentro da imagem
COPY import_logs.py /app/import_logs.py

# Defaults (podem ser sobrescritos no compose)
ENV PGHOST=postgres PGDATABASE=logdb PGUSER=loguser PGPASSWORD=logpass PGPORT=5432

# Por padrão, roda o script; o caminho do arquivo de log vem no CMD
ENTRYPOINT ["python", "/app/import_logs.py"]
CMD ["/logs/auth.log"]
