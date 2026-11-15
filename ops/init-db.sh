#!/bin/sh
# Cria o papel da aplicação (só lê e grava dados) no primeiro início do banco.
# O PostgreSQL executa este arquivo, ou o carrega com "." quando ele não tem
# permissão de execução (o Git no Windows pode perder essa permissão). Por isso
# o arquivo não muda as opções do shell que o carrega: um erro no psql
# (ON_ERROR_STOP) interrompe a inicialização do mesmo jeito.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v db_name="$POSTGRES_DB" -v app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE sentinel_app LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE :"db_name" TO sentinel_app;
GRANT USAGE ON SCHEMA public TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
SQL
