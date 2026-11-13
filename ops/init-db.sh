#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v db_name="$POSTGRES_DB" -v app_password="$POSTGRES_APP_PASSWORD" <<'SQL'
CREATE ROLE sentinel_app LOGIN PASSWORD :'app_password';
GRANT CONNECT ON DATABASE :"db_name" TO sentinel_app;
GRANT USAGE ON SCHEMA public TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sentinel_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO sentinel_app;
SQL
