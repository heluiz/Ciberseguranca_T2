#!/bin/sh
# Mostra a situação da instalação sem alterar nada e sem exibir segredos.
set -eu
cd "$(dirname "$0")/../.."
COMPOSE="docker compose -f compose.servidor.yaml"
PORTA=$(grep '^SENTINEL_PORT=' .env 2>/dev/null | cut -d= -f2)
PORTA=${PORTA:-8080}
echo "== Containers (STATUS mostra ha quanto tempo estao no ar)"
$COMPOSE ps
echo
echo "== Inicio do container da aplicacao e politica de reinicio"
docker inspect --format 'iniciado em {{.State.StartedAt}} | reinicios: {{.RestartCount}} | politica: {{.HostConfig.RestartPolicy.Name}}' "$($COMPOSE ps -q app)"
echo
echo "== Resposta HTTP"
$COMPOSE exec -T app python -c "import urllib.request as u; print('/health/ ->', u.urlopen(u.Request('http://127.0.0.1:8000/health/', headers={'Host': 'localhost'}), timeout=5).read().decode())"
echo "Endereco externo: http://IP-DO-SERVIDOR:$PORTA/"
echo
echo "== Registro de disponibilidade (primeira e ultimas verificacoes)"
$COMPOSE logs --no-log-prefix monitor 2>/dev/null | head -n 1
$COMPOSE logs --no-log-prefix --tail 3 monitor
