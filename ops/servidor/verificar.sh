#!/bin/sh
# Mostra a situação da instalação sem alterar nada e sem exibir segredos.
set -eu
cd "$(dirname "$0")/../.."
COMPOSE="docker compose -f compose.servidor.yaml"
PORTA=$(grep '^SENTINEL_PORT=' .env 2>/dev/null | cut -d= -f2)
PORTA=${PORTA:-2200}
echo "== Containers (STATUS mostra ha quanto tempo estao no ar)"
$COMPOSE ps
echo
echo "== Inicio dos containers e politica de reinicio"
for c in trab02_2026_2_12621cbs200 trab02_2026_2_12621cbs200_terminal; do
    docker inspect --format '{{.Name}}: iniciado em {{.State.StartedAt}} | reinicios: {{.RestartCount}} | politica: {{.HostConfig.RestartPolicy.Name}} | saude: {{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}' "$c" || true
done
echo
echo "== Resposta HTTP"
$COMPOSE exec -T app python -c "import urllib.request as u; print('/health/ ->', u.urlopen(u.Request('http://127.0.0.1:8000/health/', headers={'Host': 'localhost'}), timeout=5).read().decode())"
echo "Endereco externo: http://IP-DO-SERVIDOR:$PORTA/"
echo
echo "== Registro de disponibilidade (primeira e ultimas verificacoes)"
$COMPOSE logs --no-log-prefix monitor 2>/dev/null | head -n 1
$COMPOSE logs --no-log-prefix --tail 3 monitor
