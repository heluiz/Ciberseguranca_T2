#!/bin/sh
# Sobe o SENTINEL web no servidor da disciplina.
#   sh ops/servidor/subir.sh            porta 8080
#   SENTINEL_PORT=8123 sh ops/servidor/subir.sh
# Na primeira execução cria o arquivo .env com segredos aleatórios e a senha
# do administrador inicial. Nas seguintes, reaproveita o .env existente.
set -eu
cd "$(dirname "$0")/../.."
COMPOSE="docker compose -f compose.servidor.yaml"

segredo() {
    # 48 bytes aleatórios do sistema em texto seguro para arquivo .env
    head -c 48 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_'
}

if [ ! -f .env ]; then
    if docker volume ls --format '{{.Name}}' | grep -qx 'sentinel-servidor_postgres-data'; then
        echo "Existe um banco do SENTINEL, mas falta o arquivo .env." >&2
        echo "Recupere o .env original; uma senha nova nao abriria esse banco." >&2
        exit 1
    fi
    # Enderecos pelos quais o servidor e acessado, para a lista de hosts aceitos.
    HOSTS="localhost,127.0.0.1,$(hostname)"
    for ip in $(hostname -I 2>/dev/null || true); do
        case "$ip" in *:*) ;; *) HOSTS="$HOSTS,$ip" ;; esac
    done
    umask 077
    {
        echo "DJANGO_SECRET_KEY=$(segredo)$(segredo)"
        echo "POSTGRES_OWNER_PASSWORD=$(segredo)"
        echo "POSTGRES_PASSWORD=$(segredo)"
        echo "POSTGRES_DB=sentinel"
        echo "DJANGO_ALLOWED_HOSTS=$HOSTS"
        echo "DJANGO_HTTPS=0"
        echo "DJANGO_REQUIRE_MFA=0"
        echo "SENTINEL_PORT=${SENTINEL_PORT:-8080}"
        echo "SENTINEL_ADMIN_USER=admin"
        echo "SENTINEL_ADMIN_PASSWORD=$(segredo | cut -c1-20)"
        echo "SENTINEL_DEMO=1"
    } > .env
    echo "Arquivo .env criado (somente o seu usuario pode ler)."
fi

# Sobe na ordem: banco, preparação (termina sozinha), aplicação e monitor.
$COMPOSE up -d --build

# Espera a aplicação responder à verificação de saúde (até 3 minutos).
APP=$($COMPOSE ps -q app)
tentativa=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' "$APP" 2>/dev/null)" = "healthy" ]; do
    tentativa=$((tentativa + 1))
    if [ "$tentativa" -gt 90 ]; then
        echo "A aplicacao nao ficou pronta. Ultimas linhas do log:" >&2
        $COMPOSE logs --tail 30 preparar app >&2
        exit 1
    fi
    sleep 2
done
PORTA=$(grep '^SENTINEL_PORT=' .env | cut -d= -f2)
PORTA=${PORTA:-8080}
echo
echo "SENTINEL em execucao."
for host in $(grep '^DJANGO_ALLOWED_HOSTS=' .env | cut -d= -f2 | tr ',' ' '); do
    echo "  http://$host:$PORTA/"
done
echo "Usuario inicial: admin   Senha: veja SENTINEL_ADMIN_PASSWORD no arquivo .env"
echo "Disponibilidade:  $COMPOSE logs --tail 5 monitor"
