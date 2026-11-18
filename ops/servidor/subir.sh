#!/bin/sh
# Sobe o Trabalho 2 no servidor da disciplina: a versão web (porta 2200,
# a da matrícula 12621CBS200) e o menu de terminal (sem porta).
#   sh ops/servidor/subir.sh
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
    if docker volume ls --format '{{.Name}}' | grep -qx 'trab02_2026_2_12621cbs200_db_data'; then
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
        echo "SENTINEL_PORT=${SENTINEL_PORT:-2200}"
        echo "SENTINEL_ADMIN_USER=admin"
        echo "SENTINEL_ADMIN_PASSWORD=$(segredo | cut -c1-20)"
        echo "SENTINEL_DEMO=1"
    } > .env
    echo "Arquivo .env criado (somente o seu usuario pode ler)."
fi

# Constrói as duas imagens (web e terminal).
$COMPOSE build

# Menu de terminal: na primeira vez, o volume recebe a base de exemplo
# (fictícia), com o dono certo; depois disso, nunca é sobrescrito.
# Roda com o próprio usuário do programa (UID 10001), dono da pasta.
$COMPOSE run --rm -T --no-deps --entrypoint sh terminal -c \
    '[ -f /app/dados/inventario.json ] || { cp /app/dados_exemplo/inventario_exemplo.json /app/dados/inventario.json && echo "Base de exemplo copiada para o menu de terminal."; }'

# Sobe na ordem: banco, preparação (termina sozinha), aplicação, monitor e
# o menu de terminal.
$COMPOSE up -d

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
PORTA=${PORTA:-2200}
echo
echo "Trabalho 2 em execucao (trab02_2026_2_12621cbs200)."
for host in $(grep '^DJANGO_ALLOWED_HOSTS=' .env | cut -d= -f2 | tr ',' ' '); do
    echo "  http://$host:$PORTA/"
done
echo "Usuario inicial: admin   Senha: veja SENTINEL_ADMIN_PASSWORD no arquivo .env"
echo "Disponibilidade:  $COMPOSE logs --tail 5 monitor"
echo "Menu de terminal: docker attach trab02_2026_2_12621cbs200_terminal   (sair sem parar: Ctrl+P, Ctrl+Q)"
