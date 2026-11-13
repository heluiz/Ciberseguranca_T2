# Executar a versão web

Há três formas de subir a interface web. Todas usam Docker e a mesma imagem (`Dockerfile.web`).

| Onde | Arquivo | Endereço |
|---|---|---|
| Seu Windows | `ABRIR-SENTINEL.cmd` | http://127.0.0.1:8000 |
| Servidor da disciplina (rede interna) | `compose.servidor.yaml` | http://IP-DO-SERVIDOR:8080 |
| Internet, com domínio e HTTPS | `compose.web.yaml` | https://seu-dominio |

O programa de terminal original continua disponível com `compose.yaml` e não é afetado.

## 1. No Windows

Instale e abra o Docker Desktop e dê dois cliques em `ABRIR-SENTINEL.cmd`. O passo a passo está em [INICIALIZACAO-WINDOWS.md](INICIALIZACAO-WINDOWS.md).

## 2. No servidor da disciplina

```sh
git clone https://github.com/heluiz/Ciberseguranca_T2.git
cd Ciberseguranca_T2
sh ops/servidor/subir.sh
```

Para usar outra porta: `SENTINEL_PORT=8123 sh ops/servidor/subir.sh` (vale na primeira execução; depois, edite `SENTINEL_PORT` no `.env`).

O script faz tudo em uma execução:

1. cria o arquivo `.env` com segredos aleatórios e a senha do administrador inicial (só na primeira vez);
2. constrói a imagem e sobe o PostgreSQL;
3. aplica as migrações, cria os grupos, a conta `admin` e carrega o inventário de exemplo (container `preparar`, que termina sozinho);
4. sobe a aplicação e o registro de disponibilidade;
5. mostra os endereços de acesso.

A senha inicial fica em `SENTINEL_ADMIN_PASSWORD`, no `.env` do servidor. Troque-a no primeiro acesso, em `/senha/`.

Este perfil atende por HTTP, sem certificado, porque o servidor fica em rede interna e não tem domínio. Por isso `DJANGO_HTTPS=0` e `DJANGO_REQUIRE_MFA=0` são definidos de forma explícita; os demais controles (login com bloqueio por tentativas, CSRF, permissões por grupo, cabeçalhos de segurança) continuam ativos.

### Comprovar as 24 horas

```sh
sh ops/servidor/verificar.sh
```

Mostra há quanto tempo cada container está no ar, quando a aplicação iniciou, a política de reinício e o registro de disponibilidade. O container `monitor` consulta `/health/` a cada minuto e escreve uma linha por verificação, com data, hora e total de falhas:

```sh
docker compose -f compose.servidor.yaml logs monitor
```

A aplicação e o banco usam `restart: unless-stopped`: voltam sozinhos após uma falha ou o reinício do servidor. Os dados ficam no volume `sentinel-servidor_postgres-data` e sobrevivem à recriação dos containers.

### Comandos úteis

```sh
docker compose -f compose.servidor.yaml ps                # situação
docker compose -f compose.servidor.yaml logs --tail 50 app  # log da aplicação
docker compose -f compose.servidor.yaml down              # parar (os dados ficam)
sh ops/servidor/subir.sh                                   # subir de novo ou atualizar após git pull
```

Não use `down -v`: isso apaga o banco.

## 3. Na internet, com domínio e HTTPS

Use somente `compose.web.yaml`. Copie `.env.example` para `.env`, preencha os três segredos com valores aleatórios diferentes (`python -c "import secrets; print(secrets.token_urlsafe(64))"`), o domínio e as origens HTTPS.

```sh
docker compose -f compose.web.yaml build
docker compose -f compose.web.yaml up -d db
docker compose -f compose.web.yaml run --rm migrate
docker compose -f compose.web.yaml run --rm app python manage.py setup_roles
docker compose -f compose.web.yaml run --rm app python manage.py createsuperuser
docker compose -f compose.web.yaml up -d app proxy
```

O proxy (Caddy) obtém e renova o certificado e encaminha as requisições à aplicação. Neste perfil o HTTPS é obrigatório e contas administrativas precisam de segundo fator. Provisione-o por usuário antes do primeiro acesso:

```sh
docker compose -f compose.web.yaml exec app python manage.py provision_mfa USUARIO --output /tmp/mfa.json
docker compose -f compose.web.yaml cp app:/tmp/mfa.json ./mfa-privado.json
```

O arquivo traz o endereço para cadastrar no aplicativo autenticador e oito códigos de recuperação. Guarde-o em local seguro e apague as cópias; ele nunca deve ir para o Git.

## Contas e grupos

Crie as contas em **Usuários** (menu, só para o superusuário) e inclua cada uma em um grupo:

| Grupo | Pode |
|---|---|
| Leitor | Ver inventário, vulnerabilidades, tratamentos, dependências, mapa e análise de risco |
| Analista | O mesmo, mais cadastrar, alterar e excluir |
| Administrador | O mesmo, mais ver a auditoria |

Uma conta sem grupo entra, mas não vê nenhum dado.

## Desenvolvimento sem Docker

É preciso Python 3.12 ou mais novo e um PostgreSQL. Defina as variáveis `DJANGO_SECRET_KEY` (50 caracteres ou mais), `DJANGO_DEBUG=1`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` e `POSTGRES_HOST`; o Django não lê o arquivo `.env` sozinho.

```sh
pip install -r requirements-dev.txt
python manage.py bootstrap          # migrações e grupos
python manage.py createsuperuser
python manage.py import_inventory dados_exemplo/inventario_exemplo.json
python manage.py runserver 127.0.0.1:8000
```

Verificações:

```sh
ruff check .
python testes.py                    # programa original
pytest --cov=inventory --cov=academic
```

Os testes criam e apagam o banco temporário `test_<nome>`; o usuário do PostgreSQL usado neles precisa poder criar bancos.

## API e Postman

Importe `docs/web/SENTINEL.postman_collection.json` no Postman, defina as variáveis `base_url`, `username` e `password` e execute a coleção inteira. Ela entra no sistema, cria, consulta, altera (PUT e PATCH), testa os casos de erro e apaga o que criou. Pela linha de comando:

```sh
npx newman run docs/web/SENTINEL.postman_collection.json \
  --env-var base_url=http://127.0.0.1:8000 --env-var username=USUARIO --env-var password=SENHA
```

## Backup e restauração

```sh
docker compose -f compose.servidor.yaml exec -T db pg_dump -U sentinel_owner -d sentinel -Fc > sentinel.dump
```

O arquivo contém todo o banco, inclusive as contas. Guarde-o protegido e teste a restauração em um banco separado (`pg_restore --exit-on-error --no-owner --no-acl`) antes de precisar dele. A exportação JSON do menu leva só o inventário, no formato do programa original; não substitui o backup.
