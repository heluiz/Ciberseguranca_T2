# Executar a versão web

## Local com Docker Desktop (Windows ou Linux)

Pré-requisitos: Git, Docker Engine/Compose ou Docker Desktop. No Windows, usar containers Linux. Não é necessário instalar PostgreSQL nem Python no host.

1. Copie `.env.example` para `.env`. Gere três valores aleatórios diferentes para `DJANGO_SECRET_KEY`, `POSTGRES_PASSWORD` e `POSTGRES_OWNER_PASSWORD`. Exemplo com Python: `python -c "import secrets; print(secrets.token_urlsafe(64))"`. Não envie `.env` ao GitHub. No Linux: `chmod 600 .env`.
2. Para acesso local, configure `DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1`, deixe `DJANGO_CSRF_TRUSTED_ORIGINS` vazio e use os dois arquivos Compose abaixo.

```sh
docker compose -f compose.web.yaml -f compose.web.local.yaml build
docker compose -f compose.web.yaml -f compose.web.local.yaml up -d db
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm migrate
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm app python manage.py setup_roles
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm app python manage.py collectstatic --noinput
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm app python manage.py createsuperuser
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm app python manage.py import_inventory dados_exemplo/inventario_exemplo.json --dry-run
docker compose -f compose.web.yaml -f compose.web.local.yaml run --rm app python manage.py import_inventory dados_exemplo/inventario_exemplo.json
docker compose -f compose.web.yaml -f compose.web.local.yaml up -d app
```

Abra http://127.0.0.1:8000. O modo local habilita DEBUG e não exige MFA; atende somente no endereço local do host. O comando `run migrate` cria e altera tabelas usando o proprietário; a aplicação recebe só permissões de dados. O banco não publica porta no host.

No admin, crie contas, defina senha forte e associe a Analista ou Leitor. Não marque essas contas como superusuário ou equipe. Administradores de contas usam o superusuário inicial; o grupo Administrador concede apenas permissões de inventário e exige MFA em produção.

O script de inicialização do banco é executado somente no primeiro volume vazio. Para instalações existentes, provisionar o papel `sentinel_app` e privilégios manualmente. Trocar uma senha no `.env` não troca a senha já gravada no PostgreSQL. Nunca remova o volume de dados como atalho para corrigir configuração.

## Desenvolvimento sem Docker

Crie um ambiente Python 3.12 e instale `requirements-dev.txt`. Use PostgreSQL real, um banco dedicado e credenciais por ambiente. Exporte as variáveis do `.env` usando mecanismo seguro do seu shell; Django não carrega esse arquivo automaticamente fora do Compose. Defina `DJANGO_DEBUG=1` apenas localmente.

```sh
python manage.py migrate
python manage.py setup_roles
python manage.py createsuperuser
python manage.py import_inventory dados_exemplo/inventario_exemplo.json
python manage.py runserver 127.0.0.1:8000
python testes.py
pytest --cov=inventory --cov=academic
ruff check .
```

Os testes precisam de papel com permissão de criar o banco temporário `test_sentinel`. O papel da aplicação de produção não deve ter essa permissão.

## Servidor e HTTPS (depois da aprovação)

Use apenas `compose.web.yaml`, DEBUG=0, domínio real e origens HTTPS explícitas. Configure DNS, abra somente 80/443 para a aplicação e restrinja SSH por chave. Caddy emite e renova certificado; encaminha o esquema original ao Gunicorn. Não exponha diretamente a porta do app quando confiar no cabeçalho do proxy.

Faça migrações, `setup_roles`, coleta de estáticos e criação da primeira conta antes de subir o app. Provisione MFA localmente, por usuário, antes do primeiro acesso público:

```sh
docker compose -f compose.web.yaml exec app python manage.py provision_mfa USUARIO --output /tmp/mfa.json
```

Com o app em execução, esse comando cria um arquivo temporário privado no container. Para obter o arquivo com controle de acesso, copie com `docker compose cp app:/tmp/mfa.json ./mfa-privado.json`, restrinja o arquivo no host e remova as cópias depois de cadastrar o autenticador e guardar os códigos de recuperação em cofre. Nunca inclua esse arquivo no Git ou nos logs. No Windows configure a ACL equivalente. Revogar/reprovisionar dispositivo exige acesso administrativo ao servidor; a recuperação deve confirmar a identidade do titular.

```sh
docker compose -f compose.web.yaml exec app python manage.py check --deploy
docker compose -f compose.web.yaml logs --tail=100 app proxy
```

Não declare disponibilidade de 24 horas antes de monitorar `/health/` de fora do servidor durante esse período, incluindo um reinício controlado e recuperação.

## Backup e restauração

Use o proprietário do banco, proteja o dump e teste restauração em um banco separado antes de substituir dados. O dump pode conter informações pessoais, hashes, sementes MFA e auditoria.

```sh
docker compose -f compose.web.yaml exec -T db pg_dump -U sentinel_owner -d sentinel -Fc > sentinel.dump
```

Restauração em ambiente isolado: crie banco vazio, use `pg_restore --exit-on-error --no-owner --no-acl` e compare contagens, vínculos, versões e risco com a origem. Confira também login/permissões e os arquivos estáticos. O volume persistente não substitui backup fora do servidor. Para reverter uma atualização, preserve dump anterior e versão de código compatível com o esquema.
