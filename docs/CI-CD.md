# Integração e entrega contínuas

Card S5_14. Dois workflows no GitHub Actions (aba **Actions** do repositório):

| Arquivo | Jobs | Quando |
| --- | --- | --- |
| `.github/workflows/verificacao.yml` | `estilo-e-testes` (ruff, mypy, `testes.py`), `container` (imagem do terminal e autotestes dentro dela) | Todo push e pull request |
| `.github/workflows/web.yml` (cópia em `ops/ci/web.yml`) | `web`, `container`, `publicar` | Todo push, pull request e tag `v*.*.*` |

## O que roda

`web` (PostgreSQL 17 de serviço):

1. `ruff check .` (PEP 8 e PEP 257)
2. `mypy` (tipos do domínio e da persistência, `mypy.ini`)
3. `bandit -c .bandit.yaml -r .` (segurança do código)
4. `openapi-spec-validator docs/web/openapi.yaml`
5. `python testes.py` (terminal, com o repositório SQLAlchemy em SQLite)
6. `pytest --cov --cov-fail-under=80` (web, API, permissões, senhas, SQLi, N+1)
7. `makemigrations --check` e `check --deploy`
8. `pip-audit -r requirements-web.txt`
9. Schemathesis contra a aplicação rodando, com uma chave de API criada na
   hora (relatório JUnit guardado como artefato)

`container`: sobe o perfil do servidor (`ops/servidor/subir.sh`, porta 2200),
consulta saúde, login, CSS, a API v1 e o contrato; confere que o terminal está
no ar sem porta e lê a base; recria os containers e confere que os 76 ativos
continuam no volume; roda o Trivy nas duas imagens.

`publicar` (só numa tag `vX.Y.Z`, depois de `web` e `container` passarem):
constrói e publica no GitHub Container Registry as duas imagens, com
proveniência e SBOM:

```text
ghcr.io/heluiz/trab02_2026_2_12621cbs200:1.0.0           (e :1.0, :sha-xxxxxxx)
ghcr.io/heluiz/trab02_2026_2_12621cbs200_terminal:1.0.0
```

## Publicar uma versão

```bash
git switch main && git pull
git tag -a v1.0.0 -m "Trabalho 02 entregue"
git push origin v1.0.0
```

Depois que o job `publicar` terminar: no GitHub, **Packages** → cada imagem →
**Package settings** → **Change visibility** → Public (para o servidor baixar
sem login). A release: **Releases** → **Draft a new release** → tag `v1.0.0` →
cole a seção da versão do `CHANGELOG.md` → **Publish release**.

## Implantar no servidor

O card pede implantação automática por SSH com segredos do repositório. **Não
é possível aqui**: o servidor `10.0.99.150` só é alcançável de dentro da rede
da UFU, e os runners do GitHub ficam na internet. Um runner hospedado dentro da
rede resolveria, mas exigiria instalar um serviço no servidor do docente.

Como seria, num servidor alcançável (segredos `SSH_HOST`, `SSH_USER`,
`SSH_KEY` e `SSH_KNOWN_HOSTS` em **Settings → Secrets and variables →
Actions**, chave exclusiva para o deploy, só com permissão no diretório do
projeto):

```yaml
  implantar:
    needs: publicar
    runs-on: ubuntu-latest
    environment: producao          # exige aprovação manual, se configurado
    steps:
      - run: |
          install -m 600 /dev/null ~/.ssh/id && echo "${{ secrets.SSH_KEY }}" > ~/.ssh/id
          echo "${{ secrets.SSH_KNOWN_HOSTS }}" > ~/.ssh/known_hosts
          ssh -i ~/.ssh/id ${{ secrets.SSH_USER }}@${{ secrets.SSH_HOST }} \
            "cd ~/trab02_2026_2_12621cbs200 && git fetch --tags && git checkout ${GITHUB_REF_NAME} && sh ops/servidor/subir.sh"
```

No servidor da disciplina, o mesmo efeito, à mão (README, seção 4):

```bash
ssh ufu
cd ~/trab02_2026_2_12621cbs200
git fetch --tags && git checkout v1.0.0
sh ops/servidor/subir.sh
sh ops/servidor/verificar.sh
```

## Voltar para a versão anterior (rollback)

Os dados ficam no volume `trab02_2026_2_12621cbs200_db_data`, separado da
imagem: voltar o código não apaga dado.

```bash
cd ~/trab02_2026_2_12621cbs200
# 1. backup antes (README, seção 10)
docker compose -f compose.servidor.yaml exec -T db pg_dump -U sentinel_owner -d sentinel -Fc > antes-do-rollback.dump
# 2. código e imagem da versão anterior
git checkout v0.9.0
sh ops/servidor/subir.sh
sh ops/servidor/verificar.sh
```

Com as imagens do GHCR, sem reconstruir: `docker pull
ghcr.io/heluiz/trab02_2026_2_12621cbs200:0.9.0`, `docker tag` para
`trab02_2026_2_12621cbs200:1.0` e `docker compose -f compose.servidor.yaml up
-d --no-build`.

Cuidado com migrações: se a versão nova alterou o esquema, a antiga pode não
entender o banco. Antes de voltar, veja se a versão nova trouxe migração
(`inventory/migrations/`); se trouxe, restaure o backup feito antes da
atualização (seção 10 do README) em vez de só trocar a imagem.

## Riscos de um pipeline e o que foi feito

| Risco | Mitigação aqui |
| --- | --- |
| Ação de terceiros trocada (a tag `v4` passa a apontar para código malicioso) | Todas as ações fixadas pelo SHA do commit, com a versão em comentário |
| Token do workflow com poder demais | `permissions: contents: read` em tudo; `packages: write` só no job `publicar`, que só roda em tag |
| Pull request de fork roubando segredos | O gatilho é `pull_request` (sem segredos para forks), nunca `pull_request_target` |
| Segredo no log | Senhas do CI são descartáveis (`ci-only-not-production`); a chave de API criada no job é mascarada (`::add-mask::`) |
| Dependência com falha conhecida | `pip-audit` e Trivy derrubam a verificação |
| Imagem adulterada no caminho | Proveniência (SLSA) e SBOM anexados pelo `build-push-action`; a imagem é construída no próprio CI a partir da tag |
| Publicar sem testar | `publicar` tem `needs: [web, container]` |
| Alguém publica direto na `main` | Proteção do ramo `main` (veja [GIT-FLOW.md](GIT-FLOW.md)) |
| Chave de deploy com acesso total | Chave só para deploy, `known_hosts` fixo, usuário sem `sudo` |

## Ativar as mudanças no GitHub

Arquivos em `.github/workflows/` só sobem se o token do Git tiver a permissão
`workflow`. Se o `git push` recusar com "refusing to allow ... workflow", faça
o login de novo no Git Credential Manager (ou use `gh auth refresh -s
workflow`) e repita o push.
