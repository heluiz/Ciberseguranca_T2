# Registro de mudanças

Formato de [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/);
versões em [Versionamento Semântico](https://semver.org/lang/pt-BR/)
(MAIOR.MENOR.CORREÇÃO). Cada versão publicada tem uma tag `vX.Y.Z` e uma
release no GitHub (veja [docs/GIT-FLOW.md](docs/GIT-FLOW.md)).

## [Não publicado]

## [1.0.0] - 2026-11-17

Versão entregue do Trabalho 02 (Sprints 3, 4 e 5).

### Adicionado
- **API v1** (`/api/v1/`): recursos no plural, recursos aninhados
  (`/vulnerabilities/{id}/assets`, `/assets/{id}/findings`), 201 com
  `Location`, erros em Problem Details (RFC 9457), paginação com links,
  ordenação por risco, versões com `ETag`/`If-Match` (409 e 428) e 405 com
  `Allow`.
- Autenticação da API por **JWT** (15 minutos, papel no token, algoritmo fixo)
  e por **chave de API** guardada como hash (`manage.py apikey`).
- Contrato **OpenAPI 3.1** (`docs/web/openapi.yaml`) e **Swagger UI** local em
  `/api/v1/docs/`.
- Repositório do terminal em banco relacional com **SQLAlchemy 2** e
  migrações **Alembic** (`repositorio_sql.py`, `migracoes_sql/`), escolhido
  pela variável `INVENTARIO_BANCO`; o JSON continua o padrão.
- Laboratórios de **SQL injection** (`academic/sqli_lab.py`) e de **hash de
  senha** (`academic/senhas_lab.py`), com testes de regressão.
- Testes de número de consultas (N+1), de senhas e cookies, da matriz de
  permissões, de IDOR e Schemathesis contra o contrato.
- Verificação de tipos com **mypy** (`mypy.ini`) e de segurança com
  **bandit** (`.bandit.yaml`).
- CI: mypy, bandit, validação do OpenAPI, Schemathesis, Trivy e publicação das
  imagens no GHCR numa tag; ações fixadas por SHA.
- Laboratório de HTTPS com Caddy (`compose.tls.yaml`, `ops/Caddyfile.lab`).
- Pasta "API v1" na coleção do Postman (49 verificações a mais).
- Documentos: API, ORM e SQLAlchemy, SQL injection, senhas e acesso, OWASP Top
  10, TLS, hardening, CI/CD, Git Flow, nuvem, arquitetura (C4, ADR, STRIDE),
  refatoração, dívida técnica, apresentação e retrospectiva.

### Alterado
- **Nomes padronizados** (S5_20): projeto Compose, containers, imagens e
  volumes com `trab02_2026_2_12621cbs200`; aplicação web na porta 2200
  (2000 + 200); o terminal sem porta (`trab02_2026_2_12621cbs200_terminal`);
  repositório renomeado para `trab02_2026_2_12621cbs200`.
- Limites de memória e de processos em todos os containers.
- `abrir_url()` só aceita HTTPS (antes, só quem a chamava conferia).
- O healthcheck do container do terminal confere o repositório em uso.

### Corrigido
- Caractere de controle num campo de texto deixava a base impossível de
  reabrir (achado pelo Schemathesis).
- Usuário muito longo no token derrubava a API com erro 500.
- Rota desconhecida sob `/api/v1/` respondia em HTML.
- Objeto JSON num campo de texto era convertido em texto em vez de recusado.
- Lotação longa era cortada em silêncio.
- `?cenario=` vazio caía no banco real em vez de ser recusado.

### Segurança
- `pip-audit`: nenhuma vulnerabilidade conhecida nas dependências.
- `bandit`: nenhum alerta aberto.

## [0.4.0] - 2026-11-14

### Alterado
- Revisão da interface web: botões e filtros funcionais; README com os
  comandos exatos (pull request #15).

## [0.3.0] - 2026-11-13

### Adicionado
- Interface web SENTINEL (Django + PostgreSQL): inventário, mapa de
  dependências, análise de risco, catálogo KEV, auditoria, importação e
  exportação, API REST; container do servidor (pull request #14).

## [0.2.0] - 2026-10-30

### Adicionado
- Programa de terminal em orientação a objetos com modelo de risco linear,
  plano de correção, base de CVEs exploradas, ficha técnica, árvore de
  dependências e container; implantado no servidor em 27/10/2026
  (pull requests #1 a #13).

## [0.1.0] - 2026-10-02

### Adicionado
- Trabalho 2: inventário em orientação a objetos a partir do CRUD do
  Trabalho 1, com Docker e verificação automática no GitHub.

[Não publicado]: https://github.com/heluiz/trab02_2026_2_12621cbs200/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/heluiz/trab02_2026_2_12621cbs200/releases/tag/v1.0.0
