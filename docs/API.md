# API v1: projeto REST, autenticação e contrato OpenAPI

Cards S5_03, S5_04, S5_09 e S5_12. Código em `inventory/api_v1.py`, contrato em
`docs/web/openapi.yaml`, testes em `tests_web/test_api_v1.py` e coleção do
Postman em `docs/web/SENTINEL.postman_collection.json` (pasta 5).

A API antiga (`/api/<tipo>/`, com sessão e token CSRF) continua funcionando
para as telas. A v1 é a API pública: sem cookie, sem CSRF, com token.

## Onde ver

| Endereço | O que é |
| --- | --- |
| `/api/v1/` | Índice: versão, recursos e links |
| `/api/v1/docs/` | Swagger UI (servido pela própria aplicação, sem CDN, dentro da CSP) |
| `/api/v1/openapi.yaml` | O contrato OpenAPI 3.1, o mesmo arquivo do repositório |
| `/api/v1/problemas/<tipo>` | A explicação de cada tipo de erro |

No servidor: `http://10.0.99.150:2200/api/v1/docs/`.

## Rotas

| Rota | Métodos | Observação |
| --- | --- | --- |
| `/api/v1/auth/token` | POST | Usuário e senha (e `otp` do administrador) → JWT |
| `/api/v1/assets` | GET, POST | Filtros `tipo` e `lotacao`; `ordering=risco`, `-risco`, `hostname`, `id` |
| `/api/v1/assets/{id}` | GET, PUT, PATCH, DELETE | |
| `/api/v1/assets/{id}/findings` | GET | Tratamentos do equipamento (recurso aninhado) |
| `/api/v1/vulnerabilities` | GET, POST | |
| `/api/v1/vulnerabilities/{id}` | GET, PUT, PATCH, DELETE | |
| `/api/v1/vulnerabilities/{id}/assets` | GET | Equipamentos afetados (recurso aninhado, pedido no S5_03) |
| `/api/v1/findings` | GET, POST | Filtro `situacao` |
| `/api/v1/findings/{id}` | GET, PUT, PATCH, DELETE | |
| `/api/v1/dependencies` | GET, POST | A soma das frações de um equipamento fica abaixo de 1 |
| `/api/v1/dependencies/{id}` | GET, PUT, PATCH, DELETE | |
| `/api/v1/risk` | GET | Risco próprio e efetivo; `cenario=exemplo` ou `singular` |
| `/api/v1/audit-events` | GET | Só com o papel Administrador no token |

Nomes no plural, substantivos, sem verbo na URL; a ação é o método HTTP.

## Códigos de status

| Código | Quando |
| --- | --- |
| 200 | Consulta, PUT e PATCH |
| 201 | POST, com `Location` apontando o recurso criado e `ETag` com a versão |
| 204 | DELETE, sem corpo |
| 400 | JSON malformado, parâmetro de consulta inválido (`limit=0`, `cenario=`) |
| 401 | Sem token, token vencido, adulterado ou de outro segredo (`WWW-Authenticate: Bearer`) |
| 403 | O papel não permite (fica registrado na auditoria) |
| 404 | Recurso ou rota inexistente (também em `/api/v1/qualquer-coisa`) |
| 405 | Método não aceito, com `Allow` |
| 409 | Versão antiga (alguém alterou antes) ou registro duplicado |
| 422 | Campo inválido, faltando ou não permitido (`errors` diz qual) |
| 428 | Alteração ou exclusão sem versão (`If-Match` ou `version`) |
| 429 | Conta bloqueada depois de cinco senhas erradas (15 minutos) |

Todo erro sai em **Problem Details** (RFC 9457), `application/problem+json`:

```json
{
  "type": "/api/v1/problemas/dados-invalidos",
  "title": "Dados inválidos",
  "status": 422,
  "detail": "Corrija os campos indicados.",
  "instance": "/api/v1/assets",
  "errors": {"hostname": ["Este campo é obrigatório."]}
}
```

## Concorrência otimista

Cada recurso tem `version`. A resposta traz `ETag: "N"`. Para alterar ou
excluir, mande `If-Match: "N"` (ou `version` no corpo). Se alguém alterou antes,
a resposta é 409; sem versão, 428. Assim uma edição nunca apaga outra sem
aviso.

## Paginação e ordenação

`?limit=` (1 a 100, padrão 20) e `?offset=`. A resposta:

```json
{"count": 76, "limit": 5, "offset": 0,
 "links": {"self": "...", "next": "...?limit=5&offset=5", "prev": null},
 "results": [...]}
```

Cada equipamento traz `risco.proprio` e `risco.efetivo`;
`/api/v1/assets?ordering=-risco` lista do maior para o menor risco efetivo.

## Validação

Toda entrada passa pelos mesmos formulários das telas (os "modelos de
validação" do S5_03, no papel do Pydantic) e pelas classes do domínio. Antes, a
API confere os tipos do JSON (texto é texto, número é número), recusa campo
desconhecido (`is_superuser` no corpo vira 422, nunca é ignorado em silêncio) e
caracteres de controle.

## Autenticação (S5_09)

Duas formas, as duas sem cookie:

**JWT** para pessoas. `POST /api/v1/auth/token` com usuário e senha passa pelo
mesmo bloqueio do login das telas (django-axes: cinco erros, 15 minutos) e, para
o administrador, exige o código do segundo fator no campo `otp`. O token:

- HS256, assinado com `JWT_SECRET_KEY` (ou derivado da chave do Django por
  HMAC, se a variável não existir);
- vale 15 minutos (`exp`), com `iss=sentinel`, `aud=sentinel-api`, `sub` (id da
  conta) e `roles` (grupos);
- na verificação, o algoritmo é fixo (`algorithms=["HS256"]`: um token com
  `alg: none` é recusado), e emissor, público, expiração e emissão são
  obrigatórios;
- a conta desativada perde o acesso na hora, mesmo com token válido.

A carga do JWT **não é cifrada**, só assinada: qualquer um lê (base64url). Por
isso ela leva só o id e os papéis, nunca senha, e-mail ou dado do inventário.
Para conferir:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"analista","password":"SUA_SENHA"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
echo "$TOKEN" | cut -d. -f2 | python -c "import sys,base64;s=sys.stdin.read().strip();print(base64.urlsafe_b64decode(s+'='*(-len(s)%4)).decode())"
curl -s http://127.0.0.1:8000/api/v1/assets?limit=2 -H "Authorization: Bearer $TOKEN"
```

**Chave de API** para scripts e integrações. A chave tem o formato
`snt_<prefixo>_<segredo>`; o banco guarda só o prefixo (para achar) e o
SHA-256 do segredo, comparado em tempo constante (`hmac.compare_digest`). Ela é
mostrada uma vez só:

```bash
python manage.py apikey criar analista "script de relatório"
python manage.py apikey listar
python manage.py apikey revogar PREFIXO
curl -s http://127.0.0.1:8000/api/v1/assets -H "X-API-Key: snt_..."
```

No servidor, os mesmos comandos dentro do container:
`docker compose -f compose.servidor.yaml exec app python manage.py apikey listar`.

Por que SHA-256 serve para a chave e não serve para senha: a chave tem 256 bits
aleatórios gerados pelo `secrets`, então não há dicionário para testar; a senha
é escolhida por uma pessoa e precisa de um hash lento (veja
[SENHAS-E-ACESSO.md](SENHAS-E-ACESSO.md)).

O papel e as permissões são conferidos em cada rota (matriz em
[SENHAS-E-ACESSO.md](SENHAS-E-ACESSO.md)).

## Contrato OpenAPI (S5_04)

Abordagem **contract-first**: o `openapi.yaml` foi escrito à mão e o código
segue o contrato; a aplicação serve o próprio arquivo. Tem `info`, `servers`,
14 caminhos, os dois `securitySchemes` (`bearerAuth` e `apiKeyAuth`),
parâmetros, cabeçalhos (`Location`, `ETag`, `If-Match`), respostas de erro
reaproveitadas e esquemas (`Asset`, `Vulnerability`, `Finding`, `Dependency`,
cada um com as variantes de entrada e de PATCH, `Problem`, `Page`, `Token`,
`Risk`), com exemplos.

Validar:

```bash
pip install -r requirements-dev.txt
openapi-spec-validator docs/web/openapi.yaml
```

Importar no Postman: **Import** → `docs/web/openapi.yaml` gera uma coleção a
partir do contrato. A coleção pronta, com os testes, é a
`SENTINEL.postman_collection.json`.

## Testes da API (S5_12)

- `tests_web/test_api_v1.py` (pytest, PostgreSQL real): ciclo completo de
  CRUD, 201/Location/ETag, 409/428, 422 com campo desconhecido, paginação e
  ordenação por risco, recursos aninhados, 405, CSRF desnecessário e cookie de
  sessão recusado, tokens vencido, adulterado, de outro segredo, com
  `alg: none` e de outro público, conta desativada, chave de API guardada como
  hash e revogada, bloqueio depois de cinco senhas erradas, nenhuma senha no
  log, matriz de permissões e IDOR.
- **Schemathesis** gera milhares de pedidos a partir do contrato e confere se
  as respostas seguem o que ele promete. Os achados viraram correções e testes
  de regressão (`test_found_by_schemathesis_*`):

  | Achado | Correção |
  | --- | --- |
  | Caractere de controle aceito no texto deixava a base impossível de reabrir | Recusado no formulário, na API e nas telas |
  | Usuário com mais de 150 caracteres derrubava o token com erro 500 | Tamanho conferido antes do bloqueio |
  | `/api/v1/assets/%20` devolvia a página 404 em HTML | Toda rota desconhecida sob `/api/v1/` responde Problem Details |
  | `{"vetor": {}}` virava texto em vez de ser recusado | Tipos do JSON conferidos antes do formulário |
  | Lotação longa era cortada em silêncio | Recusada com 400 |
  | `?cenario=` vazio caía no banco real | Parâmetro presente tem de estar no enum |

  Rodar (com a aplicação no ar e uma chave de API):

  ```bash
  schemathesis run docs/web/openapi.yaml --url http://127.0.0.1:8000 \
    -H "X-API-Key: snt_..." --max-examples 25 \
    --exclude-checks ignored_auth,positive_data_acceptance,missing_required_header
  ```

  As três verificações excluídas: `missing_required_header` porque o 428 sem
  `If-Match` é proposital; `ignored_auth` e `positive_data_acceptance` porque
  geram falsos positivos com a chave de administrador (que tem acesso a tudo) e
  com as regras de negócio que o esquema não expressa (hostname único, soma
  das frações).
- O pytest e o Schemathesis rodam no GitHub Actions
  (`.github/workflows/web.yml`) a cada envio; a coleção do Postman (pasta 5,
  49 verificações) roda com `npx newman` contra a aplicação no ar (README,
  seção 9).
