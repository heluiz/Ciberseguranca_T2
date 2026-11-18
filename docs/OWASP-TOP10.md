# O SENTINEL segundo o OWASP Top 10:2025

Card S5_02 (e a parte de análise estática do S5_07 e do S5_14). Referência:
[OWASP Top 10:2025](https://owasp.org/Top10/), a edição vigente, apresentada
em novembro de 2025; CWE em [cwe.mitre.org](https://cwe.mitre.org/).

Escopo: a aplicação web (Django, API v1, PostgreSQL, containers) e o programa
de terminal. Não é auditoria independente: é a revisão do próprio autor, com
as ferramentas abaixo.

## Categoria por categoria

| Categoria | O que é, com um exemplo web | CWE | No SENTINEL | Situação |
| --- | --- | --- | --- | --- |
| **A01** Broken Access Control | Trocar o id na URL e ver ou alterar o que não devia; inclui SSRF | CWE-284, CWE-639 (IDOR), CWE-918 (SSRF) | Permissão conferida em cada view e rota da API; papel no token para a rota administrativa; recusas na auditoria; a aplicação não busca URL informada pelo usuário (a base CVE web é local) | Controlado; testes da matriz e de IDOR ([SENHAS-E-ACESSO.md](SENHAS-E-ACESSO.md)) |
| **A02** Security Misconfiguration | DEBUG ligado em produção, cabeçalho faltando, porta de banco exposta | CWE-16, CWE-489, CWE-1004 | `DEBUG=0` nos perfis de servidor; `check --deploy` sem aviso no CI; CSP `'self'`, `X-Frame-Options: DENY`, `nosniff`; banco sem porta publicada; containers `read_only`, `cap_drop: ALL`, `no-new-privileges`, limites de memória e processos | Controlado; ver achado 1 (HTTP no servidor) |
| **A03** Software Supply Chain Failures | Biblioteca com falha conhecida, ação de CI trocada, imagem adulterada | CWE-1104, CWE-1357, CWE-494 | Versões fixas em `requirements*.txt`; pip-audit e Trivy no CI; ações do GitHub fixadas por SHA; Swagger UI copiado para o repositório (sem CDN); imagem publicada com proveniência e SBOM | Controlado; ver achado 6 |
| **A04** Cryptographic Failures | Senha em MD5, tráfego sem TLS, segredo no código | CWE-319, CWE-327, CWE-916 | Senhas em Argon2id; chave de API em SHA-256 de 256 bits aleatórios; JWT HS256 com algoritmo fixo; segredos só em variável de ambiente (`.env` fora do Git e da imagem); HTTPS com HSTS no perfil de internet | **Achado 1**: o servidor da disciplina é HTTP |
| **A05** Injection | SQL montado com texto do usuário; XSS | CWE-89, CWE-79 | Só ORM e parâmetros ligados; escape automático dos templates e `textContent` no JavaScript; CSP sem `unsafe-inline` | Controlado; laboratório e testes em [LAB-SQL-INJECTION.md](LAB-SQL-INJECTION.md) |
| **A06** Insecure Design | Fluxo que permite abuso por desenho (sem limite, sem confirmação) | CWE-770, CWE-841 | Versões com `If-Match` (nada se sobrescreve sem aviso); importação só em base vazia e atômica; modelo de risco recusa sistema singular | **Achado 2**: sem limite de taxa na API fora do login |
| **A07** Authentication Failures | Força bruta, sessão que não expira, token eterno | CWE-307, CWE-613, CWE-308 | Bloqueio após 5 erros; segundo fator para administrador; sessão de 1 hora; JWT de 15 minutos; senha conforme NIST 800-63B | **Achados 3 e 4** |
| **A08** Software or Data Integrity Failures | Desserializar dado não confiável, atualização sem verificação | CWE-502, CWE-345 | JSON lido com recusa de chave repetida, tamanho máximo, validação completa do domínio e conferência de ida e volta; base de CVE só por HTTPS, conferida antes de substituir | Controlado |
| **A09** Security Logging and Alerting Failures | Ataque que ninguém vê | CWE-778, CWE-117 | Auditoria de entradas, recusas, alterações e emissão de token, sem senha; logs com rotação | **Achado 5**: ninguém é avisado |
| **A10** Mishandling of Exceptional Conditions | Erro que vira 500, revela pilha ou deixa estado pela metade | CWE-703, CWE-209, CWE-460 | Exceções da API viram Problem Details sem pilha; transações desfazem tudo em erro; páginas 403/404/500 próprias; o Schemathesis procura 500 | Controlado (os 500 achados pelo Schemathesis foram corrigidos) |

## Achados e prioridade

Cada achado tem nota CVSS 3.1 e foi pensado para ser cadastrado no próprio
SENTINEL (como vulnerabilidade do ativo "SENTINEL", tipo Sistema interno), o
que deixa o modelo de risco ordenar as correções junto com o resto do
inventário.

| # | Achado | Categoria, CWE | Vetor CVSS 3.1 | Nota | Correção | Prioridade |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Servidor da disciplina em HTTP: senha e cookie trafegam sem cifra na rede interna | A04, CWE-319 | `AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N` | 6,3 | Proxy com TLS (já pronto em `compose.web.yaml`, [TLS.md](TLS.md)); depende de o docente liberar a porta 443 ou um certificado interno | 1 |
| 2 | API sem limite de taxa fora do login: um token válido pode varrer o inventário rápido | A06, CWE-770 | `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L` | 4,3 | Limite por token/IP no proxy (Caddy `rate_limit`) ou na aplicação | 3 |
| 3 | JWT não pode ser revogado antes de vencer (só desativando a conta) | A07, CWE-613 | `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` | 4,8 | Lista de revogação por `jti`, ou token de 5 minutos com renovação | 2 |
| 4 | Segundo fator desligado no perfil do servidor da disciplina (`DJANGO_REQUIRE_MFA=0`) | A07, CWE-308 | `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` | 6,8 | Ligar com `DJANGO_REQUIRE_MFA=1` e `manage.py provision_mfa` (o aplicativo autenticador precisa ser cadastrado antes) | 1 |
| 5 | Auditoria sem alerta: tentativas negadas e bloqueios só aparecem se alguém abrir a tela | A09, CWE-778 | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N` | 0,0 (sem impacto direto) | Enviar `denied` e bloqueios para um coletor (syslog) e alertar acima de um limite | 4 |
| 6 | Imagem base `python:3.14-slim` com pacotes do Debian que podem ganhar CVE depois da construção | A03, CWE-1104 | depende da CVE | — | Trivy no CI recusa CRÍTICA com correção; reconstruir a imagem periodicamente | contínua |

A ordem: 1 e 4 primeiro (protegem a senha do administrador, que dá acesso a
tudo), depois 3, 2 e 5.

Para cadastrar os achados pela API v1 (o ativo "SENTINEL" precisa existir):

```bash
TOKEN=...   # POST /api/v1/auth/token, veja docs/API.md
curl -s -X POST http://127.0.0.1:8000/api/v1/vulnerabilities \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"descricao":"Servidor da disciplina em HTTP, sem TLS","cwe":"CWE-319","origem":1,"cvss":6.3,"vetor":"CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"}'
```

e vincular com `POST /api/v1/findings` (`asset`, `vulnerability`,
`situacao`). Pelas telas: Vulnerabilidades → Nova; Ficha do ativo → Vincular.

## Dependências: pip-audit

```bash
pip-audit -r requirements-web.txt
```

Resultado em 17/11/2026: **No known vulnerabilities found** (Django 5.2.19,
psycopg 3.3.8, Gunicorn 23.0.0, django-axes 8.3.1, django-otp 1.7.5,
argon2-cffi 25.1.0, WhiteNoise 6.12.0, PyJWT 2.15.1, NumPy, cvss 3.6,
SQLAlchemy 2.1.9, Alembic 1.20.1). O mesmo comando roda no CI a cada envio:
uma dependência que ganhe CVE derruba a verificação.

## Análise estática: bandit

```bash
bandit -c .bandit.yaml -r .
```

Resultado: nenhum alerta aberto. O que havia e o que foi feito:

| Alerta | Onde | Decisão |
| --- | --- | --- |
| B605 alto: `os.system` | `entrada.py` (limpar tela), `surpresa.py`, `cores.py` | Comando fixo (`cls`/`clear`/vazio), sem nada do usuário: marcado `# nosec` com o motivo |
| B310 médio: `urlopen` | `atualizacao_cve.py` | **Corrigido**: `abrir_url()` passou a recusar qualquer esquema que não seja `https://` (antes só quem a chamava conferia) |
| B310 médio: `urlopen` | `ops/monitor.py`, `ops/smoke_browser.py` | URL fixa da configuração: marcado |
| B608 médio: SQL por texto | `academic/sqli_lab.py` | Vulnerável de propósito, só no laboratório: marcado |
| B311 baixo: `random` | ordenações e medições (`academic/`, `risco.py`) | Não é segredo (pivô, dados de medição): marcado |
| B105 baixo: "senha no código" | `"Bearer"`, rótulo `"Emissão de token da API"` | Falso positivo: marcado |
| B404/B603/B607 baixo: `subprocess` | `ops/smoke_browser.py` | Lista fixa, sem shell: marcado |
| B101: `assert` | autotestes e testes | Fora do caminho do usuário: desligado em `.bandit.yaml` |

## Tipos: mypy

`mypy` (configuração em `mypy.ini`) confere o domínio e a persistência:
`classificacoes`, `validacao`, `ficha_tecnica`, `equipamentos`,
`vulnerabilidades`, `inventario`, `risco`, `armazenamento`, `migracao` e
`repositorio_sql`. Resultado: **Success: no issues found in 10 source files**.
O que ele achou e foi corrigido está em [REFATORACAO.md](REFATORACAO.md).

## Varredura das imagens

O job `container` do CI roda o Trivy nas duas imagens
(`trab02_2026_2_12621cbs200:1.0` e `trab02_2026_2_12621cbs200_terminal:1.0`) e
falha com vulnerabilidade CRÍTICA que já tenha correção. Para ver todas,
inclusive as altas, no seu computador:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest \
  image --severity HIGH,CRITICAL trab02_2026_2_12621cbs200:1.0
```

O relatório "antes e depois" do S5_15 está em [HARDENING.md](HARDENING.md).
