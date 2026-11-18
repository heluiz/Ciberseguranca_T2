# Dívida técnica registrada

Cards S5_01 (dívida que sobrou da refatoração) e S5_02 (achados de
segurança). Cada item vira uma issue no GitHub; os comandos estão no fim.

| # | Dívida | Onde | Por que importa | Proposta | Rótulos |
| --- | --- | --- | --- | --- | --- |
| D1 | Classe `Aplicacao` grande (1.340 linhas, 57 métodos) | `main.py` | Difícil de ler e de testar por partes | Extrair uma classe por grupo de opções (equipamentos, vulnerabilidades, risco, CVE), mantendo o menu | `refatoracao` |
| D2 | Métodos longos | `Aplicacao.atualizar_equipamento`, `inventory/views.py: collection` | Muitas responsabilidades num lugar | Extrair função por campo / por tipo de recurso | `refatoracao` |
| D3 | Telas sem anotação de tipo | `main.py`, `telas.py`, `arvore.py`, `atualizacao_cve.py`, `base_cve.py` (48 apontamentos com `--check-untyped-defs`) | O mypy não confere essa parte | Anotar e tirar de `ignore_errors` no `mypy.ini` | `tipos` |
| D4 | Servidor da disciplina em HTTP | `compose.servidor.yaml` | Senha e cookie sem cifra na rede interna (OWASP A04, CVSS 6,3) | Proxy TLS (`compose.tls.yaml`) quando o docente liberar porta ou certificado | `seguranca` |
| D5 | Segundo fator desligado no servidor | `.env` (`DJANGO_REQUIRE_MFA=0`) | Senha do administrador sozinha dá acesso total (A07, CVSS 6,8) | `DJANGO_REQUIRE_MFA=1` + `provision_mfa` | `seguranca` |
| D6 | JWT sem revogação | `inventory/api_v1.py` | Token roubado vale até 15 minutos (A07, CVSS 4,8) | Lista de `jti` revogados ou token mais curto com renovação | `seguranca`, `api` |
| D7 | Sem limite de taxa na API fora do login | proxy / `api_v1.py` | Varredura rápida do inventário com um token (A06, CVSS 4,3) | Limite por token/IP | `seguranca`, `api` |
| D8 | Auditoria sem alerta | `AuditEvent` | Recusas e bloqueios só aparecem se alguém olhar (A09) | Enviar a um coletor e alertar acima de um limite | `seguranca` |
| D9 | Implantação manual | servidor da disciplina | O servidor fica na rede interna; o CI não alcança | Runner do GitHub dentro da rede, se o docente permitir | `ci` |
| D10 | Duas APIs | `/api/<tipo>/` (sessão) e `/api/v1/` | Duas implementações para manter | Telas passarem a usar a v1 e a antiga ser removida numa v2.0 | `api` |
| D11 | Links OpenAPI entre operações | `docs/web/openapi.yaml` | O Schemathesis avisa que não encadeia POST → GET/PUT/DELETE pelo id criado | Declarar `links` nas respostas 201 | `api`, `testes` |

## Abrir as issues

Com o [GitHub CLI](https://cli.github.com/) (`gh auth login` uma vez), na
pasta do projeto:

```powershell
gh label create refatoracao --color 1d76db
gh label create tipos --color 5319e7
gh label create seguranca --color b60205
gh label create api --color 0e8a16
gh label create ci --color fbca04
gh label create testes --color c2e0c6
gh issue create --title "D1: dividir a classe Aplicacao (main.py)" --label refatoracao --body "Extrair uma classe por grupo de opções do menu, mantendo os números das opções. Ver docs/DIVIDA-TECNICA.md."
gh issue create --title "D2: encurtar métodos longos" --label refatoracao --body "Aplicacao.atualizar_equipamento e inventory/views.py: collection. Ver docs/DIVIDA-TECNICA.md."
gh issue create --title "D3: anotar tipos das telas do terminal" --label tipos --body "main, telas, arvore, atualizacao_cve, base_cve; tirar de ignore_errors no mypy.ini."
gh issue create --title "D4: HTTPS no servidor da disciplina" --label seguranca --body "OWASP A04, CWE-319, CVSS 6,3. compose.tls.yaml pronto; depende de porta/certificado."
gh issue create --title "D5: ligar o segundo fator no servidor" --label seguranca --body "OWASP A07, CWE-308, CVSS 6,8. DJANGO_REQUIRE_MFA=1 + manage.py provision_mfa."
gh issue create --title "D6: revogação de JWT" --label seguranca --label api --body "OWASP A07, CWE-613, CVSS 4,8."
gh issue create --title "D7: limite de taxa na API" --label seguranca --label api --body "OWASP A06, CWE-770, CVSS 4,3."
gh issue create --title "D8: alerta de eventos de segurança" --label seguranca --body "OWASP A09, CWE-778."
gh issue create --title "D9: implantação automática no servidor" --label ci --body "Servidor na rede interna; avaliar runner próprio."
gh issue create --title "D10: unificar as APIs na v1" --label api --body "Telas usarem /api/v1 e remover /api/<tipo>/ numa v2.0."
gh issue create --title "D11: links OpenAPI entre operações" --label api --label testes --body "Declarar links nas respostas 201 para o Schemathesis encadear."
```

Ou pelo site: **Issues** → **New issue**, um por linha da tabela.
