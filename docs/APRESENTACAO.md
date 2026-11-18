# Apresentação final

Cards S5_19 e S5_21. Roteiro para 15 minutos (ajuste ao tempo que o docente
definir), dados de demonstração, plano alternativo e perguntas prováveis.

## Roteiro (15 min)

| Tempo | Parte | O que mostrar |
| --- | --- | --- |
| 0:00–1:30 | Problema | Inventário de TI de uma delegacia: o que está exposto e o que corrigir primeiro |
| 1:30–3:00 | Visão da solução | Diagrama de containers ([ARQUITETURA.md](ARQUITETURA.md)); um domínio, duas interfaces |
| 3:00–6:30 | Demonstração web | Roteiro abaixo, passos 1 a 6 |
| 6:30–8:30 | Modelo de risco | Análise de risco: invertibilidade, risco próprio × efetivo, cenário singular recusado; plano de correção |
| 8:30–10:30 | API e segurança | Swagger, token, 401/403/409/428 em Problem Details; OWASP: os achados e o que foi feito |
| 10:30–12:00 | Qualidade | CI verde (ruff, mypy, bandit, pytest, Schemathesis, Trivy); N+1 e SQLi nos testes |
| 12:00–13:00 | Implantação | Servidor: `verificar.sh` com as 24 horas; nomes `trab02_2026_2_12621cbs200`; terminal sem porta |
| 13:00–15:00 | Fechamento | O que aprendi, o que faria diferente, backlog; perguntas |

## Roteiro da demonstração

Dados: a base de exemplo (76 equipamentos fictícios da 1ª DRPC), carregada pela
preparação. Antes da apresentação, crie uma conta Leitor e uma Analista
(README, seção 6) para mostrar as permissões.

1. Entrar como **Leitor**: o menu não tem "Novo"; tentar
   `/registros/asset/novo/` pelo endereço → 403 (aparece na auditoria).
2. Entrar como **Analista**: **Visão geral** → clicar no indicador de críticas
   → lista filtrada.
3. **Ficha do DRPC-SRV01**: vulnerabilidades, de onde herda risco, quem alcança.
4. Vincular uma CVE do **Catálogo KEV** a um ativo; voltar à **Análise de
   risco** e mostrar o risco efetivo subindo também em quem depende dele.
5. **Mapa**: foco no servidor, simulação de correção.
6. **Plano de correção**: a primeira correção e quanto reduz.
7. `/api/v1/docs/` → **Authorize** com o token → `GET /assets?ordering=-risco`
   → `PATCH` sem `If-Match` (428) e com versão antiga (409).
8. No terminal do servidor: `ssh -t 12621CBS200@10.0.99.150 docker attach
   trab02_2026_2_12621cbs200_terminal` → opção 14 (risco), Ctrl+P Ctrl+Q.

## Plano alternativo

- **Gravação**: grave os passos 1 a 8 antes (OBS Studio ou a gravação de tela
  do Windows, `Win+Alt+R`), 1080p, sem som do sistema. **[preencher: link do
  vídeo]**
- **Sem rede da UFU**: rodar a versão local (`ABRIR-SENTINEL.cmd`) com a mesma
  base.
- **Sem projetor bom**: tema de alto contraste (botão de tema no cabeçalho).

## Perguntas prováveis

| # | Pergunta | Resposta curta |
| --- | --- | --- |
| 1 | Por que verificar a invertibilidade antes de resolver? | Se I − A for singular ou mal condicionada, o "risco" calculado não significa nada; o sistema recusa e diz por quê (posto, Rouché-Capelli, número de condição) |
| 2 | Por que a soma das frações tem de ficar abaixo de 1? | Garante a dominância diagonal estrita de I − A, que a torna invertível e a série x = b + Ab + A²b... convergente |
| 3 | Por que JWT de 15 minutos e não sessão? | A API é para scripts, sem cookie (sem CSRF); vida curta limita o estrago de um token roubado, que não se revoga |
| 4 | O JWT é seguro se qualquer um lê a carga? | Ele é assinado, não cifrado: ninguém altera sem a chave, mas todos leem; por isso só id e papel vão nele |
| 5 | Por que Argon2id e não SHA-256? | SHA-256 faz milhões por segundo; Argon2id ~9, e gasta 100 MiB por tentativa: força bruta inviável |
| 6 | Como vocês impedem SQL injection? | Só ORM e parâmetros ligados; o laboratório mostra a falha na concatenação e os testes provam que a aplicação trata as cargas como texto |
| 7 | O servidor está em HTTP: isso não é falha? | É, registrada (CVSS 6,3) e aceita por limitação do ambiente; o proxy TLS está pronto e testado (`compose.tls.yaml`) |
| 8 | O que acontece se dois analistas editarem o mesmo ativo? | O segundo recebe 409 (versão antiga) e recarrega; nada é sobrescrito sem aviso |
| 9 | Como provam as 24 horas? | `verificar.sh`: hora de início, reinícios zerados e o log do monitor com a primeira e a última verificação |
| 10 | Por que dois ORMs? | Django na web (o framework já traz); SQLAlchemy no terminal, que não é Django, para trocar o JSON por banco sem mudar o serviço |

## Ensaio

| Data | Para quem | Tempo | Comentários recebidos | Ajuste |
| --- | --- | --- | --- | --- |
| **[preencher]** | | | | |

## Revisão dos slides

- Contraste mínimo 4,5:1 (texto escuro em fundo claro ou o inverso).
- Fonte de pelo menos 24 pt no corpo e 32 pt nos títulos.
- Uma ideia por slide; no máximo 6 linhas; números grandes em vez de tabelas.
- Diagramas no lugar de texto (os do [ARQUITETURA.md](ARQUITETURA.md)).
- Código só o essencial, com destaque na linha que importa.
