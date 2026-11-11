# Matriz das sprints e limites de evidência

Base: cartões e referências do [quadro Sprints 1 a 4](https://trello.com/b/mA9IHmx0/sprints-1-a-4-e-trabalhos-1-e-2), consultados no planejamento. O estado de um cartão no quadro não comprova implementação. Os PDFs de enunciado anexados não foram lidos nesta etapa; confirmar requisitos finais nesses documentos antes da entrega.

Sprints 1 e 2 (39 cartões): fundamentos de Python, CRUD, enums, validações, persistência, requisitos, especificação e Git já são representados pelo projeto original e seus testes. Não se atribui atendimento individual a cada exercício teórico pela existência do programa. A extensão web preserva as regras e acrescenta documentação e testes.

## Sprint 3

| Cartões | Evidência / situação |
|---|---|
| 01 — OO | Classes originais e Factory reaproveitadas pelo adaptador PostgreSQL |
| 02 — funções/recursão | Merge Sort recursivo didático; não substitui todos os exercícios do cartão |
| 03 — filas/listas | BFS com deque; lista ligada própria ainda precisa de artefato específico se exigida |
| 04 — complexidade | Documentação dos algoritmos; relatório completo de medições pendente |
| 05 — busca/ordenação | Pesquisa no banco, ranking e algoritmos didáticos |
| 06 — qualidade | Ruff e organização em camadas; revisão humana recomendada |
| 07 — testes | Suíte original + pytest PostgreSQL |
| 08 — Git/CI | Workflow preparado localmente; execução no GitHub depende de aprovação para envio |
| 09 a 12 — álgebra linear | ModeloRisco original, NumPy, diagnóstico, resíduo e teste de equivalência |
| 13 — lógica | Entregável teórico pendente de conferência com aluno/professor |
| 14 — portas/hardware | Entregável teórico, não demonstrado pela aplicação |
| 15 — UX/Figma/WCAG | Interface responsiva implementada; Figma e relatório heurístico/manual pendentes |
| 16 — frontend | Templates, CSS Grid, variáveis CSS, JavaScript modular simples |
| 17 — Fetch | Grafo carrega JSON via Fetch e async/await, com falha tratada |
| 18 — REST | CRUD de quatro recursos e testes; coleção Postman inicial com exemplos em `SENTINEL.postman_collection.json` |
| 19 — backend/relacional | Django e PostgreSQL; substituição dos exemplos Flask/FastAPI, explicar escolha |
| 20 — segurança/rede/LGPD | Controles e modelo de ameaças; relatório acadêmico de estatística/sustentabilidade pendente |

## Sprint 4 (todos os 20 cartões)

| Cartão | Evidência / situação |
|---|---|
| 01 — camadas | `views`, `services`, `repository`, domínio original e esquema relacional |
| 02 — SOLID | Interface Repository e implementações memória/PostgreSQL; teste de reconstrução |
| 03 — padrões | Factory e Repository concretos; Strategy alterna ranking por risco próprio/efetivo |
| 04 — JSON | Importação/exportação e CLI legado preservados; banco ativo conforme orientação verbal |
| 05 — HTTP | Django/Gunicorn, `/health/`, teste cliente, API; 24h ainda sem evidência |
| 06 — JOINs | FKs, M:N Finding, autorrelação Dependency, ORM parametrizado |
| 07 — agregações | Relatório com COUNT/AVG/MAX/GROUP BY; exemplos HAVING/CASE em `consultas.sql` |
| 08 — hash/índices | Hash encadeado testado, índices PostgreSQL; comparação 10/1000/100000 em `MEDICOES.md`; EXPLAIN em `consultas.sql` |
| 09 — BST | Inserção, percurso em ordem, altura, entradas ordenadas/aleatórias; percursos pré/pós-ordem incluídos |
| 10 — BFS/DFS | Alcançabilidade e detecção de ciclo testadas; sem alegar descoberta de ataque |
| 11 — Merge Sort | Implementação estável e teste de estabilidade/equivalência; medições em `MEDICOES.md` |
| 12 — Quick Sort | Lomuto aleatório iterativo e testes; comparação em `MEDICOES.md` |
| 13 — desempenho | Complexidades documentadas; timeit/cProfile e solve 10/100/1000 em `MEDICOES.md` (não mede pipeline completo) |
| 14 — pytest/cobertura | Fixtures, approx, tmp_path, testes de concorrência; CI preparado |
| 15 — Docker básico | Dockerfile e Compose preparados; execução Docker ainda não verificada localmente |
| 16 — imagem | Slim, usuário sem root, read-only, healthcheck, .dockerignore; build pendente |
| 17 — Compose | App, PostgreSQL, proxy, volumes, dependências e migração separada; smoke Compose pendente |
| 18 — logs | stdout, rotação, eventos de auditoria; monitoramento real pendente |
| 19 — Linux | Instruções SSH/firewall/segredos/backup; implantação real pendente |
| 20 — integração/24h | Importação e risco reconciliados; apresentação, implantação e medição 24h pendentes |

## Critério de entrega

Esta matriz evita transformar exercícios acadêmicos em funções desnecessárias da interface. Código pronto, teste passando, documento produzido e evidência operacional são estados diferentes. Revisar os itens pendentes com o enunciado e professor antes de marcar qualquer sprint como concluída.
