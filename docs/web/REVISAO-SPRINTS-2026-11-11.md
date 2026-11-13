# Revisão do SENTINEL — projeto, GitHub e Sprints 1 a 4

**Data:** 11/11/2026. **Versão analisada:** branch local `work/sentinel-web`, commit `73c4a6e`. **Base original:** `c17e2481c9996c166c319ace4ebf68ef43f37619`.

## Parecer

A evolução web tem uma base funcional consistente: preserva o domínio original, utiliza PostgreSQL, acrescenta autenticação, permissões, histórico de tratamentos e mapa de dependências. Entretanto, **ainda não está pronta para ser declarada integralmente aderente às sprints nem para publicação sem correções**. Há dois defeitos reproduzidos, lacunas de equivalência com a CLI e entregáveis acadêmicos/operacionais sem evidência.

A principal correção é de autorização: uma conta que pode visualizar ativos, mas não vulnerabilidades, consegue exportar as vulnerabilidades vinculadas. A segunda é a listagem REST incompleta, limitada aos primeiros 100 registros sem mecanismo de continuação.

Esta revisão produziu documentos e verificações locais. **Não corrigiu o código de aplicação, não fez push, não abriu PR e não implantou a versão web.** As falhas listadas continuam abertas no commit analisado.

## Escopo e qualidade da evidência

Fontes de requisitos: [repositório original](https://github.com/heluiz/Ciberseguranca_T2), [quadro de sprints](https://trello.com/b/mA9IHmx0/sprints-1-a-4-e-trabalhos-1-e-2), descrições dos 79 cartões de sprint e dois cartões de trabalhos. Foram considerados objetivos, exercícios recomendados, entregável e referências. Um exercício recomendado não foi tratado automaticamente como exigência de uma tela de produção.

Foram comparados os 34 itens da raiz do GitHub com a árvore Git da base local, incluindo hashes das subárvores: nenhuma diferença. O README remoto também corresponde ao da base. O diff da evolução web preserva os arquivos Python originais de domínio; acrescenta Django, persistência relacional, interface, algoritmos didáticos, testes e documentação.

Foram revistos os componentes de domínio, persistência, serviços, views/API, autenticação, formulários, auditoria, grafo, temas, algoritmos, testes e configuração de execução. A revisão combina inspeção estática, comparação de versões e execução local; não é uma certificação formal nem um teste de invasão completo.

**Limite documental importante:** os PDFs dos enunciados não ficaram acessíveis. A leitura autenticada dos cartões trouxe as descrições, mas não os anexos; o acesso direto aos dados retornou 401 e o navegador exigiu login. Não foi possível verificar cláusulas, rubricas e eventuais diferenças dos PDFs. Pesos transcritos no README (20% classes, 20% JSON, 45% container/24h e 15% álgebra) são tratados como transcrição, não como conferência do enunciado original.

**Limite dos vídeos e livros:** todas as URLs encontradas nas descrições foram inventariadas e tiveram tentativa de acesso. Isso não equivale a assistir aos vídeos ou ler livros integrais. Muitos links do YouTube retornaram falha ou somente metadados, sem transcrição. Livros sem texto acessível foram analisados como indicação bibliográfica; capítulos não fornecidos permanecem pendentes. A transcrição do vídeo introdutório de acessibilidade do W3C foi consultada; isso não valida os demais vídeos. O catálogo no final discrimina o alcance da consulta.

## Verificações executadas nesta revisão

| Verificação | Resultado | O que comprova |
|---|---|---|
| Suíte original `python testes.py` | 115 testes passaram | Regressão dos cenários originais cobertos |
| Suíte `pytest tests_web` com PostgreSQL real | 57 testes passaram | Cenários web, persistência, tratamentos e algoritmos cobertos |
| Cobertura `inventory` + `academic` | 84%; 946 instruções medidas, 150 não cobertas | Cobertura dos módulos selecionados; não é 84% de todo o repositório |
| Ruff | Todos os checks passaram | Regras estáticas configuradas |
| Conta com apenas `inventory.view_asset` | API de vulnerabilidades 403; exportação 200 com vulnerabilidades | Defeito R01 reproduzido |
| API de dependências | 164 no banco; 100 retornadas; resposta apenas `results` e `limit` | Defeito R02 reproduzido |
| Árvore original remota × base local | 34 itens, nenhuma diferença | Base usada na comparação corresponde ao conteúdo remoto consultado |

Ambiente: Python 3.12.14 e PostgreSQL 17.11. Os testes de autorização usaram conta temporária em transação revertida. Não foram utilizados dados reais de investigação. Os resultados de navegador, backup/restauração, `check --deploy` e auditoria de dependências anteriormente registrados em `docs/web/VALIDACAO.md` são evidências de etapas anteriores; não foram todos reexecutados nesta rodada. Docker não está disponível neste ambiente, logo não houve build ou execução do Compose web nesta revisão.

## Achados por prioridade

### R01 — Alta: exportação contorna a permissão de vulnerabilidades

**Arquivo:** `inventory/views.py`, função `export`, aproximadamente linha 402. **Sprints:** S3_20, S3_18 e S4_14.

O endpoint exige somente `view_asset`, mas exporta `snapshot().para_dict()`, incluindo vulnerabilidades, tratamentos e dependências. Uma conta autenticada com apenas essa permissão recebe 403 em `/api/vulnerability/`, mas recebe 200 e dados de vulnerabilidades em `/dados/exportar/`. O teste reproduziu exatamente essa combinação.

O impacto depende da política de acesso: os três grupos padrão recebem leitura ampla, mas permissões específicas podem ser atribuídas/removidas no Django. Nessa configuração restrita, a API bloqueia e a exportação permite os mesmos dados. Não foi demonstrada exploração anônima nem acesso por outro inventário.

**Correção proposta:** definir a política da exportação completa e exigir todas as permissões dos recursos exportados, ou gerar uma exportação filtrada e explicitamente documentada. Revisar também o dashboard, que exige apenas `view_asset` e apresenta detalhes/indicadores derivados de vulnerabilidades. Acrescentar testes com permissões individuais e combinações parciais. Critério: nenhum caminho alternativo revela um recurso negado pela política.

A [orientação de autorização da OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) recomenda verificar permissões em todas as requisições e testar a matriz de acesso. O framework não elimina a necessidade de aplicar essa política em cada saída de dados.

### R02 — Média: listagem REST não permite recuperar todos os registros

**Arquivo:** `inventory/views.py`, função `rest`, aproximadamente linha 439. **Sprints:** S3_18 e S3_19.

O GET aplica `[:100]` e não oferece página, offset ou cursor. Com 164 dependências, somente 100 são retornadas. Isso pode produzir integrações e inventários incompletos. O limite é informado, mas não há continuação. A API específica do mapa é diferente e entrega as conexões completas; esse achado não significa que o grafo perdeu 64 arestas.

**Correção proposta:** paginação determinística com tamanho máximo, total e indicador de próxima página; testar pelo menos 101 registros, ordenação estável, página vazia e limites inválidos. Manter limitação por página em vez de retirar todo limite.

### R03 — Média: abstração de repositório não atende integralmente ao DIP da Sprint 4

**Arquivos:** `inventory/repository.py` e `inventory/services.py`, especialmente chamadas a `PostgresRepository().load()`. **Sprints:** S4_01, S4_02 e S4_03.

Existem `InventoryRepository`, `MemoryRepository` e `PostgresRepository`. Porém a interface define apenas carga e a camada de serviço instancia o adaptador concreto e escreve diretamente nos modelos Django. Não é possível executar os mesmos casos de uso com memória e PostgreSQL apenas trocando a implementação recebida.

Isso é uma diferença concreta em relação ao exercício do cartão: alternar repositórios sem modificar o serviço. O domínio matemático continua independente e foi preservado; a falha de aderência está na abstração dos casos de uso/persistência, não em todo o desenho da aplicação.

**Correção proposta:** contrato para as operações necessárias e fronteira transacional, composição dos adaptadores fora do serviço e testes do mesmo caso de uso com duas implementações. Preservar as transações e a proteção concorrente do PostgreSQL. A [camada de serviços de Architecture Patterns with Python](https://www.cosmicpython.com/book/chapter_04_service_layer.html), referência da sprint, exemplifica receber a abstração do repositório explicitamente.

### R04 — Média: interface web ainda não cobre todas as operações do original

**Arquivos:** `main.py`, `telas.py`, `inventory/views.py`, templates e `graph.js`. **Sprints:** S2_09, S2_14, S3_16 e S3_18.

| Função original | Situação na web | Ajuste proposto |
|---|---|---|
| Busca por ID, custodiante, tipo e ficha técnica | Listagem pesquisa hostname, lotação, patrimônio e descrição; filtros originais não estão todos presentes | Acrescentar campos/filtros combináveis e testar ausência/case-insensitive |
| Pendências por situação e severidade | Tratamentos mostram dados, mas não há equivalente completo dos filtros/ordenação da CLI | Filtros por situação, gravidade, ativo e datas |
| Diagnóstico matricial M, v, Mv, F, b, A, posto/núcleo | Modelo preservado, mas sem tela didática completa equivalente à opção 15 | Página de análise para cenários pequenos, com interpretação e limites de tamanho |
| Consulta/atualização KEV, explicação e registro de CVE | Busca local disponível; atualização e fluxo completo continuam na CLI | Completar o fluxo autorizado na web, preservando origem confiável e validações |
| Risco de todos os ativos e plano de correção | Grafo contém todos; painel resume seis no ranking e oito correções; API do grafo tem plano completo | Disponibilizar tabela completa filtrável/exportável, sem depender apenas do resumo visual |

Essas diferenças não exigem reescrever a aplicação. São incrementos sobre funções já existentes. A CLI e a web não compartilham a mesma persistência em tempo real: editar o JSON não atualiza automaticamente o PostgreSQL.

### R05 — Média acadêmica: coleção Postman contém exemplos, não testes completos

**Arquivo:** `docs/web/SENTINEL.postman_collection.json`. **Sprint:** S3_18.

A coleção tem 16 requisições, mas não tem scripts `event`/`pm.test`. IDs e versões são exemplos. Não demonstra um ciclo automatizado que cadastre, valide resposta, consulte, altere e exclua os próprios registros. Os testes pytest são úteis, porém não substituem o entregável específico Postman.

**Correção proposta:** ambiente com URL, sessão/CSRF de teste, encadeamento dos IDs retornados, asserts de códigos/campos e cenários negativos 403/404/409; execução registrada. A API implementa PATCH e recusa PUT; isso pode ser uma decisão válida, mas precisa ser explicado frente ao exercício que cita PUT.

### R06 — Média acadêmica: algoritmos existem, mas parte da aplicação e dos relatórios falta

**Arquivos:** `academic/algorithms.py`, `academic/benchmark.py`, `tests_web/test_algorithms.py`, `docs/web/MEDICOES.md`.

- S3_03: deque no BFS não é a lista encadeada própria com diagrama exigida.
- S3_05: Merge/Quick Sort não substituem a lista de algoritmos básicos desse cartão.
- S4_08: benchmark compara hash próprio e dict, sem lista; há consulta EXPLAIN, mas não planos antes/depois documentados.
- S4_09: BST oferece inserção, em ordem, pré/pós-ordem e altura; faltam busca, percurso por nível e relatório de alturas.
- S4_10: BFS/DFS são testados em grafo sintético; faltam análise sobre os ativos reais de exemplo, alcance e saltos. Dependência modelada não comprova caminho explorável de ataque.
- S4_11: Merge Sort implementado e estável, mas o ranking usa `sorted`. Demonstrar o algoritmo sobre o relatório real em um módulo didático é suficiente para aproximar a entrega, sem obrigar a produção a abandonar a função nativa.
- S4_13: perfilamento atual é do Merge Sort; tempos de `solve` usam matriz diagonal densa isolada. Não medem montagem do inventário, diagnóstico e plano de correção do trabalho completo.

**Correção proposta:** completar módulos/relatórios didáticos com entradas reprodutíveis e vínculo explícito aos cartões. Não adicionar telas sem utilidade apenas para comprovar um exercício.

### R07 — Média acadêmica: documentação distribuída não substitui todos os entregáveis

Existem documentos úteis em `docs/web` e um README extenso, mas não foram localizados `docs/requisitos.md`, `docs/criterios_aceitacao.md` e `docs/especificacao.md` nos formatos pedidos por S2_04/06/07. Também não foram localizados o Figma e relatório WCAG 2.1/heurístico de S3_15, nem as listas de lógica/circuitos de S3_13/14.

**Correção proposta:** reutilizar o conteúdo existente, preencher lacunas e criar rastreabilidade cartão → requisito → implementação → teste → evidência. Não considerar entrega externa inexistente apenas por não estar no repositório; pedir/vincular os artefatos que o aluno já tenha produzido em outro local.

### R08 — Alta para declarar entrega operacional: nova versão sem evidência Docker/24h

**Sprints:** S4_05 e S4_15 a S4_20.

O README original registra 46 horas e 1 minuto de funcionamento após reinício, além de monitoramento. Essa documentação pertence ao container original e deve ser preservada como evidência histórica. Não foi verificada novamente por acesso ao servidor nesta rodada.

A versão Django/PostgreSQL possui novos Dockerfile e Compose. Ainda exige build, execução, reinício, recriação com preservação de dados, backup/restauração do conjunto implantado, HTTPS externo e registro de disponibilidade por 24 horas. YAML válido e testes Django não provam essas etapas. O workflow web também não foi executado no GitHub, pois a branch permanece local.

**Correção proposta:** validar primeiro em ambiente de teste, depois implantar a versão aprovada e recolher evidências com commit/imagem, horários e resultados. Não substituir as provas da versão antiga nem apresentar testes não executados como aprovados.

### R09 — Limites relevantes para uso futuro

Não são necessariamente defeitos do escopo acadêmico, mas devem orientar os próximos requisitos:

- Inventário compartilhado com grupos de acesso; não há isolamento entre organizações/tenants.
- Trava transacional global conserva coerência, mas serializa operações de leitura composta/escrita. Testes de concorrência de integridade não demonstram capacidade para muitos usuários.
- Cálculo matricial completo precisa de medição representativa antes de crescer muito; não há SLA medido.
- Exportação JSON compatível não inclui usuários, datas, histórico e todo o catálogo sem vínculos. Backup completo requer PostgreSQL; o JSON não é backup integral.
- Histórico registra alterações e autoria disponível, mas não é imutável contra o proprietário do banco. Datas históricas informadas e instante automático do evento são informações diferentes.
- Risco efetivo é pontuação do modelo, não porcentagem de chance de ataque; pode ultrapassar 100. As frações das dependências não são probabilidade de exploração.

## Confronto com as referências das sprints

| Conjunto | O que sustenta | Aplicação à revisão |
|---|---|---|
| Python/OO, documentação Python, material CS50P e bibliografia de Python | Classes, funções, validação e persistência | Há implementação substancial; exercícios individuais e material completo devem ter sua própria evidência |
| Percival/Gregory e Fowler | Separação de responsabilidades e persistência | Confirma a necessidade de serviço depender de contrato, em vez de instanciar o adaptador concreto |
| Goodrich, Cormen e materiais MIT | Estruturas, buscas, árvores e ordenação | Comparação com entregáveis revela falta de lista encadeada, busca/percurso da BST e aplicação ao inventário |
| Lay, Strang e bibliografia de análise numérica | Formulação linear e interpretação | O modelo original tem material relevante; faltam algumas listas e ensaios completos, não todo o conteúdo de álgebra |
| W3C/WCAG e bibliografia de usabilidade | Operabilidade, semântica, contraste e avaliação | Responsividade/neon não demonstram WCAG; é preciso auditar teclado, foco, contraste em todos os temas e alternativa ao mapa |
| Documentação Docker/Compose e materiais Linux | Construção, execução e persistência operacional | Arquivos preparados precisam ser executados; provas antigas não se transferem à web |
| Referências REST, SQL e testes | Contratos HTTP, modelo relacional e verificação | Paginação, Postman, MER/DDL e consultas precisam de evidência mais completa |

O vídeo do W3C, cuja transcrição foi acessível, aborda uso por teclado, leitores de tela, contraste, descrições textuais e princípios de acessibilidade. Isso reforça a avaliação funcional além da aparência. [Fonte](https://www.w3.org/WAI/videos/standards-and-benefits/).

Foram observadas referências que precisam de saneamento: alguns links levam a resultados de busca ou playlists, não a uma aula fixa; links Python `/3/` podem mudar de versão; há variações de capítulos atribuídos ao mesmo livro de estruturas entre cartões. Recomenda-se registrar edição, capítulo, título da aula e link direto, sem corrigir automaticamente a bibliografia do professor sem conferir a edição. Falha ao buscar um vídeo não comprova que ele foi removido.

**Django e PostgreSQL permanecem coerentes com a evolução escolhida.** A presença de Flask/FastAPI nas leituras não demonstra, por si só, obrigação de trocar o framework. A arquitetura pode ser ensinada usando Django. A alteração de JSON para PostgreSQL foi autorizada no relato do aluno sobre o professor; documentar essa orientação junto à especificação e confrontá-la com os PDFs quando disponíveis. Não há motivo identificado nesta revisão para retornar ao SQLite.

## Ordem recomendada para concluir

1. Corrigir R01 e revisar a matriz de permissões em todas as saídas, incluindo exportações, painel e histórico. Executar testes negativos por recurso.
2. Corrigir R02 e completar os filtros/fluxos web que faltam em relação ao original. Validar inventário maior que uma página.
3. Refatorar o contrato de persistência para S4_02, preservando integridade/concorrência e demonstrando dois adaptadores com os mesmos casos de uso.
4. Completar Postman e os módulos/relatórios acadêmicos faltantes. Priorizar o campo Entregável de cada cartão e manter exercícios adicionais identificados.
5. Consolidar requisitos, aceitação, especificação, MER e relatório de acessibilidade; incorporar enunciados PDF antes de fechar aderência formal.
6. Construir/executar Compose em teste, verificar restauração e reinícios, medir carga representativa e então preparar a apresentação.
7. Após aprovação da versão, publicar a branch/PR e executar CI; implantar a versão aprovada e coletar as 24h da web. Nenhuma dessas ações remotas foi feita nesta revisão.

## Como ler a matriz

“Evidência funcional” significa implementação encontrada e, quando indicado, testes executados; não certifica que a entrega foi enviada ao professor. “Parcial” identifica conteúdo existente com lacunas. “Não localizado” refere-se ao material acessível, e não afirma que o aluno nunca produziu o exercício. “Evidência histórica” não equivale a prova operacional da nova versão. Não foi calculada uma porcentagem global de conclusão, pois os cartões têm pesos e naturezas diferentes e os PDFs estão pendentes.


## Matriz dos 79 cartões


### Sprint 1 — 20 cartões

| Cartão | Situação | Evidência / pendência |
|---|---|---|
| [S1_01 — Engenharia de Requisitos: Compreensão do Problema](https://trello.com/c/1zcBsxvn) | Parcial | README descreve o problema e o contexto; falta vincular o resumo técnico ao enunciado original, cujo PDF não foi acessado. |
| [S1_02 — Requisitos Funcionais](https://trello.com/c/on4Qdxz4) | Parcial | Requisitos do Trabalho 1 estão transcritos no README. Confirmar com o PDF e identificar os três casos de uso pedidos nos exercícios. |
| [S1_03 — Critérios de Aceitação](https://trello.com/c/LmxixL5s) | Parcial | Testes cobrem cadastros e falhas, mas não substituem critérios de aceitação explicitamente revisados. |
| [S1_04 — Python: Alô Mundo](https://trello.com/c/sQFAeUhn) | Não localizado | O projeto executa Python, mas não foi localizado o exercício isolado Hello World. Não é necessário acrescentá-lo à interface de produção. |
| [S1_05 — Python: Variáveis e Tipos de Dados](https://trello.com/c/8zAUt3cB) | Evidência funcional | CLI recebe e exibe informações de equipamentos; classes e testes demonstram tipos e variáveis. Confirmar se a entrega individual do exercício é exigida. |
| [S1_06 — Python: Entrada e Saída de Dados](https://trello.com/c/Wjlx4A2l) | Evidência funcional | CLI cadastra hostname, custodiante e lotação, com apresentação formatada e validações. |
| [S1_07 — Estruturas Condicionais](https://trello.com/c/pLbCEkpT) | Evidência funcional | Classificação de severidade e validações implementadas no domínio e exercitadas na suíte original. |
| [S1_08 — Estruturas de Repetição](https://trello.com/c/ciwg4Mci) | Evidência funcional | Menu original permanece em laço até a saída escolhida pelo usuário. |
| [S1_09 — Funções](https://trello.com/c/e2XSw8eO) | Evidência funcional | Funções/métodos apresentam detalhes dos equipamentos; rastrear a equivalência do exercício com a ficha existente. |
| [S1_10 — Listas](https://trello.com/c/pYToJgWn) | Parcial | CRUD funcional existe; armazenamento principal em memória usa dicionário. Não foi identificado um artefato separado que demonstre especificamente a lista pedida. |
| [S1_11 — Tuplas e Sets](https://trello.com/c/jMyc59Y0) | Não localizado | Uso eventual de tuplas/sets não comprova o entregável de união/interseção de conjuntos com execução comentada. |
| [S1_12 — Dicionários](https://trello.com/c/jVq82tHp) | Evidência funcional | Inventario mantém registros e vulnerabilidades em dicionários, com atualização e testes. |
| [S1_13 — Enumerações](https://trello.com/c/QJFuT0iv) | Parcial | Há enums de tipos, gravidade e tratamento; status operacional do ativo (Ativo/Inativo/Manutenção) é conceito diferente e não foi localizado como entregável. |
| [S1_14 — Persistência em Arquivos](https://trello.com/c/kQxWePhz) | Evidência funcional | Persistência JSON original e arquivos de exemplo permanecem; web mantém importação/exportação e usa PostgreSQL como fonte de verdade. |
| [S1_15 — Tratamento de Erros](https://trello.com/c/LDJkS1uw) | Evidência funcional | Persistência e domínio tratam erros de arquivo e entradas inválidas; testes originais passaram. |
| [S1_16 — Git Fundamentos](https://trello.com/c/afoNTOK7) | Evidência histórica | GitHub original tem histórico e repositório verificáveis; a branch web permanece local por escolha do usuário. |
| [S1_17 — Git Versionamento e Colaboração](https://trello.com/c/dMyX24v5) | Evidência histórica | Histórico original contém merges de funcionalidades, inclusive PR #10. Não confundir com integração da branch web, ainda não feita. |
| [S1_18 — Git Branches, Merge e Fluxo de Trabalho](https://trello.com/c/EfEx7HQZ) | Evidência histórica | Git log confirma múltiplos merges; documentação de colaboração no README. Exercício de conflito exige evidência própria se cobrado. |
| [S1_19 — GitHub, Pull Requests e Code Review](https://trello.com/c/LHfSbffy) | Parcial | Merges de PRs constam do histórico, mas não foi auditada a aprovação por outro integrante nem seus comentários. |
| [S1_20 — Revisão Geral da Sprint 1](https://trello.com/c/bTZ39k6T) | Sem entregável obrigatório | O cartão pede conferência das entregas anteriores; não atribuir conclusão automática aos itens sem evidência. |

### Sprint 2 — 19 cartões

| Cartão | Situação | Evidência / pendência |
|---|---|---|
| [S2_01 — Boas Práticas de Código](https://trello.com/c/rKrJG9xH) | Parcial | README registra decisões e correções; Ruff passou. Relacionar uma refatoração concreta ao commit e ao antes/depois solicitado. |
| [S2_02 — Classes, Funções e Chamadas](https://trello.com/c/vKYv0CK9) | Evidência funcional | equipamentos.py, vulnerabilidades.py, inventario.py e testes.py demonstram modelos, instanciação, consulta e alteração. |
| [S2_03 — O que é CRUD?](https://trello.com/c/DGPpypYI) | Evidência funcional | Inventario oferece CRUD em memória; README descreve operações e fluxo de uso da CLI. |
| [S2_04 — Requisitos do CRUD](https://trello.com/c/4ZaOtzCX) | Parcial | Há requisitos no README, mas docs/requisitos.md não existe; consolidar histórias e requisitos verificáveis da versão web. |
| [S2_05 — Regras e Validações](https://trello.com/c/pzSd3Tgh) | Parcial | Validações e testes são extensos; consolidar matriz campo × regra × mensagem para domínio, formulários e banco. |
| [S2_06 — Critérios de Aceitação CRUD](https://trello.com/c/CXtlyUcL) | Não localizado | docs/criterios_aceitacao.md não foi localizado; testes existentes não demonstram a revisão dos cenários exigida. |
| [S2_07 — Especificação Completa do seu sistema](https://trello.com/c/O256bnJG) | Não localizado | docs/especificacao.md versão 1.0 revisada não foi localizado; há documentação distribuída no README e docs/web. |
| [S2_08 — Cadastro de Ativos](https://trello.com/c/tzCLQiV6) | Evidência funcional | Cadastro, validação e duplicidade cobertos no legado e no serviço web, com execução das suítes nesta revisão. |
| [S2_09 — Busca de Ativos](https://trello.com/c/dYM7yu8d) | Parcial | Busca original tem mais opções; busca web não cobre custodiante, ID e filtros combináveis de tipo/setor. Ver achado R04. |
| [S2_10 — Atualização de Ativos](https://trello.com/c/2BvgaaAe) | Evidência funcional | Atualização validada e testes; web adiciona controle de versão e auditoria. Completar rastreio dos cenários do cartão. |
| [S2_11 — Exclusão de Ativos](https://trello.com/c/Qah5QO3C) | Evidência funcional | Exclusão, confirmação, testes e política estão documentados; web preserva catálogo órfão e histórico, diferença explícita do legado. |
| [S2_12 — Fundamentos de Vulnerabilidades](https://trello.com/c/rO9vZ9dN) | Parcial | Base de exemplo contém CVEs reais e prioridade calculada; falta separar dois estudos com justificativa, responsável e evidência de verificação. |
| [S2_13 — Cadastro de Vulnerabilidades](https://trello.com/c/673p1eZo) | Evidência funcional | Cadastro e validações CVE/CVSS/vetor existem com testes e exemplos. Catalogar dois exemplos como evidência acadêmica. |
| [S2_14 — Consulta de Vulnerabilidades](https://trello.com/c/tk1xKlt2) | Parcial | Busca por CVE/CWE e base KEV local existem; filtros combinados e conferência externa datada precisam ser demonstrados. |
| [S2_15 — Dicionários (Hashmaps)](https://trello.com/c/1Jw8OSvH) | Evidência funcional | Repositório em memória original baseado em dicionários e suíte original cobrem operações e inexistência. |
| [S2_16 — Branches](https://trello.com/c/xOzm2lWg) | Parcial | Branches e merges originais comprovados; não foi localizada evidência específica da resolução do conflito solicitado. |
| [S2_17 — Colaboração GitHub](https://trello.com/c/jDKkGSmu) | Parcial | PRs integrados aparecem no histórico original; retrospectiva e revisão de outro integrante precisam de identificação. |
| [S2_18 — Testes e Correções](https://trello.com/c/2nQvqnsz) | Evidência funcional | 115 testes originais e 57 novos passaram. README contém tabela de defeitos/correções; esta revisão acrescenta falhas ainda abertas. |
| [S2_19 — Entrega Trabalho 1](https://trello.com/c/SfrMkG1e) | Parcial | README, repositório e roteiro existem; tag/avaliação do Trabalho 1 e demonstração devem ser vinculadas à entrega correspondente, não à web inédita. |

### Sprint 3 — 20 cartões

| Cartão | Situação | Evidência / pendência |
|---|---|---|
| [S3_01 — Orientação a Objetos: Herança, Polimorfismo e Abstração](https://trello.com/c/kzEZH12P) | Evidência funcional | Hierarquia, fábrica, polimorfismo e recarga JSON preservados; adaptador relacional reconstrói as classes originais. |
| [S3_02 — Paradigmas de Programação: Funções de Alta Ordem e Recursão](https://trello.com/c/Nuzxljri) | Parcial | Há funções de chave e Merge Sort recursivo; não há conjunto completo de fatorial/Fibonacci/memoização com comparação prevista no cartão. |
| [S3_03 — Estruturas Lineares: Filas e Listas Encadeadas](https://trello.com/c/zd07Gn0q) | Não localizado | BFS usa deque, mas faltam lista encadeada própria, operações, diagrama e comparação solicitados no entregável. |
| [S3_04 — Análise de Algoritmos e Complexidade](https://trello.com/c/5GaQkoxS) | Parcial | Complexidades em academic e MEDICOES.md; falta relatório com classes assintóticas, busca linear/binária e justificativas completas. |
| [S3_05 — Busca e Ordenação](https://trello.com/c/B5spIbL8) | Não localizado | Merge/Quick Sort não substituem Bubble/Selection/Insertion Sort e busca binária com relatório comparativo pedidos aqui. |
| [S3_06 — Qualidade de Software e Código Limpo](https://trello.com/c/kDO7tu56) | Parcial | Ruff passou e há histórico de mudanças; faltam relatório antes/depois e evidências das ferramentas citadas ou justificativa de substituição por Ruff. |
| [S3_07 — Estratégias de Teste e Testes Unitários](https://trello.com/c/MEYpgGCj) | Evidência funcional | unittest legado e pytest web executados; cobertura agregada 84% nos módulos web/didáticos medidos, sem incluir todo o legado. |
| [S3_08 — GitHub, Pull Requests e Integração Contínua](https://trello.com/c/CGSdcRqH) | Parcial | Workflow web preparado localmente. Não há execução remota desta branch nem PR web; histórico original não comprova o novo workflow. |
| [S3_09 — Álgebra Linear I: Matrizes e Transformações Lineares](https://trello.com/c/RuwZtteK) | Parcial | README/modelo original explicam M, F, núcleo/posto e cenário pequeno; completar a lista de transformações e explicitar a imagem com os cálculos pedidos. |
| [S3_10 — Álgebra Linear II: Sistemas Lineares](https://trello.com/c/V9yc6b9U) | Parcial | Cenário de três equipamentos resolvido no README e validado por NumPy; lista geral de escalonamento/classificações não está consolidada por cartão. |
| [S3_11 — Álgebra Linear III: Determinantes e Invertibilidade](https://trello.com/c/AJxQkwCL) | Parcial | Singularidade, condição de soma menor que 1 e cenário singular estão no legado; faltam exercícios completos de determinantes/inversas com etapas. |
| [S3_12 — Erros Numéricos e Representação Computacional](https://trello.com/c/xdOXKSLn) | Parcial | Diagnóstico de condição, posto, tolerâncias e resíduos são robustos; falta relatório completo de arredondamento, truncamento e comparação solve/inv. |
| [S3_13 — Lógica Proposicional e Argumentação](https://trello.com/c/AbGo3V52) | Não localizado | Lista de tabelas-verdade, equivalências e argumentos não localizada; condicionais do software não substituem esse entregável. |
| [S3_14 — Portas Lógicas e Arquitetura de Computadores](https://trello.com/c/oeWbSmbX) | Não localizado | Relatório de portas, circuitos e arquitetura de Von Neumann não localizado. |
| [S3_15 — Usabilidade, Prototipação e Acessibilidade](https://trello.com/c/6nqldsas) | Parcial | Interface responsiva, controles de movimento e capturas existem; faltam Figma e relatório heurístico/WCAG 2.1. Não há certificação de acessibilidade. |
| [S3_16 — Front-End Moderno](https://trello.com/c/40c5rl8Z) | Evidência funcional | Templates, CSS Grid/variáveis e grafo alimentado por objetos JS atendem ao núcleo do protótipo responsivo; capturas anteriores documentam desktop e celular. |
| [S3_17 — JavaScript Assíncrono e Consumo de APIs](https://trello.com/c/fXY7pye0) | Evidência funcional | graph.js consome JSON via Fetch/async-await e trata falhas. API própria atende ao entregável, embora o exercício adicional cite API pública. |
| [S3_18 — APIs REST e Testes de Integração](https://trello.com/c/c2pBweYs) | Parcial | API CRUD existe; coleção Postman tem 16 requisições sem scripts pm.test. PATCH é usado em lugar de PUT citado nos exercícios; documentar decisão. Há truncamento na listagem. |
| [S3_19 — Backend e Persistência de Dados](https://trello.com/c/tCJlfNsj) | Parcial | PostgreSQL, migrações e API funcionais; formalizar MER e SQL de criação revisável, além dos exemplos de consultas disponíveis. |
| [S3_20 — Redes, Segurança, LGPD e Sustentabilidade](https://trello.com/c/15fQna65) | Parcial | Controles e documento de segurança existem; autorização tem falha confirmada. Relatório de comunicação, estatística, LGPD e sustentabilidade não está completo. |

### Sprint 4 — 20 cartões

| Cartão | Situação | Evidência / pendência |
|---|---|---|
| [S4_01 — Arquitetura de Software e Separação de Camadas](https://trello.com/c/WOChXnXI) | Parcial | Pacotes web e domínio original separados; arquitetura descrita. Consolidar diagrama por classes e reduzir mistura da persistência nos serviços. |
| [S4_02 — SOLID: Princípios de Projeto Orientado a Objetos](https://trello.com/c/7A33X7Qh) | Parcial | Protocol e dois leitores existem, porém serviços instanciam PostgresRepository e escrevem via ORM; não são substituíveis sem alterar serviço. Falta relatório SOLID. |
| [S4_03 — Padrões de Projeto: Introdução ao Design Patterns](https://trello.com/c/GH3VoX8Y) | Parcial | Factory e Strategy concretos; Repository só abstrai carga. Isolar escrita e justificar padrões; Singleton não precisa ser introduzido. |
| [S4_04 — Persistência de Dados em JSON e Modelagem Orientada a Objetos](https://trello.com/c/gYNqKsic) | Evidência funcional / adaptação | JSON legado com recarga preservado; importação web validada. Registrar a orientação de usar PostgreSQL e manter compatibilidade, sem voltar JSON a banco principal. |
| [S4_05 — Arquitetura Cliente-Servidor e Sistemas Multicamadas](https://trello.com/c/UJQOScPL) | Parcial | Django/Gunicorn e health endpoint implementados; testes HTTP locais. Falta evidência operacional contínua da web e cliente externo/diagrama final. |
| [S4_06 — SQL Relacional: JOINs e Consultas Integradas](https://trello.com/c/9nVqSCbV) | Parcial | Modelos, FKs, migrações, ORM e consultas JOIN presentes. Entregar DDL, LEFT JOIN para não vinculadas e demonstração Python parametrizada conforme cartão. |
| [S4_07 — SQL: Agregações e Relatórios com GROUP BY](https://trello.com/c/xpU9GwDa) | Parcial | Página de relatório e consultas CASE/GROUP BY/HAVING existem; completar comparação soma CVSS × risco com fator F e evidência de execução das consultas do cartão. |
| [S4_08 — Tabelas Hash e Otimização de Consultas](https://trello.com/c/hs4dAfCU) | Parcial | Hash encadeado e índices testados; benchmark compara hash próprio/dict, mas não lista. SQL contém EXPLAIN sem planos antes/depois registrados. |
| [S4_09 — Estruturas Hierárquicas: Árvores Binárias](https://trello.com/c/ImhHRLNV) | Parcial | BST tem inserção, três percursos e altura/testes; faltam busca, percurso em largura e relatório de alturas aplicado a vulnerabilidades. |
| [S4_10 — Busca em Grafos: BFS e DFS](https://trello.com/c/oG9AMNbM) | Parcial | BFS/DFS/ciclos testados em grafo sintético. Falta aplicação explícita ao inventário, relatório de alcançabilidade e número de saltos. |
| [S4_11 — Algoritmos de Ordenação Avançados: Merge Sort](https://trello.com/c/yUWvybBB) | Parcial | Merge Sort estável testado com chave; ranking de produção usa sorted. Demonstrar Merge Sort sobre o ranking real em módulo acadêmico. |
| [S4_12 — Algoritmos de Ordenação Avançados: Quick Sort](https://trello.com/c/fPjER5uu) | Evidência funcional | Quick Sort Lomuto aleatório, testes e tabela comparativa com Merge/sorted existem. Ensaios adicionais ordenados/pivô fixo ficam como complemento dos exercícios. |
| [S4_13 — Complexidade Computacional de Estruturas e Algoritmos](https://trello.com/c/Hf5a29uW) | Parcial | MEDICOES.md mede hash, sorts e solve isolado de matriz diagonal; cProfile é do Merge Sort. Falta perfil e medição do pipeline real de risco. |
| [S4_14 — Testes Automatizados com Pytest](https://trello.com/c/l8R3aeYV) | Parcial | pytest com PostgreSQL, tmp_path, approx e cobertura passou; workflow existe, mas execução remota web ainda não ocorreu. |
| [S4_15 — Docker: Conceitos Fundamentais e Containers](https://trello.com/c/G17FPuTq) | Evidência antiga / web pendente | README registra Docker do legado; Docker indisponível nesta revisão. Falta roteiro executado e evidência da versão web. |
| [S4_16 — Dockerfiles, Imagens e Execução de Aplicações Python](https://trello.com/c/Ndd7Iogd) | Evidência antiga / web pendente | Dockerfile.web preparado com usuário sem root e healthcheck; imagem web ainda sem build/execução verificados. |
| [S4_17 — Docker Compose e Aplicações Multicontainer](https://trello.com/c/GiF9vOcZ) | Evidência antiga / web pendente | Compose web inclui banco, proxy, volumes e política de reinício. Faltam testes reais de reinício, recriação e persistência da nova composição. |
| [S4_18 — Monitoramento e Logs de Aplicações](https://trello.com/c/l2w2sRst) | Parcial | Logs/auditoria e rotação configurados; monitoramento anterior pertence ao legado. Falta registro periódico de disponibilidade HTTP web. |
| [S4_19 — Implantação de Aplicações em Ambiente Linux](https://trello.com/c/ri3PQ6WX) | Evidência antiga / web pendente | README documenta implantação Linux/reinício do legado. A web não foi implantada nem verificada no servidor. |
| [S4_20 — Integração do Trabalho 2: Aplicação OO Executando em Container](https://trello.com/c/NVHOekCv) | Evidência antiga / web pendente | Código/testes/docs locais existem; 46h01 documentadas no legado não comprovam web. Faltam container web, 24h, apresentação atualizada e conferência PDF. |

## Cartões dos trabalhos e PDFs

- [Atividades Trabalho 01](https://trello.com/c/L2eUeB6V): descrição acessada; anexos PDF não disponibilizados. Conferência formal pendente.
- [Atividades Trabalho 02](https://trello.com/c/gWnKIPu3): descrição acessada; anexos PDF não disponibilizados. Conferência formal pendente.

Para fechar essa parte, são necessários os PDFs dos Trabalhos 1 e 2 e eventuais anexos adicionais das sprints, ou acesso autenticado que permita obter seus arquivos. Não é necessário enviar senha. Vídeos sem texto acessível exigem transcrição/legendas ou outra fonte verificável do conteúdo.


## Catálogo de referências com rastreabilidade

Inventário das descrições: **178 URLs distintas**, sendo **87 do YouTube** e **91 de outros endereços**. URLs duplicadas entre cartões aparecem uma vez nesta tabela. Anexos não expostos pelo acesso aos cartões não estão incluídos nessa contagem.

“Resposta textual/parcial” pode ser apenas título, navegação ou metadados. **Não significa conteúdo integral analisado.** Para YouTube, nenhuma transcrição integral foi recuperada nesta revisão. As referências efetivamente utilizadas nas conclusões são identificadas no corpo do relatório.

| Referência | Cartões | Alcance da consulta |
|---|---|---|
| [1. https://12factor.net/logs](https://12factor.net/logs) | S4_18 | Resposta textual/parcial; leitura integral não atestada |
| [2. https://attack.mitre.org/tactics/TA0008/](https://attack.mitre.org/tactics/TA0008/) | S4_10 | Resposta textual/parcial; leitura integral não atestada |
| [3. https://black.readthedocs.io/](https://black.readthedocs.io/) | S3_06 | Resposta textual/parcial; leitura integral não atestada |
| [4. https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | S4_18 | Resposta textual/parcial; leitura integral não atestada |
| [5. https://cs50.harvard.edu/cybersecurity/weeks/0/](https://cs50.harvard.edu/cybersecurity/weeks/0/) | S3_20 | Resposta textual/parcial; leitura integral não atestada |
| [6. https://cs50.harvard.edu/python/weeks/5/](https://cs50.harvard.edu/python/weeks/5/) | S4_14 | Resposta textual/parcial; leitura integral não atestada |
| [7. https://cs50.harvard.edu/python/weeks/6/](https://cs50.harvard.edu/python/weeks/6/) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [8. https://cs50.harvard.edu/python/weeks/8/](https://cs50.harvard.edu/python/weeks/8/) | S3_01 | Resposta textual/parcial; leitura integral não atestada |
| [9. https://cs50.harvard.edu/sql/weeks/0/](https://cs50.harvard.edu/sql/weeks/0/) | S4_07 | Resposta textual/parcial; leitura integral não atestada |
| [10. https://cs50.harvard.edu/sql/weeks/1/](https://cs50.harvard.edu/sql/weeks/1/) | S4_06, S4_07 | Resposta textual/parcial; leitura integral não atestada |
| [11. https://cs50.harvard.edu/sql/weeks/2/](https://cs50.harvard.edu/sql/weeks/2/) | S3_19 | Resposta textual/parcial; leitura integral não atestada |
| [12. https://cs50.harvard.edu/sql/weeks/3/](https://cs50.harvard.edu/sql/weeks/3/) | S3_19 | Resposta textual/parcial; leitura integral não atestada |
| [13. https://cs50.harvard.edu/sql/weeks/5/](https://cs50.harvard.edu/sql/weeks/5/) | S4_08 | Resposta textual/parcial; leitura integral não atestada |
| [14. https://csrc.nist.gov/publications](https://csrc.nist.gov/publications) | S2_12, S2_13, S2_14 | Resposta textual/parcial; leitura integral não atestada |
| [15. https://docs.docker.com/build/building/best-practices/](https://docs.docker.com/build/building/best-practices/) | S4_16 | Resposta textual/parcial; leitura integral não atestada |
| [16. https://docs.docker.com/compose/](https://docs.docker.com/compose/) | S4_17 | Resposta textual/parcial; leitura integral não atestada |
| [17. https://docs.docker.com/engine/install/linux-postinstall/](https://docs.docker.com/engine/install/linux-postinstall/) | S4_19 | Resposta textual/parcial; leitura integral não atestada |
| [18. https://docs.docker.com/engine/install/ubuntu/](https://docs.docker.com/engine/install/ubuntu/) | S4_19 | Resposta textual/parcial; leitura integral não atestada |
| [19. https://docs.docker.com/get-started/](https://docs.docker.com/get-started/) | S4_15 | Resposta textual/parcial; leitura integral não atestada |
| [20. https://docs.docker.com/guides/docker-concepts/building-images/writing-a-dockerfile/](https://docs.docker.com/guides/docker-concepts/building-images/writing-a-dockerfile/) | S4_16 | Resposta textual/parcial; leitura integral não atestada |
| [21. https://docs.docker.com/guides/docker-concepts/the-basics/what-is-a-container/](https://docs.docker.com/guides/docker-concepts/the-basics/what-is-a-container/) | S4_15 | Resposta textual/parcial; leitura integral não atestada |
| [22. https://docs.docker.com/guides/docker-concepts/the-basics/what-is-an-image/](https://docs.docker.com/guides/docker-concepts/the-basics/what-is-an-image/) | S4_15 | Resposta textual/parcial; leitura integral não atestada |
| [23. https://docs.docker.com/reference/compose-file/](https://docs.docker.com/reference/compose-file/) | S4_17 | Resposta textual/parcial; leitura integral não atestada |
| [24. https://docs.docker.com/reference/dockerfile/](https://docs.docker.com/reference/dockerfile/) | S4_16 | Resposta textual/parcial; leitura integral não atestada |
| [25. https://docs.github.com/en/actions](https://docs.github.com/en/actions) | S4_14 | Resposta textual/parcial; leitura integral não atestada |
| [26. https://docs.pytest.org/](https://docs.pytest.org/) | S4_14 | Resposta textual/parcial; leitura integral não atestada |
| [27. https://docs.python.org/3/howto/functional.html](https://docs.python.org/3/howto/functional.html) | S3_02 | Resposta textual/parcial; leitura integral não atestada |
| [28. https://docs.python.org/3/howto/logging.html](https://docs.python.org/3/howto/logging.html) | S4_18 | Resposta textual/parcial; leitura integral não atestada |
| [29. https://docs.python.org/3/howto/sorting.html](https://docs.python.org/3/howto/sorting.html) | S4_11 | Resposta textual/parcial; leitura integral não atestada |
| [30. https://docs.python.org/3/library/abc.html](https://docs.python.org/3/library/abc.html) | S4_02 | Resposta textual/parcial; leitura integral não atestada |
| [31. https://docs.python.org/3/library/collections.html#collections.deque](https://docs.python.org/3/library/collections.html#collections.deque) | S3_03 | Resposta textual/parcial; leitura integral não atestada |
| [32. https://docs.python.org/3/library/dataclasses.html](https://docs.python.org/3/library/dataclasses.html) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [33. https://docs.python.org/3/library/json.html](https://docs.python.org/3/library/json.html) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [34. https://docs.python.org/3/library/logging.html](https://docs.python.org/3/library/logging.html) | S4_18 | Resposta textual/parcial; leitura integral não atestada |
| [35. https://docs.python.org/3/library/os.html#os.replace](https://docs.python.org/3/library/os.html#os.replace) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [36. https://docs.python.org/3/library/profile.html](https://docs.python.org/3/library/profile.html) | S4_13 | Resposta textual/parcial; leitura integral não atestada |
| [37. https://docs.python.org/3/library/sqlite3.html](https://docs.python.org/3/library/sqlite3.html) | S4_06 | Resposta textual/parcial; leitura integral não atestada |
| [38. https://docs.python.org/3/library/timeit.html](https://docs.python.org/3/library/timeit.html) | S4_12, S4_13 | Resposta textual/parcial; leitura integral não atestada |
| [39. https://docs.python.org/3/reference/datamodel.html#object.__hash__](https://docs.python.org/3/reference/datamodel.html#object.__hash__) | S4_08 | Resposta textual/parcial; leitura integral não atestada |
| [40. https://docs.python.org/3/tutorial/controlflow.html](https://docs.python.org/3/tutorial/controlflow.html) | S3_02 | Resposta textual/parcial; leitura integral não atestada |
| [41. https://docs.python.org/pt-br/3/](https://docs.python.org/pt-br/3/) | S2_02, S2_15 | Resposta textual/parcial; leitura integral não atestada |
| [42. https://docs.python.org/pt-br/3/tutorial/classes.html](https://docs.python.org/pt-br/3/tutorial/classes.html) | S3_01 | Resposta textual/parcial; leitura integral não atestada |
| [43. https://docs.python.org/pt-br/3/tutorial/modules.html](https://docs.python.org/pt-br/3/tutorial/modules.html) | S4_01 | Resposta textual/parcial; leitura integral não atestada |
| [44. https://fastapi.tiangolo.com/tutorial/](https://fastapi.tiangolo.com/tutorial/) | S4_05 | Resposta textual/parcial; leitura integral não atestada |
| [45. https://flake8.pycqa.org/](https://flake8.pycqa.org/) | S3_06 | Resposta textual/parcial; leitura integral não atestada |
| [46. https://flask.palletsprojects.com/en/stable/quickstart/](https://flask.palletsprojects.com/en/stable/quickstart/) | S4_05 | Resposta textual/parcial; leitura integral não atestada |
| [47. https://git-scm.com/book/pt-br/v2](https://git-scm.com/book/pt-br/v2) | S2_17 | Resposta textual/parcial; leitura integral não atestada |
| [48. https://git-scm.com/doc](https://git-scm.com/doc) | S3_08 | Resposta textual/parcial; leitura integral não atestada |
| [49. https://git-scm.com/docs](https://git-scm.com/docs) | S2_17 | Resposta textual/parcial; leitura integral não atestada |
| [50. https://github.com/skills/hello-github-actions](https://github.com/skills/hello-github-actions) | S3_08 | Resposta textual/parcial; leitura integral não atestada |
| [51. https://github.com/skills/introduction-to-github](https://github.com/skills/introduction-to-github) | S3_08 | Resposta textual/parcial; leitura integral não atestada |
| [52. https://github.com/skills/review-pull-requests](https://github.com/skills/review-pull-requests) | S3_08 | Resposta textual/parcial; leitura integral não atestada |
| [53. https://hub.docker.com/_/python](https://hub.docker.com/_/python) | S4_16 | Resposta textual/parcial; leitura integral não atestada |
| [54. https://istqb.org](https://istqb.org) | S2_18 | Resposta textual/parcial; leitura integral não atestada |
| [55. https://json-schema.org/](https://json-schema.org/) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [56. https://link.springer.com/book/10.1007/978-1-4842-0076-6](https://link.springer.com/book/10.1007/978-1-4842-0076-6) | S2_17 | Resposta textual/parcial; leitura integral não atestada |
| [57. https://linuxcommand.org/tlcl.php](https://linuxcommand.org/tlcl.php) | S4_19 | Resposta textual/parcial; leitura integral não atestada |
| [58. https://martinfowler.com/bliki/PresentationDomainDataLayering.html](https://martinfowler.com/bliki/PresentationDomainDataLayering.html) | S4_01 | Resposta textual/parcial; leitura integral não atestada |
| [59. https://nandgame.com/](https://nandgame.com/) | S3_14 | Resposta textual/parcial; leitura integral não atestada |
| [60. https://nostarch.com/pythoncrashcourse2e](https://nostarch.com/pythoncrashcourse2e) | S2_02, S2_15 | Resposta textual/parcial; leitura integral não atestada |
| [61. https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-18-properties-of-determinants/](https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-18-properties-of-determinants/) | S3_11 | Resposta textual/parcial; leitura integral não atestada |
| [62. https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-2-elimination-with-matrices/](https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-2-elimination-with-matrices/) | S3_10 | Resposta textual/parcial; leitura integral não atestada |
| [63. https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-20-cramers-rule-inverse-matrix-and-volume/](https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-20-cramers-rule-inverse-matrix-and-volume/) | S3_11 | Resposta textual/parcial; leitura integral não atestada |
| [64. https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-fall-2011/resources/recitation-5-recursion-trees-binary-search-trees/](https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-fall-2011/resources/recitation-5-recursion-trees-binary-search-trees/) | S3_02 | Resposta textual/parcial; leitura integral não atestada |
| [65. https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/](https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/) | S4_08, S4_09, S4_10, S4_11, S4_13 | Resposta textual/parcial; leitura integral não atestada |
| [66. https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/) | S2_12, S2_13, S2_14 | Resposta textual/parcial; leitura integral não atestada |
| [67. https://peps.python.org/pep-0544/](https://peps.python.org/pep-0544/) | S4_02 | Resposta textual/parcial; leitura integral não atestada |
| [68. https://pylint.pycqa.org/](https://pylint.pycqa.org/) | S3_06 | Resposta textual/parcial; leitura integral não atestada |
| [69. https://pytest-cov.readthedocs.io/](https://pytest-cov.readthedocs.io/) | S4_14 | Resposta textual/parcial; leitura integral não atestada |
| [70. https://realpython.com/python-recursion/](https://realpython.com/python-recursion/) | S3_02 | Resposta textual/parcial; leitura integral não atestada |
| [71. https://realpython.com/solid-principles-python/](https://realpython.com/solid-principles-python/) | S4_02 | Resposta textual/parcial; leitura integral não atestada |
| [72. https://refactoring.guru/design-patterns](https://refactoring.guru/design-patterns) | S4_03 | Resposta textual/parcial; leitura integral não atestada |
| [73. https://refactoring.guru/pt-br/design-patterns](https://refactoring.guru/pt-br/design-patterns) | S3_01 | Resposta textual/parcial; leitura integral não atestada |
| [74. https://ubuntu.com/server/docs](https://ubuntu.com/server/docs) | S4_19 | Resposta textual/parcial; leitura integral não atestada |
| [75. https://visualgo.net/en](https://visualgo.net/en) | S3_04 | Falha de recuperação; conteúdo não conferido |
| [76. https://visualgo.net/en/bst](https://visualgo.net/en/bst) | S4_09 | Resposta textual/parcial; leitura integral não atestada |
| [77. https://visualgo.net/en/dfsbfs](https://visualgo.net/en/dfsbfs) | S4_10 | Resposta textual/parcial; leitura integral não atestada |
| [78. https://visualgo.net/en/hashtable](https://visualgo.net/en/hashtable) | S4_08 | Resposta textual/parcial; leitura integral não atestada |
| [79. https://visualgo.net/en/sorting](https://visualgo.net/en/sorting) | S3_05, S4_11, S4_12 | Resposta textual/parcial; leitura integral não atestada |
| [80. https://wiki.python.org/moin/TimeComplexity](https://wiki.python.org/moin/TimeComplexity) | S4_08, S4_13 | Resposta textual/parcial; leitura integral não atestada |
| [81. https://www.3blue1brown.com/lessons/inverse-matrices](https://www.3blue1brown.com/lessons/inverse-matrices) | S3_10 | Resposta textual/parcial; leitura integral não atestada |
| [82. https://www.3blue1brown.com/lessons/matrix-multiplication](https://www.3blue1brown.com/lessons/matrix-multiplication) | S3_09 | Resposta textual/parcial; leitura integral não atestada |
| [83. https://www.cosmicpython.com/book/preface.html](https://www.cosmicpython.com/book/preface.html) | S4_01 | Resposta textual/parcial; leitura integral não atestada |
| [84. https://www.makeareadme.com/](https://www.makeareadme.com/) | S4_20 | Resposta textual/parcial; leitura integral não atestada |
| [85. https://www.oreilly.com/library/view/fluent-python-2nd/9781492056348/](https://www.oreilly.com/library/view/fluent-python-2nd/9781492056348/) | S2_02, S2_15 | Resposta textual/parcial; leitura integral não atestada |
| [86. https://www.pearson.com](https://www.pearson.com) | S2_01, S2_03, S2_04, S2_05, S2_06, S2_07, S2_08, S2_09, S2_10, S2_11, S2_12, S2_13, S2_14, S2_16, S2_19 | Resposta textual/parcial; leitura integral não atestada |
| [87. https://www.rfc-editor.org/rfc/rfc8259](https://www.rfc-editor.org/rfc/rfc8259) | S4_04 | Resposta textual/parcial; leitura integral não atestada |
| [88. https://www.sqlite.org/eqp.html](https://www.sqlite.org/eqp.html) | S4_08 | Resposta textual/parcial; leitura integral não atestada |
| [89. https://www.sqlite.org/lang_aggfunc.html](https://www.sqlite.org/lang_aggfunc.html) | S4_07 | Resposta textual/parcial; leitura integral não atestada |
| [90. https://www.sqlite.org/lang_select.html](https://www.sqlite.org/lang_select.html) | S4_06, S4_07 | Resposta textual/parcial; leitura integral não atestada |
| [91. https://www.w3.org/WAI/videos/standards-and-benefits/](https://www.w3.org/WAI/videos/standards-and-benefits/) | S3_15 | Página e transcrição textual consultadas; vídeo não assistido |
| [92. https://www.youtube.com/playlist?list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e](https://www.youtube.com/playlist?list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e) | S1_08 | Somente resposta/metadados; sem transcrição conferida |
| [93. https://www.youtube.com/playlist?list=PLHz_AreHm4dm7ZULPAmadvNhH6vk9oNZA](https://www.youtube.com/playlist?list=PLHz_AreHm4dm7ZULPAmadvNhH6vk9oNZA) | S1_16 | Somente resposta/metadados; sem transcrição conferida |
| [94. https://www.youtube.com/playlist?list=PLJOFJ3Ok_idtb2YeifXlG1-TYoMBLoG6I](https://www.youtube.com/playlist?list=PLJOFJ3Ok_idtb2YeifXlG1-TYoMBLoG6I) | S3_15 | Somente resposta/metadados; sem transcrição conferida |
| [95. https://www.youtube.com/results?search_query=Abdul+Bari+Queue+Data+Structure](https://www.youtube.com/results?search_query=Abdul+Bari+Queue+Data+Structure) | S3_03 | Falha de recuperação; conteúdo não conferido |
| [96. https://www.youtube.com/results?search_query=CS+Dojo+Linked+Lists](https://www.youtube.com/results?search_query=CS+Dojo+Linked+Lists) | S3_03 | Falha de recuperação; conteúdo não conferido |
| [97. https://www.youtube.com/results?search_query=crit%C3%A9rios+de+aceita%C3%A7%C3%A3o+scrum](https://www.youtube.com/results?search_query=crit%C3%A9rios+de+aceita%C3%A7%C3%A3o+scrum) | S1_03 | Falha de recuperação; conteúdo não conferido |
| [98. https://www.youtube.com/results?search_query=python+hello+world+iniciantes](https://www.youtube.com/results?search_query=python+hello+world+iniciantes) | S1_04 | Falha de recuperação; conteúdo não conferido |
| [99. https://www.youtube.com/watch?v=0sdtkjISZIE&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=17](https://www.youtube.com/watch?v=0sdtkjISZIE&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=17) | S1_10 | Falha de recuperação; conteúdo não conferido |
| [100. https://www.youtube.com/watch?v=1ZFe-OqMB28&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=34](https://www.youtube.com/watch?v=1ZFe-OqMB28&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=34) | S1_14 | Falha de recuperação; conteúdo não conferido |
| [101. https://www.youtube.com/watch?v=2KL-z9A56SQ](https://www.youtube.com/watch?v=2KL-z9A56SQ) | S3_16 | Somente resposta/metadados; sem transcrição conferida |
| [102. https://www.youtube.com/watch?v=3GT1rMVBnAA&list=PLAgbpJQADBGL2CLP1sJB54VPjBewYhfRo](https://www.youtube.com/watch?v=3GT1rMVBnAA&list=PLAgbpJQADBGL2CLP1sJB54VPjBewYhfRo) | S4_03 | Falha de recuperação; conteúdo não conferido |
| [103. https://www.youtube.com/watch?v=4ixiRLTtsL8](https://www.youtube.com/watch?v=4ixiRLTtsL8) | S2_03, S2_08, S2_10, S2_11 | Falha de recuperação; conteúdo não conferido |
| [104. https://www.youtube.com/watch?v=5o8CwafCxnU](https://www.youtube.com/watch?v=5o8CwafCxnU) | S3_20 | Somente resposta/metadados; sem transcrição conferida |
| [105. https://www.youtube.com/watch?v=6tNS--WetLI](https://www.youtube.com/watch?v=6tNS--WetLI) | S2_18 | Somente resposta/metadados; sem transcrição conferida |
| [106. https://www.youtube.com/watch?v=7EmboKQH8lM](https://www.youtube.com/watch?v=7EmboKQH8lM) | S2_01 | Falha de recuperação; conteúdo não conferido |
| [107. https://www.youtube.com/watch?v=7Jo4OofFQTQ](https://www.youtube.com/watch?v=7Jo4OofFQTQ) | S2_07 | Falha de recuperação; conteúdo não conferido |
| [108. https://www.youtube.com/watch?v=8JJ101D3knE](https://www.youtube.com/watch?v=8JJ101D3knE) | S1_16 | Somente resposta/metadados; sem transcrição conferida |
| [109. https://www.youtube.com/watch?v=8aGhZQkoFbQ](https://www.youtube.com/watch?v=8aGhZQkoFbQ) | S3_17 | Somente resposta/metadados; sem transcrição conferida |
| [110. https://www.youtube.com/watch?v=9dlBZlkvvxY](https://www.youtube.com/watch?v=9dlBZlkvvxY) | S3_02 | Falha de recuperação; conteúdo não conferido |
| [111. https://www.youtube.com/watch?v=AYdF7b3nMto](https://www.youtube.com/watch?v=AYdF7b3nMto) | S3_20 | Somente resposta/metadados; sem transcrição conferida |
| [112. https://www.youtube.com/watch?v=BrNBuX40t1w](https://www.youtube.com/watch?v=BrNBuX40t1w) | S2_19 | Falha de recuperação; conteúdo não conferido |
| [113. https://www.youtube.com/watch?v=DKGZlaPlVLY](https://www.youtube.com/watch?v=DKGZlaPlVLY) | S3_14 | Falha de recuperação; conteúdo não conferido |
| [114. https://www.youtube.com/watch?v=DZwmZ8Usvnk](https://www.youtube.com/watch?v=DZwmZ8Usvnk) | S1_07 | Somente resposta/metadados; sem transcrição conferida |
| [115. https://www.youtube.com/watch?v=D_ha0g9yS2E](https://www.youtube.com/watch?v=D_ha0g9yS2E) | S4_17 | Falha de recuperação; conteúdo não conferido |
| [116. https://www.youtube.com/watch?v=DdoncfOdru8](https://www.youtube.com/watch?v=DdoncfOdru8) | S4_15 | Falha de recuperação; conteúdo não conferido |
| [117. https://www.youtube.com/watch?v=EXMr1u2bnjc&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=23](https://www.youtube.com/watch?v=EXMr1u2bnjc&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=23) | S1_12 | Falha de recuperação; conteúdo não conferido |
| [118. https://www.youtube.com/watch?v=Ez8cqoSRVsA](https://www.youtube.com/watch?v=Ez8cqoSRVsA) | S3_20 | Falha de recuperação; conteúdo não conferido |
| [119. https://www.youtube.com/watch?v=FMc7pZbvWKA](https://www.youtube.com/watch?v=FMc7pZbvWKA) | S3_13 | Somente resposta/metadados; sem transcrição conferida |
| [120. https://www.youtube.com/watch?v=FTFaQWZBqQ8](https://www.youtube.com/watch?v=FTFaQWZBqQ8) | S3_15 | Somente resposta/metadados; sem transcrição conferida |
| [121. https://www.youtube.com/watch?v=FZGugFqdr60](https://www.youtube.com/watch?v=FZGugFqdr60) | S3_14 | Falha de recuperação; conteúdo não conferido |
| [122. https://www.youtube.com/watch?v=FxCEHvk3SjI&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=37](https://www.youtube.com/watch?v=FxCEHvk3SjI&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=37) | S1_15 | Falha de recuperação; conteúdo não conferido |
| [123. https://www.youtube.com/watch?v=IADOV8UZO34](https://www.youtube.com/watch?v=IADOV8UZO34) | S3_20 | Falha de recuperação; conteúdo não conferido |
| [124. https://www.youtube.com/watch?v=Ip3X9LOh2dk](https://www.youtube.com/watch?v=Ip3X9LOh2dk) | S3_11 | Somente resposta/metadados; sem transcrição conferida |
| [125. https://www.youtube.com/watch?v=Jzr0Jdnq_EI](https://www.youtube.com/watch?v=Jzr0Jdnq_EI) | S2_12 | Falha de recuperação; conteúdo não conferido |
| [126. https://www.youtube.com/watch?v=K10u3XIf1-Q](https://www.youtube.com/watch?v=K10u3XIf1-Q) | S1_07 | Falha de recuperação; conteúdo não conferido |
| [127. https://www.youtube.com/watch?v=L5BlpPU_muY](https://www.youtube.com/watch?v=L5BlpPU_muY) | S4_05 | Falha de recuperação; conteúdo não conferido |
| [128. https://www.youtube.com/watch?v=M4u3x6iguR4](https://www.youtube.com/watch?v=M4u3x6iguR4) | S2_17 | Falha de recuperação; conteúdo não conferido |
| [129. https://www.youtube.com/watch?v=Mjpj0YK5MRI](https://www.youtube.com/watch?v=Mjpj0YK5MRI) | S1_01 | Falha de recuperação; conteúdo não conferido |
| [130. https://www.youtube.com/watch?v=N1hTsbW50eM&t=2s](https://www.youtube.com/watch?v=N1hTsbW50eM&t=2s) | S3_03 | Falha de recuperação; conteúdo não conferido |
| [131. https://www.youtube.com/watch?v=Ns3gMxgXpVo](https://www.youtube.com/watch?v=Ns3gMxgXpVo) | S1_05 | Falha de recuperação; conteúdo não conferido |
| [132. https://www.youtube.com/watch?v=PZRI1IfStY0](https://www.youtube.com/watch?v=PZRI1IfStY0) | S3_12 | Somente resposta/metadados; sem transcrição conferida |
| [133. https://www.youtube.com/watch?v=PkZNo7MFNFg](https://www.youtube.com/watch?v=PkZNo7MFNFg) | S3_16 | Somente resposta/metadados; sem transcrição conferida |
| [134. https://www.youtube.com/watch?v=PoRJizFvM7s](https://www.youtube.com/watch?v=PoRJizFvM7s) | S3_17 | Falha de recuperação; conteúdo não conferido |
| [135. https://www.youtube.com/watch?v=Q-BpqyOT3a8](https://www.youtube.com/watch?v=Q-BpqyOT3a8) | S3_18 | Somente resposta/metadados; sem transcrição conferida |
| [136. https://www.youtube.com/watch?v=R-HLU9Fl5ug](https://www.youtube.com/watch?v=R-HLU9Fl5ug) | S2_09 | Somente resposta/metadados; sem transcrição conferida |
| [137. https://www.youtube.com/watch?v=RGOj5yH7evk](https://www.youtube.com/watch?v=RGOj5yH7evk) | S1_16 | Somente resposta/metadados; sem transcrição conferida |
| [138. https://www.youtube.com/watch?v=SWYqp7iY_Tc](https://www.youtube.com/watch?v=SWYqp7iY_Tc) | S3_08 | Somente resposta/metadados; sem transcrição conferida |
| [139. https://www.youtube.com/watch?v=TBIPvjZLuoA](https://www.youtube.com/watch?v=TBIPvjZLuoA) | S3_04 | Falha de recuperação; conteúdo não conferido |
| [140. https://www.youtube.com/watch?v=Vw6gLypRKmY](https://www.youtube.com/watch?v=Vw6gLypRKmY) | S1_06 | Falha de recuperação; conteúdo não conferido |
| [141. https://www.youtube.com/watch?v=Y05YeBAFCrs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=16](https://www.youtube.com/watch?v=Y05YeBAFCrs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=16) | S1_10 | Falha de recuperação; conteúdo não conferido |
| [142. https://www.youtube.com/watch?v=YHFzr-akOas&list=PLS1QulWo1RIb9WVQGJ_vh-RQusbZgO_As](https://www.youtube.com/watch?v=YHFzr-akOas&list=PLS1QulWo1RIb9WVQGJ_vh-RQusbZgO_As) | S4_19 | Falha de recuperação; conteúdo não conferido |
| [143. https://www.youtube.com/watch?v=YLd6AWKVyas](https://www.youtube.com/watch?v=YLd6AWKVyas) | S2_04 | Falha de recuperação; conteúdo não conferido |
| [144. https://www.youtube.com/watch?v=Z1RJmh_OqeA](https://www.youtube.com/watch?v=Z1RJmh_OqeA) | S3_19 | Somente resposta/metadados; sem transcrição conferida |
| [145. https://www.youtube.com/watch?v=ZDa-Z5JzLYM](https://www.youtube.com/watch?v=ZDa-Z5JzLYM) | S2_02 | Somente resposta/metadados; sem transcrição conferida |
| [146. https://www.youtube.com/watch?v=_5Z_0824RHw](https://www.youtube.com/watch?v=_5Z_0824RHw) | S3_13 | Falha de recuperação; conteúdo não conferido |
| [147. https://www.youtube.com/watch?v=_CUNnRVjpKQ&list=PLAgbpJQADBGIicaxuo9hI5EmcK85ck5X2](https://www.youtube.com/watch?v=_CUNnRVjpKQ&list=PLAgbpJQADBGIicaxuo9hI5EmcK85ck5X2) | S3_07 | Falha de recuperação; conteúdo não conferido |
| [148. https://www.youtube.com/watch?v=_QfISzy0IKs](https://www.youtube.com/watch?v=_QfISzy0IKs) | S1_06 | Falha de recuperação; conteúdo não conferido |
| [149. https://www.youtube.com/watch?v=bEKmTJPSZgs](https://www.youtube.com/watch?v=bEKmTJPSZgs) | S2_14 | Falha de recuperação; conteúdo não conferido |
| [150. https://www.youtube.com/watch?v=cGn_LTFCif0](https://www.youtube.com/watch?v=cGn_LTFCif0) | S3_18 | Falha de recuperação; conteúdo não conferido |
| [151. https://www.youtube.com/watch?v=cuEtnrL9-H0](https://www.youtube.com/watch?v=cuEtnrL9-H0) | S3_17 | Falha de recuperação; conteúdo não conferido |
| [152. https://www.youtube.com/watch?v=daefaLgNkw0](https://www.youtube.com/watch?v=daefaLgNkw0) | S2_15 | Somente resposta/metadados; sem transcrição conferida |
| [153. https://www.youtube.com/watch?v=dtv5FpYj3zU&list=PLzZut2slkqywtFxqTY8AQwIG65h_2oMBLMIT](https://www.youtube.com/watch?v=dtv5FpYj3zU&list=PLzZut2slkqywtFxqTY8AQwIG65h_2oMBLMIT) | S3_05 | Falha de recuperação; conteúdo não conferido |
| [154. https://www.youtube.com/watch?v=dwFbYHZxBpQ](https://www.youtube.com/watch?v=dwFbYHZxBpQ) | S2_13 | Falha de recuperação; conteúdo não conferido |
| [155. https://www.youtube.com/watch?v=eB0nUzAI7M8](https://www.youtube.com/watch?v=eB0nUzAI7M8) | S3_08 | Falha de recuperação; conteúdo não conferido |
| [156. https://www.youtube.com/watch?v=etjJ_4Eqrk8](https://www.youtube.com/watch?v=etjJ_4Eqrk8) | S1_09 | Falha de recuperação; conteúdo não conferido |
| [157. https://www.youtube.com/watch?v=ezfr9d7wd_k](https://www.youtube.com/watch?v=ezfr9d7wd_k) | S1_09 | Falha de recuperação; conteúdo não conferido |
| [158. https://www.youtube.com/watch?v=f4ekifyijIg](https://www.youtube.com/watch?v=f4ekifyijIg) | S3_12 | Falha de recuperação; conteúdo não conferido |
| [159. https://www.youtube.com/watch?v=f6zXyq4VPP8](https://www.youtube.com/watch?v=f6zXyq4VPP8) | S4_01 | Falha de recuperação; conteúdo não conferido |
| [160. https://www.youtube.com/watch?v=fbj5Y19x0fs&list=PLucm8g_ezqNrrtduPx7s4BM8phepMn9I2&index=32](https://www.youtube.com/watch?v=fbj5Y19x0fs&list=PLucm8g_ezqNrrtduPx7s4BM8phepMn9I2&index=32) | S3_02 | Falha de recuperação; conteúdo não conferido |
| [161. https://www.youtube.com/watch?v=fhekxMRM4Ts&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=21](https://www.youtube.com/watch?v=fhekxMRM4Ts&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=21) | S1_11 | Falha de recuperação; conteúdo não conferido |
| [162. https://www.youtube.com/watch?v=gB5Gej0O400&list=PLMdYygf53DP5Sc6yFYs6ZmjsuuA2fu0TK&index=4](https://www.youtube.com/watch?v=gB5Gej0O400&list=PLMdYygf53DP5Sc6yFYs6ZmjsuuA2fu0TK&index=4) | S3_06 | Falha de recuperação; conteúdo não conferido |
| [163. https://www.youtube.com/watch?v=gI-qXk7XojA](https://www.youtube.com/watch?v=gI-qXk7XojA) | S3_14 | Somente resposta/metadados; sem transcrição conferida |
| [164. https://www.youtube.com/watch?v=iYM2zFP3Zn0](https://www.youtube.com/watch?v=iYM2zFP3Zn0) | S3_18 | Somente resposta/metadados; sem transcrição conferida |
| [165. https://www.youtube.com/watch?v=jm3jDYIOAxs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=38](https://www.youtube.com/watch?v=jm3jDYIOAxs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=38) | S3_01 | Falha de recuperação; conteúdo não conferido |
| [166. https://www.youtube.com/watch?v=kYB8IZa5AuE](https://www.youtube.com/watch?v=kYB8IZa5AuE) | S3_09 | Somente resposta/metadados; sem transcrição conferida |
| [167. https://www.youtube.com/watch?v=kZOJCVvyF-4](https://www.youtube.com/watch?v=kZOJCVvyF-4) | S3_16 | Falha de recuperação; conteúdo não conferido |
| [168. https://www.youtube.com/watch?v=kn83BA7cRNM](https://www.youtube.com/watch?v=kn83BA7cRNM) | S3_20 | Somente resposta/metadados; sem transcrição conferida |
| [169. https://www.youtube.com/watch?v=pTB30aXS77U](https://www.youtube.com/watch?v=pTB30aXS77U) | S4_02 | Falha de recuperação; conteúdo não conferido |
| [170. https://www.youtube.com/watch?v=rXOwvnWJc1M](https://www.youtube.com/watch?v=rXOwvnWJc1M) | S2_06 | Falha de recuperação; conteúdo não conferido |
| [171. https://www.youtube.com/watch?v=rg7Fvvl3taU](https://www.youtube.com/watch?v=rg7Fvvl3taU) | S3_16 | Somente resposta/metadados; sem transcrição conferida |
| [172. https://www.youtube.com/watch?v=ve82kSSj_Hs](https://www.youtube.com/watch?v=ve82kSSj_Hs) | S4_05 | Falha de recuperação; conteúdo não conferido |
| [173. https://www.youtube.com/watch?v=wsPZUZ5R92c&t=2284s](https://www.youtube.com/watch?v=wsPZUZ5R92c&t=2284s) | S3_04 | Falha de recuperação; conteúdo não conferido |
| [174. https://www.youtube.com/watch?v=xAOBQtSVI_k](https://www.youtube.com/watch?v=xAOBQtSVI_k) | S2_16 | Falha de recuperação; conteúdo não conferido |
| [175. https://www.youtube.com/watch?v=xGcvqT0-oaY](https://www.youtube.com/watch?v=xGcvqT0-oaY) | S1_13 | Falha de recuperação; conteúdo não conferido |
| [176. https://www.youtube.com/watch?v=xm_EJI3_o8A](https://www.youtube.com/watch?v=xm_EJI3_o8A) | S1_02 | Falha de recuperação; conteúdo não conferido |
| [177. https://www.youtube.com/watch?v=yXiagNFYpPk](https://www.youtube.com/watch?v=yXiagNFYpPk) | S3_20 | Falha de recuperação; conteúdo não conferido |
| [178. https://youtube.com/playlist?list=PLHz_AreHm4dn_RXXoa3Ameh77f95Hgwv3&si=d6IAu3Kx4vTapYaz](https://youtube.com/playlist?list=PLHz_AreHm4dn_RXXoa3Ameh77f95Hgwv3&si=d6IAu3Kx4vTapYaz) | S3_01 | Falha de recuperação; conteúdo não conferido |

## Leituras e entregáveis indicados em cada cartão

Esta seção transcreve as indicações bibliográficas e os entregáveis dos cartões para permitir rastreamento. São indicações do material fornecido pelo usuário/professor, **não atestados de leitura integral ou de correção bibliográfica**. Edição e capítulo devem ser conferidos no exemplar correspondente. O campo Entregável tem prioridade sobre tratar cada exercício recomendado como uma nova função de produção.


### S1_01 — Engenharia de Requisitos: Compreensão do Problema

**Entrega indicada:** Campo sem descrição no cartão.

Leituras Obrigatórias
PRESSMAN, Roger S.; MAXIM, Bruce R. Engenharia de Software: Uma Abordagem Profissional, 9.ed. Capítulos sobre Engenharia de Requisitos. SOMMERVILLE, Ian. Engenharia de Software, 10.ed. Capítulo Engenharia de Requisitos.

➕ Leituras Complementares
PRESSMAN, Roger S.; MAXIM, Bruce R. Engenharia de Software: Uma Abordagem Profissional, 9.ed. Capítulos sobre Engenharia de Requisitos. SOMMERVILLE, Ian. Engenharia de Software, 10.ed. Capítulo Engenharia de Requisitos.


**Vídeos indicados**
 Vídeos
Engenharia de Requisitos - Introdução e Fundamentos (YouTube): https://www.youtube.com/watch?v=Mjpj0YK5MRI


### S1_02 — Requisitos Funcionais

**Entrega indicada:** Campo sem descrição no cartão.

Leituras Obrigatórias
PRESSMAN, Roger S.; MAXIM, Bruce R. Engenharia de Software: Uma Abordagem Profissional, 9.ed. Ler as seções sobre Engenharia de Requisitos, Elicitação de Requisitos, Análise de Requisitos e Casos de Uso. SOMMERVILLE, Ian. Engenharia de Software, 10.ed. Ler as seções sobre Requisitos Funcionais, Requisitos Não Funcionais, Engenharia de Requisitos e Casos de Uso.

➕ Leituras Complementares
WIEGERS, Karl; BEATTY, Joy. Software Requirements (3rd Edition). Capítulos: Functional Requirements, Use Cases e User Requirements.


**Vídeos indicados**
 Vídeos
Link: https://www.youtube.com/watch?v=xm_EJI3_o8A


### S1_03 — Critérios de Aceitação

**Entrega indicada:** Campo sem descrição no cartão.

Leituras Obrigatórias
SOMMERVILLE, Ian. Engenharia de Software, 10.ed. Seções sobre Validação de Requisitos e Engenharia de Requisitos. PRESSMAN, Roger S.; MAXIM, Bruce R. Engenharia de Software: Uma Abordagem Profissional, 9.ed. Tópicos de validação, verificação e requisitos.

➕ Leituras Complementares
COHN, Mike. User Stories Applied. Ler as seções sobre Acceptance Criteria e Definition of Done.


**Vídeos indicados**
 Vídeos
Critérios de Aceitação e Histórias de Usuário (SCRUM): https://www.youtube.com/results?search_query=crit%C3%A9rios+de+aceita%C3%A7%C3%A3o+scrum


### S1_04 — Python: Alô Mundo

**Entrega indicada:** Programa em Python contendo a mensagem 'Hello, World!' executando corretamente.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler capítulos introdutórios sobre instalação, ambiente e primeiros programas. DOWNEY, Allen. Think Python. Capítulos 1 e 2.

➕ Leituras Complementares
Documentação oficial Python: Tutorial - The Python Interpreter e An Informal Introduction to Python.


**Vídeos indicados**
 Vídeos
Python para Iniciantes - Primeiros Passos e Hello World: https://www.youtube.com/results?search_query=python+hello+world+iniciantes


### S1_05 — Python: Variáveis e Tipos de Dados

**Entrega indicada:** Exercício: desenvolver um programa em Python que solicite ao usuário o ID, nome e responsável por um ativo de TI e exiba essas informações na tela.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler os capítulos sobre variáveis, tipos de dados e entrada/saída de dados. DOWNEY, Allen. Think Python. Capítulos 1 a 3.

➕ Leituras Complementares
Documentação Python: Built-in Types e Variables.


**Vídeos indicados**
 Vídeos
Vídeo recomendado: Variáveis e Tipos de Dados em Python para Iniciantes. Link: https://www.youtube.com/watch?v=Ns3gMxgXpVo


### S1_06 — Python: Entrada e Saída de Dados

**Entrega indicada:** Exercício: desenvolver um programa em Python que solicite ID, nome, responsável e localização de um ativo de TI e exiba as informações formatadas na tela.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler os capítulos sobre entrada e saída de dados. DOWNEY, Allen. Think Python. Capítulos 2 e 3.

➕ Leituras Complementares
Documentação oficial Python: input(), print() e f-strings.


**Vídeos indicados**
 Vídeos
Curso em Vídeo - Python #07 Entrada de Dados e #08 Tratando Dados e Fazendo Contas: https://www.youtube.com/watch?v=Vw6gLypRKmY e https://www.youtube.com/watch?v=_QfISzy0IKs


### S1_07 — Estruturas Condicionais

**Entrega indicada:** Exercício: desenvolver um programa que receba a severidade de uma vulnerabilidade e exiba sua classificação utilizando estruturas condicionais.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler o capítulo sobre estruturas condicionais e tomada de decisão.
DOWNEY, Allen. Think Python. Seções sobre execução condicional e operadores lógicos.

➕ Leituras Complementares
Documentação oficial Python: if statements e Boolean Operations.


**Vídeos indicados**
 Vídeos
Curso em Vídeo Python #10 – Condições (Parte 1):
https://www.youtube.com/watch?v=K10u3XIf1-Q

Corey Schafer – If Statements and Boolean Logic:
https://www.youtube.com/watch?v=DZwmZ8Usvnk


### S1_08 — Estruturas de Repetição

**Entrega indicada:** Exercício: desenvolver um programa que exiba um menu de opções em loop e permita ao usuário encerrar a execução apenas quando selecionar a opção 'Sair'.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler o capítulo sobre estruturas de repetição (for e while).
DOWNEY, Allen. Think Python. Seções sobre iteração e loops.

➕ Leituras Complementares
Documentação oficial Python: for statements, while statements e range().


**Vídeos indicados**
 Vídeos
Vídeos: Link: https://www.youtube.com/playlist?list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e Aula 13 – Comando while (Prof. André Backes)
Aula 14 – Comando for (Prof. André Backes)
Aula 15 – Comandos break e continue (Prof. André Backes)


### S1_09 — Funções

**Entrega indicada:** Exercício: desenvolver uma função que receba o nome e o responsável por um ativo de TI e exiba essas informações formatadas.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python. Ler o capítulo sobre funções.
DOWNEY, Allen. Think Python. Capítulos sobre funções, parâmetros e retorno.

➕ Leituras Complementares
Documentação oficial Python: Defining Functions e Function Definitions.


**Vídeos indicados**
 Vídeos
Curso em Vídeo Python #20 – Funções Parte 1: https://www.youtube.com/watch?v=ezfr9d7wd_k
Curso em Vídeo Python #21 – Funções Parte 2: https://www.youtube.com/watch?v=etjJ_4Eqrk8


### S1_10 — Listas

**Entrega indicada:** Desenvolver um programa em Python que mantenha uma lista de ativos de TI, permitindo cadastrar, remover e listar os ativos armazenados.

Leituras Obrigatórias
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python (4ª ed.). Capítulo 7 – Listas. DOWNEY, Allen. Think Python (2ª ed.). Capítulo 10 – Lists.

➕ Leituras Complementares
Documentação Python: Lists e More on Lists.


**Vídeos indicados**
 Vídeos
Curso em Vídeo – https://www.youtube.com/watch?v=Y05YeBAFCrs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=16
Curso em Vídeo – https://www.youtube.com/watch?v=0sdtkjISZIE&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=17


### S1_11 — Tuplas e Sets

**Entrega indicada:** Implementação do Exercício 3 com código-fonte comentado e evidências de execução.

Leituras Obrigatórias
RAMALHO, Luciano. Python Fluente (2ª ed.). Ler o capítulo sobre Sequências e Coleções (seções de Tuplas).
MENEZES, Nilo Ney Coutinho. Introdução à Programação com Python (4ª ed.). Ler o capítulo sobre Conjuntos (Sets) e estruturas de dados.
Documentação oficial Python: Tuples e Sets (Built-in Types).

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Curso em Vídeo – https://www.youtube.com/watch?v=fhekxMRM4Ts&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=21


### S1_12 — Dicionários

**Entrega indicada:** Exercício 2 – Programa de cadastro e atualização de vulnerabilidades utilizando dicionários.

Leituras Obrigatórias
MATTHES, Eric. Curso Intensivo de Python (3ª ed.). Capítulo 6 – Dicionários.
RAMALHO, Luciano. Python Fluente (2ª ed.). Seções sobre mapeamentos e dicionários.
Documentação Python: Estruturas de Dados – Dictionaries.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Curso em Vídeo – https://www.youtube.com/watch?v=EXMr1u2bnjc&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=23


### S1_13 — Enumerações

**Entrega indicada:** Exercício 2 – Enumeração para representar o status de ativos do sistema.

Leituras Obrigatórias
• Documentação Oficial Python – módulo enum (Enum)
• Curso Intensivo de Python (Eric Matthes) – Cap. 8 (Funções) e consulta à documentação oficial sobre módulos
• Python Fluente (Luciano Ramalho) – seções sobre Enumerações e tipos de dados avançados

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Vídeo: https://www.youtube.com/watch?v=xGcvqT0-oaY


### S1_14 — Persistência em Arquivos

**Entrega indicada:** Exercício 2 – Cadastro de vulnerabilidades persistido em arquivo JSON.

Leituras Obrigatórias
Curso Intensivo de Python (Eric Matthes) – Cap. 10 (Arquivos e Exceções).
Documentação Python – Arquivos e JSON.
Python Fluente – seções sobre serialização e persistência de dados.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Curso em Vídeo Python: https://www.youtube.com/watch?v=1ZFe-OqMB28&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=34


### S1_15 — Tratamento de Erros

**Entrega indicada:** Exercício 2 – Sistema de cadastro de ativos com tratamento de erros em operações de leitura e gravação de arquivos.

Leituras Obrigatórias
Eric Matthes – Curso Intensivo de Python, Capítulo 10 (Arquivos e Exceções). Documentação Oficial do Python – Errors and Exceptions. Luciano Ramalho – Python Fluente, seções sobre exceções.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Curso em Vídeo – Tratamento de Erros e Exceções em Python. https://www.youtube.com/watch?v=FxCEHvk3SjI&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=37


### S1_16 — Git Fundamentos

**Entrega indicada:** Exercício 2 – Repositório GitHub contendo o projeto e histórico mínimo de commits documentando sua evolução.

Leituras Obrigatórias
• Pro Git (Scott Chacon e Ben Straub) – Capítulos 1 e 2
• Documentação oficial Git – Getting Started e Git Basics
• GitHub Docs – Introduction to GitHub

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
• Curso em Vídeo – Git e GitHub (Gustavo Guanabara): https://www.youtube.com/playlist?list=PLHz_AreHm4dm7ZULPAmadvNhH6vk9oNZA
• Git and GitHub for Beginners (freeCodeCamp): https://www.youtube.com/watch?v=RGOj5yH7evk
• Git Tutorial for Beginners (Programming with Mosh): https://www.youtube.com/watch?v=8JJ101D3knE


### S1_17 — Git Versionamento e Colaboração

**Entrega indicada:** Exercício 1 – Branch de funcionalidade criada, integrada por merge e documentada no repositório GitHub.

Leituras Obrigatórias
Pro Git (Scott Chacon e Ben Straub) – Cap. 2 (Git Basics) e Cap. 3 (Git Branching).
Documentação Git: Branching and Merging.
GitHub Docs: Pull Requests e Collaboration.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Assistir vídeos indicados no card S1_16.


### S1_18 — Git Branches, Merge e Fluxo de Trabalho

**Entrega indicada:** Exercício 1 – Branch de funcionalidade criada, documentada e integrada à branch principal por meio de merge.

Leituras Obrigatórias
Pro Git (Scott Chacon e Ben Straub)
Capítulo 3 – Git Branching:
• What a Branch Is
• Basic Branching and Merging
• Branch Management

GitHub Docs:
• About Pull Requests
• About Branches

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Assistir vídeos indicados no card S1_16.


### S1_19 — GitHub, Pull Requests e Code Review

**Entrega indicada:** Exercício 1 – Pull Request completo contendo alteração documentada e aprovada.

Leituras Obrigatórias
Pro Git – Cap. 3 (Git Branching) e Cap. 6 (GitHub).
GitHub Docs – Pull Requests.
GitHub Docs – Code Review e Collaboration.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Assistir vídeos indicados no card S1_16.


### S1_20 — Revisão Geral da Sprint 1

**Entrega indicada:** Não há entregável obrigatório neste card. Antes de avançar para a próxima Sprint, confirme que todos os entregáveis dos cards anteriores foram concluídos e enviados.

Leituras Obrigatórias
Revisar anotações, materiais, leituras obrigatórias e documentação utilizados nos cards S1_01 a S1_19. Priorizar os tópicos com maior dificuldade identificada durante a Sprint.

➕ Leituras Complementares



**Vídeos indicados**
 Vídeos
Revisar os vídeos indicados nos cards S1_01 a S1_19, com foco nos tópicos em que houver dúvidas ou dificuldades.


### S2_01 — Boas Práticas de Código

**Entrega indicada:** Commit de refatoração + nota no README com as decisões adotadas.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
Clean Code Explained: https://www.youtube.com/watch?v=7EmboKQH8lM


### S2_02 — Classes, Funções e Chamadas

**Entrega indicada:** Módulo de modelos + script de demonstração ou testes automatizados.

Leituras Obrigatórias
Livro: Curso Intensivo de Python (Eric Matthes), 2ª edição.
Capítulos: 2 (Variáveis), 3 (Listas), 6 (Dicionários), 8 (Funções), 10 (Arquivos e Exceções).
Disponibilidade: Comercial.
Editora: No Starch Press.
Página oficial: https://nostarch.com/pythoncrashcourse2e
Complementar gratuito: Documentação Python https://docs.python.org/pt-br/3/
Complementar avançado: Python Fluente (Luciano Ramalho, 2ª edição) https://www.oreilly.com/library/view/fluent-python-2nd/9781492056348/
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
Python OOP (Corey Schafer): https://www.youtube.com/watch?v=ZDa-Z5JzLYM


### S2_03 — O que é CRUD?

**Entrega indicada:** Protótipo CRUD em memória + fluxo documentado no README.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=4ixiRLTtsL8";"CRUD com Python e SQLite3"


### S2_04 — Requisitos do CRUD

**Entrega indicada:** Arquivo docs/requisitos.md versionado no repositório.

Leituras Obrigatórias
Livro: Engenharia de Software (Ian Sommerville), 10ª edição.
Capítulos: Engenharia de Requisitos, Elicitação, Casos de Uso e Especificação.
Editora: Pearson.
Página da editora: https://www.pearson.com
Complementar: Engenharia de Software (Roger Pressman), capítulos sobre requisitos.
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=YLd6AWKVyas";"Requisitos funcionais e não funcionais de software"


### S2_05 — Regras e Validações

**Entrega indicada:** Módulo de validações + matriz de regras + testes.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos


### S2_06 — Critérios de Aceitação CRUD

**Entrega indicada:** Arquivo docs/criterios_aceitacao.md com cenários revisados.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=rXOwvnWJc1M";"Critérios de aceitação: como escrever"


### S2_07 — Especificação Completa do seu sistema

**Entrega indicada:** Arquivo docs/especificacao.md, versão 1.0 revisada.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=7Jo4OofFQTQ";"Especificação de Requisitos — Introdução"


### S2_08 — Cadastro de Ativos

**Entrega indicada:** Função de cadastro + três testes + evidência de execução.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=4ixiRLTtsL8";"CRUD com Python e SQLite3 — foco em cadastro"


### S2_09 — Busca de Ativos

**Entrega indicada:** Funções de consulta/filtro + testes de resultado e ausência.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
Busca em Estruturas de Dados Python: https://www.youtube.com/watch?v=R-HLU9Fl5ug


### S2_10 — Atualização de Ativos

**Entrega indicada:** Função de atualização + testes + registro resumido da mudança.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=4ixiRLTtsL8";"CRUD com Python e SQLite3 — foco em atualização"


### S2_11 — Exclusão de Ativos

**Entrega indicada:** Função de exclusão + testes + política registrada no README.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=4ixiRLTtsL8";"CRUD com Python e SQLite3 — foco em exclusão"


### S2_12 — Fundamentos de Vulnerabilidades

**Entrega indicada:** Dois registros de vulnerabilidade analisados e documentados.

Leituras Obrigatórias
Livro: Segurança de Computadores (William Stallings), 6ª edição.
Capítulos: Gestão de Vulnerabilidades, Avaliação de Riscos e Segurança de Sistemas.
Editora: Pearson.
Página da editora: https://www.pearson.com
Complementar: OWASP Top 10 https://owasp.org/www-project-top-ten/
Complementar: NIST SP 800-40 https://csrc.nist.gov/publications
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=Jzr0Jdnq_EI


### S2_13 — Cadastro de Vulnerabilidades

**Entrega indicada:** Função de cadastro + dois exemplos reais + testes de validação.

Leituras Obrigatórias
Livro: Segurança de Computadores (William Stallings), 6ª edição.
Capítulos: Gestão de Vulnerabilidades, Avaliação de Riscos e Segurança de Sistemas.
Editora: Pearson.
Página da editora: https://www.pearson.com
Complementar: OWASP Top 10 https://owasp.org/www-project-top-ten/
Complementar: NIST SP 800-40 https://csrc.nist.gov/publications
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=dwFbYHZxBpQ";"NVD, CVE e CVSS"


### S2_14 — Consulta de Vulnerabilidades

**Entrega indicada:** Funções de consulta/filtro + evidência de conferência externa.

Leituras Obrigatórias
Livro: Segurança de Computadores (William Stallings), 6ª edição.
Capítulos: Gestão de Vulnerabilidades, Avaliação de Riscos e Segurança de Sistemas.
Editora: Pearson.
Página da editora: https://www.pearson.com
Complementar: OWASP Top 10 https://owasp.org/www-project-top-ten/
Complementar: NIST SP 800-40 https://csrc.nist.gov/publications
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=bEKmTJPSZgs";"Como localizar informações de vulnerabilidades em NVD/CVE"


### S2_15 — Dicionários (Hashmaps)

**Entrega indicada:** Repositório em memória baseado em dicionário + testes.

Leituras Obrigatórias
Livro: Curso Intensivo de Python (Eric Matthes), 2ª edição.
Capítulos: 2 (Variáveis), 3 (Listas), 6 (Dicionários), 8 (Funções), 10 (Arquivos e Exceções).
Disponibilidade: Comercial.
Editora: No Starch Press.
Página oficial: https://nostarch.com/pythoncrashcourse2e
Complementar gratuito: Documentação Python https://docs.python.org/pt-br/3/
Complementar avançado: Python Fluente (Luciano Ramalho, 2ª edição) https://www.oreilly.com/library/view/fluent-python-2nd/9781492056348/
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
Python Dictionaries Deep Dive: https://www.youtube.com/watch?v=daefaLgNkw0


### S2_16 — Branches

**Entrega indicada:** Branch integrada + histórico de commits + evidência da resolução.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=xAOBQtSVI_k";"Git Branches com exemplo"


### S2_17 — Colaboração GitHub

**Entrega indicada:** Link do pull request integrado + retrospectiva curta da revisão.

Leituras Obrigatórias
Livro: Pro Git (Scott Chacon e Ben Straub), 2ª edição.
Disponibilidade: Gratuito online.
Capítulos: Cap. 1 (Introdução ao Controle de Versão), Cap. 2 (Fundamentos do Git), Cap. 3 (Branching).
Livro online: https://git-scm.com/book/pt-br/v2
Editora: Apress.
Página da editora: https://link.springer.com/book/10.1007/978-1-4842-0076-6
Complementar: Documentação Git https://git-scm.com/docs
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=M4u3x6iguR4";"Pull Requests e Issues no GitHub"


### S2_18 — Testes e Correções

**Entrega indicada:** Pasta de testes + relatório curto de falhas e correções.

Leituras Obrigatórias
Livro: Testes de Software (Leonardo Molinari).
Capítulos: Fundamentos, Planejamento de Testes, Casos de Teste e Evidências.
Editora: Érica.
Complementar: ISTQB Foundation Syllabus https://istqb.org
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
Python Unit Testing (Corey Schafer): https://www.youtube.com/watch?v=6tNS--WetLI


### S2_19 — Entrega Trabalho 1

**Entrega indicada:** Link Repositório/tag da entrega + README + relatório e demonstração final.

Leituras Obrigatórias
Livro: Engenharia de Software (Roger Pressman), 8ª edição.
Capítulos: Processo de Software, Planejamento, Modelagem e Qualidade.
Editora: McGraw-Hill.
Complementar: Engenharia de Software (Ian Sommerville), 10ª edição.
Página da editora: https://www.pearson.com
    

**Referências complementares**
 Leituras Complementares

    

**Vídeos indicados**
 Vídeos
https://www.youtube.com/watch?v=BrNBuX40t1w";"Definição de Pronto (DoD)"


### S3_01 — Orientação a Objetos: Herança, Polimorfismo e Abstração

**Entrega indicada:** Hierarquia de classes implementada, demonstração polimórfica, arquivo JSON contendo objetos persistidos e evidência de recarga.

Leituras Obrigatórias
    LUTZ, Mark. Learning Python, 5th ed. O'Reilly.
Capítulo 31 – Class Design with Python OOP.
Capítulo 32 – A More Realistic Example.

RAMALHO, Luciano. Python Fluente, 2ª ed.
Parte III – Classes e Protocolos.
Capítulo 12 – Métodos Especiais para Sequências.
Capítulo 14 – Herança: Para o Bem ou Para o Mal.

GOODRICH, Tamassia e Goldwasser. Data Structures and Algorithms in Python.
Seções sobre herança, composição e reutilização de classes.
        

**Referências complementares**
 Leituras Complementares
    Documentação Oficial Python:
https://docs.python.org/pt-br/3/tutorial/classes.html

Refactoring Guru – Herança e Composição:
https://refactoring.guru/pt-br/design-patterns
        

**Vídeos indicados**
 Vídeos
    Harvard CS50P – Week 8: Object-Oriented Programming
https://cs50.harvard.edu/python/weeks/8/                                                                                                                                                                                                                                                                                                                                                                                                                                Python POO: Programação Orientada a Objetos - Curso em Vídeo de Python 3                                                                                                                                                                                                                                                                                               https://youtube.com/playlist?list=PLHz_AreHm4dn_RXXoa3Ameh77f95Hgwv3&si=d6IAu3Kx4vTapYaz                                                                                                                                                                                                                                                                                      Python | Aula 38 - Programação Orientada a Objetos (POO)                                                                                                                                                                                                                                                                                                                                 https://www.youtube.com/watch?v=jm3jDYIOAxs&list=PL8iN9FQ7_jt5TITT-3c4L6xNSmQMx1T4e&index=38


### S3_02 — Paradigmas de Programação: Funções de Alta Ordem e Recursão

**Entrega indicada:** Conjunto de algoritmos implementados, análise comparativa de desempenho e exemplos de uso de funções de alta ordem.

Leituras Obrigatórias
    RAMALHO, Luciano. Python Fluente, 2ª ed.
Capítulo 7 – Funções como Objetos de Primeira Classe.
Capítulo 10 – Padrões de Projeto com Funções.

LUTZ, Mark. Learning Python, 5th ed.
Capítulo 17 – Scopes.
Capítulo 19 – Advanced Function Topics.

GOODRICH, Tamassia e Goldwasser. Data Structures and Algorithms in Python.
Seções sobre recursão e análise de algoritmos recursivos.
        

**Referências complementares**
 Leituras Complementares
    Documentação Python:
https://docs.python.org/3/tutorial/controlflow.html

Real Python – Recursion in Python
https://realpython.com/python-recursion/

Python Functional Programming HOWTO
https://docs.python.org/3/howto/functional.html
        

**Vídeos indicados**
 Vídeos
    Curso de Python - Funções - Recursividade: https://www.youtube.com/watch?v=fbj5Y19x0fs&list=PLucm8g_ezqNrrtduPx7s4BM8phepMn9I2&index=32                                                                                                                                                                                                                                                                                       MIT OpenCourseWare – Introduction to Algorithms (Recursion)
CS50P – Functions and Advanced Python Topics                                                                                                                                                                                                                                                                                                                                                                        https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-fall-2011/resources/recitation-5-recursion-trees-binary-search-trees/                                                                                                                                                                                                                                                                                                                                                                                                             Cálculo do Fatorial: https://www.youtube.com/watch?v=9dlBZlkvvxY


### S3_03 — Estruturas Lineares: Filas e Listas Encadeadas

**Entrega indicada:** Código-fonte contendo uma implementação funcional de fila e lista encadeada, acompanhado de exemplos de uso, análise simplificada de complexidade e diagrama representando a estrutura encadeada.

Leituras Obrigatórias
    GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael.
Data Structures and Algorithms in Python.
Capítulo 7 – Linked Lists.
Capítulo 12 – Queues.

MILLER, Brad; RANUM, David.
Problem Solving with Algorithms and Data Structures Using Python.
Seção 3.13 – Queues.
Seção 3.18 – Linked Lists.
        

**Referências complementares**
 Leituras Complementares
    Cormen, Thomas et al.
Introduction to Algorithms (CLRS).
Capítulo 10 – Elementary Data Structures.

Documentação Python:
collections.deque
https://docs.python.org/3/library/collections.html#collections.deque
        

**Vídeos indicados**
 Vídeos
    CS Dojo – Linked Lists Explained
https://www.youtube.com/results?search_query=CS+Dojo+Linked+Lists

Abdul Bari – Queue Data Structure
https://www.youtube.com/results?search_query=Abdul+Bari+Queue+Data+Structure

Curso Python Listas: https://www.youtube.com/watch?v=N1hTsbW50eM&t=2s


### S3_04 — Análise de Algoritmos e Complexidade

**Entrega indicada:** Relatório curto contendo análise de complexidade de algoritmos estudados, tabela comparativa das classes assintóticas e justificativa das respostas.

Leituras Obrigatórias
    GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael.
Data Structures and Algorithms in Python.
Capítulo 5 – Algorithm Analysis.

CORMEN, Thomas H. et al.
Introduction to Algorithms (CLRS).
Capítulo 3 – Growth of Functions.
Capítulo 2.3 – Analyzing Algorithms.
        

**Referências complementares**
 Leituras Complementares
    SKIENA, Steven.
The Algorithm Design Manual.
Capítulo 2 – Algorithm Analysis.

VisuAlgo:
https://visualgo.net/en
        

**Vídeos indicados**
 Vídeos
    Estruturas de Dados - Aula 5.1. Complexidade de Algoritmos: https://www.youtube.com/watch?v=wsPZUZ5R92c&t=2284s
MIT OpenCourseWare – Algorithm Analysis
CS50 – Big O Notation: https://www.youtube.com/watch?v=TBIPvjZLuoA


### S3_05 — Busca e Ordenação

**Entrega indicada:** Código-fonte contendo as implementações dos algoritmos estudados, relatório comparativo de complexidade e tabela de análise de desempenho.

Leituras Obrigatórias
    GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael.
Data Structures and Algorithms in Python.
Capítulo 13 – Sorting and Selection.
Seções sobre busca binária e algoritmos de ordenação.

CORMEN, Thomas H. et al.
Introduction to Algorithms (CLRS).
Capítulo 2 – Getting Started.
Capítulo 8 – Sorting in Linear Time (leitura complementar).
        

**Referências complementares**
 Leituras Complementares
    SKIENA, Steven.
The Algorithm Design Manual.
Capítulo 4 – Sorting and Searching.

VisuAlgo:
https://visualgo.net/en/sorting
        

**Vídeos indicados**
 Vídeos
    Introdução ao Estudo de Algoritmos de Ordenação:                                                                                                                                                                                                                                                                                                                                                           https://www.youtube.com/watch?v=dtv5FpYj3zU&list=PLzZut2slkqywtFxqTY8AQwIG65h_2oMBLMIT OpenCourseWare – Sorting and Searching
CS50 – Search and Sort


### S3_06 — Qualidade de Software e Código Limpo

**Entrega indicada:** Relatório contendo evidências da execução das ferramentas de qualidade, trechos de código antes e depois da refatoração e descrição das melhorias realizadas.

Leituras Obrigatórias
    MARTIN, Robert C.
Clean Code: A Handbook of Agile Software Craftsmanship.
Capítulo 1 – Clean Code.
Capítulo 2 – Meaningful Names.
Capítulo 3 – Functions.
Capítulo 10 – Classes.

SOMMERVILLE, Ian.
Software Engineering.
Capítulo sobre Software Quality Management.

PEP 8 – Style Guide for Python Code.
        

**Referências complementares**
 Leituras Complementares
    FOWLER, Martin.
Refactoring: Improving the Design of Existing Code.
Capítulo 1 – Refactoring.

Documentação:
https://flake8.pycqa.org/
https://pylint.pycqa.org/
https://black.readthedocs.io/
        

**Vídeos indicados**
 Vídeos
    Clean Code – https://www.youtube.com/watch?v=gB5Gej0O400&list=PLMdYygf53DP5Sc6yFYs6ZmjsuuA2fu0TK&index=4


### S3_07 — Estratégias de Teste e Testes Unitários

**Entrega indicada:** Suite de testes automatizados para o Trabalho 02, contendo casos de teste, evidências de execução, relatório resumido de cobertura e descrição das correções realizadas.

Leituras Obrigatórias
    MYERS, Glenford J.; SANDLER, Corey; BADGETT, Tom. The Art of Software Testing. Cap. 2, 4 e 5.

Python Documentation: unittest — Unit Testing Framework.

PERCIVAL, Harry; GREGORY, Bob. Architecture Patterns with Python. Capítulos iniciais sobre testes automatizados.
        

**Referências complementares**
 Leituras Complementares
    Clean Code (Robert C. Martin) – Capítulo 9: Unit Tests.
pytest Documentation.
coverage.py Documentation.
        

**Vídeos indicados**
 Vídeos
    Testes unitários em Python:

https://www.youtube.com/watch?v=_CUNnRVjpKQ&list=PLAgbpJQADBGIicaxuo9hI5EmcK85ck5X2


### S3_08 — GitHub, Pull Requests e Integração Contínua

**Entrega indicada:** Repositório GitHub contendo histórico de commits, Pull Request documentado, workflow GitHub Actions funcional e evidências da execução automática dos testes.

Leituras Obrigatórias
    CHACON, Scott; STRAUB, Ben.
Pro Git (2nd Edition).
Capítulo 2 – Git Basics.
Capítulo 3 – Git Branching.
Capítulo 5 – Distributed Git.

GITHUB DOCUMENTATION.
GitHub Flow.
Understanding Pull Requests.
Introduction to GitHub Actions.
        

**Referências complementares**
 Leituras Complementares
    FOWLER, Martin.
Continuous Integration.

GitHub Skills:
Review Pull Requests.
Hello GitHub Actions.

Documentação Oficial Git:
https://git-scm.com/doc
        

**Vídeos indicados**
 Vídeos
    GitHub Skills — Introduction to GitHub
https://github.com/skills/introduction-to-github

GitHub Skills — Review pull requests
https://github.com/skills/review-pull-requests

GitHub Skills — Hello GitHub Actions
https://github.com/skills/hello-github-actions

Traversy Media — Git & GitHub Crash Course For Beginners
https://www.youtube.com/watch?v=SWYqp7iY_Tc

Fireship — GitHub Actions Tutorial
https://www.youtube.com/watch?v=eB0nUzAI7M8


### S3_09 — Álgebra Linear I: Matrizes e Transformações Lineares

**Entrega indicada:** Relatório contendo exercícios resolvidos, representação matricial de transformações, cálculo de núcleo e imagem e o cálculo do risco próprio de um cenário com 3 equipamentos (à mão e em Python/NumPy), com interpretação dos resultados.

Leituras Obrigatórias
    LAY, David C.; LAY, Steven R.; McDONALD, Judi J.
Linear Algebra and Its Applications.
Capítulo 1 – Seções 1.3 e 1.4 (Vector Equations; The Matrix Equation Ax = b).
Capítulo 1 – Seções 1.8 e 1.9 (Introduction to Linear Transformations; The Matrix of a Linear Transformation).
Capítulo 2 – Seção 2.1 (Matrix Operations).

STRANG, Gilbert.
Introduction to Linear Algebra. 5th ed.
Capítulo 8 – Linear Transformations.
        

**Referências complementares**
 Leituras Complementares
    ANTON, Howard; RORRES, Chris.
Elementary Linear Algebra.
Capítulos sobre transformações lineares.

3Blue1Brown – Essence of Linear Algebra.
        

**Vídeos indicados**
 Vídeos
    3Blue1Brown — Linear transformations and matrices | Essence of linear algebra
https://www.youtube.com/watch?v=kYB8IZa5AuE

3Blue1Brown — Matrix multiplication as composition | Essence of linear algebra
https://www.3blue1brown.com/lessons/matrix-multiplication


### S3_10 — Álgebra Linear II: Sistemas Lineares

**Entrega indicada:** Lista resolvida de exercícios contendo resolução de sistemas por escalonamento, classificação de sistemas e a modelagem e resolução manual do sistema de risco efetivo de um cenário com 3 equipamentos, validada com Python/NumPy.

Leituras Obrigatórias
    LAY, David C.; LAY, Steven R.; McDONALD, Judi J.
Linear Algebra and Its Applications.
Capítulo 1 – Seções 1.1, 1.2 e 1.5 (Systems of Linear Equations; Row Reduction and Echelon Forms; Solution Sets of Linear Systems).

ANTON, Howard; RORRES, Chris.
Elementary Linear Algebra.
Capítulo sobre sistemas lineares e eliminação gaussiana.
        

**Referências complementares**
 Leituras Complementares
    STRANG, Gilbert.
Introduction to Linear Algebra. 5th ed.
Capítulo 2 – Solving Linear Equations.

Khan Academy – Álgebra Linear.
Módulos sobre matrizes e sistemas lineares.
        

**Vídeos indicados**
 Vídeos
    MIT OpenCourseWare — Gilbert Strang, Lecture 2: Elimination with matrices
https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-2-elimination-with-matrices/

3Blue1Brown — Inverse matrices, column space and null space | Essence of linear algebra
https://www.3blue1brown.com/lessons/inverse-matrices


### S3_11 — Álgebra Linear III: Determinantes e Invertibilidade

**Entrega indicada:** Lista resolvida contendo cálculo de determinantes e inversas com as etapas, identificação de matrizes singulares e análise da invertibilidade de I − A em dois cenários do modelo de risco (um invertível e um singular), com verificação em Python/NumPy.

Leituras Obrigatórias
    LAY, David C.; LAY, Steven R.; McDONALD, Judi J.
Linear Algebra and Its Applications.
Capítulo 2 – Seções 2.2 e 2.3 (The Inverse of a Matrix; Characterizations of Invertible Matrices).
Capítulo 3 – Seções 3.1 a 3.3 (Determinants).
        

**Referências complementares**
 Leituras Complementares
    ANTON, Howard; RORRES, Chris.
Elementary Linear Algebra.
Capítulos sobre determinantes e matrizes inversíveis.

BURDEN, Richard L.; FAIRES, J. Douglas.
Numerical Analysis.
Seção 6.6 – Special Types of Matrices (matrizes estritamente diagonal dominantes).
        

**Vídeos indicados**
 Vídeos
    MIT OpenCourseWare — Gilbert Strang, Lecture 18: Properties of determinants
https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-18-properties-of-determinants/

MIT OpenCourseWare — Gilbert Strang, Lecture 20: Cramer's rule, inverse matrix, and volume
https://ocw.mit.edu/courses/18-06-linear-algebra-spring-2010/resources/lecture-20-cramers-rule-inverse-matrix-and-volume/

3Blue1Brown — The determinant | Essence of linear algebra
https://www.youtube.com/watch?v=Ip3X9LOh2dk


### S3_12 — Erros Numéricos e Representação Computacional

**Entrega indicada:** Relatório contendo experimentos em Python demonstrando erros numéricos, comparação entre truncamento e arredondamento, cálculo de erros absoluto e relativo e discussão dos resultados observados, além da análise numérica do sistema de risco do Trabalho 2 (tolerância no determinante, número de condição e comparação entre solve e inv).

Leituras Obrigatórias
    BURDEN, Richard L.; FAIRES, J. Douglas.
Numerical Analysis.
Capítulo 1 – Mathematical Preliminaries and Error Analysis.
Seções sobre erro absoluto, erro relativo e aritmética computacional.
Capítulo 7 – Seção Error Bounds and Iterative Refinement (número de condição).

CHAPRA, Steven C.; CANALE, Raymond P.
Numerical Methods for Engineers.
Capítulo 3 – Errors.
Seções sobre truncamento, arredondamento e propagação de erros.

IEEE 754 Standard (visão geral).
        

**Referências complementares**
 Leituras Complementares
    GOLDBERG, David.
What Every Computer Scientist Should Know About Floating-Point Arithmetic.

Python Documentation:
Floating Point Arithmetic: Issues and Limitations.

NumPy Documentation:
numpy.linalg.solve, numpy.linalg.cond e numpy.isclose.
        

**Vídeos indicados**
 Vídeos
    Computerphile — Floating Point Numbers
https://www.youtube.com/watch?v=PZRI1IfStY0

Computerphile — Floating Point Numbers (floating point versus fixed)
https://www.youtube.com/watch?v=f4ekifyijIg


### S3_13 — Lógica Proposicional e Argumentação

**Entrega indicada:** Lista resolvida contendo tabelas-verdade, demonstrações de equivalência, análise de argumentos e resolução de exercícios de lógica proposicional.

Leituras Obrigatórias
    ROSEN, Kenneth H.
Discrete Mathematics and Its Applications.
Capítulo 1 – The Foundations: Logic and Proofs.
Seções sobre proposições, equivalências lógicas, regras de inferência e argumentação.

EPP, Susanna S.
Discrete Mathematics with Applications.
Capítulo 3 – Logic.
Capítulo 4 – Logical Reasoning.
        

**Referências complementares**
 Leituras Complementares
    LEWIS, Harry; PAPADIMITRIOU, Christos.
Elements of the Theory of Computation.
Seções introdutórias sobre lógica matemática.

Khan Academy – Logic and Proofs.
        

**Vídeos indicados**
 Vídeos
    Mathispower4u — Truth Tables for Compound Statements
https://www.youtube.com/watch?v=_5Z_0824RHw

NotesForMsc — Logical Equivalences (lógica proposicional e leis de De Morgan)
https://www.youtube.com/watch?v=FMc7pZbvWKA


### S3_14 — Portas Lógicas e Arquitetura de Computadores

**Entrega indicada:** Relatório contendo tabelas-verdade, resolução de exercícios de álgebra booleana, análise de circuitos combinacionais e descrição dos componentes da arquitetura de Von Neumann.

Leituras Obrigatórias
    STALLINGS, William.
Computer Organization and Architecture.
Capítulo 1 – Basic Concepts and Computer Evolution.
Capítulo 3 – Data Representation.
Capítulo 11 – Computer Arithmetic.

MANO, M. Morris; CILETTI, Michael.
Digital Design.
Capítulo 2 – Boolean Algebra and Logic Gates.
Capítulo 4 – Combinational Logic.
        

**Referências complementares**
 Leituras Complementares
    PATTERSON, David; HENNESSY, John.
Computer Organization and Design.
Capítulos introdutórios sobre arquitetura de computadores.

NANDGame:
https://nandgame.com/
        

**Vídeos indicados**
 Vídeos
    Crash Course — Boolean Logic & Logic Gates: Crash Course Computer Science #3
https://www.youtube.com/watch?v=gI-qXk7XojA

Crash Course — The Central Processing Unit (CPU): Crash Course Computer Science #7
https://www.youtube.com/watch?v=FZGugFqdr60

Code.org — How Computers Work: CPU, Memory, Input & Output
https://www.youtube.com/watch?v=DKGZlaPlVLY


### S3_15 — Usabilidade, Prototipação e Acessibilidade

**Entrega indicada:** Protótipo de alta fidelidade desenvolvido no Figma, acompanhado de relatório de avaliação heurística e análise de acessibilidade baseada nas diretrizes WCAG 2.1.

Leituras Obrigatórias
    NIELSEN, Jakob.
10 Usability Heuristics for User Interface Design.
Leitura integral das 10 heurísticas.

KRUG, Steve.
Don't Make Me Think.
Capítulo 1 – Don't Make Me Think.
Capítulo 3 – Billboard Design 101.
Capítulo 6 – Street Signs and Breadcrumbs.

W3C.
Web Content Accessibility Guidelines (WCAG) 2.1.
Princípios POUR e critérios de conformidade.
        

**Referências complementares**
 Leituras Complementares
    NORMAN, Don.
The Design of Everyday Things.
Capítulos sobre design centrado no usuário.

Material Figma Learn.
Guias introdutórios de prototipação.
        

**Vídeos indicados**
 Vídeos
    NNgroup — The 10 Usability Heuristics
https://www.youtube.com/playlist?list=PLJOFJ3Ok_idtb2YeifXlG1-TYoMBLoG6I

W3C WAI — Introduction to Web Accessibility and W3C Standards
https://www.w3.org/WAI/videos/standards-and-benefits/

AJ&Smart — Figma UI Design Tutorial: Get Started in Just 24 Minutes
https://www.youtube.com/watch?v=FTFaQWZBqQ8


### S3_16 — Front-End Moderno

**Entrega indicada:** Protótipo funcional de interface Web responsiva contendo listagem dinâmica de dados utilizando arrays e objetos JavaScript, com aplicação de CSS Grid e variáveis CSS.

Leituras Obrigatórias
    MDN Web Docs.
CSS Grid Layout.
Seções: Basic Concepts of Grid Layout e Realizing Common Layouts Using Grids.

MDN Web Docs.
Responsive Design.
Seções: Responsive Design Basics e Media Queries.

ELOQUENT JAVASCRIPT (Marijn Haverbeke).
Capítulo 4 – Data Structures: Objects and Arrays.
        

**Referências complementares**
 Leituras Complementares
    JON DUCKETT.
HTML & CSS.
Capítulos sobre Layout e Design Responsivo.

JON DUCKETT.
JavaScript & jQuery.
Capítulos sobre Arrays e Objetos.

freeCodeCamp – Responsive Web Design.
        

**Vídeos indicados**
 Vídeos
    Kevin Powell — Learn CSS Grid the easy way
https://www.youtube.com/watch?v=rg7Fvvl3taU

Kevin Powell — CSS Media Queries in less than 5 minutes
https://www.youtube.com/watch?v=2KL-z9A56SQ

Lea Verou — CSS Variables: var(--subtitle)
https://www.youtube.com/watch?v=kZOJCVvyF-4

freeCodeCamp — Learn JavaScript (arrays, objetos e renderização)
https://www.youtube.com/watch?v=PkZNo7MFNFg


### S3_17 — JavaScript Assíncrono e Consumo de APIs

**Entrega indicada:** Aplicação Web capaz de consumir uma API REST, processar respostas JSON e exibir dados dinamicamente na interface utilizando Fetch API e Async/Await.

Leituras Obrigatórias
    MDN Web Docs.
Using Promises.
Seções: Introduction to Promises e Promise Chaining.

MDN Web Docs.
async function.
Seções: Async Functions e Await.

MDN Web Docs.
Using the Fetch API.
Leitura integral.

ELOQUENT JAVASCRIPT.
Capítulo 11 – Asynchronous Programming.
        

**Referências complementares**
 Leituras Complementares
    You Don't Know JS Yet (Kyle Simpson).
Livro: Async & Performance.
Capítulos sobre Promises e Async Programming.

JavaScript.info.
Seções sobre Fetch e Async/Await.
        

**Vídeos indicados**
 Vídeos
    Traversy Media — Async JS Crash Course: Callbacks, Promises, Async Await
https://www.youtube.com/watch?v=PoRJizFvM7s

Web Dev Simplified — Learn Fetch API In 6 Minutes
https://www.youtube.com/watch?v=cuEtnrL9-H0

JSConf — What the heck is the event loop anyway? | Philip Roberts
https://www.youtube.com/watch?v=8aGhZQkoFbQ


### S3_18 — APIs REST e Testes de Integração

**Entrega indicada:** Coleção Postman contendo testes de integração para os endpoints da aplicação, acompanhada de documentação dos recursos REST implementados.

Leituras Obrigatórias
    RICHARDSON, Leonard; RUBY, Sam.
RESTful Web Services.
Capítulos 1 a 5 – Fundamentos de REST.

MDN Web Docs.
HTTP Overview.
HTTP Request Methods.
HTTP Response Status Codes.

Postman Learning Center.
Introduction to APIs e API Testing.
        

**Referências complementares**
 Leituras Complementares
    FIELDING, Roy.
Architectural Styles and the Design of Network-based Software Architectures.
Capítulo 5 – Representational State Transfer (REST).

OpenAPI Specification (visão geral).
        

**Vídeos indicados**
 Vídeos
    Traversy Media — What Is A RESTful API? Explanation of REST & HTTP
https://www.youtube.com/watch?v=Q-BpqyOT3a8

Traversy Media — HTTP Crash Course & Exploration
https://www.youtube.com/watch?v=iYM2zFP3Zn0

Automation Step by Step — Postman Beginner Tutorial: What is Postman
https://www.youtube.com/watch?v=cGn_LTFCif0


### S3_19 — Backend e Persistência de Dados

**Entrega indicada:** Modelo MER, script SQL e API funcional com operações CRUD persistidas em banco relacional.

Leituras Obrigatórias
    ELMASRI; NAVATHE.
Fundamentals of Database Systems.
Capítulo 3 – Data Modeling Using the Entity-Relationship Model.
Capítulo 7 – The Relational Data Model.
Capítulo 8 – SQL.

FASTAPI Documentation.
Tutorial: Path Operations.
Tutorial: SQL Databases.

FLASK Documentation.
Tutorial: Flaskr Application.
        

**Referências complementares**
 Leituras Complementares
    SILBERSCHATZ; KORTH; SUDARSHAN.
Database System Concepts.

SQLite Documentation.
        

**Vídeos indicados**
 Vídeos
    freeCodeCamp — Learn Flask for Python
https://www.youtube.com/watch?v=Z1RJmh_OqeA

CS50 SQL — Week 2: Designing (modelo e CREATE TABLE)
https://cs50.harvard.edu/sql/weeks/2/

CS50 SQL — Week 3: Writing (INSERT, UPDATE e DELETE)
https://cs50.harvard.edu/sql/weeks/3/


### S3_20 — Redes, Segurança, LGPD e Sustentabilidade

**Entrega indicada:** Relatório técnico contendo análise dos mecanismos de comunicação da aplicação, proposta de controle de acesso baseada no menor privilégio, identificação de requisitos LGPD aplicáveis ao sistema, análise estatística simples dos dados e reflexão sobre sustentabilidade.

Leituras Obrigatórias
    KUROSE, James F.; ROSS, Keith.
Computer Networking: A Top-Down Approach.
Capítulo 1 – Computer Networks and the Internet.
Capítulo 3 – Transport Layer (seções TCP e UDP).

STALLINGS, William.
Network Security Essentials.
Capítulos introdutórios sobre autenticação, controle de acesso e segurança.

Lei nº 13.709/2018 (LGPD).
Artigos 5º, 6º, 7º e 46º.
        

**Referências complementares**
 Leituras Complementares
    TANENBAUM, Andrew.
Computer Networks.
Capítulos sobre TCP/IP.

MONTGOMERY, Douglas.
Applied Statistics and Probability for Engineers.
Capítulos introdutórios sobre estatística descritiva.

Green Software Foundation – materiais introdutórios sobre computação sustentável.
        

**Vídeos indicados**
 Vídeos
    Code.org — The Internet: IP Addresses & DNS
https://www.youtube.com/watch?v=5o8CwafCxnU

Code.org — The Internet: Packets, Routing & Reliability
https://www.youtube.com/watch?v=AYdF7b3nMto

Computerphile — TCP: entrega confiável e em ordem
https://www.youtube.com/watch?v=IADOV8UZO34

Harvard CS50 Cybersecurity — Securing Accounts
https://cs50.harvard.edu/cybersecurity/weeks/0/

Kultivi — Revisão dos Conceitos da LGPD
https://www.youtube.com/watch?v=yXiagNFYpPk

Crash Course — Mean, Median, and Mode
https://www.youtube.com/watch?v=kn83BA7cRNM

GOTO Conferences — Building Green Software Part 1: Introduction, Anne Currie
https://www.youtube.com/watch?v=Ez8cqoSRVsA


### S4_01 — Arquitetura de Software e Separação de Camadas

**Entrega indicada:** Diagrama de camadas do Trabalho 02, projeto reorganizado em pacotes por responsabilidade e seção do README descrevendo a arquitetura adotada.

Leituras Obrigatórias
    PERCIVAL, Harry; GREGORY, Bob.
Architecture Patterns with Python. O'Reilly.
Introdução; Capítulo 2 – Repository Pattern; Capítulo 4 – Flask API and Service Layer.
Versão online gratuita: https://www.cosmicpython.com/book/preface.html

FOWLER, Martin.
Patterns of Enterprise Application Architecture.
Capítulo 1 – Layering.

MARTIN, Robert C.
Clean Architecture.
Capítulo 22 – The Clean Architecture.
        

**Referências complementares**
 Leituras Complementares
    FOWLER, Martin. Presentation Domain Data Layering:
https://martinfowler.com/bliki/PresentationDomainDataLayering.html

Documentação Oficial Python – Módulos e Pacotes:
https://docs.python.org/pt-br/3/tutorial/modules.html
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=f6zXyq4VPP8


### S4_02 — SOLID: Princípios de Projeto Orientado a Objetos

**Entrega indicada:** Código do Trabalho 02 refatorado segundo os princípios SOLID, com interface de repositório e pelo menos duas implementações, acompanhado de relatório das violações encontradas e das correções aplicadas.

Leituras Obrigatórias
    MARTIN, Robert C.
Agile Software Development: Principles, Patterns, and Practices.
Capítulos 8 a 12 – SRP, OCP, LSP, DIP e ISP.

MARTIN, Robert C.
Clean Architecture.
Parte III – Design Principles (Capítulos 7 a 11).

Complementar: https://realpython.com/solid-principles-python/
        

**Referências complementares**
 Leituras Complementares
    RAMALHO, Luciano. Python Fluente, 2ª ed.
Capítulo 13 – Interfaces, Protocolos e ABCs.

Documentação Oficial Python – abc:
https://docs.python.org/3/library/abc.html

PEP 544 – Protocols:
https://peps.python.org/pep-0544/
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=pTB30aXS77U


### S4_03 — Padrões de Projeto: Introdução ao Design Patterns

**Entrega indicada:** Implementação de Factory, Repository e Strategy no Trabalho 02, com documento curto justificando cada padrão adotado.

Leituras Obrigatórias
    GAMMA, Erich; HELM, Richard; JOHNSON, Ralph; VLISSIDES, John.
Design Patterns: Elements of Reusable Object-Oriented Software.
Capítulo 1 – Introduction.

FREEMAN, Eric; ROBSON, Elisabeth.
Head First Design Patterns, 2nd ed.
Capítulos 1 (Strategy), 2 (Observer) e 4 (Factory).

Complementar: https://refactoring.guru/design-patterns
        

**Referências complementares**
 Leituras Complementares
    RAMALHO, Luciano. Python Fluente, 2ª ed.
Capítulo 10 – Padrões de Projeto com Funções de Primeira Classe.

PERCIVAL, Harry; GREGORY, Bob. Architecture Patterns with Python.
Capítulo 2 – Repository Pattern.
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=3GT1rMVBnAA&list=PLAgbpJQADBGL2CLP1sJB54VPjBewYhfRo


### S4_04 — Persistência de Dados em JSON e Modelagem Orientada a Objetos

**Entrega indicada:** Camada de persistência do Trabalho 02 funcionando, com arquivos JSON de exemplo em formato de array de objetos e evidência de gravação e recarga preservando tipos e vínculos.

Leituras Obrigatórias
    Documentação Oficial Python – json:
https://docs.python.org/3/library/json.html

Documentação Oficial Python – dataclasses:
https://docs.python.org/3/library/dataclasses.html

RAMALHO, Luciano. Python Fluente, 2ª ed.
Capítulo 5 – Construtores de Classes de Dados.

BRAY, T. (ed.). RFC 8259 – The JavaScript Object Notation (JSON) Data Interchange Format.
https://www.rfc-editor.org/rfc/rfc8259
        

**Referências complementares**
 Leituras Complementares
    JSON Schema:
https://json-schema.org/

Documentação Oficial Python – os.replace:
https://docs.python.org/3/library/os.html#os.replace
        

**Vídeos indicados**
 Vídeos
    Harvard CS50P – Week 6: File I/O
https://cs50.harvard.edu/python/weeks/6/


### S4_05 — Arquitetura Cliente-Servidor e Sistemas Multicamadas

**Entrega indicada:** Trabalho 02 executando como serviço HTTP contínuo, com endpoint de verificação de funcionamento, cliente de teste e diagrama da arquitetura.

Leituras Obrigatórias
    TANENBAUM, Andrew S.; VAN STEEN, Maarten.
Distributed Systems.
Capítulo 2 – Architectures.

KUROSE, James F.; ROSS, Keith W.
Redes de Computadores e a Internet.
Capítulo 2 – Camada de Aplicação.

FASTAPI Documentation – Tutorial:
https://fastapi.tiangolo.com/tutorial/
        

**Referências complementares**
 Leituras Complementares
    MDN Web Docs. HTTP Overview.

FLASK Documentation – Quickstart:
https://flask.palletsprojects.com/en/stable/quickstart/
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=L5BlpPU_muY

https://www.youtube.com/watch?v=ve82kSSj_Hs


### S4_06 — SQL Relacional: JOINs e Consultas Integradas

**Entrega indicada:** Script SQL de criação das tabelas, conjunto de consultas com junções comentadas e módulo Python executando as consultas de forma parametrizada.

Leituras Obrigatórias
    ELMASRI, Ramez; NAVATHE, Shamkant B.
Fundamentals of Database Systems.
Capítulo sobre consultas SQL complexas (More SQL: Complex Queries), incluindo junções.

SQLite Documentation – SELECT:
https://www.sqlite.org/lang_select.html

Documentação Oficial Python – sqlite3:
https://docs.python.org/3/library/sqlite3.html
        

**Referências complementares**
 Leituras Complementares
    SILBERSCHATZ; KORTH; SUDARSHAN.
Database System Concepts.
Capítulos sobre SQL intermediário.
        

**Vídeos indicados**
 Vídeos
    CS50 SQL — Week 1: Relating
https://cs50.harvard.edu/sql/weeks/1/


### S4_07 — SQL: Agregações e Relatórios com GROUP BY

**Entrega indicada:** Conjunto de consultas de relatório comentadas e relatório gerado a partir do banco de dados do Trabalho 02.

Leituras Obrigatórias
    ELMASRI, Ramez; NAVATHE, Shamkant B.
Fundamentals of Database Systems.
Seções sobre funções de agregação e agrupamento em SQL.

SQLite Documentation – Aggregate Functions:
https://www.sqlite.org/lang_aggfunc.html

SQLite Documentation – SELECT:
https://www.sqlite.org/lang_select.html
        

**Referências complementares**
 Leituras Complementares
    SILBERSCHATZ; KORTH; SUDARSHAN.
Database System Concepts.
Seções sobre agregação e agrupamento.
        

**Vídeos indicados**
 Vídeos
    CS50 SQL — Week 0: Querying
https://cs50.harvard.edu/sql/weeks/0/

CS50 SQL — Week 1: Relating
https://cs50.harvard.edu/sql/weeks/1/


### S4_08 — Tabelas Hash e Otimização de Consultas

**Entrega indicada:** Implementação da tabela hash simples, índices aplicados ao Trabalho 02 e relatório comparando tempos de busca e planos de execução.

Leituras Obrigatórias
    CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 11 – Hash Tables.

GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael H.
Data Structures and Algorithms in Python.
Capítulo 10 – Maps, Hash Tables, and Skip Lists.

Documentação Oficial Python – Modelo de Dados (__hash__):
https://docs.python.org/3/reference/datamodel.html#object.__hash__
        

**Referências complementares**
 Leituras Complementares
    Python Wiki – TimeComplexity:
https://wiki.python.org/moin/TimeComplexity

SQLite Documentation – EXPLAIN QUERY PLAN:
https://www.sqlite.org/eqp.html

VisuAlgo – Hash Table:
https://visualgo.net/en/hashtable
        

**Vídeos indicados**
 Vídeos
    MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 4: Hashing
https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/

CS50 SQL — Week 5: Optimizing
https://cs50.harvard.edu/sql/weeks/5/


### S4_09 — Estruturas Hierárquicas: Árvores Binárias

**Entrega indicada:** Implementação da árvore binária de busca com testes, percursos e relatório comparando a altura da árvore em diferentes ordens de inserção.

Leituras Obrigatórias
    GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael H.
Data Structures and Algorithms in Python.
Capítulo 8 – Trees.
Capítulo 11 – Search Trees.

CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 12 – Binary Search Trees.
        

**Referências complementares**
 Leituras Complementares
    VisuAlgo – Binary Search Tree:
https://visualgo.net/en/bst
        

**Vídeos indicados**
 Vídeos
    MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 6: Binary Trees, Part 1
MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 7: Binary Trees, Part 2: AVL
https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/


### S4_10 — Busca em Grafos: BFS e DFS

**Entrega indicada:** Módulo de grafos aplicado ao Trabalho 02, com BFS, DFS, detecção de ciclos e relatório de alcançabilidade a partir de ativos expostos.

Leituras Obrigatórias
    GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael H.
Data Structures and Algorithms in Python.
Capítulo 14 – Graph Algorithms.

CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 22 – Elementary Graph Algorithms.
        

**Referências complementares**
 Leituras Complementares
    VisuAlgo – DFS e BFS:
https://visualgo.net/en/dfsbfs

MITRE ATT&CK – Lateral Movement (TA0008):
https://attack.mitre.org/tactics/TA0008/
        

**Vídeos indicados**
 Vídeos
    MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 9: Breadth-First Search
MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 10: Depth-First Search
https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/


### S4_11 — Algoritmos de Ordenação Avançados: Merge Sort

**Entrega indicada:** Implementação do Merge Sort com testes e ranking de equipamentos do Trabalho 02 ordenado por risco.

Leituras Obrigatórias
    CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 2 – Seção 2.3 (Designing Algorithms).

GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael H.
Data Structures and Algorithms in Python.
Capítulo 12 – Sorting and Selection.
        

**Referências complementares**
 Leituras Complementares
    Documentação Oficial Python – Sorting Techniques:
https://docs.python.org/3/howto/sorting.html

VisuAlgo – Sorting:
https://visualgo.net/en/sorting
        

**Vídeos indicados**
 Vídeos
    MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 3: Sets and Sorting
https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/


### S4_12 — Algoritmos de Ordenação Avançados: Quick Sort

**Entrega indicada:** Implementação do Quick Sort com testes e relatório comparativo de desempenho entre Quick Sort, Merge Sort e sorted().

Leituras Obrigatórias
    CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 7 – Quicksort.

GOODRICH, Michael T.; TAMASSIA, Roberto; GOLDWASSER, Michael H.
Data Structures and Algorithms in Python.
Capítulo 12 – Sorting and Selection.
        

**Referências complementares**
 Leituras Complementares
    VisuAlgo – Sorting:
https://visualgo.net/en/sorting

Documentação Oficial Python – timeit:
https://docs.python.org/3/library/timeit.html
        

**Vídeos indicados**
 Vídeos


### S4_13 — Complexidade Computacional de Estruturas e Algoritmos

**Entrega indicada:** Tabela de complexidades, relatório de perfilamento do Trabalho 02 e medições do cálculo de risco com análise do crescimento observado.

Leituras Obrigatórias
    CORMEN, Thomas H. et al.
Introduction to Algorithms, 3rd ed.
Capítulo 3 – Growth of Functions.
Capítulo 17 – Amortized Analysis.

Python Wiki – TimeComplexity:
https://wiki.python.org/moin/TimeComplexity
        

**Referências complementares**
 Leituras Complementares
    Documentação Oficial Python – timeit:
https://docs.python.org/3/library/timeit.html

Documentação Oficial Python – The Python Profilers:
https://docs.python.org/3/library/profile.html
        

**Vídeos indicados**
 Vídeos
    MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 1: Algorithms and Computation
MIT 6.006 Introduction to Algorithms (Spring 2020) — Lecture 2: Data Structures and Dynamic Arrays
https://ocw.mit.edu/courses/6-006-introduction-to-algorithms-spring-2020/


### S4_14 — Testes Automatizados com Pytest

**Entrega indicada:** Suíte pytest do Trabalho 02 cobrindo persistência, regras de negócio e cálculo de risco, com relatório de cobertura e workflow de integração contínua executando os testes.

Leituras Obrigatórias
    OKKEN, Brian.
Python Testing with pytest, 2nd ed. Pragmatic Bookshelf.
Capítulos 2 (Writing Test Functions), 3 (pytest Fixtures) e 5 (Parametrization).

pytest Documentation:
https://docs.pytest.org/
        

**Referências complementares**
 Leituras Complementares
    pytest-cov Documentation:
https://pytest-cov.readthedocs.io/

GitHub Actions Documentation:
https://docs.github.com/en/actions
        

**Vídeos indicados**
 Vídeos
    Harvard CS50P – Week 5: Unit Tests
https://cs50.harvard.edu/python/weeks/5/


### S4_15 — Docker: Conceitos Fundamentais e Containers

**Entrega indicada:** Roteiro executado com os comandos Docker essenciais, evidências de execução e explicação da diferença entre imagem, container e volume.

Leituras Obrigatórias
    Docker Documentation – Get started:
https://docs.docker.com/get-started/

KANE, Sean P.; MATTHIAS, Karl.
Docker: Up & Running, 3rd ed. O'Reilly.
Capítulos introdutórios sobre containers, imagens e o Docker Engine.
        

**Referências complementares**
 Leituras Complementares
    POULTON, Nigel.
Docker Deep Dive.
Capítulos sobre imagens e containers.
        

**Vídeos indicados**
 Vídeos
    Docker Docs — What is a container? (página com vídeo)
https://docs.docker.com/guides/docker-concepts/the-basics/what-is-a-container/

Docker Docs — What is an image? (página com vídeo)
https://docs.docker.com/guides/docker-concepts/the-basics/what-is-an-image/

https://www.youtube.com/watch?v=DdoncfOdru8


### S4_16 — Dockerfiles, Imagens e Execução de Aplicações Python

**Entrega indicada:** Dockerfile e .dockerignore do Trabalho 02, imagem construída com sucesso e evidência de execução local do container.

Leituras Obrigatórias
    Docker Documentation – Dockerfile reference:
https://docs.docker.com/reference/dockerfile/

Docker Documentation – Building best practices:
https://docs.docker.com/build/building/best-practices/

Docker Hub – Imagem oficial Python:
https://hub.docker.com/_/python
        

**Referências complementares**
 Leituras Complementares
    KANE, Sean P.; MATTHIAS, Karl.
Docker: Up & Running, 3rd ed.
Capítulo sobre construção de imagens.
        

**Vídeos indicados**
 Vídeos
    Docker Docs — Writing a Dockerfile (página com vídeo)
https://docs.docker.com/guides/docker-concepts/building-images/writing-a-dockerfile/


### S4_17 — Docker Compose e Aplicações Multicontainer

**Entrega indicada:** Arquivo compose.yaml do Trabalho 02 com volume, política de reinício e healthcheck, acompanhado de evidências dos testes de reinício e de persistência.

Leituras Obrigatórias
    Docker Documentation – Docker Compose:
https://docs.docker.com/compose/

Docker Documentation – Compose file reference:
https://docs.docker.com/reference/compose-file/
        

**Referências complementares**
 Leituras Complementares
    Docker Documentation – seção sobre políticas de reinício (restart policies) do Docker Engine.

KANE, Sean P.; MATTHIAS, Karl.
Docker: Up & Running, 3rd ed.
Capítulo sobre Docker Compose.
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=D_ha0g9yS2E


### S4_18 — Monitoramento e Logs de Aplicações

**Entrega indicada:** Trabalho 02 instrumentado com logging, configuração de rotação de logs e registro de monitoramento de disponibilidade.

Leituras Obrigatórias
    Documentação Oficial Python – Logging HOWTO:
https://docs.python.org/3/howto/logging.html

The Twelve-Factor App – XI. Logs:
https://12factor.net/logs

OWASP Cheat Sheet Series – Logging Cheat Sheet:
https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
        

**Referências complementares**
 Leituras Complementares
    Docker Documentation – seção Logging do Docker Engine.

Documentação Oficial Python – logging:
https://docs.python.org/3/library/logging.html
        

**Vídeos indicados**
 Vídeos


### S4_19 — Implantação de Aplicações em Ambiente Linux

**Entrega indicada:** Trabalho 02 implantado no servidor Linux, com roteiro de implantação documentado e evidência de funcionamento após reinicialização.

Leituras Obrigatórias
    SHOTTS, William.
The Linux Command Line (edição gratuita).
Parte 1 – Learning the Shell (navegação, permissões e processos).
https://linuxcommand.org/tlcl.php

Docker Documentation – Install Docker Engine on Ubuntu:
https://docs.docker.com/engine/install/ubuntu/

Docker Documentation – Linux post-installation steps:
https://docs.docker.com/engine/install/linux-postinstall/
        

**Referências complementares**
 Leituras Complementares
    Ubuntu Server Documentation:
https://ubuntu.com/server/docs
        

**Vídeos indicados**
 Vídeos
    https://www.youtube.com/watch?v=YHFzr-akOas&list=PLS1QulWo1RIb9WVQGJ_vh-RQusbZgO_As


### S4_20 — Integração do Trabalho 2: Aplicação OO Executando em Container

**Entrega indicada:** Repositório do Trabalho 02 com código-fonte, testes, Dockerfile, compose.yaml e README; aplicação em execução no servidor por no mínimo 24 horas; roteiro da apresentação de cinco minutos.

Leituras Obrigatórias
    Enunciado do Trabalho 02 (versão vigente).

Revisão dos cards S3_01, S3_09 a S3_12, S4_04 e S4_14 a S4_19.
        

**Referências complementares**
 Leituras Complementares
    Make a README:
https://www.makeareadme.com/
        

**Vídeos indicados**
 Vídeos


## Registro final de pendências externas

- PDFs de enunciado: não lidos; acesso aos anexos bloqueado/indisponível.
- Vídeos YouTube: links inventariados; não assistidos e sem transcrições integrais recuperadas.
- Livros comerciais: indicações bibliográficas catalogadas; texto integral não fornecido.
- Aprovação do professor sobre migração de persistência: relatada pelo aluno, a registrar na especificação.
- Execução remota de CI, Docker web e disponibilidade de 24h: ainda não realizadas.

A revisão técnica acessível está registrada acima. A validação integral do material acadêmico permanece condicionada a esses conteúdos e evidências; este documento não os presume aprovados.
