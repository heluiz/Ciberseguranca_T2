# Relação entre as sprints e o projeto

Resumo de onde cada cartão das Sprints 1 a 4 aparece no projeto. O programa de terminal (arquivos na raiz) e a versão web (`inventory/`, `sentinel/`, `academic/`) usam as mesmas classes de domínio.

O enunciado do Trabalho 2 cobre as Sprints 3, 4 e 5; o quadro consultado tinha cartões até a Sprint 4.

## Requisitos do enunciado (Tabela 1)

| Nº | Requisito | Onde está |
|---|---|---|
| 1 | Cada ativo é um objeto de uma classe | `equipamentos.py` (classe base e filhas por tipo, com fator de exposição polimórfico); a web reconstrói esses objetos a partir do banco em `inventory/repository.py` |
| 2 | Armazenamento em arquivo ou banco SQL, em lista de objetos JSON | Terminal: `armazenamento.py` (arquivo JSON). Web: PostgreSQL, com importação e exportação no mesmo formato JSON (`/dados/`) |
| 3 | Container em execução por 24 horas | `Dockerfile` + `compose.yaml` (terminal) e `Dockerfile.web` + `compose.servidor.yaml` (web); comprovação com `sh ops/servidor/verificar.sh` |
| 4 | Risco efetivo pelo modelo linear, verificando a invertibilidade | `risco.py`; na web, tela **Análise de risco** (`/analise/`), com o cenário conferível à mão e o cenário singular |

## Sprint 1

| Cartão | Onde está |
|---|---|
| 01 a 03 — Requisitos e critérios de aceitação | README, seção "Requisitos do Trabalho 2"; critérios escritos como testes em `testes.py` e `tests_web/` |
| 04 e 05 — Primeiro programa, variáveis e tipos | `main.py` (terminal) e `manage.py` (web); tipos conferidos nas propriedades de `equipamentos.py` e nos campos de `inventory/models.py` |
| 06 — Entrada e saída | `entrada.py` (o único módulo que chama `input()`) e `telas.py` |
| 07 e 08 — Condicionais e repetição | Laço do menu em `main.py`; perguntas repetidas até a resposta ser válida em `entrada.py` |
| 09 — Funções | Funções curtas com docstring em todos os módulos |
| 10 a 13 — Listas, tuplas, sets, dicionários e enumerações | `Inventario` (dicionários por id), `classificacoes.py` (`IntEnum` dos tipos e situações) |
| 14 — Persistência em arquivos | `armazenamento.py` (JSON com gravação atômica); na web, importação e exportação no mesmo formato |
| 15 — Tratamento de erros | Exceções do domínio, `validacao.py` e o isolamento em `main.py`; na web, erros de formulário e respostas 4xx da API |
| 16 a 19 — Git, branches e pull requests | Histórico público com 14 pull requests integrados após a verificação automática |
| 20 — Revisão | Não tem entregável próprio |

## Sprint 2

| Cartão | Onde está |
|---|---|
| 01 e 02 — Boas práticas, classes e funções | Ruff; classes de domínio; camadas separadas |
| 03 — CRUD | Terminal: opções 1 a 12. Web: Inventário, Vulnerabilidades, Tratamentos e Dependências, e a API REST |
| 04, 06 e 07 — Requisitos, critérios e especificação | README e `docs/web/` (modelo de dados, segurança, execução); os critérios estão nos testes automáticos |
| 05 — Regras e validações | Domínio, formulários (`inventory/forms.py`), serviço (`inventory/services.py`) e restrições do banco |
| 08 a 11 — Cadastro, busca, atualização e exclusão de ativos | Opções 1 a 5; na web, formulários com controle de versão e exclusão com confirmação |
| 12 a 14 — Vulnerabilidades | CVSS, CVE e CWE; catálogo KEV offline; filtros por situação e gravidade |
| 15 — Dicionários (hashmaps) | Buscas por id em O(1); `ChainedHash` em `academic/algorithms.py` |
| 16 e 17 — Branches e colaboração | Uma branch por mudança, pull request e merge após a CI |
| 18 — Testes e correções | `testes.py` (115 testes) e `tests_web/` (132 testes); seção "Defeitos encontrados e corrigidos" do README |
| 19 — Entrega do Trabalho 1 | Entregue em 25/09/2026; `migracao.py` converte o arquivo do Trabalho 1 |

## Sprint 3

| Cartão | Onde está |
|---|---|
| 01 — Orientação a objetos | Hierarquia de equipamentos, fábrica e polimorfismo do programa original, reaproveitados pela web |
| 02 — Funções de alta ordem e recursão | Funções de chave nas ordenações; Merge Sort recursivo; fatorial iterativo e recursivo; Fibonacci com e sem memorização (`academic/algorithms.py`) |
| 03 — Filas e listas encadeadas | `LinkedList` e `LinkedQueue` próprias; `deque` nas buscas em largura |
| 04 — Complexidade | Complexidade anotada em cada algoritmo; medições em [MEDICOES.md](MEDICOES.md) |
| 05 — Busca e ordenação | Bubble, Selection e Insertion Sort; busca linear e binária; comparação medida |
| 06 — Qualidade de código | Ruff (estilo e docstrings) em todo o projeto; camadas separadas |
| 07 — Testes unitários | `testes.py` (programa original) e `tests_web/` com pytest e PostgreSQL real |
| 08 — GitHub e integração contínua | `.github/workflows/`: estilo, testes, verificação de implantação e container |
| 09 a 12 — Álgebra linear e erros numéricos | `risco.py`; tela de análise mostra M, v, A, I − A, determinante, posto, número de condição e resíduo; comparação solve × inversa em MEDICOES.md |
| 13 — Lógica proposicional | Conteúdo de lista de exercícios; não é parte do programa |
| 14 — Portas lógicas e arquitetura | Conteúdo de relatório; não é parte do programa |
| 15 — Usabilidade e acessibilidade | Interface responsiva (desktop e celular), verificação automática WCAG 2.1 A/AA em [ACESSIBILIDADE.md](ACESSIBILIDADE.md). O protótipo no Figma é uma entrega à parte |
| 16 — Front-end | Templates HTML, CSS Grid e variáveis CSS; tabela de risco montada no navegador a partir de um array de objetos (`risk_table.js`) |
| 17 — JavaScript assíncrono | `fetch` com `async/await` e tratamento de falha no mapa (`graph.js`) e na tabela de risco |
| 18 — API REST e Postman | `/api/<recurso>/` com GET, POST, PUT, PATCH e DELETE; coleção Postman com 47 verificações automáticas |
| 19 — Backend e banco relacional | Django e PostgreSQL; [MODELO-DADOS.md](MODELO-DADOS.md) (diagrama) e [esquema.sql](esquema.sql) (script de criação) |
| 20 — Redes, segurança e LGPD | [SEGURANCA.md](SEGURANCA.md): autenticação, permissões, CSRF, cabeçalhos, auditoria e cuidados com dados pessoais |

## Sprint 4

| Cartão | Onde está |
|---|---|
| 01 — Separação em camadas | `views` → `services` / `analysis` → `repository` → domínio original |
| 02 — SOLID | `analysis.py` depende do contrato `InventoryRepository`, não do banco; duas implementações intercambiáveis, testadas com o mesmo caso de uso |
| 03 — Padrões de projeto | Factory (criação do equipamento pelo tipo), Repository (leitura do inventário) e Strategy (critério de ordenação do painel) |
| 04 — Persistência em JSON | Formato original preservado; importação validada e exportação compatível |
| 05 — Cliente-servidor | Navegador ↔ Gunicorn/Django ↔ PostgreSQL; endereço de saúde `/health/` |
| 06 — JOINs | Chaves estrangeiras, relação N:N e autorrelacionamento; [consultas.sql](consultas.sql) com INNER e LEFT JOIN |
| 07 — Agregações | Relatório por setor (COUNT, AVG, MAX no banco); GROUP BY, HAVING e CASE em consultas.sql |
| 08 — Tabelas hash e índices | `ChainedHash`; comparação lista × hash × dict; planos de execução com e sem índice em consultas.sql |
| 09 — Árvores binárias | `BST` com inserção, busca, percursos em ordem, pré, pós e por nível, e altura medida |
| 10 — BFS e DFS | Aplicadas ao inventário: ativos alcançados e saltos na ficha do ativo; ciclos na tela de análise |
| 11 — Merge Sort | Ordena o ranking de risco exibido na tela de análise |
| 12 — Quick Sort | `quick_sort` com pivô aleatório; comparação medida |
| 13 — Desempenho | MEDICOES.md: tempos, crescimento e perfil da análise completa |
| 14 — Pytest | Fixtures, parametrização, `approx`, `tmp_path`, cobertura acima de 80% |
| 15 a 17 — Docker e Compose | `Dockerfile.web` (usuário sem privilégio, sistema de arquivos só de leitura, verificação de saúde) e três arquivos Compose |
| 18 — Logs e monitoramento | Logs em saída padrão com rotação; container `monitor` registra a disponibilidade a cada minuto |
| 19 — Implantação em Linux | `ops/servidor/subir.sh` e `verificar.sh`; reinício automático e volume persistente |
| 20 — Integração do Trabalho 2 | Aplicação orientada a objetos em container, com o modelo de risco consultável pela web e pelo terminal |
