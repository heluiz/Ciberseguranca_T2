# SENTINEL Web — implementação

A interface web usa Django 5.2 LTS, PostgreSQL, templates HTML, CSS e JavaScript. O programa de terminal original permanece disponível e as duas interfaces usam as mesmas classes de domínio e o mesmo modelo de risco. Como executar: [EXECUTAR.md](EXECUTAR.md). O que foi verificado: [VALIDACAO.md](VALIDACAO.md).

## Funcionalidades

- Login por sessão, logout por POST, alteração de senha e grupos Administrador, Analista e Leitor.
- Inventário com sete tipos, ficha técnica, pesquisa, paginação e validação do domínio original.
- Catálogo de vulnerabilidades compartilhadas, CVE/CWE, CVSS e vetor com conferência da nota.
- Datas de detecção/correção por ocorrência, linha do tempo e exportação administrativa de histórico (veja [TRATAMENTOS.md](TRATAMENTOS.md)).
- Tratamento por ativo; corrigida sai do risco, aceita como risco continua contando.
- Dependências direcionadas com frações e soma abaixo de 1, protegidas também por trigger PostgreSQL.
- Análise de risco: verificação de invertibilidade de I − A antes de resolver, risco próprio e efetivo de todos os equipamentos em tabela com filtro e ordenação, matrizes montadas (inventários pequenos), ciclos de dependência e dois cenários de demonstração somente de leitura (um conferível à mão e um singular).
- Ficha do ativo com a origem do risco herdado e os ativos alcançados a partir dele, com número de saltos.
- Listagens com busca por todos os campos do ativo (inclusive custodiante, ficha técnica e ID) e filtros por tipo, situação e gravidade.
- Painel, ranking, plano de correção, relatório por setor e mapa com seleção, busca, zoom e enquadramento.
- Importação inicial de JSON com validação, simulação, transação, reconciliação e recibo idempotente; exportação compatível.
- Consulta local ao CISA KEV incluído no projeto. Atualização remota continua no fluxo CLI original; não há atualização automática ou URL arbitrária na web.
- API REST de sessão para os quatro recursos (GET, POST, PUT, PATCH e DELETE), com CSRF, permissões por recurso e paginação, e coleção Postman com testes automáticos; exportação completa exige as quatro permissões de leitura do inventário.
- Auditoria de mutações e autenticação; eventos de administração de usuários também têm o histórico do admin Django.

## Arquitetura

`sentinel/` configura HTTP, segurança e PostgreSQL. `inventory/views.py` entrega HTML e JSON; os formulários aceitam somente campos explícitos; `services.py` executa os casos de uso de escrita, com autorização e transação; `analysis.py` reúne os casos de uso de leitura; `repository.py` reconstrói os objetos de domínio originais; `models.py` representa o esquema relacional ([MODELO-DADOS.md](MODELO-DADOS.md)). `academic/` guarda as estruturas de dados e os algoritmos.

A fábrica original escolhe a subclasse de equipamento e o polimorfismo fornece o fator de exposição de cada tipo. O cálculo continua em `risco.ModeloRisco`: `x = b + Ax`, resolvido com `numpy.linalg.solve` depois do diagnóstico de invertibilidade, com conferência do resíduo.

**Inversão de dependência.** `analysis.py` não conhece Django nem PostgreSQL: recebe um repositório, isto é, qualquer objeto com `load()` que devolva um `Inventario`. A tela de análise usa `SnapshotRepository` (banco real) para o inventário e `MemoryRepository` para os cenários de demonstração; os testes executam o mesmo caso de uso com os dois e comparam os resultados. As escritas ficam em `services.py`, sobre o ORM, porque dependem de transação, trava e histórico do PostgreSQL; essa parte não tem implementação em memória.

**Algoritmos aplicados ao inventário.** O ranking de risco é ordenado pelo Merge Sort de `academic/algorithms.py`; os ativos alcançados e seus saltos vêm de uma busca em largura no grafo de dependências; os ciclos, de uma busca em profundidade. As demais estruturas (tabela hash, árvore binária de busca, lista encadeada, fila, ordenações básicas, busca binária) têm testes e medições em [MEDICOES.md](MEDICOES.md).

**Arquivos estáticos.** CSS e JavaScript são coletados na construção da imagem e entregues pela própria aplicação (WhiteNoise), o que dispensa proxy no servidor da disciplina.

O risco próprio e efetivo são pontos sem limite de 100. CVSS é a escala de 0,1 a 10. Setas mostram a propagação do risco pelas dependências declaradas, sem medir tráfego ou comprovar exploração. Ciclos não significam necessariamente singularidade.

## Decisões e diferenças do legado

1. PostgreSQL é a fonte de verdade da web, inclusive nos testes. JSON é compatibilidade de entrada/saída e arquivo histórico. A mudança decorre da orientação verbal do professor relatada pelo aluno; o requisito textual antigo de JSON deve ser explicado na apresentação.
2. A CLI ainda lê seu próprio JSON. Ela não deve ser usada para editar simultaneamente o inventário web. Não existe sincronização bidirecional.
3. A importação exige base vazia, preserva IDs, não sobrescreve inventário existente, aceita até 2 MB/1000 ativos e não altera o arquivo original. Arquivo idêntico repetido é ignorado. Guarde a cópia original em armazenamento protegido.
4. Exclusão de ativo remove seus vínculos e dependências. O catálogo é mantido mesmo sem vínculos, diferentemente da limpeza de órfãos do legado. O JSON exportado contém as falhas vinculadas aos ativos; backup completo exige `pg_dump`.
5. Escritas usam uma trava transacional do inventário e atualizam somente a entidade solicitada. Leituras de múltiplas tabelas usam a mesma trava para obter um conjunto coerente. Essa serialização privilegia correção e simplicidade; para alta carga, medir antes de substituir por travas mais granulares.
6. Campos de versão recusam alterações e exclusões baseadas em uma tela antiga com HTTP 409.
7. Backend de produção usa papel sem criação de tabelas; migrações usam outro papel. Não se registra os modelos de inventário no admin para evitar contornar os serviços.
8. O mapa é uma melhoria visual, e as tabelas oferecem uma alternativa acessível. A arte do painel é decorativa; o mapa usa o inventário real.

## Segurança e limites

Produção exige segredo externo de ao menos 50 caracteres, HTTPS, cookies Secure/HttpOnly/SameSite, CSRF, HSTS, hosts e origens explícitos, CSP com scripts locais, validação de campos e templates com escape. Senhas usam Argon2. Axes limita tentativas e django-otp verifica TOTP/códigos de recuperação. Administradores sem MFA são direcionados à verificação em produção.

O controle é por grupo em um inventário compartilhado. Não existe isolamento de organizações ou propriedade por usuário. Não cadastrar dados de investigações ou terceiros para demonstração. Responsável deve preferir cargo/setor. Não se afirma certificação OWASP nem conformidade jurídica automática com LGPD.

Os logs não incluem corpo de requisição, senha, token ou conteúdo do inventário. O banco contém sementes TOTP e códigos de recuperação: proteger disco, backups e acessos administrativos. Auditoria de aplicação não é imutável contra o proprietário do banco. Avaliar retenção, rotação e armazenamento externo antes de uso institucional.

## Verificações e limites

Os testes automatizados cobrem migração, equivalência de risco, análise de risco com banco e memória, cenário singular, filtros, permissões negativas, CSRF, escape HTML, API (inclusive PUT), versões, concorrência na soma das dependências, MFA, limitação de login, preparação da instalação e algoritmos. A suíte do programa original é executada separadamente. Os resultados estão em [VALIDACAO.md](VALIDACAO.md).

Limites conhecidos:

- A construção da imagem e o `docker compose` do servidor são verificados pelo GitHub Actions a cada push; as 24 horas no servidor da disciplina precisam ser comprovadas lá, com `sh ops/servidor/verificar.sh`.
- O inventário é único e compartilhado pelas contas; não há separação por organização.
- As escritas são serializadas por uma trava global: correto para poucos usuários simultâneos, não medido para muitos.
- A exportação JSON leva o inventário no formato do programa original; contas, datas e histórico só vão no backup do PostgreSQL.
- Risco efetivo é pontuação do modelo, não probabilidade de ataque; dependência declarada não comprova caminho de ataque.
