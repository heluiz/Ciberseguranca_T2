# SENTINEL Web — implementação em revisão

A versão web usa Django 5.2 LTS, PostgreSQL, templates HTML, CSS, JavaScript, SVG e Cytoscape.js. A CLI original permanece disponível. Esta branch é local; não houve publicação nem implantação no servidor.

**Pendências confirmadas na revisão de 11/11/2026:** exportação permite consultar vulnerabilidades com apenas a permissão de visualizar ativos; listagens REST param em 100 registros sem paginação. O contrato de Repository também não permite substituir os serviços completos por um adaptador em memória. Os testes existentes passam, mas não cobriam esses casos. Ver [relatório completo](REVISAO-SPRINTS-2026-11-11.md). Falhas ainda não corrigidas nesta rodada de revisão.

A revisão visual segue a referência enviada pelo aluno; veja [VISUAL.md](VISUAL.md) e o vídeo real dos efeitos em `screenshots/sentinel-neon.mp4`.

## Funcionalidades

- Login por sessão, logout por POST, alteração de senha e grupos Administrador, Analista e Leitor.
- Inventário com sete tipos, ficha técnica, pesquisa, paginação e validação do domínio original.
- Catálogo de vulnerabilidades compartilhadas, CVE/CWE, CVSS e vetor com conferência da nota.
- Datas de detecção/correção por ocorrência, linha do tempo e exportação administrativa de histórico (veja [TRATAMENTOS.md](TRATAMENTOS.md)).
- Tratamento por ativo; corrigida sai do risco, aceita como risco continua contando.
- Dependências direcionadas com frações e soma abaixo de 1, protegidas também por trigger PostgreSQL.
- Painel, ranking, plano de correção, relatório por setor e mapa com seleção, busca, zoom e enquadramento.
- Importação inicial de JSON com validação, simulação, transação, reconciliação e recibo idempotente; exportação compatível.
- Consulta local ao CISA KEV incluído no projeto. Atualização remota continua no fluxo CLI original; não há atualização automática ou URL arbitrária na web.
- API de sessão para os quatro recursos, com CSRF e permissões por recurso; revisar a inconsistência de autorização da exportação descrita acima.
- Auditoria de mutações e autenticação; eventos de administração de usuários também têm o histórico do admin Django.

## Arquitetura

`sentinel/` configura HTTP, segurança e PostgreSQL. `inventory/views.py` entrega HTML e JSON, os formulários permitem somente campos explícitos, `services.py` executa casos de uso e `repository.py` reconstrói os objetos de domínio originais. `models.py` representa o esquema relacional. `academic/` guarda os algoritmos didáticos.

A Factory original escolhe a subclasse de equipamento; o polimorfismo fornece o fator de exposição. O Repository possui adaptadores PostgreSQL e memória. O serviço aplica autorização e transação. O cálculo continua em `risco.ModeloRisco`: `x = b + Ax`, usando `numpy.linalg.solve`, diagnóstico de condição e conferência de resíduo.

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

## Verificações e pendências

Os testes automatizados cobrem migração, equivalência de risco, permissões negativas, CSRF, escape HTML, API, versões, concorrência na soma das dependências, MFA, limitação de login e algoritmos. A suíte CLI original é executada separadamente.

Ainda exigem evidência em ambiente real: construção e execução de Docker Compose, domínio/HTTPS externo, teste de indisponibilidade/reinício, monitoramento HTTP por 24 horas, auditoria manual de acessibilidade/teclado e revisão de segurança antes da exposição pública. Docker não está disponível neste ambiente de desenvolvimento. A documentação acadêmica integral, protótipo Figma e apresentação devem ser concluídos pelo aluno; não são comprovados só pela implementação.
