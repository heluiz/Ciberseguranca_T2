# Evidências desta versão local

## Correções posteriores à revisão — 11/11/2026

Autorização da exportação/dashboard e paginação REST corrigidas: 115 testes originais e 69 web/didáticos passaram, com 85% de cobertura agregada de `inventory` + `academic`. O modo local agora serve os CSS/JS: cinco endereços HTTP retornaram 200 com PostgreSQL real. Iniciador Windows preparado e verificado em PowerShell/Linux com serviços simulados; Docker Desktop/Windows real continua sem acesso para confirmação. Detalhes em [INICIALIZACAO-WINDOWS.md](INICIALIZACAO-WINDOWS.md). Os achados R01/R02 abaixo descrevem a versão anterior.

## Revisão contra as sprints — 11/11/2026

No commit de aplicação `73c4a6e`, foram reexecutados os 115 testes originais, 57 testes web/didáticos e Ruff: todos passaram. Cobertura agregada de `inventory` e `academic`: 84% (946 instruções, 150 não cobertas).

Duas verificações adicionais encontraram defeitos ainda abertos: uma conta com apenas `view_asset` recebe 403 na API de vulnerabilidades, mas 200 na exportação com essas vulnerabilidades; a API de dependências retorna 100 dos 164 registros sem mecanismo de continuação. A conta de teste foi usada em transação revertida. Não houve correção de aplicação nesta rodada.

O [relatório detalhado](REVISAO-SPRINTS-2026-11-11.md) compara os 79 cartões e cataloga as referências. PDFs de enunciado e conteúdo integral dos vídeos sem transcrição permanecem pendentes. A base original foi confrontada com a árvore remota (34 itens, sem diferenças); não houve push ou implantação.

## Evidências das etapas anteriores

Verificações executadas em 11/11/2026, com Python 3.12.14 e PostgreSQL 17.11 reais:

- 115 testes originais: passaram.
- 57 testes novos: passaram, com cerca de 84% de cobertura agregada dos módulos web e didáticos medidos. Cobertura não equivale a ausência de falhas.
- Migrações aplicadas e `makemigrations --check --dry-run`: sem alteração pendente.
- Ruff: passou.
- `check --deploy --fail-level WARNING`, com configuração de produção: sem alertas.
- `pip-audit -r requirements-web.txt`: nenhuma vulnerabilidade conhecida encontrada na consulta realizada. A verificação deve ser repetida antes de publicar.
- 76 ativos importados, referências preservadas e risco total 1348,055858 reconciliado com o JSON original.
- `pg_dump` e restauração em banco separado: inventário e risco equivalentes.
- Navegador Chromium: login, painel, grafo real, quatro listagens, cadastro/edição/exclusão de ativo, viewport móvel de 390 px sem transbordamento da página e sem exceções JavaScript no fluxo testado.
- Capturas reais em `screenshots/`: painel desktop, mapa desktop, foco alternativo, mapa mobile e painel mobile; vídeo real dos efeitos em `sentinel-neon.mp4`.

As capturas usam exclusivamente o inventário de exemplo do repositório. A conta temporária de teste foi removida após a navegação. Os testes visuais usam modo local, sem expor a aplicação à internet.

Docker Compose teve a sintaxe YAML conferida; não houve build ou execução do conjunto Docker neste ambiente. CI, domínio/HTTPS externo, disponibilidade de 24 horas, acessibilidade manual completa e revisão independente de segurança continuam sem evidência operacional. Nenhum push, PR ou implantação foi feito.

A revisão de neon e mapa está descrita em [VISUAL.md](VISUAL.md). Foram testados também o modo com todos os ativos, busca por tipo, controles visuais e simulação sem gravação.

Direção visual do risco: API e navegador conferem que A depende de B implica animação B → A. Verificadas as 164 conexões desenhadas e curvas separadas para relações recíprocas, além de fixture com frações 50%/25% nos dois sentidos.

Datas de tratamento: 57 testes novos passaram no PostgreSQL, incluindo datas desconhecidas, limites cronológicos, fuso, reabertura, histórico preservado após exclusão, permissões, CSV e ausência de efeito das datas no risco. O navegador exercitou fechamento, reabertura e linha do tempo; capturas em `datas-tratamento.png` e `historico-tratamento.png`.

Temas: verificados no navegador os quatro esquemas, persistência ao recarregar e navegar, fallback de preferência inválida, cores dos SVG e gravidade preservada; tema verde em celular sem transbordamento. Marca gráfica derivada das referências do aluno, sem dizeres acadêmicos dentro do símbolo. Veja `TEMAS.md`.

### Leitura da marca no cabeçalho

Marca SVG simplificada com escudo maior, fechadura preenchida, circuitos secundários e brilho reduzido. Conferida no Chromium real nos quatro temas: cabeçalho de 46 px, celular de 38 px e entrada de 74 px. Viewport de 390 × 844 px sem transbordamento horizontal da página e sem erros JavaScript. Capturas: `screenshots/logo-corrigida-previa.png`, `screenshots/mapa-logo-corrigida-mobile-tela.png` e `screenshots/mapa-logo-corrigida-mobile.png` (página completa). Mudança visual; suíte de backend não reexecutada nesta revisão.

### Configuração discreta de aparência

Tema recolhido em uma engrenagem, com nomes de cores. Conferidos no Chromium: abertura por teclado, Escape com retorno do foco, clique externo, quatro paletas, persistência após recarga, uso na entrada e larguras de 320, 390, 768 e 1600 px. Menu dentro da tela, sem transbordamento horizontal da página e sem erros JavaScript. Capturas: `screenshots/aparencia-desktop.png`, `screenshots/aparencia-celular.png` e `screenshots/aparencia-configuracoes.png`.
