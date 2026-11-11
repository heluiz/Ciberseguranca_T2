# Temas e identidade visual

A interface oferece quatro paletas no seletor “Tema visual”, no cabeçalho e na tela de login:

| Tema | Referência | Características |
|---|---|---|
| Neon ciano e roxo | Referência conceitual já aprovada como direção visual | Mantém a paleta existente |
| NQ Sniper · verde neon | Código de `NQOpeningSniper.cs` fornecido pelo aluno | Verde `#00FF41`, fundo `#040A06`, monoespaçada, scanlines discretas e cantos de HUD |
| NinjaTrader · verde escuro | Print enviado pelo aluno | Verde menos saturado, superfícies escuras e barras em degradê |
| Campo Aberto · verde suave | `heluiz/campo-aberto-osint/index.html` | Verde `#6DFF9B`, fundo `#07100D`, painéis verdes e acentos âmbar |

A preferência é salva apenas no navegador por `localStorage`; não é sincronizada entre dispositivos ou contas. A escolha é restaurada antes do CSS para reduzir flashes da paleta padrão. Valores inválidos voltam ao neon original, e indisponibilidade do armazenamento não impede o uso. Mudanças feitas em outra aba do mesmo navegador são refletidas pelo evento de armazenamento.

As paletas afetam cabeçalho, menu, botões, painéis, cartões, setas, rótulos, gradientes SVG e brilho. Vermelho/rosa e amarelo das gravidades, ações de exclusão e erros mantêm seus significados. A direção do risco e os dados do inventário não dependem do tema.

A marca gráfica foi adaptada em SVG a partir da família de símbolos enviada (escudo, cadeado/fechadura e circuitos), coerente com a arte original em `banner.py`. Aparece no cabeçalho, na entrada e na visão geral, sem textos “UFU”, “Cibersegurança” ou “2ª turma” dentro do símbolo. A versão compacta prioriza um escudo maior e uma fechadura preenchida, com apenas três terminais discretos de cada lado. O anel externo foi removido e o brilho reduzido para preservar a leitura em 38 e 46 px. O nome do produto continua SENTINEL. A CLI original não foi alterada.

Referências foram inspecionadas sem executar a estratégia nem alterar o NinjaTrader. A imagem enviada contém informações de trading que não foram copiadas para a aplicação. O código de trading e as fotos de referência não são distribuídos no repositório web.

Validação de navegador: alternância das quatro opções; cor efetiva dos cartões SVG; preservação da cor de gravidade; escolha após recarregar e navegar; retorno seguro para preferência inválida; mapa e controles em viewport de 390 px sem transbordamento. Capturas reais em `screenshots/mapa-tema-*.png`.

Demonstração real de 16 segundos: `screenshots/sentinel-animacoes-verdes.mp4`. Mostra verde NQ Sniper e verde NinjaTrader com fluxo ativo, realce ao passar o mouse, seleção, zoom, pausa e retomada. Os quadros foram capturados no navegador com movimento habilitado e os tempos preservados na montagem. MP4 H.264, 1280×800, sem áudio. A gravação não altera o inventário.
