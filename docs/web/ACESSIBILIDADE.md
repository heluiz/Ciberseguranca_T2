# Acessibilidade

## O que foi verificado

Verificação automática com o axe-core, regras WCAG 2.0 e 2.1 níveis A e AA, em um Chromium controlado por script, com os dados de exemplo carregados.

| Páginas | Temas | Resultado |
|---|---|---|
| Entrada, visão geral, análise de risco (com matrizes), inventário, tratamentos, formulário de ativo, ficha do ativo, mapa, relatórios, auditoria e catálogo KEV | Os quatro temas da interface | Nenhuma violação nas 11 páginas, em cada tema |

Também foi conferido por script, em tela de 390 px de largura, que a visão geral, a análise de risco, o inventário, os tratamentos e a ficha do ativo não geram rolagem horizontal da página.

## Correções feitas a partir da verificação

- Cartões do mapa: o nome lido pelo leitor de tela passou a ser o próprio texto visível do cartão; o tipo completo e o CVSS máximo ficam na descrição.
- Tabelas de matrizes com rolagem: recebem foco pelo teclado e têm rótulo.
- Textos de 7 a 10 px passaram para 11 px.
- A tabela de risco continua completa com o JavaScript desligado; os cabeçalhos de ordenação são botões e informam a ordem atual (`aria-sort`).

## O que a verificação automática não cobre

Ferramentas automáticas encontram só parte dos problemas de acessibilidade. Não foram feitos teste com leitor de tela, percurso completo só por teclado nem avaliação heurística com pessoas. O mapa de dependências é visual; a alternativa textual equivalente são a ficha do ativo (de onde herda risco e quem é alcançado) e a tabela da análise de risco.
