# Convenção visual e referências de animação

Referências primárias consultadas em 11/11/2026:

- [React Flow — Animating Edges](https://reactflow.dev/examples/edges/animating-edges): exemplos de animação percorrendo caminhos entre nós.
- [React Flow — Edge Markers](https://reactflow.dev/examples/edges/markers): marcadores SVG no início/fim das relações.
- [Grafana — Node graph](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/node-graph/): nós, relações, origem/destino e metadados associados.
- [Microsoft Defender — Graph icons and visualizations](https://learn.microsoft.com/en-us/defender-xdr/understand-graph-icons): relações com significados explícitos e seleção de nós/arestas para detalhes.
- [W3C — Pause, Stop, Hide](https://www.w3.org/WAI/WCAG22/Understanding/pause-stop-hide.html): controle de movimento contínuo nas condições do critério.

A pesquisa confirma o uso da técnica de animação em interfaces de grafos, mas não estabelece um estilo obrigatório de neon para produtos de cibersegurança. O neon é uma preferência visual deste projeto. O significado das conexões deve ser definido pelo modelo, em vez de inferido da estética.

No SENTINEL:

1. Se A depende de B, B transmite risco para A. A seta visual e o movimento percorrem B → A. A API mantém a dependência em `source`/`target` e explicita a direção visual em `risk_source`/`risk_target`.
2. Relações recíprocas são curvas distintas, com pesos independentes. O cálculo vem do domínio original, sem interpretar uma simples conexão física como relação de risco recíproca.
3. A seta continua visível sem animação. Há botão de pausa e respeito a movimento reduzido.
4. A animação não mede tráfego nem tempo de propagação; a velocidade é decorativa e igual nas duas cores. As frações estão nos rótulos; não são probabilidades de ataque.
5. Ciano destaca relações do ativo focal, roxo mostra contexto. Essas cores não codificam velocidade, severidade nem intensidade de ataques.
6. O foco mostra um recorte legível; a visão completa disponibiliza todas as relações, com setas estáticas para reduzir sobrecarga visual.

Essa aplicação das referências é uma decisão de design do projeto, não uma alegação de equivalência com a análise de ataques de produtos comerciais nem de conformidade integral com WCAG.
