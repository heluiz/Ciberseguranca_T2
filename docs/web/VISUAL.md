# Revisão visual com base na referência do aluno

O mapa foi reconstruído seguindo a imagem enviada: cabeçalho com escudo, barra lateral, métricas compactas, cartões de ativos com ícones, grade de fundo, conexões luminosas, inspeção à direita e correções abaixo do mapa. O tema foi aplicado também à estrutura das demais páginas.

## Interação e efeitos

- SVG com cartões acessíveis por teclado; Cytoscape fornece o modelo do grafo em memória.
- Ícones locais de estação, servidor, roteador, impressora, sistema e banco de dados.
- Fluxo visual nas conexões, halo no cartão selecionado, realce de controles e fundo com curvas de neon.
- Botão para pausar efeitos e respeito a `prefers-reduced-motion`; a animação é decorativa, não mede tráfego.
- Clique inspeciona o ativo. Duplo clique muda o foco para suas relações. Busca aceita hostname, setor e tipo.
- O modo de foco prioriza cartões legíveis e um recorte de relações realmente cadastradas. “Todos os ativos” mostra o conjunto completo. Há zoom, arraste, enquadramento e expansão do mapa.
- No celular, o mapa começa ampliado ao redor do foco; é possível arrastar e usar os controles para explorar.
- A ficha mostra os dados completos e os tratamentos. A simulação calcula a correção das vulnerabilidades ativas do ativo sem gravar alterações.

## Precisão dos dados

Nenhum ativo, ligação ou valor da imagem conceitual foi inventado na aplicação. Os percentuais das setas são as frações de dependência. A convenção do mapa é a propagação do risco: se A depende de B, seta e animação vão de B para A. Relações recíprocas têm curvas separadas e podem ter frações diferentes. O esquema relacional e os campos `source`/`target` da API continuam representando a dependência; `risk_source`/`risk_target` explicitam a direção visual. Risco próprio, herdado, efetivo e redução prevista são pontos do modelo, não percentuais. Gravidade nos cartões é baseada no maior CVSS não corrigido.

O plano usa a redução calculada pelo ModeloRisco. “Revisar tratamento” abre os tratamentos filtrados pelo ativo; não se apresenta uma remediação genérica como solução comprovada de uma CVE.

## Validação

Testes de navegador: login, seleção, detalhes, busca por tipo, todos os 76 ativos, pausa de efeitos, simulação, CRUD e viewport de 390 px sem transbordamento da página. Capturas e vídeo reais com o inventário de exemplo em `screenshots/`. O vídeo `sentinel-neon.mp4` mostra quatro segundos dos efeitos ativos. A suíte PostgreSQL foi ampliada para verificar dados do painel, permissões e simulação sem escrita.

Revisão visual pelo aluno continua necessária. Nenhuma alteração foi enviada ao GitHub nem implantada no servidor.
