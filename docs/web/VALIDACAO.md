# Evidências desta versão local

Verificações executadas em 11/11/2026, com Python 3.12.14 e PostgreSQL 17.11 reais:

- 115 testes originais: passaram.
- 41 testes novos: passaram, com cerca de 83% de cobertura agregada dos módulos web e didáticos medidos. Cobertura não equivale a ausência de falhas.
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
