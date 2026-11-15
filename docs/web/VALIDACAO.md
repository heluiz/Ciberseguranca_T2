# Verificações desta versão

Executadas em 13 e 14/11/2026, em Linux, com Python 3.13 e PostgreSQL 16. A integração contínua repete as verificações automáticas com Python 3.12 e PostgreSQL 17, e o job `container` sobe o perfil do servidor de verdade (passou no merge do Pull Request #14).

| Verificação | Resultado |
|---|---|
| `ruff check .` | Sem apontamentos |
| `python testes.py` (programa de terminal) | 115 testes aprovados |
| `pytest` (web, com PostgreSQL real) | 132 testes aprovados |
| Cobertura de `inventory` e `academic` | 90% |
| `manage.py makemigrations --check` | Migrações em dia |
| `manage.py check --deploy` | Sem apontamentos, no perfil com HTTPS e no perfil do servidor da disciplina |
| `pip-audit -r requirements-web.txt` | Nenhuma vulnerabilidade conhecida nas dependências |
| Coleção Postman (newman) | 34 requisições e 47 verificações aprovadas, com o servidor de desenvolvimento e com o perfil do servidor (Gunicorn, sem DEBUG) |
| `docs/web/consultas.sql` | Todas as consultas executam no banco de exemplo |
| Backup e restauração (`pg_dump`/`pg_restore`, seção 10 do README) | Restauração por cima de dados alterados e numa instalação nova; o papel da aplicação continua lendo e gravando |
| Acessibilidade automática | Sem violações WCAG 2.1 A/AA nas telas, nos 4 temas ([ACESSIBILIDADE.md](ACESSIBILIDADE.md)) |

## Revisão das telas no navegador

Um roteiro no Chromium, controlado por script, percorreu todas as telas com três contas (administrador, Analista e Leitor), uma conta sem grupo e a tela de celular: 188 verificações, nenhuma falha. Inclui:

- cabeçalho (busca, sino com o número real de tratamentos em aberto, troca de tema, senha, sair) e cada item do menu;
- indicadores da visão geral, que levam às listas correspondentes (o total de ocorrências críticas bate com a lista aberta);
- cadastro, busca, filtros, paginação, edição, cancelamento e exclusão de ativos, vulnerabilidades, tratamentos e dependências, com as recusas de dado inválido;
- atalhos entre telas: da ficha do ativo para editar, excluir, vincular vulnerabilidade, alterar a situação e criar dependência (voltando para a ficha); da lista de vulnerabilidades para os ativos afetados; do relatório por setor para os ativos daquela lotação; do catálogo KEV para o cadastro já preenchido;
- mapa: busca, foco, zoom, enquadrar, tela cheia, pausa dos efeitos, teclado, simulação de correção e a tabela de prioridades;
- auditoria em português e exportação CSV, exportação JSON, validação e importação;
- criação de conta pelo painel de usuários, troca de senha, saída e entrada;
- o que cada perfil vê e o que é negado pelo endereço direto.

Também foram conferidos: todas as telas com o inventário vazio e com um único ativo, sem erro de JavaScript; e as páginas de erro 403, 404 e 500 sem modo de depuração.

## Perfil do servidor da disciplina

Simulado sem Docker, com as mesmas variáveis de `compose.servidor.yaml`:

- o banco foi criado com os dois papéis de `ops/init-db.sh` (proprietário e aplicação);
- `manage.py bootstrap`, com o papel proprietário, aplicou as migrações, criou os grupos e a conta inicial e carregou os 76 ativos; a segunda execução não alterou nada;
- o Gunicorn, com o papel da aplicação (sem permissão para criar tabelas), `DJANGO_DEBUG=0` e `DJANGO_HTTPS=0`, respondeu por HTTP a um endereço de rede interna: saúde, entrada, CSS e JavaScript, login, todas as telas, a API e uma gravação com CSRF; recusou gravação sem CSRF e endereço de host não listado;
- `ops/monitor.py` registrou a disponibilidade.

Os arquivos Compose foram validados com `docker compose config`.

## O que ainda não foi executado

- **Construção e execução dos containers.** Não havia Docker no ambiente destas verificações. O job `container` do GitHub Actions constrói a imagem, sobe `compose.servidor.yaml`, consulta a aplicação por HTTP e confere que os dados sobrevivem à recriação dos containers; o resultado aparece na aba Actions depois do push.
- **As 24 horas no servidor da disciplina.** Dependem de subir lá e aguardar; `sh ops/servidor/verificar.sh` mostra a evidência.
- **`ABRIR-SENTINEL.cmd` em um Windows com Docker Desktop.**
- **Perfil com domínio e HTTPS** (`compose.web.yaml`): exige um domínio real.
