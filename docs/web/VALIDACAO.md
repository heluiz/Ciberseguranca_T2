# Verificações desta versão

Executadas em 13/11/2026, em Linux, com Python 3.13 e PostgreSQL 16. A integração contínua repete as verificações com Python 3.12 e PostgreSQL 17.

| Verificação | Resultado |
|---|---|
| `ruff check .` | Sem apontamentos |
| `python testes.py` (programa original) | 115 testes aprovados |
| `pytest` (web, com PostgreSQL real) | 110 testes aprovados |
| Cobertura de `inventory` e `academic` | 88% |
| `manage.py makemigrations --check` | Migrações em dia |
| `manage.py check --deploy` | Sem apontamentos, no perfil com HTTPS e no perfil do servidor da disciplina |
| `pip-audit -r requirements-web.txt` | Nenhuma vulnerabilidade conhecida nas dependências |
| Coleção Postman (newman) | 34 requisições, 47 verificações aprovadas, em duas execuções seguidas |
| `docs/web/consultas.sql` | Todas as consultas executam no banco de exemplo |
| Navegador (Chromium por script) | Login, mapa, CRUD, tela de celular, filtro e ordenação da tabela de risco, sem erros de JavaScript |
| Acessibilidade automática | Sem violações WCAG 2.1 A/AA em 11 páginas e 4 temas ([ACESSIBILIDADE.md](ACESSIBILIDADE.md)) |

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
