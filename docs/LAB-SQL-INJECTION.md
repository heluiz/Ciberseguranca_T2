# Laboratório de SQL injection e mitigação

Card S5_07. O laboratório roda **só em memória**, com dados fictícios, num
módulo à parte (`academic/sqli_lab.py`) que a aplicação não importa. A rota
vulnerável nunca existiu na aplicação nem no servidor.

```bash
python -m academic.sqli_lab
python -m pytest tests_web/test_sqli_e_consultas.py -k "laboratorio or orm or api"
```

## A consulta vulnerável

```python
sql = ("SELECT hostname, lotacao FROM equipamentos "
       "WHERE lotacao = '" + lotacao + "'")
banco.execute(sql)
```

A aspa digitada pelo usuário fecha a string do SQL, e o resto vira comando.

## A demonstração (saída de `python -m academic.sqli_lab`)

| Entrada | Consulta montada | Resultado na vulnerável | Na parametrizada |
| --- | --- | --- | --- |
| `Sede` | `... WHERE lotacao = 'Sede'` | 2 equipamentos da Sede | os mesmos 2 |
| `' OR '1'='1` | `... WHERE lotacao = '' OR '1'='1'` | **todos** os equipamentos | nenhum |
| `' UNION SELECT usuario, hash_senha FROM contas --` | junta a tabela de contas | **usuários e hashes** das contas | nenhum |
| `x'; DROP TABLE equipamentos; --` (com `executescript`) | dois comandos | **a tabela some** | nenhum, a tabela fica |

## A correção

```python
banco.execute(
    "SELECT hostname, lotacao FROM equipamentos WHERE lotacao = ?",
    (lotacao,))
```

O comando e o valor vão separados ao banco (parâmetro ligado): o banco compila
o comando primeiro e só depois recebe o valor, que é sempre um dado, nunca SQL.
Escapar aspas à mão não é correção: depende de cada banco e de cada
codificação.

## Testes de regressão

`tests_web/test_sqli_e_consultas.py`:

- `test_laboratorio_concatenacao_e_exploravel`: prova que as três cargas
  funcionam na versão errada (o teste falharia se o laboratório deixasse de
  demonstrar o ataque);
- `test_laboratorio_parametro_ligado_nao_e_exploravel`: as três cargas, na
  versão parametrizada, devolvem nada e não mudam as tabelas;
- `test_orm_trata_a_carga_como_texto`: as mesmas cargas no Django ORM
  (`filter(lotacao=...)`, `hostname__icontains`) são texto literal;
- `test_api_filtros_nao_injetam`: as cargas nos filtros e na ordenação da API
  v1 (`?lotacao=`, `?tipo=`, `?ordering=`) dão 200 vazio ou 400/422, e o
  inventário continua com os mesmos registros.

## Revisão do código

Busca por SQL montado com texto no projeto inteiro:

```bash
grep -rnE "execute\(|raw\(|extra\(|cursor\(" --include=*.py . | grep -v ".venv"
bandit -c .bandit.yaml -r .
```

| Onde | Situação |
| --- | --- |
| `inventory/` (web) | Django ORM. Os três `cursor()` usam SQL fixo, sem texto do usuário: `SELECT 1` (saúde), `pg_advisory_xact_lock(%s)` com o número como parâmetro e o `sequence_reset_sql` gerado pelo próprio Django. Nenhum `raw()` ou `extra()` |
| `repositorio_sql.py` (terminal) | Só SQLAlchemy ORM (`select`, `delete`), parâmetros ligados; o único SQL literal é o `PRAGMA foreign_keys = ON`, fixo |
| `migracoes_sql/` | Comandos do Alembic (`op.create_table`), sem entrada do usuário |
| `docs/web/consultas.sql` | Consultas de estudo, executadas à mão no `psql`, sem entrada do usuário |
| `academic/sqli_lab.py` | As duas funções vulneráveis de propósito, marcadas `# nosec B608` |

## Resultado do bandit

`bandit -c .bandit.yaml -r .` (bandit 1.9.4, 12.900 linhas): **nenhum alerta
aberto**. Antes das correções eram 2 de severidade alta, 5 médias (2 do próprio laboratório) e 12 baixas
(fora os `assert` dos autotestes). Os de SQL (B608) são só os do laboratório,
marcados. O que mudou por causa dos outros alertas está em
[OWASP-TOP10.md](OWASP-TOP10.md#análise-estática-bandit).
