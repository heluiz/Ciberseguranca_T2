# Modelo de dados

O inventário fica em PostgreSQL. O script de criação está em [esquema.sql](esquema.sql) e as consultas de estudo, em [consultas.sql](consultas.sql). As classes do domínio (`Equipamento` e suas filhas, `Vulnerabilidade`, `Inventario`, `ModeloRisco`) continuam nos módulos Python originais: a cada leitura, `inventory/repository.py` monta esses objetos a partir das tabelas.

## Diagrama entidade-relacionamento

```mermaid
erDiagram
    ASSET ||--o{ FINDING : "tem"
    VULNERABILITY ||--o{ FINDING : "afeta"
    ASSET ||--o{ DEPENDENCY : "herda risco (source)"
    ASSET ||--o{ DEPENDENCY : "transmite risco (target)"
    FINDING ||--o{ FINDING_HISTORY : "registra"
    USER ||--o{ FINDING_HISTORY : "autor"
    USER ||--o{ AUDIT_EVENT : "autor"

    ASSET {
        bigint id PK
        varchar hostname UK "único sem diferenciar maiúsculas"
        smallint tipo "1 a 7 (TipoEquipamento)"
        varchar custodiante
        varchar lotacao
        varchar descricao
        varchar fabricante
        varchar modelo
        varchar numero_serie
        varchar patrimonio
        varchar patrimonio_key UK "patrimônio normalizado"
        varchar sistema
        varchar versao
        int version "controle de edição simultânea"
    }
    VULNERABILITY {
        bigint id PK
        varchar descricao
        smallint origem "1 a 6 (OrigemVulnerabilidade)"
        decimal cvss "0.1 a 10.0"
        varchar cve UK
        varchar cwe
        varchar vetor
        int version
    }
    FINDING {
        bigint id PK
        bigint asset_id FK
        bigint vulnerability_id FK
        smallint situacao "1 a 4 (SituacaoTratamento)"
        timestamptz detected_at
        timestamptz corrected_at
        int version
    }
    DEPENDENCY {
        bigint id PK
        bigint source_id FK "quem herda"
        bigint target_id FK "de quem herda"
        decimal fracao "maior que 0 e menor que 1"
        int version
    }
    FINDING_HISTORY {
        bigint id PK
        bigint finding_id FK "nulo se o tratamento foi excluído"
        bigint asset_ref
        bigint vulnerability_ref
        bigint actor_id FK
        timestamptz occurred_at
        varchar event
    }
    AUDIT_EVENT {
        bigint id PK
        bigint actor_id FK
        timestamptz occurred_at
        varchar action
        varchar target
    }
    IMPORT_RECEIPT {
        bigint id PK
        varchar digest UK "SHA-256 do arquivo importado"
        timestamptz imported_at
        int assets
    }
```

## Como o modelo de risco usa as tabelas

| Elemento do modelo | De onde vem |
|---|---|
| Matriz de incidência M (equipamento × vulnerabilidade) | Tabela `finding`: M vale 1 quando existe o vínculo e a situação não é Corrigida |
| Vetor de severidade v | Coluna `cvss` de `vulnerability` |
| Fator de exposição F | Método polimórfico de cada classe de equipamento, escolhida pela coluna `tipo` |
| Matriz de dependências A | Tabela `dependency`: A[source][target] = `fracao` |

## Regras garantidas pelo próprio banco

- `finding`: um par (ativo, vulnerabilidade) só pode existir uma vez; data de correção só com situação Corrigida e nunca anterior à detecção.
- `dependency`: um ativo não depende de si mesmo; a fração fica entre 0 e 1; um gatilho recusa a gravação quando a soma das frações de um ativo chegaria a 1 ou mais. Essa regra mantém I − A estritamente diagonal dominante e, portanto, invertível.
- Excluir um ativo apaga seus tratamentos e dependências (`ON DELETE CASCADE`); o catálogo de vulnerabilidades e o histórico permanecem.
- A aplicação acessa o banco com um papel que só lê e grava dados; criar e alterar tabelas cabe ao papel proprietário, usado apenas nas migrações.
