"""Laboratório de SQL injection: consulta vulnerável x consulta parametrizada.

Card S5_07. Roda só em memória (sqlite3 da biblioteca padrão), com dados
fictícios; nada aqui é usado pela aplicação. A função vulnerável existe
para o teste provar que o ataque funciona nela e falha na versão certa.

    python -m academic.sqli_lab

A aplicação de verdade não monta SQL com texto: o Django ORM e o
SQLAlchemy (repositorio_sql.py) mandam os valores separados do comando
(parâmetros ligados), e o banco nunca os interpreta como SQL.
"""

import sqlite3

# Cargas clássicas, usadas no teste e na demonstração.
TAUTOLOGIA = "' OR '1'='1"
UNION = "' UNION SELECT usuario, hash_senha FROM contas --"
EMPILHADA = "x'; DROP TABLE equipamentos; --"


def criar_banco():
    """Cria um banco em memória com equipamentos e contas fictícios."""
    banco = sqlite3.connect(":memory:")
    banco.executescript(
        """
        CREATE TABLE equipamentos (hostname TEXT, lotacao TEXT);
        CREATE TABLE contas (usuario TEXT, hash_senha TEXT);
        INSERT INTO equipamentos VALUES
            ('SRV-01', 'Sede'), ('PC-02', 'Cartório'), ('RT-03', 'Sede');
        INSERT INTO contas VALUES
            ('admin', 'argon2$fictício-1'), ('analista', 'argon2$fictício-2');
        """
    )
    return banco


def buscar_vulneravel(banco, lotacao):
    """ERRADO: junta o texto do usuário ao SQL (o que não se faz).

    A aspa do usuário fecha a string do comando e o resto vira SQL.
    """
    sql = (
        "SELECT hostname, lotacao FROM equipamentos "  # nosec B608
        "WHERE lotacao = '" + lotacao + "'"
    )
    # Vulnerável de propósito, só no laboratório (bandit B608 marcado).
    return banco.execute(sql).fetchall()  # nosec B608


def buscar_vulneravel_script(banco, lotacao):
    """ERRADO e pior: executescript aceita vários comandos (empilhados)."""
    sql = (
        "SELECT hostname FROM equipamentos WHERE lotacao = '"  # nosec B608
        + lotacao + "'"
    )
    banco.executescript(sql)


def buscar_seguro(banco, lotacao):
    """CERTO: o valor vai como parâmetro (?), separado do comando."""
    return banco.execute(
        "SELECT hostname, lotacao FROM equipamentos WHERE lotacao = ?",
        (lotacao,),
    ).fetchall()


def tabelas(banco):
    """Devolve as tabelas que existem no banco."""
    return sorted(
        nome
        for (nome,) in banco.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    )


if __name__ == "__main__":
    banco = criar_banco()
    print("Consulta normal:", buscar_seguro(banco, "Sede"))
    for nome, carga in (("tautologia", TAUTOLOGIA), ("UNION", UNION)):
        print(f"\nCarga {nome}: {carga!r}")
        print("  vulnerável  ->", buscar_vulneravel(banco, carga))
        print("  parametrizada ->", buscar_seguro(banco, carga))
    print(f"\nCarga empilhada: {EMPILHADA!r}")
    print("  parametrizada ->", buscar_seguro(banco, EMPILHADA))
    print("  tabelas depois:", tabelas(banco))
    buscar_vulneravel_script(banco, EMPILHADA)
    print("  vulnerável (executescript) -> tabelas depois:", tabelas(banco))
