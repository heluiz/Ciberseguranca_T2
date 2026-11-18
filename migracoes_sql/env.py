r"""Ambiente do Alembic para o banco do inventário (repositorio_sql.py).

Usa a conexão que o programa passa (config.attributes["connection"]) ou,
na linha de comando, a URL da variável INVENTARIO_BANCO:

    INVENTARIO_BANCO=sqlite:///dados/inventario.db \\
        alembic -c migracoes_sql/alembic.ini upgrade head
"""

import os
import sys

from alembic import context
from sqlalchemy import create_engine

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from repositorio_sql import VARIAVEL_DO_BANCO, Base  # noqa: E402

config = context.config
alvo = Base.metadata


def executar(conexao):
    """Roda as migrações na conexão dada."""
    # render_as_batch: o SQLite não altera colunas no lugar; o Alembic
    # recria a tabela. No PostgreSQL não muda nada.
    context.configure(connection=conexao, target_metadata=alvo,
                      render_as_batch=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


conexao = config.attributes.get("connection")
if conexao is not None:
    executar(conexao)
else:
    url = os.environ.get(VARIAVEL_DO_BANCO)
    if not url:
        raise SystemExit(f"defina {VARIAVEL_DO_BANCO} com a URL do banco")
    with create_engine(url).begin() as nova:
        executar(nova)
