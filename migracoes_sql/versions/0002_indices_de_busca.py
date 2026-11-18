"""Índices de busca: lotação e vínculo por vulnerabilidade.

Revisão: 0002
Anterior: 0001

Primeira alteração de esquema depois da criação (card S5_06): bancos
já criados pela 0001 ganham os índices sem perder dados.
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade():
    """Cria os dois índices."""
    op.create_index("ix_equipamentos_lotacao", "equipamentos", ["lotacao"])
    op.create_index("ix_vinculos_vulnerabilidade_id", "vinculos",
                    ["vulnerabilidade_id"])


def downgrade():
    """Apaga os dois índices."""
    op.drop_index("ix_vinculos_vulnerabilidade_id", table_name="vinculos")
    op.drop_index("ix_equipamentos_lotacao", table_name="equipamentos")
