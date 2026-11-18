"""Esquema inicial do banco do inventário (quatro tabelas).

Revisão: 0001
Anterior: nenhuma
"""
import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Cria as quatro tabelas."""
    op.create_table(
        "equipamentos",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("tipo", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("custodiante", sa.String(), nullable=False),
        sa.Column("lotacao", sa.String(), nullable=False),
        sa.Column("descricao", sa.String(), nullable=False),
        sa.Column("fabricante", sa.String(length=60), nullable=True),
        sa.Column("modelo", sa.String(length=60), nullable=True),
        sa.Column("numero_serie", sa.String(length=60), nullable=True),
        sa.Column("patrimonio", sa.String(length=60), nullable=True),
        sa.Column("sistema", sa.String(length=60), nullable=True),
        sa.Column("versao", sa.String(length=60), nullable=True),
        sa.CheckConstraint("tipo BETWEEN 1 AND 7",
                           name="ck_equipamento_tipo"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hostname"),
    )
    op.create_table(
        "vulnerabilidades",
        sa.Column("id", sa.Integer(), autoincrement=False, nullable=False),
        sa.Column("descricao", sa.String(), nullable=False),
        sa.Column("cve", sa.String(length=20), nullable=True),
        sa.Column("cwe", sa.String(length=20), nullable=True),
        sa.Column("origem", sa.Integer(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=False),
        sa.Column("vetor", sa.String(), nullable=True),
        sa.CheckConstraint("cvss >= 0 AND cvss <= 10", name="ck_vuln_cvss"),
        sa.CheckConstraint("origem BETWEEN 1 AND 6", name="ck_vuln_origem"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve"),
    )
    op.create_table(
        "vinculos",
        sa.Column("equipamento_id", sa.Integer(), nullable=False),
        sa.Column("vulnerabilidade_id", sa.Integer(), nullable=False),
        sa.Column("situacao", sa.Integer(), nullable=False),
        sa.CheckConstraint("situacao BETWEEN 1 AND 4",
                           name="ck_vinculo_situacao"),
        sa.ForeignKeyConstraint(["equipamento_id"], ["equipamentos.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["vulnerabilidade_id"],
                                ["vulnerabilidades.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("equipamento_id", "vulnerabilidade_id"),
    )
    op.create_table(
        "dependencias",
        sa.Column("equipamento_id", sa.Integer(), nullable=False),
        sa.Column("depende_de_id", sa.Integer(), nullable=False),
        sa.Column("fracao", sa.Float(), nullable=False),
        sa.CheckConstraint("fracao > 0 AND fracao < 1",
                           name="ck_dependencia_fracao"),
        sa.CheckConstraint("equipamento_id <> depende_de_id",
                           name="ck_dependencia_propria"),
        sa.ForeignKeyConstraint(["equipamento_id"], ["equipamentos.id"],
                                ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["depende_de_id"], ["equipamentos.id"],
                                ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("equipamento_id", "depende_de_id"),
    )


def downgrade():
    """Apaga as quatro tabelas, na ordem inversa das chaves."""
    op.drop_table("dependencias")
    op.drop_table("vinculos")
    op.drop_table("vulnerabilidades")
    op.drop_table("equipamentos")
