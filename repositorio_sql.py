"""Gravação e leitura do inventário em banco relacional (SQLAlchemy 2).

Alternativa ao arquivo JSON de armazenamento.py, com a mesma interface
(carregar() e salvar()): main.py não sabe qual das duas está em uso. A
escolha é pela variável de ambiente INVENTARIO_BANCO, que recebe uma URL
do SQLAlchemy, por exemplo:

    INVENTARIO_BANCO=sqlite:///dados/inventario.db
    INVENTARIO_BANCO=postgresql+psycopg://usuario@servidor/banco

Sem a variável, o programa continua no JSON.

Modelo (normalizado, ao contrário do JSON, em que a vulnerabilidade
compartilhada se repete em cada equipamento):

    equipamentos (1) --< vinculos >-- (1) vulnerabilidades
    equipamentos (1) --< dependencias >-- (1) equipamentos

O esquema é criado e atualizado pelas migrações do Alembic
(migracoes_sql/), nunca por create_all(): a mudança de esquema fica
versionada como o código. As regras continuam no domínio: carregar()
monta o mesmo conteúdo do arquivo e passa por Inventario.de_dict(), que
confere tudo (hostname repetido, CVE repetida, dependência sem destino,
fração fora da faixa...). As restrições do banco (chaves, UNIQUE e
CHECK) são uma segunda barreira, para quem mexer no banco por fora.

Todo acesso é pelo ORM, com parâmetros ligados: nenhum SQL é montado
juntando texto (ver docs/LAB-SQL-INJECTION.md).
"""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import (CheckConstraint, Float, ForeignKey, Integer, String,
                        create_engine, delete, event, inspect, select)
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import (DeclarativeBase, Mapped, Session, mapped_column,
                            relationship)

from armazenamento import BaseInvalidaError
from classificacoes import (OrigemVulnerabilidade, SituacaoTratamento,
                            TipoEquipamento)
from ficha_tecnica import CAMPOS as CAMPOS_DA_FICHA
from inventario import Inventario

VARIAVEL_DO_BANCO = "INVENTARIO_BANCO"
PASTA_DO_PROJETO = os.path.dirname(os.path.abspath(__file__))
PASTA_DAS_MIGRACOES = os.path.join(PASTA_DO_PROJETO, "migracoes_sql")


def _faixa(coluna: str, enumeracao: Any) -> str:
    """CHECK de uma coluna que guarda o valor de uma Enum do domínio."""
    valores = [item.value for item in enumeracao]
    return f"{coluna} BETWEEN {min(valores)} AND {max(valores)}"


class Base(DeclarativeBase):
    """Base declarativa das tabelas do inventário."""


class EquipamentoSQL(Base):
    """Linha da tabela equipamentos (com a ficha técnica)."""

    __tablename__ = "equipamentos"
    __table_args__ = (
        CheckConstraint(_faixa("tipo", TipoEquipamento),
                        name="ck_equipamento_tipo"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True,
                                    autoincrement=False)
    tipo: Mapped[int] = mapped_column(Integer)
    hostname: Mapped[str] = mapped_column(String, unique=True)
    custodiante: Mapped[str] = mapped_column(String)
    # Índice da migração 0002: busca e relatório filtram por lotação.
    lotacao: Mapped[str] = mapped_column(String, index=True)
    descricao: Mapped[str] = mapped_column(String)
    fabricante: Mapped[str | None] = mapped_column(String(60))
    modelo: Mapped[str | None] = mapped_column(String(60))
    numero_serie: Mapped[str | None] = mapped_column(String(60))
    patrimonio: Mapped[str | None] = mapped_column(String(60))
    sistema: Mapped[str | None] = mapped_column(String(60))
    versao: Mapped[str | None] = mapped_column(String(60))

    vinculos: Mapped[list[VinculoSQL]] = relationship(
        back_populates="equipamento", cascade="all, delete-orphan",
        order_by="VinculoSQL.vulnerabilidade_id")
    dependencias: Mapped[list[DependenciaSQL]] = relationship(
        foreign_keys="DependenciaSQL.equipamento_id",
        cascade="all, delete-orphan",
        order_by="DependenciaSQL.depende_de_id")


class VulnerabilidadeSQL(Base):
    """Linha da tabela vulnerabilidades (o catálogo, sem repetição)."""

    __tablename__ = "vulnerabilidades"
    __table_args__ = (
        CheckConstraint("cvss >= 0 AND cvss <= 10", name="ck_vuln_cvss"),
        CheckConstraint(_faixa("origem", OrigemVulnerabilidade),
                        name="ck_vuln_origem"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True,
                                    autoincrement=False)
    descricao: Mapped[str] = mapped_column(String)
    cve: Mapped[str | None] = mapped_column(String(20), unique=True)
    cwe: Mapped[str | None] = mapped_column(String(20))
    origem: Mapped[int] = mapped_column(Integer)
    cvss: Mapped[float] = mapped_column(Float)
    vetor: Mapped[str | None] = mapped_column(String)


class VinculoSQL(Base):
    """Equipamento x vulnerabilidade, com a situação do tratamento."""

    __tablename__ = "vinculos"
    __table_args__ = (
        CheckConstraint(_faixa("situacao", SituacaoTratamento),
                        name="ck_vinculo_situacao"),
    )

    equipamento_id: Mapped[int] = mapped_column(
        ForeignKey("equipamentos.id", ondelete="CASCADE"), primary_key=True)
    # Índice da migração 0002: "quais equipamentos têm esta
    # vulnerabilidade" não usa a chave primária, que começa pelo
    # equipamento.
    vulnerabilidade_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerabilidades.id", ondelete="RESTRICT"),
        primary_key=True, index=True)
    situacao: Mapped[int] = mapped_column(Integer)

    equipamento: Mapped[EquipamentoSQL] = relationship(
        back_populates="vinculos")
    vulnerabilidade: Mapped[VulnerabilidadeSQL] = relationship()


class DependenciaSQL(Base):
    """Equipamento que depende de outro, com a fração herdada."""

    __tablename__ = "dependencias"
    __table_args__ = (
        CheckConstraint("fracao > 0 AND fracao < 1",
                        name="ck_dependencia_fracao"),
        CheckConstraint("equipamento_id <> depende_de_id",
                        name="ck_dependencia_propria"),
    )

    equipamento_id: Mapped[int] = mapped_column(
        ForeignKey("equipamentos.id", ondelete="CASCADE"), primary_key=True)
    depende_de_id: Mapped[int] = mapped_column(
        ForeignKey("equipamentos.id", ondelete="RESTRICT"), primary_key=True)
    fracao: Mapped[float] = mapped_column(Float)


def url_padrao() -> str | None:
    """Devolve a URL do banco da variável de ambiente, ou None."""
    return os.environ.get(VARIAVEL_DO_BANCO) or None


def atualizar_esquema(engine: Engine) -> None:
    """Aplica as migrações que faltam (como alembic upgrade head)."""
    # Importado aqui: só quem usa o banco precisa do Alembic.
    from alembic import command
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", PASTA_DAS_MIGRACOES)
    with engine.begin() as conexao:
        config.attributes["connection"] = conexao
        command.upgrade(config, "head")


def _ligar_chaves_estrangeiras(conexao: Any, _registro: Any) -> None:
    """Liga as chaves estrangeiras em cada conexão nova do SQLite.

    No SQLite elas vêm desligadas; no PostgreSQL valem sempre.
    """
    cursor = conexao.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    cursor.close()


class BancoInventario:
    """O banco do inventário: salvar() e carregar(), como o arquivo."""

    def __init__(self, url: str | None = None,
                 engine: Engine | None = None) -> None:
        """Abre o banco da URL (ou da variável de ambiente).

        engine permite aos testes passar um banco em memória já aberto.
        caminho é a URL sem a senha, para as mensagens de erro.
        """
        if engine is None:
            url = url or url_padrao()
            if not url:
                raise ValueError(f"defina {VARIAVEL_DO_BANCO} com a URL "
                                 f"do banco")
            engine = create_engine(url)
        if engine.dialect.name == "sqlite":
            event.listen(engine, "connect", _ligar_chaves_estrangeiras)
        self.engine = engine
        self.caminho = make_url(str(engine.url)).render_as_string(
            hide_password=True)
        # Mesmo atributo do ArquivoInventario: o banco não converte
        # arquivos do Trabalho 1, então nunca há migração a contar.
        self.migracao_feita: tuple[str, list[str]] | None = None
        self._esquema_pronto = False

    def _preparar(self) -> None:
        """Cria ou atualiza o esquema na primeira vez que for usado."""
        if not self._esquema_pronto:
            atualizar_esquema(self.engine)
            self._esquema_pronto = True

    def salvar(self, inventario: Inventario) -> None:
        """Grava o inventário inteiro em uma transação só.

        Substitui o conteúdo anterior, como a gravação do arquivo: ou
        tudo é gravado, ou nada muda (rollback em qualquer erro).
        """
        self._preparar()
        dados = inventario.para_dict()
        with Session(self.engine) as sessao, sessao.begin():
            for tabela in (VinculoSQL, DependenciaSQL, EquipamentoSQL,
                           VulnerabilidadeSQL):
                sessao.execute(delete(tabela))
            catalogo: dict[int, VulnerabilidadeSQL] = {}
            for objeto in dados:
                for vuln in objeto["vulnerabilidades"]:
                    if vuln["id"] not in catalogo:
                        catalogo[vuln["id"]] = VulnerabilidadeSQL(
                            id=vuln["id"], descricao=vuln["descricao"],
                            cve=vuln.get("cve"), cwe=vuln.get("cwe"),
                            origem=vuln["origem"], cvss=vuln["cvss"],
                            vetor=vuln.get("vetor"))
            sessao.add_all(catalogo.values())
            sessao.flush()
            for objeto in dados:
                ficha = objeto.get("ficha", {})
                linha = EquipamentoSQL(
                    id=objeto["id"], tipo=objeto["tipo"],
                    hostname=objeto["hostname"],
                    custodiante=objeto["custodiante"],
                    lotacao=objeto["lotacao"],
                    descricao=objeto["descricao"],
                    **{campo: ficha.get(campo) for campo in CAMPOS_DA_FICHA})
                linha.vinculos = [
                    VinculoSQL(vulnerabilidade_id=v["id"],
                               situacao=v["situacao"])
                    for v in objeto["vulnerabilidades"]]
                sessao.add(linha)
            sessao.flush()
            for objeto in dados:
                for dep in objeto["dependencias"]:
                    sessao.add(DependenciaSQL(
                        equipamento_id=objeto["id"],
                        depende_de_id=dep["equipamento_id"],
                        fracao=dep["fracao"]))

    def carregar(self) -> Inventario:
        """Lê o banco e devolve um Inventario.

        Banco vazio devolve um inventário vazio. Levanta
        BaseInvalidaError se o banco não abrir ou se o conteúdo não
        passar pelas regras do domínio.
        """
        try:
            self._preparar()
            with Session(self.engine) as sessao:
                dados = self._montar(sessao)
        except SQLAlchemyError as erro:
            raise BaseInvalidaError(
                f"não foi possível ler o banco ({type(erro).__name__})"
            ) from erro
        try:
            return Inventario.de_dict(dados)
        except (KeyError, ValueError, TypeError, AttributeError) as erro:
            raise BaseInvalidaError(
                f"conteúdo do banco fora das regras ({erro})") from erro

    @staticmethod
    def _montar(sessao: Session) -> list[dict[str, Any]]:
        """Monta, do banco, o mesmo conteúdo que o arquivo JSON tem."""
        catalogo = {v.id: v for v in sessao.scalars(
            select(VulnerabilidadeSQL))}
        lista: list[dict[str, Any]] = []
        for linha in sessao.scalars(
                select(EquipamentoSQL).order_by(EquipamentoSQL.id)):
            objeto: dict[str, Any] = {
                "id": linha.id, "tipo": linha.tipo,
                "hostname": linha.hostname,
                "custodiante": linha.custodiante,
                "lotacao": linha.lotacao, "descricao": linha.descricao,
            }
            ficha = {campo: getattr(linha, campo)
                     for campo in CAMPOS_DA_FICHA
                     if getattr(linha, campo) is not None}
            if ficha:
                objeto["ficha"] = ficha
            objeto["vulnerabilidades"] = []
            for vinculo in linha.vinculos:
                vuln = catalogo[vinculo.vulnerabilidade_id]
                item: dict[str, Any] = {"id": vuln.id,
                                        "descricao": vuln.descricao}
                if vuln.cve is not None:
                    item["cve"] = vuln.cve
                if vuln.cwe is not None:
                    item["cwe"] = vuln.cwe
                item["origem"] = vuln.origem
                item["cvss"] = vuln.cvss
                if vuln.vetor is not None:
                    item["vetor"] = vuln.vetor
                item["situacao"] = vinculo.situacao
                objeto["vulnerabilidades"].append(item)
            objeto["dependencias"] = [
                {"equipamento_id": d.depende_de_id, "fracao": d.fracao}
                for d in linha.dependencias]
            lista.append(objeto)
        return lista

    def tabelas(self) -> list[str]:
        """Devolve as tabelas que existem no banco (conferência)."""
        return sorted(inspect(self.engine).get_table_names())


# Teste: exercita o banco sem ninguém digitar nada (SQLite em memória).
if __name__ == "__main__":
    import json

    from sqlalchemy.pool import StaticPool

    memoria = create_engine("sqlite://", poolclass=StaticPool,
                            connect_args={"check_same_thread": False})
    banco = BancoInventario(engine=memoria)
    assert len(banco.carregar()) == 0, "banco novo deveria estar vazio"
    print("Tabelas:", ", ".join(banco.tabelas()))

    with open(os.path.join(PASTA_DO_PROJETO, "dados_exemplo",
                           "inventario_exemplo.json"),
              encoding="utf-8") as arquivo:
        exemplo = Inventario.de_dict(json.load(arquivo))
    banco.salvar(exemplo)
    relido = banco.carregar()
    assert relido.para_dict() == exemplo.para_dict(), "ida e volta mudou"
    print(f"Ida e volta: {len(relido)} equipamentos iguais aos do JSON.")
    print("OK: teste do repositório SQL concluído.")
