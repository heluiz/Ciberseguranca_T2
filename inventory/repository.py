"""Adaptador relacional para os objetos de domínio originais."""

from typing import Protocol
from django.db import connection, transaction
from inventario import Inventario
from .models import Asset, Vulnerability, Finding, Dependency
from ficha_tecnica import CAMPOS


class InventoryRepository(Protocol):
    def load(self) -> Inventario: ...


class MemoryRepository:
    def __init__(self, inventory):
        self.inventory = inventory

    def load(self):
        return Inventario.de_dict(self.inventory.para_dict())


class PostgresRepository:
    def load(self):
        assets = list(Asset.objects.all())
        vulns = {
            v.pk: vulnerability_dict(v) for v in Vulnerability.objects.all()
        }
        findings = {}
        for f in Finding.objects.all():
            findings.setdefault(f.asset_id, []).append(
                dict(vulns[f.vulnerability_id], situacao=f.situacao)
            )
        dependencies = {}
        for d in Dependency.objects.all():
            dependencies.setdefault(d.source_id, []).append(
                {"equipamento_id": d.target_id, "fracao": float(d.fracao)}
            )
        return Inventario.de_dict(
            [
                dict(
                    asset_dict(a),
                    vulnerabilidades=findings.get(a.pk, []),
                    dependencias=dependencies.get(a.pk, []),
                )
                for a in assets
            ]
        )


def asset_dict(a):
    return {
        "id": a.pk,
        "tipo": a.tipo,
        "hostname": a.hostname,
        "custodiante": a.custodiante,
        "lotacao": a.lotacao,
        "descricao": a.descricao,
        "ficha": {c: getattr(a, c) for c in CAMPOS if getattr(a, c)},
    }


def vulnerability_dict(v):
    return {
        "id": v.pk,
        "descricao": v.descricao,
        "origem": v.origem,
        "cvss": float(v.cvss),
        "cve": v.cve,
        "cwe": v.cwe,
        "vetor": v.vetor,
    }


def lock_inventory():
    # Serializa alterações do conjunto. Evita soma inválida e corridas entre importação,
    # edição e exclusão. É deliberadamente conservador para este projeto acadêmico.
    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_xact_lock(%s)", [73194021])


@transaction.atomic
def snapshot():
    # Mesmo lock das escritas: as quatro consultas enxergam um conjunto consistente.
    lock_inventory()
    return PostgresRepository().load()
