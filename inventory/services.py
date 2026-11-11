"""Casos de uso transacionais. Escrevem somente a entidade alterada."""

from decimal import Decimal
import hashlib
import json
from django.db import transaction, connection
from django.core.exceptions import PermissionDenied
from django.http import Http404
from classificacoes import TipoEquipamento
from inventario import Inventario
from vulnerabilidades import Vulnerabilidade
from risco import ModeloRisco
from formatacao import para_busca
from ficha_tecnica import CAMPOS
from .models import (
    Asset,
    Vulnerability,
    Finding,
    Dependency,
    AuditEvent,
    ImportReceipt,
)
from .repository import PostgresRepository, lock_inventory


class Conflict(ValueError):
    pass


PERMS = {
    "asset": "asset",
    "vulnerability": "vulnerability",
    "finding": "finding",
    "dependency": "dependency",
}
MODELS = {
    "asset": Asset,
    "vulnerability": Vulnerability,
    "finding": Finding,
    "dependency": Dependency,
}


def authorize(user, permission):
    if not user.has_perm("inventory." + permission):
        AuditEvent.objects.create(
            actor=user, action="denied", target=permission
        )
        raise PermissionDenied


def audit(user, action, target):
    AuditEvent.objects.create(actor=user, action=action, target=str(target))


def check_version(obj, version):
    if obj.version != version:
        raise Conflict(
            "Este registro mudou. Recarregue a página antes de salvar."
        )


def assign_asset(obj, equipment):
    for field in ("hostname", "custodiante", "lotacao", "descricao"):
        setattr(obj, field, getattr(equipment, field))
    obj.tipo = equipment.tipo.value
    for field in CAMPOS:
        setattr(obj, field, getattr(equipment.ficha, field) or "")
    obj.patrimonio_key = para_busca(obj.patrimonio) if obj.patrimonio else None
    obj.full_clean()
    obj.save()


def assign_vulnerability(obj, vuln):
    for field in ("descricao", "cvss", "cve", "cwe", "vetor"):
        setattr(obj, field, getattr(vuln, field))
    obj.cvss = Decimal(str(vuln.cvss))
    obj.origem = vuln.origem.value
    obj.full_clean()
    obj.save()


def save_entity(user, kind, data, pk=None):
    authorize(user, ("change_" if pk else "add_") + PERMS[kind])
    with transaction.atomic():
        lock_inventory()
        model = MODELS[kind]
        obj = model.objects.filter(pk=pk).first() if pk else model()
        if obj is None:
            raise Http404
        if pk:
            check_version(obj, data["version"])
            obj.version += 1
        inv = PostgresRepository().load()
        if kind == "asset":
            fields = {
                k: data[k]
                for k in ("hostname", "custodiante", "lotacao", "descricao")
            }
            fields["tipo"] = TipoEquipamento(int(data["tipo"]))
            fields["ficha"] = {c: data.get(c) or None for c in CAMPOS}
            if pk:
                inv.atualizar_equipamento(pk, fields)
                equipment = inv.buscar_por_id(pk)
            else:
                equipment = inv.cadastrar_equipamento(**fields)
            assign_asset(obj, equipment)
        elif kind == "vulnerability":
            payload = {
                k: data.get(k) or None
                for k in ("descricao", "cve", "cwe", "vetor")
            }
            payload.update(
                id=pk or 1,
                origem=int(data["origem"]),
                cvss=float(data["cvss"]),
            )
            vuln = Vulnerabilidade.de_dict(payload)
            if vuln.cve and inv.vulnerabilidade_com_cve(vuln.cve, pk):
                raise ValueError("Esta CVE já está no catálogo.")
            assign_vulnerability(obj, vuln)
        elif kind == "finding":
            asset, vuln = data["asset"], data["vulnerability"]
            if (
                not pk
                and Finding.objects.filter(
                    asset=asset, vulnerability=vuln
                ).exists()
            ):
                raise ValueError(
                    "Esta vulnerabilidade já está vinculada ao ativo."
                )
            obj.asset, obj.vulnerability = asset, vuln
            obj.situacao = int(data["situacao"])
            obj.full_clean()
            obj.save()
        else:
            source, target = data["source"], data["target"]
            if pk:
                inv.remover_dependencia(obj.source_id, obj.target_id)
            inv.registrar_dependencia(
                source.pk, target.pk, float(data["fracao"])
            )
            obj.source, obj.target, obj.fracao = source, target, data["fracao"]
            obj.full_clean()
            obj.save()
        audit(user, ("change_" if pk else "add_") + kind, obj.pk)
        return obj


def delete_entity(user, kind, pk, version):
    authorize(user, "delete_" + PERMS[kind])
    with transaction.atomic():
        lock_inventory()
        obj = MODELS[kind].objects.filter(pk=pk).first()
        if obj is None:
            raise Http404
        check_version(obj, version)
        obj.delete()
        # Catálogo compartilhado fica preservado: excluir vínculo ou ativo não apaga a CVE.
        audit(user, "delete_" + kind, pk)


def import_json(content, user=None, dry_run=False):
    if len(content) > 2 * 1024 * 1024:
        raise ValueError("Arquivo excede 2 MB.")

    def strict_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Objeto JSON contém campo duplicado.")
            result[key] = value
        return result

    def reject_constant(value):
        raise ValueError("JSON deve conter somente números finitos.")

    try:
        raw = json.loads(
            content,
            object_pairs_hook=strict_object,
            parse_constant=reject_constant,
        )
    except RecursionError as error:
        raise ValueError("JSON excede a profundidade permitida.") from error
    if not isinstance(raw, list):
        raise ValueError("A raiz do inventário deve ser uma lista JSON.")
    if len(raw) > 1000:
        raise ValueError("Importe até 1000 ativos por arquivo.")
    inv = Inventario.de_dict(raw)
    for equipment in inv:
        if sum(equipment.dependencias.values()) >= 1 - 1e-9:
            raise ValueError("Soma das dependências deve ser menor que 1.")
    model = ModeloRisco(inv)
    model.resolver()
    digest = hashlib.sha256(content).hexdigest()
    with transaction.atomic():
        lock_inventory()
        if ImportReceipt.objects.filter(digest=digest).exists():
            return "Arquivo já importado; nenhuma alteração."
        if Asset.objects.exists() or Vulnerability.objects.exists():
            raise ValueError(
                "A importação inicial exige uma base vazia para preservar IDs sem sobrescrever dados."
            )
        if dry_run:
            return f"Validação concluída: {len(inv.todos())} ativos, risco total {model.risco_total():.6f}."
        for equipment in inv:
            assign_asset(Asset(pk=equipment.id), equipment)
        for vuln in inv.vulnerabilidades():
            assign_vulnerability(Vulnerability(pk=vuln.id), vuln)
        for equipment in inv:
            for vid, status in equipment.vulnerabilidades.items():
                Finding.objects.create(
                    asset_id=equipment.id,
                    vulnerability_id=vid,
                    situacao=status.value,
                )
            for target, fraction in equipment.dependencias.items():
                Dependency.objects.create(
                    source_id=equipment.id, target_id=target, fracao=fraction
                )
        # IDs importados são explícitos; avança as sequências para os próximos cadastros.
        from django.core.management.color import no_style

        with connection.cursor() as cursor:
            for sql in connection.ops.sequence_reset_sql(
                no_style(), [Asset, Vulnerability]
            ):
                cursor.execute(sql)
        restored = PostgresRepository().load()
        if restored.para_dict() != inv.para_dict():
            raise ValueError("Reconciliação falhou; importação revertida.")
        if (
            abs(ModeloRisco(restored).risco_total() - model.risco_total())
            > 1e-8
        ):
            raise ValueError("Risco divergente; importação revertida.")
        ImportReceipt.objects.create(digest=digest, assets=len(inv.todos()))
        audit(user, "import", digest)
    return f"Importados {len(inv.todos())} ativos. Risco reconciliado com o JSON original."
