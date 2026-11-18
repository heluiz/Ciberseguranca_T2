"""Telas de consulta que existiam só no programa de terminal.

- base de CVEs exploradas (opção 16): busca, navegação por fabricante e
  produto, página da CVE com a explicação em português;
- onde aparece uma CVE ou um CWE no inventário (opção 3, item 7);
- calculadora CVSS 3.1 e 4.0 (as perguntas de ``calculadora_cvss.py``);
- detalhe de uma correção do plano (opção 17).

Todas são somente leitura: nada aqui grava no banco.
"""

from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views.decorators.http import require_GET

from calculadora_cvss import analisar_vetor
from classificacoes import OrigemVulnerabilidade
from risco import ModeloRisco, SistemaSingularError
from vulnerabilidades import validar_cve, validar_referencia
import explicacao_cve

from . import analysis, references
from .models import Vulnerability
from .repository import snapshot

READ_ALL = (
    "inventory.view_asset",
    "inventory.view_vulnerability",
    "inventory.view_finding",
    "inventory.view_dependency",
)
MAX_TEXT = 300


def prefill(record, back):
    """Endereço do cadastro de vulnerabilidade já preenchido com a CVE da base."""
    return urlencode(
        {
            "cve": record.cve,
            "descricao": f"{record.fabricante} {record.produto}: {record.nome}"[
                :2000
            ],
            "origem": OrigemVulnerabilidade.FALTA_ATUALIZACAO.value,
            "cvss": record.cvss or "",
            "cwe": record.cwes[0] if record.cwes else "",
            "vetor": record.vetor or "",
            "voltar": back,
        }
    )


def _base(request):
    base, warning = references.cve_base()
    if warning:
        messages.warning(request, warning)
    return base


def _rows(request, records):
    registered = dict(
        Vulnerability.objects.filter(
            cve__in=[record.cve for record in records]
        ).values_list("cve", "pk")
    )
    back = request.get_full_path()
    return [
        {
            "item": record,
            "registered": registered.get(record.cve),
            "prefill": prefill(record, back),
        }
        for record in records
    ]


@login_required
@permission_required("inventory.view_vulnerability", raise_exception=True)
@require_GET
def cve_search(request):
    """Opção 16: busca por palavras ou navegação fabricante → produto → CVEs."""
    base = _base(request)
    query = request.GET.get("q", "").strip()[:150]
    vendor = request.GET.get("fabricante", "").strip()[:MAX_TEXT]
    product = request.GET.get("produto", "").strip()[:MAX_TEXT]
    vendor_filter = request.GET.get("filtro", "").strip()[:100]
    context = {
        "query": query,
        "vendor": vendor,
        "product": product,
        "vendor_filter": vendor_filter,
        "summary": {
            "total": len(base),
            "com_nota": base.com_nota(),
            "catalogo": base.catalogo,
            "publicado": base.publicado,
        },
        "can_add": request.user.has_perm("inventory.add_vulnerability"),
        "can_link": request.user.has_perm("inventory.add_finding"),
        "mode": "vendors",
    }
    page_number = request.GET.get("page")
    if query:
        page = Paginator(base.buscar(query), 20).get_page(page_number)
        context.update(mode="results", page=page, rows=_rows(request, page))
    elif vendor and product:
        page = Paginator(base.do_produto(vendor, product), 20).get_page(
            page_number
        )
        context.update(mode="results", page=page, rows=_rows(request, page))
    elif vendor:
        context.update(mode="products", products=base.produtos(vendor))
    else:
        page = Paginator(base.fabricantes(vendor_filter), 40).get_page(
            page_number
        )
        context.update(page=page)
    # Mantém busca e navegação ao trocar de página.
    context["filters"] = "".join(
        "&" + urlencode({name: value})
        for name, value in (
            ("q", query),
            ("fabricante", vendor),
            ("produto", product),
            ("filtro", vendor_filter),
        )
        if value
    )
    return render(request, "inventory/cve.html", context)


@login_required
@permission_required(READ_ALL, raise_exception=True)
@require_GET
def cve_detail(request, cve):
    """A CVE da base, explicada em português, e onde ela está no inventário."""
    try:
        cve = validar_cve(cve)
    except ValueError:
        raise Http404 from None
    record = _base(request).buscar_cve(cve)
    if record is None:
        # Fora do catálogo KEV não há explicação da CISA; mostra onde ela está.
        messages.info(
            request,
            f"A {cve} não está na base de CVEs exploradas (catálogo KEV): "
            "não há ação nem boletim indicados pela CISA. Procure o boletim "
            "do fabricante.",
        )
        return redirect(f"{reverse('occurrences')}?ref={cve}")
    inventory = snapshot()
    registered = Vulnerability.objects.filter(cve=cve).values_list(
        "pk", flat=True
    ).first()
    return render(
        request,
        "inventory/cve_detail.html",
        {
            "item": record,
            "explicacao": references.record_explanation(record),
            "registered": registered,
            "prefill": prefill(record, request.get_full_path()),
            "occurrences": inventory.ocorrencias_da_referencia(cve),
            "matching": references.matching_assets(record, inventory),
            "can_add": request.user.has_perm("inventory.add_vulnerability"),
            "can_link": request.user.has_perm("inventory.add_finding"),
        },
    )


@login_required
@permission_required(READ_ALL, raise_exception=True)
@require_GET
def occurrences(request):
    """Opção 3, item 7: onde aparece uma CVE ou um CWE, da mais grave."""
    ref = request.GET.get("ref", "").strip()[:40]
    rows, error, target, record = [], "", "", None
    if ref:
        try:
            target = validar_referencia(ref)
            rows = snapshot().ocorrencias_da_referencia(target)
        except ValueError as exc:
            error = str(exc)
    if target.startswith("CVE-"):
        record = _base(request).buscar_cve(target)
    return render(
        request,
        "inventory/occurrences.html",
        {
            "ref": ref,
            "target": target,
            "label": explicacao_cve.cwe_com_nome(target)
            if target.startswith("CWE-")
            else target,
            "rows": rows,
            "pending": sum(1 for *_, status in rows if status.conta_no_risco),
            "error": error,
            "record": record,
        },
    )


@login_required
@require_GET
def cvss_calculator(request):
    """As perguntas do FIRST em português; ou um vetor colado, conferido."""
    version = request.GET.get("versao", "4.0")
    if version not in references.CALCULATOR_VERSIONS:
        version = "4.0"
    pasted = request.GET.get("vetor", "").strip()[:256]
    pasted_result, pasted_error = None, ""
    if pasted:
        try:
            pasted_result = references.vector_result(*analisar_vetor(pasted))
        except ValueError as exc:
            pasted_error = str(exc)
    answers = {
        key: value[:2]
        for key, value in request.GET.items()
        if key.isupper() and len(key) <= 3
    }
    questions, result = references.calculator(version, answers)
    for found in (pasted_result, result):
        if found and found["nota"]:
            found["register"] = urlencode(
                {
                    "cvss": found["nota"],
                    "vetor": found["vetor"],
                    "origem": OrigemVulnerabilidade.FALTA_ATUALIZACAO.value,
                }
            )
    return render(
        request,
        "inventory/cvss.html",
        {
            "version": version,
            "versions": references.CALCULATOR_VERSIONS,
            "questions": questions,
            "result": result,
            "pasted": pasted,
            "pasted_result": pasted_result,
            "pasted_error": pasted_error,
            "answered": sum(1 for q in questions if q["escolha"]),
            "can_add": request.user.has_perm("inventory.add_vulnerability"),
        },
    )


def _int(value):
    return int(value) if value.isdigit() and len(value) < 10 else None


@login_required
@permission_required(READ_ALL, raise_exception=True)
@require_GET
def correction(request):
    """Opção 17: uma correção do plano, por que reduz e como fazer."""
    scenario = request.GET.get("cenario", "")
    if scenario not in analysis.SCENARIOS:
        scenario = ""
    asset_id = _int(request.GET.get("ativo", ""))
    vuln_id = _int(request.GET.get("vulnerabilidade", ""))
    inventory = (
        analysis.load_scenario(scenario) if scenario else snapshot()
    )
    model = ModeloRisco(inventory)
    try:
        plan = model.plano_de_correcao()
        total = model.risco_total()
    except SistemaSingularError:
        raise Http404 from None
    position = next(
        (
            n
            for n, item in enumerate(plan, 1)
            if item.equipamento.id == asset_id
            and item.vulnerabilidade.id == vuln_id
        ),
        None,
    )
    if position is None:
        raise Http404
    item = plan[position - 1]
    record = None
    if item.vulnerabilidade.cve:
        record = _base(request).buscar_cve(item.vulnerabilidade.cve)
    return render(
        request,
        "inventory/correction.html",
        {
            "numero": position,
            "quantidade": len(plan),
            "scenario": scenario,
            "detail": references.correction_detail(
                model, inventory, item, total, record
            ),
        },
    )
