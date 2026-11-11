import json
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.views import LoginView
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.db import connection, DatabaseError, IntegrityError
from django.db.models import Count, Avg, Max, Q
from django.http import JsonResponse, HttpResponse, Http404
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_GET
from django_otp.forms import OTPTokenForm
from django_otp import login as otp_login
from risco import ModeloRisco, SistemaSingularError
from .models import Asset, Vulnerability, Finding, Dependency, AuditEvent
from .repository import snapshot
from .services import (
    save_entity,
    delete_entity,
    authorize,
    import_json,
    Conflict,
    MODELS,
)
from .strategies import EffectiveRiskRanking, OwnRiskRanking
from .forms import FORMS

TITLES = {
    "asset": "Ativos",
    "vulnerability": "Vulnerabilidades",
    "finding": "Tratamentos",
    "dependency": "Dependências",
}


class SignIn(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True


@login_required
def mfa(request):
    form = OTPTokenForm(request.user, request, data=request.POST or None)
    if request.method == "POST" and form.is_valid():
        otp_login(request, request.user.otp_device)
        return redirect("/")
    return render(request, "registration/mfa.html", {"form": form})


@require_GET
def health(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return JsonResponse({"status": "ok"})
    except DatabaseError:
        return JsonResponse({"status": "unavailable"}, status=503)


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def dashboard(request):
    inv = snapshot()
    model = ModeloRisco(inv)
    try:
        strategy = (
            OwnRiskRanking()
            if request.GET.get("ranking") == "proprio"
            else EffectiveRiskRanking()
        )
        ranking = strategy.rank(model.relatorio())
        plan = model.plano_de_correcao()[:8]
        total = model.risco_total()
        diagnostic = model.diagnosticar()
    except SistemaSingularError as error:
        ranking, plan, total, diagnostic = [], [], None, None
        messages.error(request, str(error))
    return render(
        request,
        "inventory/dashboard.html",
        {
            "ranking": ranking[:6],
            "plan": plan,
            "total": total,
            "diagnostic": diagnostic,
            "asset_count": len(inv.todos()),
            "dependency_count": Dependency.objects.count(),
            "vuln_count": Vulnerability.objects.count(),
            "open_count": Finding.objects.filter(situacao__in=[1, 2]).count(),
            "critical_count": Finding.objects.filter(
                vulnerability__cvss__gte=9
            )
            .exclude(situacao=3)
            .count(),
        },
    )


@login_required
def collection(request, kind):
    if kind not in MODELS:
        raise Http404
    authorize(request.user, "view_" + kind)
    query = request.GET.get("q", "").strip()[:150]
    objects = MODELS[kind].objects.all().order_by("pk")
    if kind == "asset" and query:
        objects = objects.filter(
            Q(hostname__icontains=query)
            | Q(lotacao__icontains=query)
            | Q(patrimonio__icontains=query)
            | Q(descricao__icontains=query)
        )
    elif kind == "vulnerability" and query:
        objects = objects.filter(
            Q(cve__icontains=query)
            | Q(cwe__icontains=query)
            | Q(descricao__icontains=query)
        )
    elif kind == "finding":
        objects = objects.select_related("asset", "vulnerability")
        if query:
            objects = objects.filter(
                Q(asset__hostname__icontains=query)
                | Q(vulnerability__descricao__icontains=query)
                | Q(vulnerability__cve__icontains=query)
            )
    elif kind == "dependency":
        objects = objects.select_related("source", "target")
    from django.core.paginator import Paginator

    page = Paginator(objects, 30).get_page(request.GET.get("page"))
    return render(
        request,
        "inventory/collection.html",
        {
            "kind": kind,
            "title": TITLES[kind],
            "page": page,
            "query": query,
            "can_add": request.user.has_perm("inventory.add_" + kind),
            "can_change": request.user.has_perm("inventory.change_" + kind),
            "can_delete": request.user.has_perm("inventory.delete_" + kind),
        },
    )


@login_required
def edit(request, kind, pk=None):
    if kind not in MODELS:
        raise Http404
    authorize(request.user, ("change_" if pk else "add_") + kind)
    obj = get_object_or_404(MODELS[kind], pk=pk) if pk else None
    form = FORMS[kind](request.POST or None, instance=obj)
    status = 200
    if request.method == "POST" and form.is_valid():
        try:
            save_entity(request.user, kind, form.cleaned_data, pk)
            messages.success(request, "Registro salvo com segurança.")
            return redirect("collection", kind=kind)
        except Conflict as error:
            form.add_error(None, str(error))
            status = 409
        except (ValueError, ValidationError) as error:
            form.add_error(None, str(error))
        except IntegrityError:
            form.add_error(
                None,
                "Registro duplicado ou referência alterada. Recarregue e confira os dados.",
            )
    return render(
        request,
        "inventory/form.html",
        {
            "form": form,
            "title": TITLES[kind],
            "kind": kind,
            "editing": bool(pk),
        },
        status=status,
    )


@login_required
def remove(request, kind, pk):
    if kind not in MODELS:
        raise Http404
    authorize(request.user, "delete_" + kind)
    obj = get_object_or_404(MODELS[kind], pk=pk)
    if request.method == "POST":
        try:
            delete_entity(
                request.user, kind, pk, int(request.POST.get("version", "0"))
            )
            messages.success(
                request,
                "Registro excluído. A ação foi registrada na auditoria.",
            )
            return redirect("collection", kind=kind)
        except ValueError as error:
            messages.error(request, str(error))
            return render(
                request,
                "inventory/delete.html",
                {"object": obj, "kind": kind},
                status=409,
            )
    return render(
        request, "inventory/delete.html", {"object": obj, "kind": kind}
    )


@login_required
@permission_required(
    (
        "inventory.view_asset",
        "inventory.view_vulnerability",
        "inventory.view_finding",
        "inventory.view_dependency",
    ),
    raise_exception=True,
)
@require_GET
def graph_data(request):
    inv = snapshot()
    model = ModeloRisco(inv)
    try:
        report = model.relatorio()
    except SistemaSingularError as error:
        return JsonResponse({"error": str(error)}, status=422)
    nodes = []
    for row in report:
        asset = row.equipamento
        findings = []
        for vuln, treatment in inv.vulnerabilidades_do(asset.id):
            findings.append(
                {
                    "id": vuln.id,
                    "descricao": vuln.descricao,
                    "cve": vuln.cve,
                    "cvss": vuln.cvss,
                    "gravidade": vuln.gravidade.rotulo,
                    "situacao": treatment.rotulo,
                    "corrigida": treatment.value == 3,
                }
            )
        active = [f for f in findings if not f["corrigida"]]
        nodes.append(
            {
                "data": {
                    "id": str(asset.id),
                    "label": asset.hostname,
                    "tipo": asset.tipo.rotulo,
                    "tipo_id": asset.tipo.value,
                    "setor": asset.lotacao,
                    "custodiante": asset.custodiante,
                    "descricao": asset.descricao,
                    "proprio": row.proprio,
                    "herdado": row.efetivo - row.proprio,
                    "contribuicoes": [
                        {
                            "hostname": other.hostname,
                            "fracao": fraction,
                            "pontos": inherited,
                        }
                        for other, fraction, effective, inherited in model.contribuicoes(
                            asset.id
                        )
                    ],
                    "risco": row.efetivo,
                    "falhas": len(findings),
                    "cvss_maximo": max((f["cvss"] for f in active), default=0),
                    "vulnerabilidades": findings,
                    "ficha_url": f"/ativos/{asset.id}/",
                }
            }
        )
    edges = [
        {
            "data": {
                "id": f"d{e.id}-{target}",
                "source": str(e.id),
                "target": str(target),
                "label": f"{fraction:.0%}",
                "fracao": fraction,
            }
        }
        for e in inv
        for target, fraction in e.dependencias.items()
    ]
    plan = [
        {
            "asset_id": str(item.equipamento.id),
            "asset": item.equipamento.hostname,
            "vulnerability": item.vulnerabilidade.cve
            or item.vulnerabilidade.descricao,
            "reducao": item.reducao,
        }
        for item in model.plano_de_correcao()
    ]
    return JsonResponse(
        {
            "elements": nodes + edges,
            "plan": plan,
            "total": model.risco_total(),
            "open_count": sum(
                1
                for node in nodes
                for f in node["data"]["vulnerabilidades"]
                if f["situacao"] in ("Aberta", "Em tratamento")
            ),
        }
    )


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
def graph(request):
    return render(request, "inventory/graph.html")


@login_required
@permission_required("inventory.view_vulnerability", raise_exception=True)
def reports(request):
    # JOIN + agregação executados no PostgreSQL, e não recontagem em JavaScript.
    summary = (
        Asset.objects.values("lotacao")
        .annotate(
            ativos=Count("id", distinct=True),
            falhas=Count("findings", filter=~Q(findings__situacao=3)),
            media=Avg(
                "findings__vulnerability__cvss",
                filter=~Q(findings__situacao=3),
            ),
            maximo=Max("findings__vulnerability__cvss"),
        )
        .order_by("-falhas", "lotacao")
    )
    return render(request, "inventory/reports.html", {"summary": summary})


@login_required
@permission_required("inventory.view_auditevent", raise_exception=True)
def audit_log(request):
    return render(
        request,
        "inventory/audit.html",
        {"events": AuditEvent.objects.select_related("actor")[:100]},
    )


@login_required
def transfer(request):
    if not request.user.is_superuser:
        from django.core.exceptions import PermissionDenied

        raise PermissionDenied
    if request.method == "POST":
        uploaded = request.FILES.get("file")
        try:
            if not uploaded or uploaded.size > 2 * 1024 * 1024:
                raise ValueError("Selecione um JSON de até 2 MB.")
            result = import_json(
                uploaded.read(),
                request.user,
                dry_run="dry_run" in request.POST,
            )
            messages.success(request, result)
        except (ValueError, UnicodeDecodeError, ValidationError) as error:
            messages.error(request, str(error))
    return render(request, "inventory/transfer.html")


@login_required
@permission_required("inventory.view_asset", raise_exception=True)
@require_GET
def export(request):
    response = HttpResponse(
        json.dumps(snapshot().para_dict(), ensure_ascii=False, indent=2),
        content_type="application/json",
    )
    response["Content-Disposition"] = (
        'attachment; filename="sentinel-inventario.json"'
    )
    return response


@login_required
@permission_required("inventory.view_vulnerability", raise_exception=True)
def cve_search(request):
    from base_cve import BaseCVE

    q = request.GET.get("q", "").strip()[:150]
    base, warning = BaseCVE.carregar()
    if warning:
        messages.warning(request, warning)
    items = base.buscar(q)[:30] if q else []
    return render(request, "inventory/cve.html", {"items": items, "query": q})


@login_required
def rest(request, kind, pk=None):
    """API de sessão: CSRF obrigatório nas mutações; versão obrigatória na edição."""
    if kind not in MODELS:
        raise Http404
    if request.method == "GET":
        authorize(request.user, "view_" + kind)
        queryset = MODELS[kind].objects.order_by("pk")
        if pk:
            queryset = queryset.filter(pk=pk)
            if not queryset.exists():
                raise Http404
        allowed = FORMS[kind]._meta.fields
        rows = list(queryset.values("id", *allowed)[:100])
        return JsonResponse({"results": rows, "limit": 100})
    if request.method not in ("POST", "PATCH", "DELETE"):
        return JsonResponse({"error": "Método não permitido."}, status=405)
    if (request.method == "POST" and pk) or (
        request.method != "POST" and not pk
    ):
        return JsonResponse(
            {"error": "Use POST na coleção e PATCH/DELETE no registro."},
            status=405,
        )
    authorize(
        request.user,
        (
            "add_"
            if request.method == "POST"
            else "delete_"
            if request.method == "DELETE"
            else "change_"
        )
        + kind,
    )
    try:
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise ValueError("Envie um objeto JSON.")
        allowed = (
            {"version"}
            if request.method == "DELETE"
            else set(FORMS[kind]._meta.fields)
        )
        if set(data) - allowed:
            raise ValueError("O corpo contém campos não permitidos.")
        if pk and ("version" not in data or type(data["version"]) is not int):
            raise ValueError("Informe a versão inteira do registro.")
        if request.method == "DELETE":
            delete_entity(request.user, kind, pk, data["version"])
            return HttpResponse(status=204)
        obj = get_object_or_404(MODELS[kind], pk=pk) if pk else None
        if pk:
            from django.forms.models import model_to_dict

            initial = model_to_dict(obj, fields=FORMS[kind]._meta.fields)
            initial.update(data)
            data = initial
        form = FORMS[kind](data, instance=obj)
        if not form.is_valid():
            return JsonResponse(
                {"errors": form.errors.get_json_data()}, status=422
            )
        saved = save_entity(request.user, kind, form.cleaned_data, pk)
        return JsonResponse(
            {"id": saved.pk, "version": saved.version},
            status=200 if pk else 201,
        )
    except Conflict as error:
        return JsonResponse({"error": str(error)}, status=409)
    except (ValueError, ValidationError, UnicodeDecodeError) as error:
        return JsonResponse({"error": str(error)}, status=422)
    except IntegrityError:
        return JsonResponse(
            {"error": "Duplicidade ou conflito de integridade."}, status=409
        )


@login_required
@permission_required(
    (
        "inventory.view_asset",
        "inventory.view_vulnerability",
        "inventory.view_finding",
        "inventory.view_dependency",
    ),
    raise_exception=True,
)
def asset_detail(request, pk):
    inv = snapshot()
    asset = inv.buscar_por_id(pk)
    if asset is None:
        raise Http404
    model = ModeloRisco(inv)
    row = model.risco_de(pk)
    return render(
        request,
        "inventory/asset_detail.html",
        {
            "asset": asset,
            "row": row,
            "findings": inv.vulnerabilidades_do(pk),
            "contributions": model.contribuicoes(pk),
        },
    )


@login_required
@permission_required(
    (
        "inventory.view_asset",
        "inventory.view_vulnerability",
        "inventory.view_finding",
        "inventory.view_dependency",
    ),
    raise_exception=True,
)
@require_GET
def simulate_correction(request, pk):
    """Simulação sem gravação usando o mesmo domínio e cálculo da aplicação."""
    from classificacoes import SituacaoTratamento
    from inventario import Inventario

    inv = snapshot()
    if inv.buscar_por_id(pk) is None:
        raise Http404
    model = ModeloRisco(inv)
    original = model.risco_total()
    changes = []
    clone = Inventario.de_dict(inv.para_dict())
    for vuln, treatment in clone.vulnerabilidades_do(pk):
        if treatment != SituacaoTratamento.CORRIGIDA:
            clone.alterar_situacao(pk, vuln.id, SituacaoTratamento.CORRIGIDA)
            changes.append(vuln.id)
    updated = ModeloRisco(clone)
    after = updated.risco_total()
    return JsonResponse(
        {
            "antes": original,
            "depois": after,
            "reducao": original - after,
            "correcoes": len(changes),
            "gravado": False,
        }
    )
