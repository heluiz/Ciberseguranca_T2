"""Interações das telas: atalhos, filtros, confirmações e rótulos."""

from pathlib import Path

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.test import Client

from inventory.models import (
    Asset,
    AuditEvent,
    Dependency,
    Finding,
    Vulnerability,
)
from inventory.services import import_json

pytestmark = pytest.mark.django_db
EXAMPLE = Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes()
FULL = Path("dados_exemplo/inventario_exemplo.json").read_bytes()
PASSWORD = "temporary-test-password-only"


@pytest.fixture
def admin_client():
    client = Client()
    client.force_login(
        User.objects.create_superuser("admin", password=PASSWORD)
    )
    return client


def group_client(name, group=None):
    call_command("setup_roles")
    user = User.objects.create_user(name, password=PASSWORD)
    if group:
        user.groups.add(Group.objects.get(name=group))
    client = Client()
    client.force_login(user)
    return client


def listed(page):
    return list(page.context["page"].paginator.object_list)


def test_dashboard_cards_link_to_matching_lists(admin_client):
    import_json(FULL)
    page = admin_client.get("/")
    text = page.content.decode()
    for href in (
        'href="/registros/asset/"',
        'href="/registros/vulnerability/"',
        'href="/registros/finding/?gravidade=4&amp;situacao=pendentes"',
        'href="/analise/"',
        'href="/analise/#plano"',
    ):
        assert href in text
    critical = admin_client.get(
        "/registros/finding/?gravidade=4&situacao=pendentes"
    )
    assert len(listed(critical)) == page.context["critical_count"] > 0
    assert all(
        f.situacao != 3 and f.vulnerability.cvss >= 9 for f in listed(critical)
    )
    # O filtro "não corrigidas" se mantém ao trocar de página.
    pending = admin_client.get("/registros/finding/?situacao=pendentes")
    assert all(f.situacao != 3 for f in listed(pending))
    if pending.context["page"].has_next():
        assert (
            "situacao=pendentes"
            in pending.content.decode().split("pagination")[1]
        )


def test_bell_shows_real_open_count_and_hides_without_permission(admin_client):
    import_json(FULL)
    opened = Finding.objects.filter(situacao=1).count()
    text = admin_client.get("/registros/asset/").content.decode()
    assert f'aria-label="Tratamentos em aberto: {opened}"' in text
    assert (
        f'<span class="alert-count" aria-hidden="true">{opened}</span>' in text
    )
    Finding.objects.filter(situacao=1).update(situacao=2)
    text = admin_client.get("/registros/asset/").content.decode()
    assert "alert-count" not in text
    no_group = group_client("semgrupo")
    denied = no_group.get("/").content.decode()
    assert "header-alert" not in denied and "global-search" not in denied


def test_sector_report_links_to_exact_sector(admin_client):
    import_json(FULL)
    report = admin_client.get("/relatorios/")
    row = report.context["summary"][0]
    assert "?lotacao=" in report.content.decode()
    page = admin_client.get("/registros/asset/", {"lotacao": row["lotacao"]})
    assets = listed(page)
    assert len(assets) == row["ativos"]
    assert all(a.lotacao == row["lotacao"] for a in assets)
    assert "Mostrando somente: lotação" in page.content.decode()


def test_delete_pages_explain_what_else_is_removed(admin_client):
    import_json(EXAMPLE)
    server = Asset.objects.get(hostname="SERVIDOR-01")
    findings = Finding.objects.filter(asset=server).count()
    dependencies = (
        Dependency.objects.filter(source=server).count()
        + Dependency.objects.filter(target=server).count()
    )
    text = admin_client.get(
        f"/registros/asset/{server.pk}/excluir/"
    ).content.decode()
    assert "Excluir este ativo?" in text
    assert (
        f"{findings} tratamento" in text
        and f"{dependencies} dependência" in text
    )
    finding = Finding.objects.filter(asset=server).first()
    text = admin_client.get(
        f"/registros/finding/{finding.pk}/excluir/"
    ).content.decode()
    assert "Excluir este tratamento?" in text and "SERVIDOR-01 · " in text
    assert "Finding object" not in text
    dependency = Dependency.objects.first()
    text = admin_client.get(
        f"/registros/dependency/{dependency.pk}/excluir/"
    ).content.decode()
    assert "depende de" in text and "Dependency object" not in text
    vuln = Vulnerability.objects.first()
    text = admin_client.get(
        f"/registros/vulnerability/{vuln.pk}/excluir/"
    ).content.decode()
    assert "Excluir esta vulnerabilidade?" in text and "vínculo" in text
    # Excluir a partir da ficha: Cancelar volta para a ficha, e depois de
    # excluir o destino é a lista (a ficha deixa de existir).
    sheet = f"/ativos/{server.pk}/"
    page = admin_client.get(
        f"/registros/asset/{server.pk}/excluir/?voltar={sheet}"
    )
    assert f'href="{sheet}">Cancelar' in page.content.decode()
    done = admin_client.post(
        f"/registros/asset/{server.pk}/excluir/",
        {"version": server.version, "voltar": sheet},
    )
    assert done.status_code == 302 and done["Location"] == "/registros/asset/"
    assert not Asset.objects.filter(pk=server.pk).exists()


def test_audit_page_uses_portuguese_descriptions(admin_client):
    import_json(EXAMPLE)
    asset = Asset.objects.first()
    admin_client.post(
        f"/registros/asset/{asset.pk}/excluir/", {"version": asset.version}
    )
    reader = group_client("leitor", "Leitor")
    reader.get("/registros/asset/novo/")  # negado e registrado
    text = admin_client.get("/auditoria/").content.decode()
    assert "Exclusão de ativo" in text and f"#{asset.pk}" in text
    assert "Acesso negado: cadastro de ativo" in text
    assert "delete_asset" not in text and ">denied<" not in text
    event = AuditEvent(action="login", target="session")
    assert event.descricao == "Entrada no sistema" and event.alvo == "—"


def test_history_and_lists_link_to_related_pages(admin_client):
    import_json(EXAMPLE)
    finding = Finding.objects.select_related("asset").first()
    text = admin_client.get(
        f"/tratamentos/{finding.pk}/historico/"
    ).content.decode()
    assert f'href="/ativos/{finding.asset_id}/"' in text
    vuln = Vulnerability.objects.exclude(cve=None).first()
    if vuln:
        text = admin_client.get("/registros/vulnerability/").content.decode()
        assert f"https://nvd.nist.gov/vuln/detail/{vuln.cve}" in text
        assert 'rel="noopener noreferrer"' in text


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/analise/",
        "/analise/?cenario=exemplo",
        "/api/risco/",
        "/api/grafo/",
        "/mapa/",
        "/relatorios/",
        "/registros/asset/",
        "/registros/finding/?situacao=pendentes",
        "/cve/",
        "/auditoria/",
        "/dados/",
    ],
)
def test_pages_work_with_empty_inventory(admin_client, path):
    page = admin_client.get(path)
    assert page.status_code == 200, page.content[:300]
