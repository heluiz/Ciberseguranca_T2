"""Análise de risco, filtros, PUT e algoritmos aplicados ao inventário."""

import json
from pathlib import Path

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.test import Client

from inventory import analysis
from inventory.models import Asset
from inventory.repository import MemoryRepository, SnapshotRepository
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


@pytest.fixture
def reader_client():
    call_command("setup_roles")
    user = User.objects.create_user("leitor", password=PASSWORD)
    user.groups.add(Group.objects.get(name="Leitor"))
    client = Client()
    client.force_login(user)
    return client


def by_host(rows):
    return {row["equipamento"].hostname: row for row in rows}


def test_hand_checked_scenario_in_memory():
    """Cenário de 3 equipamentos conferido à mão: x = (16, 24, 18)."""
    result = analysis.risk_analysis(
        MemoryRepository(analysis.load_scenario("exemplo"))
    )
    assert result["diagnostic"].invertivel and not result["error"]
    assert result["diagnostic"].determinante == pytest.approx(0.875)
    rows = by_host(result["rows"])
    assert rows["ESTACAO-01"]["proprio"] == pytest.approx(4)
    assert rows["SERVIDOR-01"]["proprio"] == pytest.approx(15)
    assert rows["BANCO-01"]["proprio"] == pytest.approx(12)
    assert rows["ESTACAO-01"]["efetivo"] == pytest.approx(16)
    assert rows["SERVIDOR-01"]["efetivo"] == pytest.approx(24)
    assert rows["BANCO-01"]["efetivo"] == pytest.approx(18)
    assert rows["ESTACAO-01"]["herdado"] == pytest.approx(12)
    assert result["total"] == pytest.approx(58)
    # Ordem do ranking (Merge Sort): maior risco efetivo primeiro.
    assert [r["equipamento"].hostname for r in result["rows"]] == [
        "SERVIDOR-01",
        "BANCO-01",
        "ESTACAO-01",
    ]
    matrices = result["matrices"]
    assert dict(matrices["M"])["SERVIDOR-01"] == [1, 1]
    assert matrices["v"] == [4.0, 6.0]
    assert dict(matrices["I_menos_A"])["BANCO-01"] == [0.0, -0.25, 1.0]


def test_singular_scenario_is_refused_before_solving():
    result = analysis.risk_analysis(
        MemoryRepository(analysis.load_scenario("singular"))
    )
    assert not result["diagnostic"].invertivel
    assert result["diagnostic"].posto == 2
    assert result["rows"] == [] and result["total"] is None
    assert "não é invertível" in result["error"]


def test_same_use_case_with_memory_and_postgres():
    """O caso de uso não muda quando a persistência muda (repositório injetado)."""
    import_json(EXAMPLE)
    database = analysis.risk_analysis(SnapshotRepository())
    memory = analysis.risk_analysis(
        MemoryRepository(analysis.load_scenario("exemplo"))
    )
    assert [r["equipamento"].hostname for r in database["rows"]] == [
        r["equipamento"].hostname for r in memory["rows"]
    ]
    for field in ("proprio", "herdado", "efetivo"):
        assert [r[field] for r in database["rows"]] == pytest.approx(
            [r[field] for r in memory["rows"]]
        )
    assert database["total"] == pytest.approx(memory["total"])


def test_reachability_hops_and_cycles_on_inventory():
    inventory = analysis.load_scenario("exemplo")
    ids = {e.hostname: e.id for e in inventory}
    # ESTACAO depende de SERVIDOR; SERVIDOR depende de BANCO; BANCO de SERVIDOR.
    graph = analysis.propagation_graph(inventory)
    assert ids["ESTACAO-01"] in graph[ids["SERVIDOR-01"]]
    reached = analysis.reachability(inventory, ids["BANCO-01"])
    assert [(r["equipamento"].hostname, r["saltos"]) for r in reached] == [
        ("SERVIDOR-01", 1),
        ("ESTACAO-01", 2),
    ]
    assert analysis.reachability(inventory, ids["ESTACAO-01"]) == []
    cycles = analysis.dependency_cycles(inventory)
    assert len(cycles) == 1
    assert {cycles[0][0].hostname, cycles[0][1].hostname} == {
        "SERVIDOR-01",
        "BANCO-01",
    }


def test_large_inventory_ranking_matches_native_sort_and_hides_matrices():
    import_json(FULL)
    result = analysis.risk_analysis(SnapshotRepository())
    assert len(result["rows"]) == 76 and result["matrices"] is None
    expected = sorted(
        result["rows"], key=lambda r: (-r["efetivo"], r["equipamento"].id)
    )
    assert result["rows"] == expected
    by_own = analysis.risk_analysis(SnapshotRepository(), order="proprio")
    values = [r["proprio"] for r in by_own["rows"]]
    assert values == sorted(values, reverse=True)


def test_analysis_pages_and_risk_api(admin_client, reader_client):
    import_json(EXAMPLE)
    page = admin_client.get("/analise/")
    assert page.status_code == 200
    text = page.content.decode()
    assert "INVERTÍVEL" in text and "SERVIDOR-01" in text and "0,875" in text
    payload = admin_client.get("/api/risco/").json()
    assert payload["total"] == pytest.approx(58)
    assert [r["hostname"] for r in payload["rows"]][0] == "SERVIDOR-01"
    assert payload["rows"][0]["ficha_url"].startswith("/ativos/")
    singular = admin_client.get("/analise/?cenario=singular")
    assert singular.status_code == 200
    assert "NÃO INVERTÍVEL" in singular.content.decode()
    refused = admin_client.get("/api/risco/?cenario=singular")
    assert (
        refused.status_code == 422 and "invertível" in refused.json()["error"]
    )
    # Cenário de demonstração não grava nem mistura dados do banco.
    demo = admin_client.get("/api/risco/?cenario=exemplo").json()
    assert all(row["ficha_url"] == "" for row in demo["rows"])
    assert Asset.objects.count() == 3
    assert reader_client.get("/analise/").status_code == 200
    assert reader_client.get("/api/risco/").status_code == 200
    assert admin_client.post("/api/risco/").status_code == 405


def test_account_without_group_sees_real_role_and_guidance():
    user = User.objects.create_user("semgrupo", password=PASSWORD)
    client = Client()
    client.force_login(user)
    for url in ("/", "/analise/", "/api/risco/", "/registros/asset/"):
        assert client.get(url).status_code == 403
    denied = client.get("/").content.decode()
    assert (
        "Sem grupo" in denied and "ainda não pertence a nenhum grupo" in denied
    )
    assert "Administrador</small>" not in denied
    # Sem permissão de leitura, o menu não oferece o que a conta não pode abrir.
    assert (
        'href="/registros/asset/"'
        not in denied.split("<nav", 1)[1].split("</nav>", 1)[0]
    )


def test_asset_filters_cover_owner_type_id_and_specs(admin_client):
    import_json(FULL)

    def hosts(query):
        page = admin_client.get("/registros/asset/" + query)
        assert page.status_code == 200
        return {
            obj.hostname for obj in page.context["page"].paginator.object_list
        }

    everything = hosts("")
    assert len(everything) == 76
    servers = hosts("?tipo=2")
    assert servers and servers == set(
        Asset.objects.filter(tipo=2).values_list("hostname", flat=True)
    )
    first = Asset.objects.order_by("pk").first()
    assert first.hostname in hosts(f"?q={first.custodiante[:12]}")
    assert hosts(f"?q=%23{first.pk}") >= {first.hostname}
    with_maker = Asset.objects.exclude(fabricante="").first()
    assert with_maker.hostname in hosts(f"?q={with_maker.fabricante}")
    assert hosts("?q=zz-inexistente-zz") == set()
    assert hosts("?tipo=99") == everything  # filtro inválido é ignorado
    # A paginação preserva o filtro.
    page = admin_client.get("/registros/asset/?tipo=1")
    if page.context["page"].has_next():
        assert "&amp;tipo=1" in page.content.decode()


def test_finding_and_vulnerability_filters(admin_client):
    import_json(FULL)
    page = admin_client.get("/registros/finding/?situacao=1&gravidade=4")
    findings = list(page.context["page"].paginator.object_list)
    assert findings
    assert all(f.situacao == 1 and f.vulnerability.cvss >= 9 for f in findings)
    page = admin_client.get("/registros/vulnerability/?gravidade=2")
    vulns = list(page.context["page"].paginator.object_list)
    assert vulns and all(4 <= v.cvss <= 6.9 for v in vulns)
    page = admin_client.get("/registros/dependency/?q=srv")
    assert page.status_code == 200


def test_put_replaces_whole_record_and_patch_stays_partial(admin_client):
    import_json(EXAMPLE)
    asset = Asset.objects.get(hostname="ESTACAO-01")
    url = f"/api/asset/{asset.pk}/"
    current = admin_client.get(url).json()["results"][0]
    # PUT sem os campos obrigatórios é recusado: não completa com o valor antigo.
    partial = admin_client.put(
        url,
        json.dumps(
            {"version": current["version"], "descricao": "Só um campo"}
        ),
        content_type="application/json",
    )
    assert partial.status_code == 422
    body = {k: v for k, v in current.items() if k != "id"}
    body.update(descricao="Estação substituída por PUT", fabricante="")
    replaced = admin_client.put(
        url, json.dumps(body), content_type="application/json"
    )
    assert replaced.status_code == 200, replaced.content
    asset.refresh_from_db()
    assert asset.descricao == "Estação substituída por PUT"
    assert asset.version == current["version"] + 1
    stale = admin_client.put(
        url, json.dumps(body), content_type="application/json"
    )
    assert stale.status_code == 409
    assert (
        admin_client.put(
            "/api/asset/", "{}", content_type="application/json"
        ).status_code
        == 405
    )


def test_asset_sheet_shows_inheritance_and_reach(admin_client):
    import_json(EXAMPLE)
    bank = Asset.objects.get(hostname="BANCO-01")
    text = admin_client.get(f"/ativos/{bank.pk}/").content.decode()
    assert "Quem é alcançado" in text and "ESTACAO-01" in text
    assert "De onde este ativo herda risco" in text
