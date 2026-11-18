"""Funções que existiam só no terminal e agora estão na web.

Cada teste compara a tela com a função do domínio que o terminal usa, para
garantir que a web mostra a mesma regra, e não uma segunda versão dela.
"""

import json
from pathlib import Path

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.test import Client

import arvore
from base_cve import BaseCVE
from inventory import references
from inventory.models import Asset, Dependency, Finding, Vulnerability
from inventory.repository import snapshot
from inventory.services import import_json
from risco import ModeloRisco

pytestmark = pytest.mark.django_db
FULL = Path("dados_exemplo/inventario_exemplo.json").read_bytes()
EXAMPLE = Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes()


@pytest.fixture
def admin_client():
    client = Client()
    client.force_login(
        User.objects.create_superuser(
            "admin", password="temporary-test-password-only"
        )
    )
    return client


@pytest.fixture
def reader_client():
    call_command("setup_roles")
    user = User.objects.create_user(
        "leitor", password="temporary-test-password-only"
    )
    user.groups.add(Group.objects.get(name="Leitor"))
    client = Client()
    client.force_login(user)
    return client


@pytest.fixture
def full():
    import_json(FULL)
    return snapshot()


# --- Base de CVEs (opção 16) --------------------------------------------


def test_cve_navigation_vendor_product_and_paging(admin_client):
    base, _ = BaseCVE.carregar()
    page = admin_client.get("/cve/")
    assert page.status_code == 200 and page.context["mode"] == "vendors"
    first_vendor, count = base.fabricantes()[0]
    assert page.context["page"][0] == (first_vendor, count)
    # Filtro de fabricante, como no terminal ("micro" acha Microsoft).
    filtered = admin_client.get("/cve/?filtro=micro").context["page"]
    assert ("Microsoft", base.fabricantes("micro")[0][1]) in list(filtered)
    products = admin_client.get("/cve/?fabricante=Microsoft")
    assert products.context["mode"] == "products"
    assert products.context["products"] == base.produtos("Microsoft")
    product = base.produtos("Microsoft")[0][0]
    listing = admin_client.get(
        "/cve/", {"fabricante": "Microsoft", "produto": product}
    )
    expected = base.do_produto("Microsoft", product)
    assert listing.context["page"].paginator.count == len(expected)
    assert [r["item"].cve for r in listing.context["rows"]] == [
        r.cve for r in expected[:20]
    ]
    # Busca por palavras passa de 30 resultados com paginação.
    windows = base.buscar("windows")
    assert len(windows) > 30
    second = admin_client.get("/cve/?q=windows&page=2")
    assert [r["item"].cve for r in second.context["rows"]] == [
        r.cve for r in windows[20:40]
    ]
    assert "q=windows" in second.context["filters"]


def test_cve_detail_explains_in_portuguese(admin_client, full):
    page = admin_client.get("/cve/CVE-2021-34527/")
    assert page.status_code == 200
    text = page.content.decode()
    explanation = page.context["explicacao"]
    record = page.context["item"]
    assert explanation["sentences"][0][0] == "Como se ataca"
    assert explanation["cwes"] and explanation["cwes"][0].startswith("CWE-")
    if record.acao:
        assert "O que fazer, segundo a CISA" in text
    # O inventário de exemplo tem a CVE no DRPC-SRV01.
    hosts = [e.hostname for e, _, _ in page.context["occurrences"]]
    assert "DRPC-SRV01" in hosts
    # Fichas com Windows combinam com o Print Spooler.
    assert any(
        "windows" in row["palavras"] for row in page.context["matching"]
    )
    # Número sem prefixo é aceito; texto inválido é 404.
    assert admin_client.get("/cve/2021-34527/").status_code == 200
    assert admin_client.get("/cve/nada/").status_code == 404


def test_cve_outside_kev_goes_to_occurrences(admin_client):
    response = admin_client.get("/cve/CVE-1999-0001/")
    assert response.status_code == 302
    assert response["Location"] == "/ocorrencias/?ref=CVE-1999-0001"


def test_record_without_vector_or_action_still_explains():
    info = references.explanation(vetor="CVSS:3.1/AV:N/bad")
    assert info["sentences"] == [] and info["action"] is None
    info = references.explanation(acao="Texto que não está na tabela")
    assert info["action"] == "Texto que não está na tabela"
    assert not info["action_translated"]


def test_cve_base_is_cached(monkeypatch):
    references._CACHE.clear()
    calls = []
    original = BaseCVE.carregar

    def counting(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(BaseCVE, "carregar", counting)
    first = references.cve_base()
    assert references.cve_base() is first and len(calls) == 1


# --- Ocorrências de CVE e CWE (opção 3, item 7) --------------------------


def test_occurrences_by_cwe_and_cve_match_domain(admin_client, full):
    page = admin_client.get("/ocorrencias/?ref=732")
    assert page.context["target"] == "CWE-732"
    assert page.context["rows"] == full.ocorrencias_da_referencia("CWE-732")
    assert page.context["rows"]
    assert "CWE-732" in page.context["label"]
    cve = admin_client.get("/ocorrencias/?ref=CVE-2021-34527")
    assert cve.context["record"] is not None
    bad = admin_client.get("/ocorrencias/?ref=nada")
    assert "Digite uma CVE" in bad.context["error"]
    assert admin_client.get("/ocorrencias/").context["rows"] == []


def test_finding_search_accepts_cwe(admin_client, full):
    page = admin_client.get("/registros/finding/?q=CWE-732")
    found = list(page.context["page"].paginator.object_list)
    assert found and all(f.vulnerability.cwe == "CWE-732" for f in found)


# --- Ficha do ativo: passo a passo, árvore e sugestões -------------------


def test_asset_page_steps_trees_and_suggestions(admin_client, full):
    asset = Asset.objects.get(hostname="DRPC-SRV01")
    page = admin_client.get(f"/ativos/{asset.pk}/")
    assert page.status_code == 200
    steps = page.context["steps"]
    row = ModeloRisco(full).risco_de(asset.pk)
    assert steps["proprio"] == pytest.approx(steps["fator"] * steps["soma"])
    assert steps["efetivo"] == pytest.approx(
        steps["proprio"] + steps["herdado"]
    )
    assert steps["efetivo"] == pytest.approx(row.efetivo)
    assert any(not s["conta"] for s in steps["vulnerabilidades"])
    for key, direction in (
        ("tree_down", arvore.DO_QUE_DEPENDE),
        ("tree_up", arvore.QUEM_DEPENDE),
    ):
        tree = arvore.montar(full, asset.pk, direction)
        rows = page.context[key]["rows"]
        assert page.context[key]["total"] == tree.total
        hosts = [e.hostname for r in rows for e in r["equipamentos"]]
        assert sorted(hosts) == sorted(
            e.hostname for e in arvore.equipamentos_da_arvore(tree)
        )
    # Ligações diretas oferecem a remoção da dependência gravada.
    direct = [r for r in page.context["tree_down"]["rows"] if r["depth"] == 0]
    for r in direct:
        if r["remover"]:
            dep = Dependency.objects.get(pk=r["remover"])
            assert dep.source_id == asset.pk
    assert "remover esta ligação" in page.content.decode()
    base, _ = BaseCVE.carregar()
    expected = base.sugestoes(full.buscar_por_id(asset.pk).ficha)
    assert page.context["suggestion_count"] == len(expected)
    assert [s["registro"].cve for s in page.context["suggestions"]] == [
        r.cve for r, _ in expected[:15]
    ]
    every, _ = references.suggestions(
        base, full.buscar_por_id(asset.pk), full, limit=len(expected)
    )
    spooler = next(
        s for s in every if s["registro"].cve == "CVE-2021-34527"
    )
    assert spooler["no_ativo"] and spooler["vulnerabilidade"].id == 82


def test_reader_sees_asset_page_without_action_links(reader_client, full):
    asset = Asset.objects.get(hostname="DRPC-SRV01")
    text = reader_client.get(f"/ativos/{asset.pk}/").content.decode()
    assert "remover esta ligação" not in text
    assert "Cadastrar no catálogo" not in text
    assert "Como o risco deste ativo foi calculado" in text


# --- Plano de correção (opção 17) ----------------------------------------


def test_correction_detail_matches_plan(admin_client, full):
    model = ModeloRisco(full)
    plan = model.plano_de_correcao()
    first = plan[0]
    page = admin_client.get(
        "/analise/correcao/",
        {
            "ativo": first.equipamento.id,
            "vulnerabilidade": first.vulnerabilidade.id,
        },
    )
    assert page.status_code == 200 and page.context["numero"] == 1
    detail = page.context["detail"]
    assert detail["percentual"] == pytest.approx(
        100 * first.reducao / model.risco_total()
    )
    assert len(detail["herdeiros"]) == len(
        model.herdam_de(first.equipamento.id)
    )
    assert "Por que esta correção vem aqui" in page.content.decode()
    analysis_page = admin_client.get("/analise/").content.decode()
    assert "/analise/correcao/?ativo=" in analysis_page
    assert (
        admin_client.get(
            "/analise/correcao/?ativo=999&vulnerabilidade=1"
        ).status_code
        == 404
    )


def test_correction_detail_in_scenario_and_without_kev(admin_client):
    page = admin_client.get(
        "/analise/correcao/?cenario=exemplo&ativo=1&vulnerabilidade=1"
    )
    if page.status_code == 404:  # o par pode não estar no plano do cenário
        from inventory import analysis

        inv = analysis.load_scenario("exemplo")
        fix = ModeloRisco(inv).plano_de_correcao()[0]
        page = admin_client.get(
            "/analise/correcao/",
            {
                "cenario": "exemplo",
                "ativo": fix.equipamento.id,
                "vulnerabilidade": fix.vulnerabilidade.id,
            },
        )
    assert page.status_code == 200 and page.context["scenario"] == "exemplo"
    assert page.context["detail"]["aviso"]
    singular = admin_client.get(
        "/analise/correcao/?cenario=singular&ativo=1&vulnerabilidade=1"
    )
    assert singular.status_code == 404


# --- CVSS: calculadora e nota pelo vetor ---------------------------------


def test_cvss_calculator_questions_and_pasted_vector(admin_client):
    page = admin_client.get("/cvss/?versao=3.1")
    assert page.context["result"] is None and page.context["answered"] == 0
    answers = dict(
        versao="3.1", AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"
    )
    done = admin_client.get("/cvss/", answers)
    result = done.context["result"]
    assert result["nota"] == 9.8 and result["vetor"].startswith("CVSS:3.1/")
    assert result["gravidade"].rotulo == "Crítica"
    assert "cvss=9.8" in result["register"]
    pasted = admin_client.get(
        "/cvss/?vetor=cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"
    )
    assert pasted.context["pasted_result"]["nota"] == 9.8
    wrong = admin_client.get("/cvss/?vetor=CVSS:3.1/AV:N")
    assert "Faltam métricas" in wrong.context["pasted_error"]
    v4 = admin_client.get("/cvss/?versao=9.9&AV=Z")
    assert v4.context["version"] == "4.0" and v4.context["answered"] == 0
    zero = admin_client.get(
        "/cvss/?vetor=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    )
    assert zero.context["pasted_result"]["nota"] == 0
    assert "register" not in zero.context["pasted_result"]


def _vuln_post(client, **fields):
    data = {"descricao": "", "origem": 2, "cvss": "", "version": 1}
    data.update(fields)
    return client.post("/registros/vulnerability/novo/", data)


def test_web_form_score_from_vector_and_mismatch(admin_client):
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    saved = _vuln_post(admin_client, descricao="Falha de teste", vetor=vector)
    assert saved.status_code == 302
    vuln = Vulnerability.objects.get(descricao="Falha de teste")
    assert float(vuln.cvss) == 9.8 and vuln.vetor == vector
    wrong = _vuln_post(
        admin_client, descricao="Outra falha", vetor=vector, cvss="5.0"
    )
    assert "não confere com o vetor" in wrong.content.decode()
    empty = _vuln_post(admin_client, descricao="Sem nota")
    assert "Informe a nota CVSS" in empty.content.decode()
    bad = _vuln_post(admin_client, descricao="Vetor ruim", vetor="CVSS:3.1/AV:N")
    assert "Faltam métricas" in bad.content.decode()
    zero = _vuln_post(
        admin_client,
        descricao="Sem impacto",
        vetor="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    )
    assert "nota 0,0" in zero.content.decode()
    nothing = _vuln_post(admin_client, cvss="5.0")
    assert "Informe a descrição" in nothing.content.decode()


def test_web_form_fills_blanks_from_kev(admin_client):
    base, _ = BaseCVE.carregar()
    record = base.buscar_cve("CVE-2021-44228")
    response = _vuln_post(admin_client, cve="CVE-2021-44228")
    assert response.status_code == 302
    vuln = Vulnerability.objects.get(cve="CVE-2021-44228")
    assert vuln.descricao == record.nome.rstrip(".") or vuln.descricao.startswith(
        record.nome[:20]
    )
    assert vuln.cwe == record.cwes[0]
    assert float(vuln.cvss) == record.cvss
    follow = admin_client.get(response["Location"])
    shown = [str(m) for m in follow.context["messages"]]
    assert any("Preenchido pela base" in m for m in shown)
    # A API continua exigindo a nota (contrato publicado).
    from inventory.forms import FORMS

    form = FORMS["vulnerability"](
        {"descricao": "x", "origem": 2, "cve": "CVE-2019-0708", "version": 1}
    )
    assert not form.is_valid() and "cvss" in form.errors


# --- Importação do formato do Trabalho 1 ---------------------------------


def test_import_accepts_trabalho_1_format():
    t1 = {
        "ativos": {
            "1": {
                "categoria": 2,
                "hostname": "SRV-T1",
                "custodiante": "TI",
                "lotacao": "Sede",
                "descricao": "Servidor antigo",
            },
            "2": {
                "categoria": 1,
                "hostname": "PC-T1",
                "custodiante": "TI",
                "lotacao": "Sede",
                "descricao": "Estação antiga",
            },
        },
        "falhas": {
            "1": {
                "ativo_id": 1,
                "descricao": "Senha padrão",
                "origem": 1,
                "gravidade": 4,
                "situacao": 1,
            },
            "2": {
                "ativo_id": 2,
                "descricao": "Senha padrão",
                "origem": 1,
                "gravidade": 4,
                "situacao": 2,
            },
        },
    }
    content = json.dumps(t1).encode()
    message = import_json(content, dry_run=True)
    assert "Trabalho 1 convertido" in message and Asset.objects.count() == 0
    message = import_json(content)
    assert "Importados 2 ativos" in message and "Trabalho 1" in message
    # Falhas iguais viram uma vulnerabilidade só, ligada aos dois ativos.
    assert Vulnerability.objects.count() == 1
    assert float(Vulnerability.objects.get().cvss) == 9.8
    assert Finding.objects.count() == 2
    with pytest.raises(ValueError, match="lista JSON"):
        import_json(b'{"outra": 1}')


def test_transfer_page_mentions_t1(admin_client):
    assert "Trabalho 1" in admin_client.get("/dados/").content.decode()


def test_new_pages_require_login_and_permission(reader_client):
    anonymous = Client()
    for url in (
        "/cve/CVE-2021-34527/",
        "/ocorrencias/",
        "/cvss/",
        "/analise/correcao/",
    ):
        assert anonymous.get(url).status_code == 302
    no_perm = Client()
    no_perm.force_login(
        User.objects.create_user("sem", password="temporary-test-password-only")
    )
    assert no_perm.get("/ocorrencias/").status_code == 403
    assert no_perm.get("/cve/CVE-2021-34527/").status_code == 403
    assert no_perm.get("/cvss/").status_code == 200
    import_json(EXAMPLE)
    assert reader_client.get("/ocorrencias/?ref=CWE-79").status_code == 200
