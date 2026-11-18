"""SQL injection (card S5_07) e número de consultas, o N+1 (card S5_08).

Parte 1: o laboratório (academic/sqli_lab.py) prova que a concatenação é
explorável e que o parâmetro ligado não é; depois, as mesmas cargas vão
contra a API e o ORM de verdade, que não podem vazar nada.

Parte 2: listar mais registros não pode fazer mais consultas. Cada
listagem é medida com a base pequena (3 equipamentos) e com a grande
(76): o número de consultas tem de ser o mesmo.
"""

import json
from pathlib import Path

import pytest
from django.contrib.auth.models import User
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext

from academic import sqli_lab
from inventory import api_v1
from inventory.models import Asset, Dependency, Finding, Vulnerability
from inventory.services import import_json

PEQUENA = Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes()
GRANDE = Path("dados_exemplo/inventario_exemplo.json").read_bytes()
CARGAS = [sqli_lab.TAUTOLOGIA, sqli_lab.UNION, sqli_lab.EMPILHADA]


# ----------------------------------------------------------------------
# Parte 1: SQL injection
# ----------------------------------------------------------------------


def test_laboratorio_concatenacao_e_exploravel():
    banco = sqli_lab.criar_banco()
    assert len(sqli_lab.buscar_vulneravel(banco, "Sede")) == 2
    # Tautologia: a condição vira sempre verdadeira e devolve tudo.
    assert len(sqli_lab.buscar_vulneravel(banco, sqli_lab.TAUTOLOGIA)) == 3
    # UNION: os hashes das contas saem junto com os equipamentos.
    vazado = sqli_lab.buscar_vulneravel(banco, sqli_lab.UNION)
    assert ("admin", "argon2$fictício-1") in vazado
    # Comandos empilhados: a tabela some.
    sqli_lab.buscar_vulneravel_script(banco, sqli_lab.EMPILHADA)
    assert "equipamentos" not in sqli_lab.tabelas(banco)


@pytest.mark.parametrize("carga", CARGAS)
def test_laboratorio_parametro_ligado_nao_e_exploravel(carga):
    banco = sqli_lab.criar_banco()
    assert sqli_lab.buscar_seguro(banco, carga) == []
    assert sqli_lab.tabelas(banco) == ["contas", "equipamentos"]


@pytest.mark.django_db
@pytest.mark.parametrize("carga", CARGAS)
def test_orm_trata_a_carga_como_texto(carga):
    import_json(PEQUENA)
    total = Asset.objects.count()
    assert not Asset.objects.filter(lotacao=carga).exists()
    assert not Asset.objects.filter(hostname__icontains=carga).exists()
    assert Asset.objects.count() == total


@pytest.mark.django_db
@pytest.mark.parametrize("carga", CARGAS)
def test_api_filtros_nao_injetam(carga):
    import_json(PEQUENA)
    user = User.objects.create_superuser("chefe", password="x" * 20)
    headers = {"HTTP_AUTHORIZATION": "Bearer " + api_v1.issue_token(user)}
    client = Client()
    for consulta in ({"lotacao": carga}, {"tipo": carga},
                     {"ordering": carga}):
        resposta = client.get("/api/v1/assets", consulta, **headers)
        assert resposta.status_code in (200, 400, 422)
        if resposta.status_code == 200:
            assert resposta.json()["count"] == 0
    assert Asset.objects.count() == 3


# ----------------------------------------------------------------------
# Parte 2: N+1
# ----------------------------------------------------------------------


def contar(funcao):
    with CaptureQueriesContext(connection) as consultas:
        funcao()
    return len(consultas)


@pytest.mark.django_db
def test_demonstracao_do_n_mais_1():
    """Sem select_related, cada achado busca o seu equipamento: 1 + N."""
    import_json(GRANDE)
    n = Finding.objects.count()
    assert n > 50

    def ingenuo():
        return [f.asset.hostname for f in Finding.objects.all()]

    def com_join():
        return [f.asset.hostname for f in
                Finding.objects.select_related("asset")]

    assert contar(ingenuo) == 1 + n
    assert contar(com_join) == 1


def medir_nas_duas_bases(django_user_model, pedido):
    medidas = []
    for base in (PEQUENA, GRANDE):
        for modelo in (Finding, Dependency, Asset, Vulnerability):
            modelo.objects.all().delete()
        import_json(base)
        medidas.append(contar(pedido))
    return medidas


@pytest.mark.django_db
@pytest.mark.parametrize(
    "caminho",
    ["/api/v1/assets?limit=100", "/api/v1/findings?limit=100",
     "/api/v1/vulnerabilities?limit=100", "/api/v1/dependencies?limit=100",
     "/api/v1/risk"],
)
def test_api_consultas_constantes(django_user_model, caminho):
    user = django_user_model.objects.create_superuser(
        "chefe", password="x" * 20)
    headers = {"HTTP_AUTHORIZATION": "Bearer " + api_v1.issue_token(user)}
    client = Client()

    def pedido():
        resposta = client.get(caminho, **headers)
        assert resposta.status_code == 200, resposta.content[:300]
        json.loads(resposta.content)

    pequena, grande = medir_nas_duas_bases(django_user_model, pedido)
    assert pequena == grande, (caminho, pequena, grande)


@pytest.mark.django_db
@pytest.mark.parametrize("caminho", ["/", "/mapa/", "/analise/",
                                     "/relatorios/", "/api/grafo/",
                                     "/api/risco/"])
def test_telas_consultas_constantes(django_user_model, caminho):
    user = django_user_model.objects.create_superuser(
        "chefe", password="x" * 20)
    client = Client()
    client.force_login(user)

    def pedido():
        resposta = client.get(caminho)
        assert resposta.status_code == 200, resposta.content[:300]

    pequena, grande = medir_nas_duas_bases(django_user_model, pedido)
    assert pequena == grande, (caminho, pequena, grande)
