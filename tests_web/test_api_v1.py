"""API v1: rotas, códigos de status, Problem Details, JWT e chave de API.

Cobre os cards S5_03 (boas práticas REST), S5_09 (autenticação), S5_10
(matriz de permissões) e S5_12 (testes de integração da API).
"""

import base64
import json
import logging
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import jwt
import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.test import Client

from inventory import api_v1
from inventory.models import ApiKey, Asset, AuditEvent, Finding, Vulnerability
from inventory.services import import_json

pytestmark = pytest.mark.django_db
EXAMPLE = Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes()
PASSWORD = "senha-de-teste-bem-longa-123"
NEW_ASSET = {
    "hostname": "SRV-API-01",
    "tipo": 2,
    "custodiante": "Setor de TI",
    "lotacao": "Sede",
    "descricao": "Servidor criado pela API",
}


def make_user(name, group=None, superuser=False):
    call_command("setup_roles")
    if superuser:
        user = User.objects.create_superuser(name, password=PASSWORD)
    else:
        user = User.objects.create_user(name, password=PASSWORD)
    if group:
        user.groups.add(Group.objects.get(name=group))
    return user


def bearer(user):
    return {"HTTP_AUTHORIZATION": "Bearer " + api_v1.issue_token(user)}


def call(method, path, headers=None, body=None, **extra):
    client = Client()
    kwargs = dict(headers or {}, **extra)
    if body is not None:
        kwargs["data"] = json.dumps(body)
        kwargs["content_type"] = "application/json"
    return getattr(client, method.lower())(path, **kwargs)


@pytest.fixture
def admin():
    return make_user("chefe", superuser=True)


@pytest.fixture
def analyst():
    return make_user("analista", "Analista")


@pytest.fixture
def reader():
    return make_user("leitor", "Leitor")


def assert_problem(response, status, slug):
    assert response.status_code == status, response.content[:400]
    assert response["Content-Type"].startswith("application/problem+json")
    body = response.json()
    assert body["status"] == status
    assert body["type"] == f"/api/v1/problemas/{slug}"
    assert body["title"] and body["detail"] and body["instance"]
    return body


# ------------------------------------------------------------ autenticação


def test_index_docs_and_spec_are_public():
    assert call("GET", "/api/v1/").json()["version"] == "1.0.0"
    spec = call("GET", "/api/v1/openapi.yaml")
    assert spec.status_code == 200 and b"openapi: 3.1.0" in spec.content
    page = call("GET", "/api/v1/docs/").content.decode()
    assert "swagger-ui-bundle.js" in page and "cdn" not in page.lower()
    kind = call("GET", "/api/v1/problemas/conflito").json()
    assert kind["status"] == 409 and kind["description"]


def test_token_login_issues_short_jwt_with_role(analyst):
    response = call(
        "POST", "/api/v1/auth/token", body={"username": "analista", "password": PASSWORD}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["token_type"] == "Bearer" and data["expires_in"] == 900
    claims = api_v1.decode_token(data["access_token"])
    assert claims["sub"] == str(analyst.pk) and claims["roles"] == ["Analista"]
    assert claims["exp"] - claims["iat"] == 900
    # A carga é legível por qualquer um (Base64URL não é criptografia): não
    # leva senha, hash nem dado pessoal.
    payload = data["access_token"].split(".")[1]
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)).decode()
    assert "Analista" in raw and PASSWORD not in raw and "argon2" not in raw
    assert AuditEvent.objects.filter(action="token", actor=analyst).exists()


def test_token_rejects_wrong_password_and_locks_after_five(analyst):
    for _ in range(4):
        wrong = call(
            "POST", "/api/v1/auth/token", body={"username": "analista", "password": "x"}
        )
        assert_problem(wrong, 401, "nao-autenticado")
        assert wrong["WWW-Authenticate"].startswith("Bearer")
    call("POST", "/api/v1/auth/token", body={"username": "analista", "password": "x"})
    locked = call(
        "POST", "/api/v1/auth/token", body={"username": "analista", "password": PASSWORD}
    )
    assert locked.status_code == 429


def test_token_requires_json_with_text_fields():
    assert_problem(
        call("POST", "/api/v1/auth/token", data="{", content_type="application/json"),
        400,
        "requisicao-invalida",
    )
    assert_problem(
        call("POST", "/api/v1/auth/token", body={"username": 1, "password": []}),
        400,
        "requisicao-invalida",
    )


def test_missing_expired_tampered_and_foreign_tokens_are_rejected(analyst):
    assert_problem(call("GET", "/api/v1/assets"), 401, "nao-autenticado")
    old = datetime.now(dt_timezone.utc) - timedelta(hours=1)
    expired = api_v1.issue_token(analyst, now=old)
    body = assert_problem(
        call("GET", "/api/v1/assets", HTTP_AUTHORIZATION="Bearer " + expired),
        401,
        "nao-autenticado",
    )
    assert "expirou" in body["detail"]
    good = api_v1.issue_token(analyst)
    head, payload, signature = good.split(".")
    forged = json.loads(base64.urlsafe_b64decode(payload + "==="))
    forged["roles"] = ["Administrador"]
    forged_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=")
    tampered = f"{head}.{forged_payload.decode()}.{signature}"
    other_secret = jwt.encode(
        api_v1.decode_token(good), "outro-segredo-qualquer-0123456789", algorithm="HS256"
    )
    unsigned = jwt.encode(
        api_v1.decode_token(good), None, algorithm="none"
    )
    wrong_audience = jwt.encode(
        dict(api_v1.decode_token(good), aud="outra-api"), api_v1.jwt_secret(), algorithm="HS256"
    )
    for token in (tampered, other_secret, unsigned, wrong_audience, "abc.def"):
        assert_problem(
            call("GET", "/api/v1/assets", HTTP_AUTHORIZATION="Bearer " + token),
            401,
            "nao-autenticado",
        )


def test_deactivated_account_token_stops_working(analyst):
    headers = bearer(analyst)
    analyst.is_active = False
    analyst.save()
    assert_problem(call("GET", "/api/v1/assets", headers), 401, "nao-autenticado")


def test_api_key_stored_as_hash_works_and_can_be_revoked(analyst):
    record, key = api_v1.create_api_key(analyst, "integração")
    assert key.startswith("snt_" + record.prefix + "_")
    assert key not in record.key_hash and len(record.key_hash) == 64
    response = call("POST", "/api/v1/assets", body=NEW_ASSET, HTTP_X_API_KEY=key)
    assert response.status_code == 201
    record.refresh_from_db()
    assert record.last_used_at is not None
    assert_problem(
        call("GET", "/api/v1/assets", HTTP_X_API_KEY=key[:-2] + "xx"),
        401,
        "nao-autenticado",
    )
    call_command("apikey", "revogar", record.prefix)
    assert_problem(call("GET", "/api/v1/assets", HTTP_X_API_KEY=key), 401, "nao-autenticado")


def test_apikey_command_shows_key_once(analyst, capsys):
    call_command("apikey", "criar", "analista", "script")
    out = capsys.readouterr().out
    key = next(word for word in out.split() if word.startswith("snt_"))
    assert ApiKey.objects.get().key_hash == api_v1._key_hash(key)
    call_command("apikey", "listar")
    listed = capsys.readouterr().out
    assert "ativa" in listed and key not in listed


def test_passwords_never_reach_logs_or_responses(analyst, caplog):
    caplog.set_level(logging.DEBUG)
    response = call(
        "POST", "/api/v1/auth/token", body={"username": "analista", "password": PASSWORD}
    )
    call("POST", "/api/v1/auth/token", body={"username": "analista", "password": "errada-1"})
    assert PASSWORD not in response.content.decode()
    assert PASSWORD not in caplog.text and "errada-1" not in caplog.text


# --------------------------------------------------------------- recursos


def test_full_crud_cycle_with_location_etag_and_versions(analyst):
    headers = bearer(analyst)
    created = call("POST", "/api/v1/assets", headers, body=NEW_ASSET)
    assert created.status_code == 201
    asset = created.json()
    assert created["Location"] == f"/api/v1/assets/{asset['id']}"
    assert created["ETag"] == '"1"' and asset["version"] == 1
    assert asset["links"]["self"] == created["Location"]
    got = call("GET", created["Location"], headers)
    assert got.status_code == 200 and got.json()["hostname"] == "SRV-API-01"
    patched = call(
        "PATCH", created["Location"], headers, body={"version": 1, "lotacao": "Sala 2"}
    )
    assert patched.status_code == 200 and patched.json()["version"] == 2
    assert patched["ETag"] == '"2"'
    stale = call("PATCH", created["Location"], headers, body={"version": 1, "lotacao": "X"})
    assert_problem(stale, 409, "conflito")
    full = dict(NEW_ASSET, descricao="Substituído", version=2)
    put = call("PUT", created["Location"], headers, body=full)
    assert put.status_code == 200 and put.json()["descricao"] == "Substituído"
    incomplete = call("PUT", created["Location"], headers, body={"version": 3})
    assert "hostname" in assert_problem(incomplete, 422, "dados-invalidos")["errors"]
    assert_problem(call("DELETE", created["Location"], headers), 428, "versao-obrigatoria")
    gone = call("DELETE", created["Location"], headers, HTTP_IF_MATCH='"3"')
    assert gone.status_code == 204 and gone.content == b""
    assert_problem(call("GET", created["Location"], headers), 404, "nao-encontrado")


def test_validation_and_unknown_fields_are_422(analyst):
    headers = bearer(analyst)
    bad = call("POST", "/api/v1/vulnerabilities", headers, body={"descricao": "x", "origem": 2, "cvss": 11})
    # A faixa do CVSS é uma restrição do banco, conferida pelo formulário.
    assert "cvss" in json.dumps(assert_problem(bad, 422, "dados-invalidos")["errors"])
    extra = call("POST", "/api/v1/assets", headers, body=dict(NEW_ASSET, is_superuser=True))
    assert assert_problem(extra, 422, "dados-invalidos")["errors"] == {
        "is_superuser": ["Campo não permitido."]
    }
    call("POST", "/api/v1/assets", headers, body=NEW_ASSET)
    again = call("POST", "/api/v1/assets", headers, body=dict(NEW_ASSET, hostname="srv-api-01"))
    assert again.status_code in (409, 422)
    assert again["Content-Type"].startswith("application/problem+json")
    assert_problem(call("POST", "/api/v1/assets", headers, data="[1]", content_type="application/json"), 400, "requisicao-invalida")


def test_dependency_sum_rule_and_singular_scenario(analyst):
    import_json(EXAMPLE)
    headers = bearer(analyst)
    first = Asset.objects.get(hostname="ESTACAO-01")
    other = Asset.objects.exclude(pk=first.pk).exclude(
        pk__in=first.dependencies.values("target")
    ).first()
    too_much = call(
        "POST", "/api/v1/dependencies", headers,
        body={"source": first.pk, "target": other.pk, "fracao": 0.99},
    )
    assert_problem(too_much, 422, "dados-invalidos")
    body = assert_problem(call("GET", "/api/v1/risk?cenario=singular", headers), 422, "sistema-singular")
    assert "invertível" in body["detail"]
    example = call("GET", "/api/v1/risk?cenario=exemplo", headers).json()
    assert [round(r["efetivo"]) for r in example["results"]] == [24, 18, 16]
    assert_problem(call("GET", "/api/v1/risk?cenario=xyz", headers), 400, "requisicao-invalida")


def test_pagination_links_ordering_by_risk_and_filters(reader):
    import_json(EXAMPLE)
    headers = bearer(reader)
    page = call("GET", "/api/v1/assets?limit=2&ordering=-risco", headers).json()
    assert page["count"] == 3 and len(page["results"]) == 2
    efetivos = [a["risco"]["efetivo"] for a in page["results"]]
    assert efetivos == sorted(efetivos, reverse=True) and round(efetivos[0]) == 24
    assert page["links"]["next"] and page["links"]["prev"] is None
    nxt = call("GET", page["links"]["next"], headers).json()
    assert len(nxt["results"]) == 1 and nxt["links"]["next"] is None
    assert call("GET", "/api/v1/assets?tipo=2", headers).json()["count"] == 1
    for bad in ("limit=0", "limit=101", "offset=-1", "ordering=senha", "tipo=9"):
        assert_problem(call("GET", "/api/v1/assets?" + bad, headers), 400, "requisicao-invalida")


def test_nested_routes(reader):
    import_json(EXAMPLE)
    headers = bearer(reader)
    vuln = Vulnerability.objects.first()
    affected = call("GET", f"/api/v1/vulnerabilities/{vuln.pk}/assets", headers).json()
    expected = Finding.objects.filter(vulnerability=vuln).count()
    assert affected["count"] == expected > 0
    assert all(a["tratamento"]["vulnerability"] == vuln.pk for a in affected["results"])
    asset = Asset.objects.get(hostname="SERVIDOR-01")
    findings = call("GET", f"/api/v1/assets/{asset.pk}/findings", headers).json()
    assert findings["count"] == Finding.objects.filter(asset=asset).count()
    assert "cvss" in findings["results"][0]["vulnerabilidade"]
    assert_problem(call("GET", "/api/v1/vulnerabilities/999999/assets", headers), 404, "nao-encontrado")


def test_wrong_method_unknown_resource_and_no_csrf_needed(analyst):
    headers = bearer(analyst)
    wrong = call("DELETE", "/api/v1/assets", headers)
    assert_problem(wrong, 405, "metodo-nao-permitido")
    assert wrong["Allow"] == "GET, POST"
    assert_problem(call("GET", "/api/v1/senhas", headers), 404, "nao-encontrado")
    # Cliente com verificação de CSRF ligada: a API não usa cookie, então não
    # precisa de token CSRF (e o cookie de sessão não autentica nela).
    strict = Client(enforce_csrf_checks=True)
    created = strict.post(
        "/api/v1/assets", data=json.dumps(NEW_ASSET), content_type="application/json", **headers
    )
    assert created.status_code == 201
    session = Client()
    session.force_login(analyst)
    assert_problem(session.get("/api/v1/assets"), 401, "nao-autenticado")


# ---------------------------------------------- matriz de permissões (S5_10)

MATRIX = [
    # (perfil, método, rota, corpo, permitido)
    ("Leitor", "GET", "/api/v1/assets", None, True),
    ("Leitor", "POST", "/api/v1/assets", NEW_ASSET, False),
    ("Leitor", "GET", "/api/v1/risk", None, True),
    ("Leitor", "GET", "/api/v1/audit-events", None, False),
    ("Analista", "POST", "/api/v1/assets", NEW_ASSET, True),
    ("Analista", "GET", "/api/v1/audit-events", None, False),
    ("Administrador", "GET", "/api/v1/audit-events", None, True),
    ("Administrador", "POST", "/api/v1/assets", NEW_ASSET, True),
    (None, "GET", "/api/v1/assets", None, False),
]


@pytest.mark.parametrize("role, method, path, body, allowed", MATRIX)
def test_permission_matrix(role, method, path, body, allowed):
    user = make_user("conta", role)
    response = call(method, path, bearer(user), body=body)
    if allowed:
        assert response.status_code in (200, 201), response.content[:300]
    else:
        assert_problem(response, 403, "sem-permissao")
        assert AuditEvent.objects.filter(action="denied", actor=user).exists()


def test_admin_route_needs_role_in_token_even_with_permission(analyst):
    analyst.user_permissions.add(
        *__import__("django.contrib.auth.models", fromlist=["Permission"]).Permission.objects.filter(
            codename="view_auditevent"
        )
    )
    assert_problem(call("GET", "/api/v1/audit-events", bearer(analyst)), 403, "sem-permissao")


def test_reader_cannot_change_other_records_by_id(reader, analyst):
    """IDOR: mudar o número na URL não dá acesso a mais do que o perfil."""
    created = call("POST", "/api/v1/assets", bearer(analyst), body=NEW_ASSET).json()
    target = f"/api/v1/assets/{created['id']}"
    for method, extra in (("PATCH", {"body": {"version": 1, "lotacao": "X"}}), ("DELETE", {"HTTP_IF_MATCH": '"1"'})):
        assert_problem(call(method, target, bearer(reader), **extra), 403, "sem-permissao")
    assert Asset.objects.get(pk=created["id"]).lotacao == "Sede"


def test_found_by_schemathesis_types_lengths_and_control_characters(analyst):
    """Falhas achadas pelo Schemathesis contra o contrato (S5_12)."""
    headers = bearer(analyst)
    # Um caractere de controle era aceito e depois impedia o inventário
    # inteiro de carregar (e com ele o modelo de risco).
    ctrl = call("POST", "/api/v1/assets", headers, body=dict(NEW_ASSET, lotacao="Sede\x1b[31m"))
    assert "lotacao" in assert_problem(ctrl, 422, "dados-invalidos")["errors"]
    wrong_types = call(
        "POST", "/api/v1/vulnerabilities", headers,
        body={"descricao": "x", "origem": "2", "cvss": True, "vetor": {}},
    )
    errors = assert_problem(wrong_types, 422, "dados-invalidos")["errors"]
    assert set(errors) == {"origem", "cvss", "vetor"}
    assert_problem(call("GET", "/api/v1/assets/%20", headers), 404, "nao-encontrado")
    assert_problem(call("PATCH", "/api/v1/nada/1/2", headers), 404, "nao-encontrado")
    assert_problem(call("GET", "/api/v1/assets?lotacao=" + "x" * 241, headers), 400, "requisicao-invalida")
    long_name = call("POST", "/api/v1/auth/token", body={"username": "a" * 151, "password": "x"})
    assert_problem(long_name, 400, "requisicao-invalida")
    assert Asset.objects.filter(lotacao__startswith="Sede\x1b").count() == 0


def test_web_form_also_rejects_control_characters(analyst):
    client = Client()
    client.force_login(analyst)
    data = dict(NEW_ASSET, descricao="linha 1\nlinha 2", version=1)
    response = client.post("/registros/asset/novo/", data)
    assert response.status_code == 200 and "caracteres visíveis" in response.content.decode()
    assert not Asset.objects.filter(hostname="SRV-API-01").exists()


def test_found_by_schemathesis_empty_scenario(analyst):
    """?cenario= vazio é parâmetro fora do enum: 400, não o banco real."""
    import_json(EXAMPLE)
    assert_problem(call("GET", "/api/v1/risk?cenario=", bearer(analyst)), 400, "requisicao-invalida")
    assert call("GET", "/api/v1/risk", bearer(analyst)).status_code == 200
    assert call("GET", "/api/v1/risk?cenario=singular", bearer(analyst)).status_code == 422
