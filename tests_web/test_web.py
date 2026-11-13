import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import pytest
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from django.db import connection, transaction, IntegrityError, connections
from django.test import Client, override_settings
from django.core.exceptions import PermissionDenied
from inventory.models import (
    Asset,
    Vulnerability,
    Dependency,
    Finding,
    AuditEvent,
)
from inventory.services import (
    import_json,
    save_entity,
    delete_entity,
    Conflict,
)
from inventory.repository import snapshot, MemoryRepository
from inventario import Inventario
from risco import ModeloRisco

pytestmark = pytest.mark.django_db
EXAMPLE = Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes()


@pytest.fixture
def admin():
    return User.objects.create_superuser(
        "admin", password="temporary-test-password-only"
    )


@pytest.fixture
def sample():
    import_json(EXAMPLE)
    return snapshot()


@pytest.fixture
def reader():
    call_command("setup_roles")
    user = User.objects.create_user(
        "leitor", password="temporary-test-password-only"
    )
    user.groups.add(Group.objects.get(name="Leitor"))
    return user


def test_real_postgres_and_roundtrip(sample):
    assert connection.vendor == "postgresql"
    expected = Inventario.de_dict(json.loads(EXAMPLE))
    assert sample.para_dict() == expected.para_dict()
    assert ModeloRisco(sample).resolver().tolist() == pytest.approx(
        ModeloRisco(expected).resolver()
    )
    assert MemoryRepository(sample).load().para_dict() == sample.para_dict()


def test_full_example_reconciled():
    import_json(Path("dados_exemplo/inventario_exemplo.json").read_bytes())
    assert Asset.objects.count() == 76
    assert ModeloRisco(snapshot()).risco_total() == pytest.approx(
        1348.055858, abs=1e-6
    )


def test_dry_run_idempotent_sequence():
    import_json(EXAMPLE, dry_run=True)
    assert Asset.objects.count() == 0
    import_json(EXAMPLE)
    assert "já importado" in import_json(EXAMPLE)
    new = Asset.objects.create(
        hostname="PC-NOVO",
        tipo=1,
        custodiante="TI",
        lotacao="TI",
        descricao="Teste",
    )
    assert new.pk > 3


def test_invalid_import_rolls_back():
    raw = json.loads(EXAMPLE)
    raw[1]["hostname"] = raw[0]["hostname"]
    with pytest.raises(ValueError):
        import_json(json.dumps(raw).encode())
    assert Asset.objects.count() == 0


def test_invalid_dependency_sum_import():
    raw = json.loads(EXAMPLE)
    raw[0]["dependencias"] = [
        {"equipamento_id": 2, "fracao": 0.5},
        {"equipamento_id": 3, "fracao": 0.5},
    ]
    with pytest.raises(ValueError):
        import_json(json.dumps(raw).encode())
    assert Asset.objects.count() == 0


def test_role_denies_writes(reader, sample):
    with pytest.raises(PermissionDenied):
        delete_entity(reader, "asset", 1, 1)
    assert AuditEvent.objects.filter(action="denied").exists()
    client = Client()
    client.force_login(reader)
    assert client.get("/registros/asset/").status_code == 200
    assert client.get("/registros/asset/1/").status_code == 403
    assert (
        client.post(
            "/api/asset/", data="{}", content_type="application/json"
        ).status_code
        == 403
    )
    assert client.get("/auditoria/").status_code == 403
    assert client.get("/admin/auth/user/").status_code == 302


def test_anonymous_cannot_read():
    client = Client()
    assert client.get("/api/grafo/").status_code == 302
    assert client.get("/").status_code == 302
    assert client.get("/health/").json() == {"status": "ok"}


def test_csrf_enforced(admin, sample):
    client = Client(enforce_csrf_checks=True)
    client.force_login(admin)
    assert (
        client.post("/registros/asset/1/excluir/", {"version": 1}).status_code
        == 403
    )
    assert (
        client.delete(
            "/api/asset/1/",
            data='{"version":1}',
            content_type="application/json",
        ).status_code
        == 403
    )
    assert Asset.objects.count() == 3


def asset_data(hostname="PC-NOVO", version=1):
    return dict(
        hostname=hostname,
        tipo=1,
        custodiante="Suporte",
        lotacao="Sala",
        descricao="Teste web",
        version=version,
    )


def test_edit_version_prevents_lost_update(admin, sample):
    save_entity(admin, "asset", asset_data("PC-EDITADO"), 1)
    with pytest.raises(Conflict):
        save_entity(admin, "asset", asset_data("PC-ATRASADO"), 1)
    assert Asset.objects.get(pk=1).hostname == "PC-EDITADO"


def test_duplicate_hostname_and_patrimony(admin, sample):
    data = asset_data("servidor-01")
    with pytest.raises(ValueError):
        save_entity(admin, "asset", data)
    data = asset_data()
    data["patrimonio"] = "ÁBC 123"
    save_entity(admin, "asset", data)
    data = asset_data("PC-OUTRO")
    data["patrimonio"] = "abc 123"
    with pytest.raises(ValueError):
        save_entity(admin, "asset", data)


def test_dependency_sum_db_guard(sample):
    with pytest.raises(IntegrityError), transaction.atomic():
        Dependency.objects.create(source_id=1, target_id=3, fracao=".5")
    assert Dependency.objects.filter(source_id=1).count() == 1


def test_dependency_service_rejects_invalid_sum(admin, sample):
    with pytest.raises(ValueError):
        save_entity(
            admin,
            "dependency",
            {
                "source": Asset.objects.get(pk=1),
                "target": Asset.objects.get(pk=3),
                "fracao": 0.6,
            },
        )


def test_delete_preserves_shared_catalog(admin, sample):
    delete_entity(admin, "asset", 1, 1)
    assert Vulnerability.objects.count() == 2
    assert not Dependency.objects.filter(source_id=1).exists()
    assert Finding.objects.filter(vulnerability_id=1, asset_id=2).exists()


def test_corrected_excluded_accepted_still_counts(admin, sample):
    baseline = ModeloRisco(sample).risco_total()
    finding = Finding.objects.get(asset_id=1, vulnerability_id=1)
    save_entity(
        admin,
        "finding",
        {
            "asset": finding.asset,
            "vulnerability": finding.vulnerability,
            "situacao": 4,
            "version": 1,
        },
        finding.pk,
    )
    assert ModeloRisco(snapshot()).risco_total() == pytest.approx(baseline)
    save_entity(
        admin,
        "finding",
        {
            "asset": finding.asset,
            "vulnerability": finding.vulnerability,
            "situacao": 3,
            "version": 2,
        },
        finding.pk,
    )
    assert ModeloRisco(snapshot()).risco_total() < baseline


def test_pages_graph_and_xss(admin, sample):
    client = Client()
    client.force_login(admin)
    Asset.objects.filter(pk=1).update(descricao="<script>alert(1)</script>")
    for url in [
        "/",
        "/mapa/",
        "/relatorios/",
        "/registros/asset/",
        "/registros/vulnerability/",
        "/registros/finding/",
        "/registros/dependency/",
        "/auditoria/",
        "/dados/",
        "/cve/?q=windows",
        "/senha/",
        "/registros/asset/1/",
    ]:
        response = client.get(url)
        assert response.status_code == 200, url
        assert "<script>alert(1)</script>" not in response.content.decode()
    assert "&lt;script&gt;" in client.get("/registros/asset/").content.decode()
    payload = client.get("/api/grafo/").json()
    assert len(payload["elements"]) == 6
    assert payload["elements"][3]["data"]["source"] == "1"


def test_rest_crud_and_mass_assignment(admin, sample):
    client = Client()
    client.force_login(admin)
    data = asset_data()
    data["is_superuser"] = True
    assert (
        client.post(
            "/api/asset/", json.dumps(data), content_type="application/json"
        ).status_code
        == 422
    )
    data.pop("is_superuser")
    result = client.post(
        "/api/asset/", json.dumps(data), content_type="application/json"
    )
    assert result.status_code == 201, result.content
    pk = result.json()["id"]
    url = f"/api/asset/{pk}/"
    assert (
        client.patch(
            url,
            json.dumps({"version": 1, "descricao": "Atualizado"}),
            content_type="application/json",
        ).status_code
        == 200
    )
    assert (
        client.patch(
            url,
            json.dumps({"version": 1, "descricao": "Atrasado"}),
            content_type="application/json",
        ).status_code
        == 409
    )
    assert (
        client.delete(
            url, json.dumps({"version": 2}), content_type="application/json"
        ).status_code
        == 204
    )


def test_mfa_enforced_for_admin(admin):
    client = Client()
    client.force_login(admin)
    with override_settings(REQUIRE_ADMIN_MFA=True):
        response = client.get("/")
        assert response.status_code == 302 and response.url == "/mfa/"
        assert client.get("/mfa/").status_code == 200


def test_login_throttle(admin):
    client = Client()
    for i in range(6):
        response = client.post(
            "/entrar/", {"username": "admin", "password": "wrong"}
        )
    assert response.status_code == 429
    assert AuditEvent.objects.filter(action="login_failed").count() >= 5


@pytest.mark.django_db(transaction=True)
def test_concurrent_dependency_sum():
    import_json(EXAMPLE)
    Dependency.objects.filter(source_id=1).delete()

    def insert(target):
        connections.close_all()
        try:
            with transaction.atomic():
                Dependency.objects.create(
                    source_id=1, target_id=target, fracao=".6"
                )
            return "ok"
        except IntegrityError:
            return "rejected"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(insert, [2, 3]))
    assert sorted(results) == ["ok", "rejected"]
    assert Dependency.objects.filter(source_id=1).count() == 1


def test_mfa_provision_and_real_token(admin, tmp_path):
    from django_otp.oath import totp
    from django_otp.plugins.otp_totp.models import TOTPDevice
    from django_otp.plugins.otp_static.models import StaticToken

    target = tmp_path / "mfa-private.json"
    call_command("provision_mfa", admin.username, output=str(target))
    assert target.stat().st_mode & 0o777 == 0o600
    assert StaticToken.objects.count() == 8
    device = TOTPDevice.objects.get(user=admin)
    token = totp(
        device.bin_key, step=device.step, t0=device.t0, digits=device.digits
    )
    client = Client()
    client.force_login(admin)
    with override_settings(REQUIRE_ADMIN_MFA=True):
        response = client.post(
            "/mfa/",
            {"otp_device": device.persistent_id, "otp_token": str(token)},
        )
        assert response.status_code == 302
        assert client.get("/").status_code == 200


def test_vulnerability_creation_and_finding(admin, sample):
    from decimal import Decimal

    v = save_entity(
        admin,
        "vulnerability",
        {
            "descricao": "Falha de teste",
            "origem": 6,
            "cvss": Decimal("8.1"),
            "version": 1,
        },
    )
    save_entity(
        admin,
        "finding",
        {"asset": Asset.objects.get(pk=1), "vulnerability": v, "situacao": 1},
    )
    assert (
        ModeloRisco(snapshot()).risco_total()
        > ModeloRisco(sample).risco_total()
    )


@pytest.mark.parametrize(
    "content",
    [
        b"null",
        b"1",
        b"{}",
        b'[{"id":1,"id":2}]',
        b"[NaN]",
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_malformed_json_rejected(content):
    with pytest.raises(ValueError):
        import_json(content)
    assert Asset.objects.count() == 0


def test_neon_map_exposes_real_details_and_simulation_without_write(
    admin, sample
):
    client = Client()
    client.force_login(admin)
    payload = client.get("/api/grafo/").json()
    node = payload["elements"][0]["data"]
    assert node["tipo_id"] == 1
    assert node["custodiante"]
    assert node["cvss_maximo"] == 4
    assert node["herdado"] == pytest.approx(node["risco"] - node["proprio"])
    assert node["vulnerabilidades"][0]["situacao"] == "Aberta"
    assert payload["open_count"] == 4
    assert payload["plan"]
    before = snapshot().para_dict()
    result = client.get("/api/simular/1/").json()
    assert result["gravado"] is False
    assert result["correcoes"] == 1
    assert result["reducao"] > 0
    assert result["antes"] - result["depois"] == pytest.approx(
        result["reducao"]
    )
    assert snapshot().para_dict() == before
    assert client.get("/ativos/1/").status_code == 200
    assert client.get("/ativos/9999/").status_code == 404
    assert client.get("/api/simular/9999/").status_code == 404


def test_simulation_requires_permission_and_read_only_method(reader, sample):
    client = Client()
    assert client.get("/api/simular/1/").status_code == 302
    client.force_login(reader)
    assert client.get("/api/simular/1/").status_code == 200
    assert client.post("/api/simular/1/").status_code == 405
    reader.groups.clear()
    assert client.get("/api/simular/1/").status_code == 403


def test_map_detail_does_not_expose_vulnerability_data_to_asset_only_account(
    sample,
):
    from django.contrib.auth.models import Permission

    user = User.objects.create_user("somente-ativos")
    user.user_permissions.add(
        Permission.objects.get(
            codename="view_asset", content_type__app_label="inventory"
        )
    )
    client = Client()
    client.force_login(user)
    for path in ["/api/grafo/", "/api/simular/1/", "/ativos/1/"]:
        assert client.get(path).status_code == 403


def test_risk_flow_direction_is_inverse_of_dependency_including_reciprocal(
    admin, sample
):
    client = Client()
    client.force_login(admin)
    payload = client.get("/api/grafo/").json()
    edges = {
        item["data"]["id"]: item["data"]
        for item in payload["elements"]
        if "source" in item["data"]
    }
    # Estação depende do servidor: risco do servidor -> estação, sem volta.
    assert edges["d1-2"]["source"] == "1"
    assert edges["d1-2"]["target"] == "2"
    assert edges["d1-2"]["risk_source"] == "2"
    assert edges["d1-2"]["risk_target"] == "1"
    assert "d2-1" not in edges
    # Servidor e banco dependem um do outro, com pesos independentes.
    assert (
        edges["d2-3"]["risk_source"],
        edges["d2-3"]["risk_target"],
        edges["d2-3"]["fracao"],
    ) == ("3", "2", 0.5)
    assert (
        edges["d3-2"]["risk_source"],
        edges["d3-2"]["risk_target"],
        edges["d3-2"]["fracao"],
    ) == ("2", "3", 0.25)
    # A contribuição deve usar exatamente a fração e o risco do emissor.
    rows = {
        item["data"]["id"]: item["data"]
        for item in payload["elements"]
        if "source" not in item["data"]
    }
    inherited = sum(
        rows[edge["risk_source"]]["risco"] * edge["fracao"]
        for edge in edges.values()
        if edge["risk_target"] == "2"
    )
    assert rows["2"]["herdado"] == pytest.approx(inherited)
