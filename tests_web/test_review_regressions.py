"""Cenários reais encontrados na revisão, incluindo leitura com permissões parciais."""

from pathlib import Path

import pytest
from django.contrib.auth.models import Permission, User

from inventory.models import Dependency
from inventory.services import import_json

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "missing", ["asset", "vulnerability", "finding", "dependency"]
)
def test_partial_permissions_cannot_export_or_read_dashboard(client, missing):
    user = User.objects.create_user("restricted")
    names = {
        "view_asset",
        "view_vulnerability",
        "view_finding",
        "view_dependency",
    } - {"view_" + missing}
    user.user_permissions.add(
        *Permission.objects.filter(
            content_type__app_label="inventory", codename__in=names
        )
    )
    client.force_login(user)
    assert client.get("/dados/exportar/").status_code == 403
    assert client.get("/").status_code == 403


def test_complete_permissions_allow_export_and_dashboard(client):
    import_json(Path("dados_exemplo/cenario_3_equipamentos.json").read_bytes())
    user = User.objects.create_user("inventory-reader")
    user.user_permissions.add(
        *Permission.objects.filter(
            content_type__app_label="inventory",
            codename__in=[
                "view_asset",
                "view_vulnerability",
                "view_finding",
                "view_dependency",
            ],
        )
    )
    client.force_login(user)
    assert client.get("/dados/exportar/").status_code == 200
    assert client.get("/").status_code == 200


def test_dependency_pagination_returns_full_inventory_once(client):
    import_json(Path("dados_exemplo/inventario_exemplo.json").read_bytes())
    user = User.objects.create_superuser("pagination-admin")
    client.force_login(user)
    first = client.get("/api/dependency/").json()
    assert first["count"] == 164
    assert len(first["results"]) == 100
    second = client.get(
        "/api/dependency/", {"offset": first["next_offset"]}
    ).json()
    assert len(second["results"]) == 64
    assert second["next_offset"] is None
    ids = [row["id"] for row in first["results"] + second["results"]]
    assert ids == list(
        Dependency.objects.order_by("pk").values_list("id", flat=True)
    )
    assert len(ids) == len(set(ids))
    last = client.get("/api/dependency/", {"offset": 164}).json()
    assert last["results"] == []
    assert last["next_offset"] is None
    limited = client.get("/api/dependency/", {"limit": 1}).json()
    assert len(limited["results"]) == 1
    assert limited["next_offset"] == 1


@pytest.mark.parametrize(
    "query",
    [
        {"limit": "abc"},
        {"limit": 0},
        {"limit": 101},
        {"offset": -1},
        {"offset": "1.5"},
        {"offset": 2**80},
    ],
)
def test_invalid_pagination_is_rejected(client, query):
    client.force_login(User.objects.create_superuser("pagination-admin"))
    assert client.get("/api/asset/", query).status_code == 400
