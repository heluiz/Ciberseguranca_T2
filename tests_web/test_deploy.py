"""Preparação da instalação, registro de disponibilidade e medições."""

import pytest
from django.contrib.auth.models import Group, User
from django.core.management import call_command
from django.core.management.base import CommandError

from academic.benchmark import full_pipeline, synthetic_inventory
from inventory.models import Asset
from ops import monitor

pytestmark = pytest.mark.django_db


def test_bootstrap_prepares_everything_once(monkeypatch, capsys):
    monkeypatch.setenv("SENTINEL_ADMIN_USER", "admin")
    monkeypatch.setenv("SENTINEL_ADMIN_PASSWORD", "senha-inicial-de-teste")
    monkeypatch.setenv("SENTINEL_DEMO", "1")
    call_command("bootstrap")
    admin = User.objects.get(username="admin")
    assert admin.is_superuser and admin.check_password(
        "senha-inicial-de-teste"
    )
    assert Group.objects.filter(name__in=["Leitor", "Analista"]).count() == 2
    assert Asset.objects.count() == 76
    assert "senha-inicial-de-teste" not in capsys.readouterr().out
    # Segunda execução: nada é duplicado e a senha trocada não é desfeita.
    admin.set_password("senha-trocada-pelo-usuario")
    admin.save()
    call_command("bootstrap")
    assert User.objects.filter(is_superuser=True).count() == 1
    assert User.objects.get(username="admin").check_password(
        "senha-trocada-pelo-usuario"
    )
    assert Asset.objects.count() == 76


def test_bootstrap_without_credentials_or_demo(monkeypatch):
    for name in (
        "SENTINEL_ADMIN_USER",
        "SENTINEL_ADMIN_PASSWORD",
        "SENTINEL_DEMO",
    ):
        monkeypatch.delenv(name, raising=False)
    call_command("bootstrap")
    assert not User.objects.exists() and not Asset.objects.exists()
    assert Group.objects.filter(name="Leitor").exists()


def test_bootstrap_refuses_short_password(monkeypatch):
    monkeypatch.setenv("SENTINEL_ADMIN_USER", "admin")
    monkeypatch.setenv("SENTINEL_ADMIN_PASSWORD", "curta")
    with pytest.raises(CommandError):
        call_command("bootstrap")
    assert not User.objects.exists()


def test_monitor_reports_up_and_down(client, live_server):
    ok, detail = monitor.check(live_server.url + "/health/")
    assert ok and detail.startswith("HTTP 200")
    ok, detail = monitor.check("http://127.0.0.1:9/health/")
    assert not ok


def test_benchmark_inventory_is_valid_and_solvable():
    inventory = synthetic_inventory(12)
    rows = full_pipeline(inventory)
    assert len(rows) == 12
    values = [row.efetivo for row in rows]
    assert values == sorted(values, reverse=True)
    assert all(row.efetivo >= row.proprio for row in rows)
