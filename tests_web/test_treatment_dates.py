from datetime import timedelta
import json
import pytest
from django.contrib.auth.models import User, Group
from django.core.management import call_command
from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError
from django.test import Client
from django.utils import timezone
from inventory.models import Asset, Finding, FindingHistory, Vulnerability
from inventory.services import (
    save_entity,
    delete_entity,
    Conflict,
    import_json,
)
from inventory.repository import snapshot
from risco import ModeloRisco
from tests_web.test_web import EXAMPLE

pytestmark = pytest.mark.django_db


@pytest.fixture
def context():
    import_json(EXAMPLE)
    user = User.objects.create_superuser(
        "auditor", password="temporary-test-only-password"
    )
    now = timezone.now().replace(microsecond=0)
    return user, now


def data(status=1, version=1, **dates):
    return dict(
        asset=Asset.objects.get(pk=1),
        vulnerability=Vulnerability.objects.get(pk=2),
        situacao=status,
        version=version,
        **dates,
    )


def test_import_keeps_unknown_dates_and_records_import_event(context):
    assert not Finding.objects.exclude(detected_at=None).exists()
    assert not Finding.objects.exclude(corrected_at=None).exists()
    assert FindingHistory.objects.filter(event="imported").count() == 4


def test_new_finding_defaults_detection_time_and_records_actor(context):
    user, now = context
    finding = save_entity(user, "finding", data())
    assert abs((finding.detected_at - now).total_seconds()) < 3
    assert finding.corrected_at is None
    event = finding.history.get()
    assert event.actor == user and event.event == "created"
    assert event.new_detected_at == finding.detected_at


def test_close_reopen_reclose_preserves_old_dates(context):
    user, now = context
    start, first, second = (
        now - timedelta(days=10),
        now - timedelta(days=5),
        now - timedelta(days=1),
    )
    finding = save_entity(user, "finding", data(detected_at=start))
    save_entity(user, "finding", data(3, 1, corrected_at=first), finding.pk)
    save_entity(user, "finding", data(1, 2), finding.pk)
    finding.refresh_from_db()
    assert finding.corrected_at is None
    event = finding.history.get(event="reopened")
    assert event.old_corrected_at == first and event.new_corrected_at is None
    save_entity(user, "finding", data(3, 3, corrected_at=second), finding.pk)
    finding.refresh_from_db()
    assert finding.corrected_at == second and finding.detected_at == start
    assert finding.history.filter(event="corrected").count() == 2


def test_closing_without_date_uses_now_and_preserves_unknown_legacy_detection(
    context,
):
    user, now = context
    finding = Finding.objects.get(asset_id=1, vulnerability_id=1)
    payload = dict(
        asset=finding.asset,
        vulnerability=finding.vulnerability,
        situacao=3,
        version=1,
    )
    save_entity(user, "finding", payload, finding.pk)
    finding.refresh_from_db()
    assert finding.detected_at is None
    assert abs((finding.corrected_at - now).total_seconds()) < 3


@pytest.mark.parametrize(
    "case", ["future_detection", "future_correction", "reverse", "uncorrected"]
)
def test_invalid_dates_rollback(context, case):
    user, now = context
    start = now - timedelta(days=5)
    params = data(3, detected_at=start, corrected_at=now - timedelta(days=1))
    if case == "future_detection":
        params["detected_at"] = now + timedelta(days=1)
    if case == "future_correction":
        params["corrected_at"] = now + timedelta(days=1)
    if case == "reverse":
        params["corrected_at"] = start - timedelta(days=1)
    if case == "uncorrected":
        params["situacao"] = 1
    before = FindingHistory.objects.count()
    with pytest.raises((ValueError, ValidationError)):
        save_entity(user, "finding", params)
    assert Finding.objects.count() == 4
    assert FindingHistory.objects.count() == before


def test_stale_edit_does_not_create_spurious_history(context):
    user, now = context
    finding = save_entity(
        user, "finding", data(detected_at=now - timedelta(days=2))
    )
    save_entity(user, "finding", data(2, 1), finding.pk)
    count = finding.history.count()
    with pytest.raises(Conflict):
        save_entity(user, "finding", data(3, 1), finding.pk)
    assert finding.history.count() == count


def test_cascade_deletion_preserves_history(context):
    user, now = context
    finding = save_entity(user, "finding", data())
    finding_id = finding.pk
    delete_entity(user, "asset", 1, 1)
    assert not Finding.objects.filter(pk=finding_id).exists()
    event = FindingHistory.objects.get(
        event="created", asset_ref=1, vulnerability_ref=2
    )
    assert event.finding_id is None
    assert FindingHistory.objects.filter(
        event="deleted", asset_ref=1, vulnerability_ref=2
    ).exists()


def test_dates_and_history_via_api_and_pages(context):
    user, now = context
    client = Client()
    client.force_login(user)
    payload = {
        "asset": 1,
        "vulnerability": 2,
        "situacao": 1,
        "version": 1,
        "detected_at": (now - timedelta(days=10)).isoformat(),
    }
    response = client.post(
        "/api/finding/", json.dumps(payload), content_type="application/json"
    )
    assert response.status_code == 201, response.content
    pk = response.json()["id"]
    result = client.patch(
        f"/api/finding/{pk}/",
        json.dumps({"version": 1, "situacao": 3}),
        content_type="application/json",
    )
    assert result.status_code == 200, result.content
    before = Finding.objects.get(pk=pk).corrected_at
    assert before is not None
    assert client.get(f"/tratamentos/{pk}/historico/").status_code == 200
    assert (
        "Detecção"
        in client.get(f"/tratamentos/{pk}/historico/").content.decode()
    )
    assert (
        "Histórico dos tratamentos"
        in client.get("/auditoria/").content.decode()
    )
    export = client.get("/auditoria/tratamentos.csv")
    assert export.status_code == 200 and "corrected" in export.content.decode(
        "utf-8-sig"
    )
    result = client.patch(
        f"/api/finding/{pk}/",
        json.dumps({"version": 2, "situacao": 1}),
        content_type="application/json",
    )
    assert result.status_code == 200, result.content
    assert Finding.objects.get(pk=pk).corrected_at is None
    assert (
        FindingHistory.objects.get(
            finding_id=pk, event="reopened"
        ).old_corrected_at
        == before
    )


def test_reader_cannot_edit_dates_or_export_global_audit(context):
    call_command("setup_roles")
    reader = User.objects.create_user("leitor")
    reader.groups.add(Group.objects.get(name="Leitor"))
    client = Client()
    client.force_login(reader)
    pk = Finding.objects.first().pk
    assert client.get(f"/tratamentos/{pk}/historico/").status_code == 200
    assert (
        client.patch(
            f"/api/finding/{pk}/",
            json.dumps({"version": 1, "detected_at": None}),
            content_type="application/json",
        ).status_code
        == 403
    )
    assert client.get("/auditoria/tratamentos.csv").status_code == 403


def test_db_guards_and_risk_unaffected_by_dates(context):
    user, now = context
    baseline = ModeloRisco(snapshot()).risco_total()
    finding = Finding.objects.get(asset_id=1, vulnerability_id=1)
    save_entity(
        user,
        "finding",
        dict(
            asset=finding.asset,
            vulnerability=finding.vulnerability,
            situacao=1,
            version=1,
            detected_at=now - timedelta(days=3),
        ),
        finding.pk,
    )
    assert ModeloRisco(snapshot()).risco_total() == pytest.approx(baseline)
    with pytest.raises(IntegrityError), transaction.atomic():
        Finding.objects.filter(pk=finding.pk).update(corrected_at=now)
    with pytest.raises(IntegrityError), transaction.atomic():
        Finding.objects.filter(pk=finding.pk).update(
            situacao=3, corrected_at=now - timedelta(days=5)
        )


def test_explicit_unknown_detection_is_not_fabricated(context):
    user, now = context
    finding = save_entity(user, "finding", data(detected_at=None))
    assert finding.detected_at is None
    assert finding.history.get().new_detected_at is None


def test_local_timestamp_is_stored_with_correct_timezone(context):
    user, now = context
    client = Client()
    client.force_login(user)
    response = client.post(
        "/api/finding/",
        json.dumps(
            {
                "asset": 1,
                "vulnerability": 2,
                "situacao": 1,
                "detected_at": "2026-01-01T13:00:00-03:00",
                "version": 1,
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 201, response.content
    stored = Finding.objects.get(pk=response.json()["id"]).detected_at
    assert stored.utcoffset().total_seconds() == 0
    assert stored.hour == 16 and stored.day == 1
