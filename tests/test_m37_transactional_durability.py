"""M3.7 transaction, migration, and audit durability checks."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from agenttrust.api import create_app
from agenttrust.db.schema import (
    DBAuditEvent,
    DBApprovalRequest,
    DBPaymentMandate,
    DBSchemaMetadata,
)
from agenttrust.repositories.audit_repo import SQLiteAuditLog
from agenttrust.repositories.approval_repo import SQLiteApprovalRepository
from agenttrust.services.approval_continuation import ApprovalContinuationError
from agenttrust.services.approval_continuation import ApprovalContinuationService

from tests.test_approval_continuation import (
    _approve,
    _create_approved,
    _db_url,
    _payload,
    _policy,
)


def _state(app):
    db = app.state.session_factory()
    return db, db.query(DBApprovalRequest).one()


def test_continuation_rolls_back_reservation_mandate_and_audit_on_failure(
    tmp_path, monkeypatch
):
    app, client, approval_id = _create_approved(tmp_path)
    original_record = SQLiteAuditLog.record

    def fail_on_mandate(self, *args, **kwargs):
        if kwargs.get("event_type") == "PAYMENT_MANDATE_CREATED_FROM_APPROVAL":
            raise RuntimeError("injected audit failure")
        return original_record(self, *args, **kwargs)

    monkeypatch.setattr(SQLiteAuditLog, "record", fail_on_mandate)
    with pytest.raises(RuntimeError, match="injected audit failure"):
        client.post(f"/approvals/{approval_id}/continue")

    db, approval = _state(app)
    try:
        assert approval.continuation_payment_id is None
        assert db.query(DBPaymentMandate).count() == 0
        assert db.query(DBAuditEvent).filter(
            DBAuditEvent.event_type == "PAYMENT_MANDATE_CREATED_FROM_APPROVAL"
        ).count() == 0
        valid, reason = SQLiteAuditLog(db).verify_chain()
        assert valid, reason
    finally:
        db.close()


def test_continuation_rolls_back_when_mandate_insert_fails(tmp_path, monkeypatch):
    app, client, approval_id = _create_approved(tmp_path)
    original_add = Session.add

    def fail_payment_insert(self, instance, _warn=True):
        if isinstance(instance, DBPaymentMandate):
            raise RuntimeError("injected mandate insert failure")
        return original_add(self, instance, _warn=_warn)

    monkeypatch.setattr(Session, "add", fail_payment_insert)
    with pytest.raises(RuntimeError, match="injected mandate insert failure"):
        client.post(f"/approvals/{approval_id}/continue")

    db, approval = _state(app)
    try:
        assert approval.continuation_payment_id is None
        assert db.query(DBPaymentMandate).count() == 0
    finally:
        db.close()


def test_successful_continuation_is_restart_readable_and_idempotent(tmp_path):
    database_url = _db_url(tmp_path)
    app, client, approval_id = _create_approved(tmp_path)
    first = client.post(f"/approvals/{approval_id}/continue")
    assert first.status_code == 200
    payment_id = first.json()["payment_mandate"]["payment_id"]

    restarted_app = create_app(database_url=database_url, policy=_policy())
    retry = TestClient(restarted_app).post(f"/approvals/{approval_id}/continue")
    assert retry.status_code in (200, 409)
    if retry.status_code == 200:
        assert retry.json()["already_completed"] is True
        assert retry.json()["payment_mandate"]["payment_id"] == payment_id

    db = restarted_app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 1
    finally:
        db.close()


def test_uncommitted_continuation_does_not_survive_restart(tmp_path):
    database_url = _db_url(tmp_path)
    app, client, approval_id = _create_approved(tmp_path)
    original_add = Session.add

    def fail_payment_insert(self, instance, _warn=True):
        if isinstance(instance, DBPaymentMandate):
            raise RuntimeError("simulated process failure")
        return original_add(self, instance, _warn=_warn)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(Session, "add", fail_payment_insert)
    with pytest.raises(RuntimeError, match="simulated process failure"):
        client.post(f"/approvals/{approval_id}/continue")
    monkeypatch.undo()

    restarted = create_app(database_url=database_url, policy=_policy())
    db, approval = _state(restarted)
    try:
        assert approval.continuation_payment_id is None
        assert approval.continuation_completed_at is None
        assert db.query(DBPaymentMandate).count() == 0
    finally:
        db.close()
    retry = TestClient(restarted).post(f"/approvals/{approval_id}/continue")
    assert retry.status_code == 200
    assert retry.json()["already_completed"] is False


def test_legacy_database_rows_survive_additive_migration(tmp_path):
    database_url = _db_url(tmp_path)
    original = create_app(database_url=database_url, policy=_policy())
    client = TestClient(original)
    body = client.post("/authorize?execute=false", json=_payload()).json()
    approval_id = body["approval"]["approval_id"]
    _approve(client, approval_id)
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 200
    before = original.state.session_factory()
    try:
        approval_before = before.query(DBApprovalRequest).one()
        payment_before = before.query(DBPaymentMandate).one()
        payment_id = payment_before.payment_id
        approval_link = approval_before.continuation_payment_id
        signature = payment_before.system_signature
        audit_before = before.query(DBAuditEvent).count()
        from sqlalchemy import text

        before.execute(text("DROP TABLE schema_metadata"))
        before.commit()
    finally:
        before.close()

    migrated = create_app(database_url=database_url, policy=_policy())
    db = migrated.state.session_factory()
    try:
        approval_after = db.get(DBApprovalRequest, approval_id)
        payment_after = db.get(DBPaymentMandate, payment_id)
        metadata = db.get(DBSchemaMetadata, "schema_version")
        assert approval_after is not None
        assert payment_after is not None
        assert approval_after.continuation_payment_id == approval_link
        assert payment_after.system_signature == signature
        assert db.query(DBAuditEvent).count() == audit_before
        assert metadata is not None
        assert metadata.value == "3.7"
    finally:
        db.close()


def test_continuation_audit_chain_remains_valid_after_commit(tmp_path):
    app, client, approval_id = _create_approved(tmp_path)
    response = client.post(f"/approvals/{approval_id}/continue")
    assert response.status_code == 200

    db = app.state.session_factory()
    try:
        audit = SQLiteAuditLog(db)
        valid, reason = audit.verify_chain()
        assert valid, reason
        records = db.query(DBAuditEvent).all()
        assert all("private" not in str(record.data).lower() for record in records)
        assert all("api_key" not in str(record.data).lower() for record in records)
    finally:
        db.close()


def test_lock_conflict_is_controlled_and_rolls_back(tmp_path, monkeypatch):
    app, client, approval_id = _create_approved(tmp_path)
    db = app.state.session_factory()
    service = ApprovalContinuationService(
        db=db,
        policy=app.state.policy,
        system_private_key=app.state.system_private_key,
        system_public_key=app.state.system_public_key,
    )

    def fail_locked(self, *args, **kwargs):
        raise OperationalError(
            "UPDATE approval_requests", {}, Exception("database is locked")
        )

    monkeypatch.setattr(SQLiteApprovalRepository, "reserve_continuation", fail_locked)
    with pytest.raises(ApprovalContinuationError) as failure:
        service.continue_approval(approval_id)
    assert failure.value.code == "continuation_transaction_failed"

    try:
        db.rollback()
        approval = db.get(DBApprovalRequest, approval_id)
        assert approval.continuation_payment_id is None
        assert db.query(DBPaymentMandate).count() == 0
        valid, reason = SQLiteAuditLog(db).verify_chain()
        assert valid, reason
    finally:
        db.close()
