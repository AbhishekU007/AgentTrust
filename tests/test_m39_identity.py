import json
import os
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.db.schema import (
    DBAuditEvent,
    DBAuthorizationDecision,
    DBApprovalRequest,
    DBPaymentMandate,
    DBSystemKey,
)
from agenttrust.payments.razorpay_adapter import RazorpayAdapter
from agenttrust.repositories.audit_repo import SQLiteAuditLog
from agenttrust.models import (
    ApprovalDecision,
    CartItem,
    CartMandate,
    IntentMandate,
    PolicyConfig,
)


def _policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon"],
        blocked_categories=["Weapons"],
        velocity_limit=50,
        velocity_window_seconds=3600,
        require_approval_above_minor=900000,
    )


def _fixed_private_key(seed: int | bytes) -> Ed25519PrivateKey:
    if isinstance(seed, int):
        raw = bytes((seed + index) % 256 for index in range(32))
    else:
        raw = seed
    return Ed25519PrivateKey.from_private_bytes(raw)


def _deterministic_keypair(seed: int | bytes):
    private = _fixed_private_key(seed)
    return private, private.public_key()


def _run_subprocess_script(
    db_path: Path,
    *,
    private_hex: str,
    key_id: str,
    script: str,
    historical_keys: dict[str, str] | None = None,
    api_tokens: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
):
    env = os.environ.copy()
    env["AGENTTRUST_SYSTEM_PRIVATE_KEY"] = private_hex
    env["AGENTTRUST_SYSTEM_KEY_ID"] = key_id
    env["AGENTTRUST_DB_URL"] = f"sqlite:///{db_path.as_posix()}"
    if historical_keys is not None:
        env["AGENTTRUST_SYSTEM_PUBLIC_KEYS"] = json.dumps(historical_keys)
    else:
        env.pop("AGENTTRUST_SYSTEM_PUBLIC_KEYS", None)
    if api_tokens is not None:
        env["AGENTTRUST_API_TOKENS"] = json.dumps(api_tokens)
    else:
        env.pop("AGENTTRUST_API_TOKENS", None)
    if extra_env:
        env.update(extra_env)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        cwd=str(Path(__file__).resolve().parents[1]),
        text=True,
        env=env,
        check=False,
    )


def _payload() -> dict:
    private_key, public_key = generate_keypair()
    intent = IntentMandate(
        description="Buy shoes",
        max_amount_minor=500000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    cart = CartMandate(
        intent_id=intent.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Shoes", price_minor=100000)],
        total_amount_minor=100000,
    )
    return {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sign_mandate(intent.canonical_bytes(), private_key).hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": cart.model_dump(mode="json"),
    }


def _auth(monkeypatch, token_map: dict[str, str]) -> None:
    monkeypatch.setenv("AGENTTRUST_API_TOKENS", json.dumps(token_map))


def test_authentication_required_and_valid_principal(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'auth.db').as_posix()}",
        policy=_policy(),
    )
    client = TestClient(app)
    assert client.post(
        "/authorize", json=_payload(), headers={}
    ).status_code == 401
    assert client.post(
        "/authorize", json=_payload(), headers={"Authorization": "Bearer wrong"}
    ).status_code == 401
    assert client.post(
        "/authorize",
        json=_payload(),
        headers={"Authorization": "Bearer alice-token"},
    ).status_code == 200
    assert client.get("/health").status_code == 200
    assert client.post(
        "/authorize", json=_payload(), headers={"Authorization": "Token alice-token"}
    ).status_code == 401


def _approval_app(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'approval-isolation.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    alice = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    response = alice.post("/authorize?execute=false", json=_payload())
    return app, alice, TestClient(app, headers={"Authorization": "Bearer bob-token"}), response.json()["approval"]["approval_id"]


def test_principal_isolation_for_approval_and_continuation(tmp_path, monkeypatch):
    _, alice, bob, approval_id = _approval_app(tmp_path, monkeypatch)
    assert bob.get(f"/approvals/{approval_id}").status_code == 404
    assert bob.post(f"/approvals/{approval_id}/continue").status_code == 404
    assert alice.get(f"/approvals/{approval_id}").status_code == 200


def test_audit_requires_authentication_when_configured(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'audit-auth.db').as_posix()}",
        policy=_policy(),
    )
    assert TestClient(app).get("/audit").status_code == 401
    assert TestClient(app, headers={"Authorization": "Bearer alice-token"}).get(
        "/audit"
    ).status_code == 200


def test_principal_isolation_for_payment_execution(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'isolation.db').as_posix()}",
        policy=_policy(),
    )
    alice = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    bob = TestClient(app, headers={"Authorization": "Bearer bob-token"})
    response = alice.post("/authorize?execute=false", json=_payload())
    payment_id = response.json()["payment_mandate"]["payment_id"]
    assert bob.post(f"/payment-mandates/{payment_id}/execute").status_code == 404
    assert alice.post(f"/payment-mandates/{payment_id}/execute").status_code == 200


def test_approval_actor_must_match_authenticated_principal(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'actor.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    response = client.post("/authorize?execute=false", json=_payload())
    approval_id = response.json()["approval"]["approval_id"]
    assert client.post(
        f"/approvals/{approval_id}/approve",
        json={
            "decided_by": "bob",
            "decided_at": datetime.now(timezone.utc).isoformat(),
            "approver_public_key": "00",
            "signature": "00",
        },
    ).status_code == 403


def test_system_key_id_registry_and_no_private_key_persistence(tmp_path, monkeypatch):
    private_key, _ = generate_keypair()
    raw = private_key.private_bytes_raw().hex()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", raw)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-a")
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'keys.db').as_posix()}",
        policy=_policy(),
    )
    response = TestClient(app).post("/authorize?execute=false", json=_payload())
    assert response.status_code == 200
    payment_id = response.json()["payment_mandate"]["payment_id"]
    assert raw not in response.text
    db = app.state.session_factory()
    try:
        assert db.get(DBPaymentMandate, payment_id).system_key_id == "key-a"
        assert db.get(DBSystemKey, "key-a").public_key != raw
        assert "private_key" not in {column.name for column in DBSystemKey.__table__.columns}
    finally:
        db.close()


def test_historical_key_verifies_after_rotation(tmp_path, monkeypatch):
    first, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", first.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "old")
    db_url = f"sqlite:///{(tmp_path / 'rotation.db').as_posix()}"
    old_app = create_app(database_url=db_url, policy=_policy())
    payment = TestClient(old_app).post(
        "/authorize?execute=false", json=_payload()
    ).json()["payment_mandate"]["payment_id"]
    second, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", second.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "new")
    monkeypatch.setenv(
        "AGENTTRUST_SYSTEM_PUBLIC_KEYS",
        json.dumps({"old": first.public_key().public_bytes_raw().hex()}),
    )
    rotated = create_app(database_url=db_url, policy=_policy())
    assert TestClient(rotated).post(f"/payment-mandates/{payment}/execute").status_code == 200


def test_missing_historical_key_fails_closed(tmp_path, monkeypatch):
    first, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", first.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "old")
    db_url = f"sqlite:///{(tmp_path / 'missing-history.db').as_posix()}"
    old_app = create_app(database_url=db_url, policy=_policy())
    payment = TestClient(old_app).post(
        "/authorize?execute=false", json=_payload()
    ).json()["payment_mandate"]["payment_id"]
    second, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", second.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "new")
    monkeypatch.delenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", raising=False)
    rotated = create_app(database_url=db_url, policy=_policy())
    assert TestClient(rotated).post(f"/payment-mandates/{payment}/execute").status_code == 409


def test_unknown_system_key_fails_closed(tmp_path, monkeypatch):
    private, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", private.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "known")
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'unknown.db').as_posix()}",
        policy=_policy(),
    )
    response = TestClient(app).post("/authorize?execute=false", json=_payload())
    payment_id = response.json()["payment_mandate"]["payment_id"]
    db = app.state.session_factory()
    try:
        db.get(DBPaymentMandate, payment_id).system_key_id = "missing"
        db.commit()
    finally:
        db.close()
    assert TestClient(app).post(f"/payment-mandates/{payment_id}/execute").status_code == 409


def test_authentication_is_fail_closed_without_registry_and_persists_nothing(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("AGENTTRUST_API_TOKENS", raising=False)
    monkeypatch.delenv("AGENTTRUST_API_TOKEN", raising=False)
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'no-auth.db').as_posix()}")
    response = TestClient(app).post("/authorize", json=_payload(), headers={})
    assert response.status_code == 401
    db = app.state.session_factory()
    try:
        assert db.query(DBAuthorizationDecision).count() == 0
        assert db.query(DBPaymentMandate).count() == 0
        assert db.query(DBAuditEvent).count() == 0
    finally:
        db.close()


def test_authentication_does_not_leak_bearer_token(tmp_path, monkeypatch, caplog):
    token = "super-secret-token"
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'secret.db').as_posix()}")
    response = TestClient(app).post(
        "/authorize",
        json=_payload(),
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401
    assert token not in response.text
    assert token not in caplog.text
    assert token not in str(response.json())


def test_audit_history_is_account_scoped(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'audit-scope.db').as_posix()}")
    alice = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    bob = TestClient(app, headers={"Authorization": "Bearer bob-token"})
    alice_payment = alice.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]
    bob_payment = bob.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]
    events = bob.get("/audit").json()["events"]
    serialized = json.dumps(events)
    assert bob_payment in serialized
    assert alice_payment not in serialized


def test_forged_identity_fields_do_not_change_principal(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'forged-id.db').as_posix()}")
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    body = _payload()
    body["account_id"] = "bob"
    body["owner_id"] = "bob"
    body["actor"] = "bob"
    response = client.post("/authorize?execute=false", json=body)
    assert response.status_code == 200
    db = app.state.session_factory()
    try:
        record = db.query(DBAuthorizationDecision).one()
        assert record.principal_id == "alice"
        assert record.account_id == "alice"
    finally:
        db.close()


def test_approval_audit_contains_authenticated_attribution(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'approval-audit.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    response = client.post("/authorize?execute=false", json=_payload())
    approval_id = response.json()["approval"]["approval_id"]
    approval = client.get(f"/approvals/{approval_id}").json()
    approver_private, approver_public = generate_keypair()
    decided_at = datetime.now(timezone.utc)
    decision = {
        "approval_id": approval_id,
        "authorization_id": approval["authorization_id"],
        "intent_id": approval["intent_id"],
        "cart_id": approval["cart_id"],
        "decision": "APPROVED",
        "decided_at": decided_at.isoformat(),
        "approver_id": "alice",
        "approver_public_key": approver_public.public_bytes_raw().hex(),
    }
    decision_request = {
        "decided_by": "alice",
        "decided_at": decided_at.isoformat(),
        "approver_public_key": decision["approver_public_key"],
        "signature": sign_mandate(
            ApprovalDecision.model_validate(decision).canonical_bytes(), approver_private
        ).hex(),
    }
    assert client.post(f"/approvals/{approval_id}/approve", json=decision_request).status_code == 200
    events = client.get("/audit").json()["events"]
    approval_events = [event for event in events if event["event_type"] == "APPROVAL_APPROVED"]
    assert approval_events
    assert approval_events[-1]["data"]["principal_id"] == "alice"
    assert approval_events[-1]["data"]["account_id"] == "alice"
    assert approver_private.private_bytes_raw().hex() not in json.dumps(events)


def test_persistence_failure_rolls_back_all_authorization_state(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'persist-fail.db').as_posix()}")
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})

    def fail(*args, **kwargs):
        raise RuntimeError("injected persistence failure")

    monkeypatch.setattr("agenttrust.api._persist_decision", fail)
    with pytest.raises(RuntimeError, match="injected persistence failure"):
        client.post("/authorize?execute=false", json=_payload())
    db = app.state.session_factory()
    try:
        assert db.query(DBAuthorizationDecision).count() == 0
        assert db.query(DBPaymentMandate).count() == 0
        assert db.query(DBAuditEvent).count() == 0
    finally:
        db.close()


def test_malformed_historical_key_configuration_fails_closed(tmp_path, monkeypatch):
    private, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", private.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", json.dumps({"old": "not-a-key"}))
    with pytest.raises(RuntimeError, match="AGENTTRUST_SYSTEM_PUBLIC_KEYS is invalid"):
        create_app(database_url=f"sqlite:///{(tmp_path / 'bad-key.db').as_posix()}")


def test_schema_migration_is_additive_and_legacy_rows_are_controlled(tmp_path):
    db_url = f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}"
    from agenttrust.db.database import build_engine, init_db

    engine = build_engine(db_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE schema_metadata (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL, "
                "updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)"
            )
        )
        connection.execute(
            text("INSERT INTO schema_metadata(key, value) VALUES ('schema_version', '3.8')")
        )
    init_db(engine)
    app = create_app(database_url=db_url, policy=_policy())
    inspector = inspect(engine)
    columns = {column["name"] for column in inspector.get_columns("payment_mandates")}
    assert {"system_key_id", "principal_id", "account_id"} <= columns
    assert app.state.session_factory() is not None


def _principal_clients(app):
    return (
        TestClient(app, headers={"Authorization": "Bearer alice-token"}),
        TestClient(app, headers={"Authorization": "Bearer bob-token"}),
    )


def _approve_as(client, approval_id, actor, approval=None):
    approval = approval or client.get(f"/approvals/{approval_id}").json()
    private, public = generate_keypair()
    decided_at = datetime.fromisoformat(approval["requested_at"]) + timedelta(minutes=1)
    decision = ApprovalDecision(
        approval_id=approval_id,
        authorization_id=approval["authorization_id"],
        intent_id=approval["intent_id"],
        cart_id=approval["cart_id"],
        decision="APPROVED",
        decided_at=decided_at,
        approver_id=actor,
        approver_public_key=public.public_bytes_raw().hex(),
    )
    return client.post(
        f"/approvals/{approval_id}/approve",
        json={
            "decided_by": actor,
            "decided_at": decided_at.isoformat(),
            "approver_public_key": decision.approver_public_key,
            "signature": sign_mandate(decision.canonical_bytes(), private).hex(),
        },
    )


def test_cross_principal_approval_race_has_one_authorized_winner(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'approval-race.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    alice, bob = _principal_clients(app)
    approval_id = alice.post("/authorize?execute=false", json=_payload()).json()["approval"][
        "approval_id"
    ]
    approval = alice.get(f"/approvals/{approval_id}").json()
    barrier = threading.Barrier(2)

    def decide(client, actor):
        barrier.wait()
        return _approve_as(client, approval_id, actor, approval).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(
            pool.map(lambda args: decide(*args), ((alice, "alice"), (bob, "bob")))
        )
    assert 200 in statuses
    assert 404 in statuses
    stored = alice.get(f"/approvals/{approval_id}").json()
    assert stored["status"] == "APPROVED"
    assert stored["decided_by"] == "alice"
    audit = alice.get("/audit").json()
    assert audit["valid"] is True
    assert all(event["data"].get("principal_id") != "bob" for event in audit["events"])


def test_cross_principal_continuation_race_creates_one_owned_mandate(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'continuation-race.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    alice, bob = _principal_clients(app)
    approval_id = alice.post("/authorize?execute=false", json=_payload()).json()["approval"][
        "approval_id"
    ]
    assert _approve_as(alice, approval_id, "alice").status_code == 200
    barrier = threading.Barrier(2)

    def continue_with(client):
        barrier.wait()
        return client.post(f"/approvals/{approval_id}/continue")

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(continue_with, (alice, bob)))
    assert [response.status_code for response in responses].count(200) == 1
    assert bob.post(f"/approvals/{approval_id}/continue").status_code == 404
    db = app.state.session_factory()
    try:
        rows = db.query(DBPaymentMandate).all()
        assert len(rows) == 1
        assert rows[0].principal_id == "alice"
        assert rows[0].account_id == "alice"
        assert rows[0].approval_id == approval_id
    finally:
        db.close()
    assert alice.get("/audit").json()["valid"] is True


def test_cross_principal_execution_race_cannot_consume_owner_claim(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice", "bob-token": "bob"})
    calls = 0
    call_lock = threading.Lock()
    started = threading.Event()
    release = threading.Event()
    original = RazorpayAdapter.execute_payment

    def controlled(self, mandate):
        nonlocal calls
        with call_lock:
            calls += 1
        started.set()
        assert release.wait(timeout=5)
        return original(self, mandate)

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", controlled)
    app = create_app(database_url=f"sqlite:///{(tmp_path / 'exec-race.db').as_posix()}")
    alice, bob = _principal_clients(app)
    payment_id = alice.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]
    barrier = threading.Barrier(2)

    def execute(client):
        barrier.wait()
        return client.post(f"/payment-mandates/{payment_id}/execute")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(execute, alice), pool.submit(execute, bob)]
        assert started.wait(timeout=5)
        release.set()
        responses = [future.result() for future in futures]
    assert any(response.status_code == 200 for response in responses)
    assert any(response.status_code == 404 for response in responses)
    assert calls == 1
    db = app.state.session_factory()
    try:
        row = db.get(DBPaymentMandate, payment_id)
        assert row.payment_execution_status == "SUCCEEDED"
        assert db.query(DBPaymentMandate).count() == 1
    finally:
        db.close()
    assert alice.get("/audit").json()["valid"] is True


def test_approval_persistence_failure_rolls_back_authorization_and_audit(
    tmp_path, monkeypatch
):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'approval-fail.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    from agenttrust.db.schema import DBApprovalRequest
    from sqlalchemy.orm import Session

    original_add = Session.add

    def fail_approval(self, instance, _warn=True):
        if isinstance(instance, DBApprovalRequest):
            raise RuntimeError("injected approval persistence failure")
        return original_add(self, instance, _warn=_warn)

    monkeypatch.setattr(Session, "add", fail_approval)
    response = TestClient(
        app,
        raise_server_exceptions=False,
        headers={"Authorization": "Bearer alice-token"},
    ).post(
        "/authorize?execute=false", json=_payload()
    )
    assert response.status_code == 500
    db = app.state.session_factory()
    try:
        assert db.query(DBApprovalRequest).count() == 0
        assert db.query(DBAuthorizationDecision).count() == 0
        assert db.query(DBAuditEvent).count() == 0
        assert SQLiteAuditLog(db).verify_chain()[0] is True
    finally:
        db.close()


def test_continuation_audit_contains_principal_and_system_key(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    key, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", key.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-a")
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'continuation-audit.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    response = client.post("/authorize?execute=false", json=_payload())
    approval_id = response.json()["approval"]["approval_id"]
    assert _approve_as(client, approval_id, "alice").status_code == 200
    continued = client.post(f"/approvals/{approval_id}/continue")
    assert continued.status_code == 200
    events = client.get("/audit").json()["events"]
    created = [
        event
        for event in events
        if event["event_type"] == "PAYMENT_MANDATE_CREATED_FROM_APPROVAL"
    ][-1]
    assert created["actor"] == "alice"
    assert created["data"]["principal_id"] == "alice"
    assert created["data"]["account_id"] == "alice"
    assert created["data"]["approval_id"] == approval_id
    assert created["data"]["system_key_id"] == "key-a"
    assert client.get("/audit").json()["valid"] is True


def test_continuation_mandate_failure_rolls_back_reservation(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    from sqlalchemy.orm import Session
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'mandate-fail.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    response = client.post("/authorize?execute=false", json=_payload())
    approval_id = response.json()["approval"]["approval_id"]
    assert _approve_as(client, approval_id, "alice").status_code == 200
    original_add = Session.add
    failed = {"value": True}

    def fail_once(self, instance, _warn=True):
        if failed["value"] and isinstance(instance, DBPaymentMandate):
            failed["value"] = False
            raise RuntimeError("injected mandate failure")
        return original_add(self, instance, _warn=_warn)

    monkeypatch.setattr(Session, "add", fail_once)
    first = TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer alice-token"}).post(
        f"/approvals/{approval_id}/continue"
    )
    assert first.status_code == 500
    monkeypatch.setattr(Session, "add", original_add)
    db = app.state.session_factory()
    try:
        approval = db.get(DBApprovalRequest, approval_id)
        assert approval.continuation_payment_id is None
        assert db.query(DBPaymentMandate).count() == 0
        assert SQLiteAuditLog(db).verify_chain()[0] is True
    finally:
        db.close()
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 200


def test_continuation_audit_failure_rolls_back_and_allows_retry(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'continuation-audit-fail.db').as_posix()}",
        policy=PolicyConfig(
            max_transaction_amount_minor=1000000,
            merchant_allowlist=["Amazon"],
            blocked_categories=["Weapons"],
            velocity_limit=50,
            require_approval_above_minor=1,
        ),
    )
    client = TestClient(app, headers={"Authorization": "Bearer alice-token"})
    approval_id = client.post("/authorize?execute=false", json=_payload()).json()[
        "approval"
    ]["approval_id"]
    assert _approve_as(client, approval_id, "alice").status_code == 200
    original_record = SQLiteAuditLog.record

    def fail_created(self, *args, **kwargs):
        if kwargs.get("event_type") == "PAYMENT_MANDATE_CREATED_FROM_APPROVAL":
            raise RuntimeError("injected continuation audit failure")
        return original_record(self, *args, **kwargs)

    monkeypatch.setattr(SQLiteAuditLog, "record", fail_created)
    first = TestClient(app, raise_server_exceptions=False, headers={"Authorization": "Bearer alice-token"}).post(
        f"/approvals/{approval_id}/continue"
    )
    assert first.status_code == 500
    monkeypatch.setattr(SQLiteAuditLog, "record", original_record)
    db = app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 0
        assert db.get(DBApprovalRequest, approval_id).continuation_payment_id is None
        assert SQLiteAuditLog(db).verify_chain()[0] is True
    finally:
        db.close()
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 200


def test_system_key_metadata_write_failure_prevents_app_start(tmp_path, monkeypatch):
    key, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", key.private_bytes_raw().hex())
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "metadata-key")
    from sqlalchemy.engine import Engine
    original_begin = Engine.begin

    def fail_metadata(self, *args, **kwargs):
        raise RuntimeError("injected system metadata failure")

    monkeypatch.setattr(Engine, "begin", fail_metadata)
    with pytest.raises(RuntimeError, match="injected system metadata failure"):
        create_app(database_url=f"sqlite:///{(tmp_path / 'metadata-fail.db').as_posix()}")
    monkeypatch.setattr(Engine, "begin", original_begin)


def test_migration_failure_does_not_prevent_clean_restart(tmp_path, monkeypatch):
    from agenttrust.db.database import build_engine, init_db
    db_url = f"sqlite:///{(tmp_path / 'migration-restart.db').as_posix()}"
    engine = build_engine(db_url)
    from agenttrust.db.database import Base
    original_create = Base.metadata.create_all

    def fail_create(*args, **kwargs):
        raise RuntimeError("injected migration failure")

    monkeypatch.setattr(Base.metadata, "create_all", fail_create)
    with pytest.raises(RuntimeError, match="injected migration failure"):
        init_db(engine)
    monkeypatch.setattr(Base.metadata, "create_all", original_create)
    assert create_app(database_url=db_url, policy=_policy()) is not None


def test_subprocess_system_key_lifecycle_and_secret_scanning(tmp_path, monkeypatch):
    db_path = tmp_path / "subprocess-lifecycle.db"
    a_private, a_public = _deterministic_keypair(17)
    b_private, b_public = _deterministic_keypair(29)
    a_hex = a_private.private_bytes_raw().hex()
    b_hex = b_private.private_bytes_raw().hex()
    a_pub_hex = a_public.public_bytes_raw().hex()
    b_pub_hex = b_public.public_bytes_raw().hex()
    _auth(monkeypatch, {"alice-token": "alice"})

    script = """
import json
import os
from fastapi.testclient import TestClient
from agenttrust.api import create_app
from agenttrust.models import PolicyConfig

policy = PolicyConfig(
    max_transaction_amount_minor=500000,
    merchant_allowlist=['Amazon'],
    blocked_categories=['Weapons'],
    velocity_limit=50,
    velocity_window_seconds=3600,
    require_approval_above_minor=900000,
)
app = create_app(database_url=os.environ['AGENTTRUST_DB_URL'], policy=policy)
client = TestClient(app, headers={'Authorization': 'Bearer alice-token'})
user_private, user_public = __import__('agenttrust.crypto', fromlist=['generate_keypair']).generate_keypair()
intent = __import__('agenttrust.models', fromlist=['IntentMandate', 'CartMandate', 'CartItem']).IntentMandate(
    description='Buy shoes',
    max_amount_minor=500000,
    allowed_merchants=['Amazon'],
    allowed_categories=['Footwear'],
    expires_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc) + __import__('datetime').timedelta(hours=1),
)
cart = __import__('agenttrust.models', fromlist=['CartMandate', 'CartItem']).CartMandate(
    intent_id=intent.intent_id,
    merchant='Amazon',
    category='Footwear',
    items=[__import__('agenttrust.models', fromlist=['CartItem']).CartItem(name='Shoes', price_minor=100000)],
    total_amount_minor=100000,
)
body = {
    'intent': intent.model_dump(mode='json'),
    'intent_signature': __import__('agenttrust.crypto', fromlist=['sign_mandate']).sign_mandate(intent.canonical_bytes(), user_private).hex(),
    'user_public_key': user_public.public_bytes_raw().hex(),
    'cart': cart.model_dump(mode='json'),
}
response = client.post('/authorize?execute=false', json=body)
print(json.dumps({'status': response.status_code, 'payment_id': response.json()['payment_mandate']['payment_id']}))
"""
    result = _run_subprocess_script(
        db_path,
        private_hex=a_hex,
        key_id="key-a",
        script=script,
        api_tokens={"alice-token": "alice"},
    )
    assert result.returncode == 0, result.stderr
    first = json.loads(result.stdout.strip())
    assert first["status"] == 200
    payment_id_a = first["payment_id"]
    assert a_hex not in result.stdout
    assert a_hex not in result.stderr
    assert db_path.read_bytes().hex()  # sanity check file exists
    db_text = db_path.read_bytes().decode("utf-8", "ignore")
    assert a_hex not in db_text
    assert b_hex not in db_text
    assert "alice-token" not in db_text
    assert "alice-token" not in result.stdout
    assert "alice-token" not in result.stderr

    verify_script = """
import json, os
from fastapi.testclient import TestClient
from agenttrust.api import create_app
from agenttrust.models import PolicyConfig
policy = PolicyConfig(max_transaction_amount_minor=500000, merchant_allowlist=['Amazon'], blocked_categories=['Weapons'], velocity_limit=50, velocity_window_seconds=3600, require_approval_above_minor=900000)
app = create_app(database_url=os.environ['AGENTTRUST_DB_URL'], policy=policy)
client = TestClient(app, headers={'Authorization': 'Bearer alice-token'})
payment_id = os.environ['PAYMENT_ID']
response = client.post(f'/payment-mandates/{payment_id}/execute')
print(json.dumps({'status': response.status_code}))
"""
    verify_result = _run_subprocess_script(
        db_path,
        private_hex=a_hex,
        key_id="key-a",
        script=verify_script,
        api_tokens={"alice-token": "alice"},
        extra_env={"PAYMENT_ID": payment_id_a},
    )
    assert verify_result.returncode == 0, verify_result.stderr
    assert json.loads(verify_result.stdout)["status"] == 200

    rotate_script = """
import json
import os
from fastapi.testclient import TestClient
from agenttrust.api import create_app
from agenttrust.models import PolicyConfig
policy = PolicyConfig(max_transaction_amount_minor=500000, merchant_allowlist=['Amazon'], blocked_categories=['Weapons'], velocity_limit=50, velocity_window_seconds=3600, require_approval_above_minor=900000)
app = create_app(database_url=os.environ['AGENTTRUST_DB_URL'], policy=policy)
client = TestClient(app, headers={'Authorization': 'Bearer alice-token'})
user_private, user_public = __import__('agenttrust.crypto', fromlist=['generate_keypair']).generate_keypair()
intent = __import__('agenttrust.models', fromlist=['IntentMandate', 'CartMandate', 'CartItem']).IntentMandate(
    description='Buy shoes',
    max_amount_minor=500000,
    allowed_merchants=['Amazon'],
    allowed_categories=['Footwear'],
    expires_at=__import__('datetime').datetime.now(__import__('datetime').timezone.utc) + __import__('datetime').timedelta(hours=1),
)
cart = __import__('agenttrust.models', fromlist=['CartMandate', 'CartItem']).CartMandate(
    intent_id=intent.intent_id,
    merchant='Amazon',
    category='Footwear',
    items=[__import__('agenttrust.models', fromlist=['CartItem']).CartItem(name='Shoes', price_minor=100000)],
    total_amount_minor=100000,
)
body = {
    'intent': intent.model_dump(mode='json'),
    'intent_signature': __import__('agenttrust.crypto', fromlist=['sign_mandate']).sign_mandate(intent.canonical_bytes(), user_private).hex(),
    'user_public_key': user_public.public_bytes_raw().hex(),
    'cart': cart.model_dump(mode='json'),
}
response = client.post('/authorize?execute=false', json=body)
print(json.dumps({'status': response.status_code, 'payment_id': response.json()['payment_mandate']['payment_id']}))
"""
    rotate_result = _run_subprocess_script(
        db_path,
        private_hex=b_hex,
        key_id="key-b",
        script=rotate_script,
        historical_keys={"key-a": a_pub_hex},
        api_tokens={"alice-token": "alice"},
    )
    assert rotate_result.returncode == 0, rotate_result.stderr
    rotated_payload = json.loads(rotate_result.stdout.strip())
    assert rotated_payload["status"] == 200
    payment_id_b = rotated_payload["payment_id"]
    assert b_hex not in rotate_result.stdout
    assert b_hex not in rotate_result.stderr

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM payment_mandates").fetchone()[0] == 2
        assert conn.execute("SELECT system_key_id FROM payment_mandates WHERE payment_id = ?", (payment_id_a,)).fetchone()[0] == "key-a"
        assert conn.execute("SELECT system_key_id FROM payment_mandates WHERE payment_id = ?", (payment_id_b,)).fetchone()[0] == "key-b"

    post_rotation_script = """
import json, os, sqlite3
from fastapi.testclient import TestClient
from agenttrust.api import create_app
from agenttrust.models import PolicyConfig
policy = PolicyConfig(max_transaction_amount_minor=500000, merchant_allowlist=['Amazon'], blocked_categories=['Weapons'], velocity_limit=50, velocity_window_seconds=3600, require_approval_above_minor=900000)
app = create_app(database_url=os.environ['AGENTTRUST_DB_URL'], policy=policy)
client = TestClient(app, headers={'Authorization': 'Bearer alice-token'})
for payment_id in [os.environ['PAYMENT_A'], os.environ['PAYMENT_B']]:
    response = client.post(f'/payment-mandates/{payment_id}/execute')
    print(json.dumps({'payment_id': payment_id, 'status': response.status_code}))
"""
    rotated_check = _run_subprocess_script(
        db_path,
        private_hex=b_hex,
        key_id="key-b",
        script=post_rotation_script,
        historical_keys={"key-a": a_pub_hex},
        api_tokens={"alice-token": "alice"},
        extra_env={"PAYMENT_A": payment_id_a, "PAYMENT_B": payment_id_b},
    )
    assert rotated_check.returncode == 0, rotated_check.stderr
    statuses = [json.loads(line) for line in rotated_check.stdout.strip().splitlines()]
    assert {item["payment_id"]: item["status"] for item in statuses} == {payment_id_a: 200, payment_id_b: 200}

    with sqlite3.connect(db_path) as conn:
        conn.execute("UPDATE payment_mandates SET system_key_id = 'missing' WHERE payment_id = ?", (payment_id_a,))
        conn.commit()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", b_hex)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-b")
    unknown_key_app = create_app(database_url=f"sqlite:///{db_path.as_posix()}", policy=_policy())
    assert TestClient(unknown_key_app, headers={"Authorization": "Bearer alice-token"}).post(f"/payment-mandates/{payment_id_a}/execute").status_code == 409

    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", b_hex)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-b")
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", json.dumps({"key-a": "not-a-key"}))
    with pytest.raises(RuntimeError, match="AGENTTRUST_SYSTEM_PUBLIC_KEYS is invalid"):
        create_app(
            database_url=f"sqlite:///{db_path.as_posix()}",
            policy=_policy(),
        )

    with sqlite3.connect(db_path) as conn:
        bad = conn.execute("SELECT SQL FROM sqlite_master WHERE name='payment_mandates'").fetchone()
        assert bad is not None
        db_bytes = db_path.read_bytes()
        for token in ["alice-token", a_hex, b_hex, "BEGIN PRIVATE KEY", "PRIVATE KEY"]:
            assert token not in db_bytes.decode('utf-8', 'ignore')
            assert token not in str(result.stdout + result.stderr + rotated_check.stdout + rotated_check.stderr)
    assert "alice-token" not in str(result.stdout + result.stderr + rotated_check.stdout + rotated_check.stderr)
    assert a_hex not in str(result.stdout + result.stderr + rotated_check.stdout + rotated_check.stderr)
    assert b_hex not in str(result.stdout + result.stderr + rotated_check.stdout + rotated_check.stderr)


def test_key_rotation_failure_rolls_back_old_active_key(tmp_path, monkeypatch):
    db_url = f"sqlite:///{(tmp_path / 'rotation-failure.db').as_posix()}"
    a_private, _ = _deterministic_keypair(41)
    b_private, _ = _deterministic_keypair(53)
    a_hex = a_private.private_bytes_raw().hex()
    b_hex = b_private.private_bytes_raw().hex()
    _auth(monkeypatch, {"alice-token": "alice"})
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", a_hex)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-a")
    app = create_app(database_url=db_url, policy=_policy())
    payment_id = TestClient(app, headers={"Authorization": "Bearer alice-token"}).post(
        "/authorize?execute=false", json=_payload()
    ).json()["payment_mandate"]["payment_id"]

    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", b_hex)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-b")
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", json.dumps({"key-a": a_private.public_key().public_bytes_raw().hex()}))
    from agenttrust import api as api_module
    original_init = api_module.init_db

    def fail_init(_engine):
        raise RuntimeError("injected rotation persistence failure")

    monkeypatch.setattr(api_module, "init_db", fail_init)
    with pytest.raises(RuntimeError, match="injected rotation persistence failure"):
        create_app(database_url=db_url, policy=_policy())
    monkeypatch.setattr(api_module, "init_db", original_init)

    monkeypatch.delenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", raising=False)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", a_hex)
    monkeypatch.setenv("AGENTTRUST_SYSTEM_KEY_ID", "key-a")
    restored = create_app(database_url=db_url, policy=_policy())
    assert TestClient(restored, headers={"Authorization": "Bearer alice-token"}).post(
        f"/payment-mandates/{payment_id}/execute"
    ).status_code == 200


def test_populated_legacy_m38_fixture_remains_readable_and_fail_closed(tmp_path, monkeypatch):
    _auth(monkeypatch, {"alice-token": "alice"})
    db_url = f"sqlite:///{(tmp_path / 'legacy-populated.db').as_posix()}"
    from agenttrust.db.database import Base, build_engine
    engine = build_engine(db_url)
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE schema_metadata (key VARCHAR PRIMARY KEY, value VARCHAR NOT NULL, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL)"
            )
        )
        connection.execute(
            text("CREATE TABLE intent_mandates (intent_id VARCHAR PRIMARY KEY, description VARCHAR NOT NULL, max_amount_minor INTEGER NOT NULL, currency VARCHAR NOT NULL, allowed_merchants TEXT NOT NULL, allowed_categories TEXT NOT NULL, nonce VARCHAR NOT NULL UNIQUE, created_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, canonical_bytes_hex VARCHAR NOT NULL)")
        )
        connection.execute(
            text("CREATE TABLE cart_mandates (cart_id VARCHAR PRIMARY KEY, intent_id VARCHAR NOT NULL, merchant VARCHAR NOT NULL, category VARCHAR NOT NULL, items TEXT NOT NULL, total_amount_minor INTEGER NOT NULL, currency VARCHAR NOT NULL, nonce VARCHAR NOT NULL UNIQUE, created_at DATETIME NOT NULL)")
        )
        connection.execute(
            text("CREATE TABLE authorization_decisions (id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id VARCHAR NOT NULL UNIQUE, intent_id VARCHAR NOT NULL, cart_id VARCHAR, status VARCHAR NOT NULL, reason VARCHAR NOT NULL, checks TEXT NOT NULL, payment_id VARCHAR, intent_signature VARCHAR, user_public_key VARCHAR, intent_hash VARCHAR, cart_hash VARCHAR, created_at DATETIME NOT NULL)")
        )
        connection.execute(
            text("CREATE TABLE approval_requests (approval_id VARCHAR PRIMARY KEY, authorization_id VARCHAR NOT NULL, intent_id VARCHAR NOT NULL, cart_id VARCHAR NOT NULL, status VARCHAR NOT NULL, reason VARCHAR NOT NULL, requested_at DATETIME NOT NULL, expires_at DATETIME NOT NULL, decided_at DATETIME, decided_by VARCHAR, approver_public_key VARCHAR, decision_signature VARCHAR, continuation_payment_id VARCHAR, continuation_completed_at DATETIME)")
        )
        connection.execute(
            text("CREATE TABLE payment_mandates (payment_id VARCHAR PRIMARY KEY, intent_id VARCHAR NOT NULL, intent_hash VARCHAR NOT NULL, cart_id VARCHAR NOT NULL, cart_hash VARCHAR NOT NULL, amount_minor INTEGER NOT NULL, currency VARCHAR NOT NULL, merchant VARCHAR NOT NULL, status VARCHAR NOT NULL, created_at DATETIME NOT NULL, system_signature VARCHAR NOT NULL, approval_id VARCHAR, authorization_id VARCHAR)")
        )
        connection.execute(
            text("CREATE TABLE audit_events (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id VARCHAR NOT NULL UNIQUE, timestamp DATETIME NOT NULL, event_type VARCHAR NOT NULL, actor VARCHAR NOT NULL, intent_id VARCHAR, cart_id VARCHAR, decision VARCHAR, reason VARCHAR NOT NULL, data TEXT, previous_hash VARCHAR NOT NULL, event_hash VARCHAR NOT NULL UNIQUE)")
        )
        connection.execute(text("INSERT INTO schema_metadata(key, value) VALUES ('schema_version', '3.8')"))
        connection.execute(
            text("INSERT INTO intent_mandates(intent_id, description, max_amount_minor, currency, allowed_merchants, allowed_categories, nonce, created_at, expires_at, canonical_bytes_hex) VALUES ('intent-legacy', 'Legacy intention', 100000, 'INR', '[\"Amazon\"]', '[\"Footwear\"]', 'nonce-legacy', datetime('now'), datetime('now','+1 day'), 'deadbeef')")
        )
        connection.execute(
            text("""INSERT INTO cart_mandates(cart_id, intent_id, merchant, category, items, total_amount_minor, currency, nonce, created_at)
            VALUES ('cart-legacy', 'intent-legacy', 'Amazon', 'Footwear', '[{"name": "Shoes", "price_minor": 100000}]', 100000, 'INR', 'cart-nonce-legacy', datetime('now'))""")
        )
        connection.execute(
            text("INSERT INTO authorization_decisions(decision_id, intent_id, cart_id, status, reason, checks, payment_id, intent_hash, cart_hash, created_at) VALUES ('auth-legacy', 'intent-legacy', 'cart-legacy', 'ALLOW', 'legacy', '{}', 'pay-legacy', 'legacy-intent-hash', 'legacy-cart-hash', datetime('now'))")
        )
        connection.execute(
            text("INSERT INTO approval_requests(approval_id, authorization_id, intent_id, cart_id, status, reason, requested_at, expires_at, decided_at, decided_by, continuation_payment_id) VALUES ('approval-legacy', 'auth-legacy', 'intent-legacy', 'cart-legacy', 'APPROVED', 'legacy approval', datetime('now'), datetime('now','+1 day'), datetime('now'), 'legacy-approver', NULL)")
        )
        connection.execute(
            text("INSERT INTO payment_mandates(payment_id, intent_id, intent_hash, cart_id, cart_hash, amount_minor, currency, merchant, status, created_at, system_signature, approval_id, authorization_id) VALUES ('pay-legacy', 'intent-legacy', 'legacy-intent-hash', 'cart-legacy', 'legacy-cart-hash', 100000, 'INR', 'Amazon', 'CREATED', datetime('now'), '00', 'approval-legacy', 'auth-legacy')")
        )
        connection.execute(
            text("INSERT INTO audit_events(event_id, timestamp, event_type, actor, intent_id, cart_id, decision, reason, data, previous_hash, event_hash) VALUES ('audit-legacy', datetime('now'), 'AUTHORIZATION_CREATED', 'legacy-actor', 'intent-legacy', 'cart-legacy', 'ALLOW', 'legacy data', '{}', '000000', 'deadbeef')")
        )

    app = create_app(database_url=db_url, policy=_policy())
    db = app.state.session_factory()
    try:
        assert db.query(DBAuthorizationDecision).count() == 1
        assert db.query(DBApprovalRequest).count() == 1
        assert db.query(DBPaymentMandate).count() == 1
        legacy_payment = db.get(DBPaymentMandate, "pay-legacy")
        assert legacy_payment.system_key_id is None
        assertion = TestClient(app, headers={"Authorization": "Bearer alice-token"})
        assert assertion.get("/approvals/approval-legacy").status_code == 404
        assert assertion.post("/payment-mandates/pay-legacy/execute").status_code == 409
        assert db.query(DBAuditEvent).count() >= 1
    finally:
        db.close()

    with sqlite3.connect(str(tmp_path / 'legacy-populated.db')) as conn:
        assert conn.execute("SELECT value FROM schema_metadata WHERE key = 'schema_version'").fetchone()[0] == '3.8'
