from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.db.schema import (
    DBAuditEvent,
    DBApprovalRequest,
    DBAuthorizationDecision,
)
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def _db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'm36.db').as_posix()}"


def _payload(amount_minor: int) -> dict:
    private_key, public_key = generate_keypair()
    intent = IntentMandate(
        description="Buy running shoes",
        max_amount_minor=500000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    cart = CartMandate(
        intent_id=intent.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Running shoes", price_minor=amount_minor)],
        total_amount_minor=amount_minor,
    )
    return {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sign_mandate(intent.canonical_bytes(), private_key).hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": cart.model_dump(mode="json"),
    }


def _approval_policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=1000000,
        merchant_allowlist=["Amazon"],
        blocked_categories=["Weapons"],
        velocity_limit=50,
        require_approval_above_minor=300000,
    )


def _allow_policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=1000000,
        merchant_allowlist=["Amazon"],
        blocked_categories=["Weapons"],
        velocity_limit=50,
        require_approval_above_minor=900000,
    )


def test_require_approval_persists_linked_approval(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_approval_policy())
    response = TestClient(app).post("/authorize?execute=false", json=_payload(479900))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "REQUIRE_APPROVAL"
    assert body["approval"]["status"] == "PENDING"
    assert body["approval"]["intent_id"] == body["intent_id"]
    assert body["approval"]["cart_id"] == body["cart_id"]

    db = app.state.session_factory()
    try:
        decision = db.query(DBAuthorizationDecision).one()
        approval = db.query(DBApprovalRequest).one()
        assert approval.authorization_id == decision.decision_id
        assert approval.intent_id == decision.intent_id
        assert approval.cart_id == decision.cart_id
        assert decision.intent_signature is not None
        assert decision.user_public_key is not None
        assert decision.intent_hash is not None
        assert decision.cart_hash is not None
        assert (
            db.query(DBAuditEvent)
            .filter(DBAuditEvent.event_type == "APPROVAL_REQUESTED")
            .count()
            == 1
        )
    finally:
        db.close()


def test_require_approval_survives_application_restart(tmp_path) -> None:
    database_url = _db_url(tmp_path)
    first = TestClient(create_app(database_url=database_url, policy=_approval_policy()))
    body = first.post("/authorize?execute=false", json=_payload(479900)).json()
    approval_id = body["approval"]["approval_id"]

    restarted = TestClient(create_app(database_url=database_url, policy=_approval_policy()))
    response = restarted.get(f"/approvals/{approval_id}")

    assert response.status_code == 200
    assert response.json()["authorization_id"] == body["approval"]["authorization_id"]
    assert response.json()["status"] == "PENDING"


def test_allow_does_not_create_approval(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_allow_policy())
    response = TestClient(app).post("/authorize?execute=false", json=_payload(200000))

    assert response.status_code == 200
    assert response.json()["status"] == "ALLOW"
    db = app.state.session_factory()
    try:
        assert db.query(DBApprovalRequest).count() == 0
    finally:
        db.close()


def test_block_does_not_create_approval(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_approval_policy())
    response = TestClient(app).post("/authorize?execute=false", json=_payload(1100000))

    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"
    db = app.state.session_factory()
    try:
        assert db.query(DBApprovalRequest).count() == 0
    finally:
        db.close()


def test_repeated_require_approval_request_has_one_persisted_approval(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_approval_policy())
    payload = _payload(479900)
    client = TestClient(app)

    first = client.post("/authorize?execute=false", json=payload)
    second = client.post("/authorize?execute=false", json=payload)

    assert first.json()["status"] == "REQUIRE_APPROVAL"
    assert second.json()["status"] == "BLOCK"
    db = app.state.session_factory()
    try:
        assert db.query(DBApprovalRequest).count() == 1
        assert db.query(DBAuthorizationDecision).count() == 2
    finally:
        db.close()


def test_concurrent_require_approval_requests_have_deterministic_result(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_approval_policy())
    payload = _payload(479900)

    def authorize() -> tuple[int, str]:
        response = TestClient(app).post("/authorize?execute=false", json=payload)
        return response.status_code, response.json()["status"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: authorize(), range(2)))

    assert sorted(results) == [(200, "BLOCK"), (200, "REQUIRE_APPROVAL")]
    db = app.state.session_factory()
    try:
        assert db.query(DBApprovalRequest).count() == 1
    finally:
        db.close()
