from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.db.schema import DBPaymentMandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def _db_url(tmp_path, name: str = "agenttrust_m3_test.db") -> str:
    return f"sqlite:///{(tmp_path / name).as_posix()}"


def _policy_allowing_5000() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        velocity_limit=50,
        velocity_window_seconds=3600,
        require_approval_above_minor=900000,
    )


def _policy_with_approval_gate() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=1000000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        velocity_limit=50,
        velocity_window_seconds=3600,
        require_approval_above_minor=300000,
    )


def _build_signed_payload(*, amount_minor: int = 479900, expires_in_seconds: int = 3600) -> tuple[dict, IntentMandate]:
    private_key, public_key = generate_keypair()
    intent = IntentMandate(
        description="Buy running shoes",
        max_amount_minor=500000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds),
    )
    cart = CartMandate(
        intent_id=intent.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Nike Air Zoom Pegasus", price_minor=amount_minor, quantity=1)],
        total_amount_minor=amount_minor,
    )
    signature = sign_mandate(intent.canonical_bytes(), private_key)
    payload = {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": signature.hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": cart.model_dump(mode="json"),
    }
    return payload, intent


def test_allow_execute_false_creates_payment_no_razorpay(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=479900)
    response = client.post("/authorize?execute=false", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ALLOW"
    assert body["payment_mandate"] is not None
    # When execute=false there should be no immediate payment_execution field
    assert "payment_execution" not in body

    payment = body["payment_mandate"]
    payment_id = payment["payment_id"]

    db = app.state.session_factory()
    try:
        row = db.query(DBPaymentMandate).get(payment_id)
        assert row is not None
        assert row.payment_execution_status == "NOT_EXECUTED"
        assert row.razorpay_order_id is None
    finally:
        db.close()


def test_allow_execute_true_preserves_existing_behavior(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=479900)
    response = client.post("/authorize", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ALLOW"
    assert body["payment_mandate"] is not None
    assert body["payment_execution"]["success"] is True
    assert body["payment_execution"]["order_id"] is not None


def test_block_no_razorpay_with_execute_false(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=550000)
    response = client.post("/authorize?execute=false", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"

    db = app.state.session_factory()
    try:
        # No payment mandates should be created for BLOCK
        assert db.query(DBPaymentMandate).count() == 0
    finally:
        db.close()


def test_require_approval_no_razorpay_with_execute_false(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_with_approval_gate())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=479900)
    response = client.post("/authorize?execute=false", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "REQUIRE_APPROVAL"
    assert body["payment_mandate"] is None


def test_execute_after_execute_false_succeeds(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=479900)
    response = client.post("/authorize?execute=false", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ALLOW"

    payment_id = body["payment_mandate"]["payment_id"]
    exec_resp = client.post(f"/payments/{payment_id}/execute")
    assert exec_resp.status_code == 200
    exec_body = exec_resp.json()
    assert exec_body["result"]["success"] is True
    assert exec_body["razorpay_order_id"] is not None
