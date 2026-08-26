from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.db.schema import DBAuditEvent, DBPaymentMandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig
from agenttrust.payments.razorpay_adapter import PaymentExecutionResult, RazorpayAdapter


def _db_url(tmp_path, name: str = "agenttrust_m2.db") -> str:
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


def test_authorize_allow_creates_signed_payment_and_executes_mock_razorpay(tmp_path) -> None:
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

    payment = body["payment_mandate"]
    system_signature = bytes.fromhex(payment["system_signature"])
    from agenttrust.models import PaymentMandate

    payment_obj = PaymentMandate(**payment)
    assert verify_signature(
        payment_obj.canonical_bytes(),
        system_signature,
        app.state.system_public_key,
    )


def test_invalid_signature_is_blocked(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    payload["intent_signature"] = "00" * 64
    response = client.post("/authorize", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "BLOCK"
    assert body["payment_mandate"] is None


def test_expired_intent_is_blocked(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(expires_in_seconds=-1)
    response = client.post("/authorize", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"


def test_intent_cart_mismatch_is_blocked(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=200000)
    payload["cart"]["merchant"] = "Flipkart"
    response = client.post("/authorize", json=payload)

    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"


def test_policy_violation_is_blocked(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=550000)
    payload["intent"]["max_amount_minor"] = 600000
    response = client.post("/authorize", json=payload)

    assert response.status_code == 200
    assert response.json()["status"] == "BLOCK"


def test_require_approval_creates_no_payment(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_with_approval_gate())
    client = TestClient(app)

    payload, _ = _build_signed_payload(amount_minor=479900)
    response = client.post("/authorize", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "REQUIRE_APPROVAL"
    assert body["payment_mandate"] is None

    db = app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 0
    finally:
        db.close()


def test_duplicate_request_is_durably_rejected(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    first = client.post("/authorize", json=payload)
    second = client.post("/authorize", json=payload)

    assert first.status_code == 200
    assert first.json()["status"] == "ALLOW"
    assert second.status_code == 200
    assert second.json()["status"] == "BLOCK"


def test_audit_chain_persists_and_survives_reload(tmp_path) -> None:
    db_url = _db_url(tmp_path)
    app1 = create_app(database_url=db_url, policy=_policy_allowing_5000())
    client1 = TestClient(app1)

    payload, _ = _build_signed_payload()
    r = client1.post("/authorize", json=payload)
    assert r.status_code == 200

    app2 = create_app(database_url=db_url, policy=_policy_allowing_5000())
    client2 = TestClient(app2)
    audit = client2.get("/audit")
    assert audit.status_code == 200
    assert audit.json()["valid"] is True
    assert audit.json()["count"] >= 1


def test_audit_tampering_detected_after_persistence(tmp_path) -> None:
    db_url = _db_url(tmp_path)
    app = create_app(database_url=db_url, policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    r = client.post("/authorize", json=payload)
    assert r.status_code == 200

    db = app.state.session_factory()
    try:
        first = db.query(DBAuditEvent).order_by(DBAuditEvent.id).first()
        assert first is not None
        first.reason = "tampered-reason"
        db.commit()
    finally:
        db.close()

    audit = client.get("/audit")
    assert audit.status_code == 200
    assert audit.json()["valid"] is False


def test_razorpay_adapter_failure_is_fail_closed_for_execution_status(tmp_path, monkeypatch) -> None:
    def _force_failure(self, mandate):
        return PaymentExecutionResult(
            success=False,
            order_id=None,
            error_code="forced_failure",
            message="forced test failure",
            is_mocked=True,
        )

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", _force_failure)

    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    response = client.post("/authorize", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ALLOW"
    assert body["payment_execution"]["success"] is False

    db = app.state.session_factory()
    try:
        row = db.query(DBPaymentMandate).first()
        assert row is not None
        assert row.payment_execution_status == "FAILED"
        assert row.razorpay_order_id is None
    finally:
        db.close()


def test_payment_idempotency_prevents_duplicate_orders(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    auth_response = client.post("/authorize", json=payload)
    assert auth_response.status_code == 200
    auth_body = auth_response.json()
    assert auth_body["status"] == "ALLOW"

    payment_id = auth_body["payment_mandate"]["payment_id"]
    original_order_id = auth_body["payment_execution"]["order_id"]

    retry_1 = client.post(f"/payments/{payment_id}/execute")
    retry_2 = client.post(f"/payments/{payment_id}/execute")

    assert retry_1.status_code == 200
    assert retry_2.status_code == 200
    assert retry_1.json()["razorpay_order_id"] == original_order_id
    assert retry_2.json()["razorpay_order_id"] == original_order_id
