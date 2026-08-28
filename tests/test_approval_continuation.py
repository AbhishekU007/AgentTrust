from datetime import datetime, timedelta, timezone
import pytest

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.db.schema import DBApprovalRequest, DBAuthorizationDecision, DBPaymentMandate
from agenttrust.models import (
    ApprovalDecision,
    ApprovalStatus,
    CartItem,
    CartMandate,
    IntentMandate,
    PaymentMandate,
    PolicyConfig,
)


def _db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'continuation.db').as_posix()}"


def _policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=1000000,
        merchant_allowlist=["Amazon"],
        blocked_categories=["Weapons"],
        velocity_limit=50,
        require_approval_above_minor=300000,
    )


def _payload(amount: int = 479900) -> dict:
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
        items=[CartItem(name="Shoes", price_minor=amount)],
        total_amount_minor=amount,
    )
    return {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sign_mandate(intent.canonical_bytes(), private_key).hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": cart.model_dump(mode="json"),
    }


def _approve(client: TestClient, approval_id: str) -> None:
    approval = client.get(f"/approvals/{approval_id}").json()
    private_key, public_key = generate_keypair()
    decided_at = datetime.fromisoformat(approval["requested_at"]) + timedelta(minutes=1)
    public_key_hex = public_key.public_bytes_raw().hex()
    decision = ApprovalDecision(
        approval_id=approval["approval_id"],
        authorization_id=approval["authorization_id"],
        intent_id=approval["intent_id"],
        cart_id=approval["cart_id"],
        decision=ApprovalStatus.APPROVED,
        decided_at=decided_at,
        approver_id="human-a",
        approver_public_key=public_key_hex,
    )
    response = client.post(
        f"/approvals/{approval_id}/approve",
        json={
            "decided_by": "human-a",
            "decided_at": decided_at.isoformat(),
            "approver_public_key": public_key_hex,
            "signature": sign_mandate(decision.canonical_bytes(), private_key).hex(),
        },
    )
    assert response.status_code == 200, response.text


def _create_approved(tmp_path):
    app = create_app(database_url=_db_url(tmp_path), policy=_policy())
    client = TestClient(app)
    response = client.post("/authorize?execute=false", json=_payload())
    assert response.json()["status"] == "REQUIRE_APPROVAL"
    approval_id = response.json()["approval"]["approval_id"]
    _approve(client, approval_id)
    return app, client, approval_id


def test_approved_continuation_creates_signed_linked_mandate_without_execution(tmp_path, monkeypatch):
    app, client, approval_id = _create_approved(tmp_path)

    def fail_if_called(self, mandate):
        raise AssertionError("Razorpay must not be called by continuation")

    from agenttrust.payments.razorpay_adapter import RazorpayAdapter

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", fail_if_called)
    response = client.post(f"/approvals/{approval_id}/continue")

    assert response.status_code == 200, response.text
    body = response.json()
    payment = body["payment_mandate"]
    assert payment["status"] == "ALLOW"
    assert body["already_completed"] is False
    assert verify_signature(
        PaymentMandate(**payment).canonical_bytes(),
        bytes.fromhex(payment["system_signature"]),
        app.state.system_public_key,
    )
    db = app.state.session_factory()
    try:
        stored = db.query(DBPaymentMandate).one()
        approval = db.query(DBApprovalRequest).one()
        assert stored.approval_id == approval_id
        assert stored.authorization_id == approval.authorization_id
        assert approval.continuation_payment_id == stored.payment_id
    finally:
        db.close()


def test_continuation_retry_returns_same_mandate(tmp_path):
    _, client, approval_id = _create_approved(tmp_path)
    first = client.post(f"/approvals/{approval_id}/continue")
    second = client.post(f"/approvals/{approval_id}/continue")

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["already_completed"] is True
    assert second.json()["payment_mandate"]["payment_id"] == first.json()["payment_mandate"]["payment_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("authorization_id", "forged"),
        ("intent_id", "forged"),
        ("cart_id", "forged"),
        ("amount", 1),
        ("merchant", "forged"),
        ("category", "forged"),
        ("payment_mandate", "forged"),
        ("approval_id", "forged"),
    ],
)
def test_continuation_rejects_non_empty_request_body(tmp_path, field, value):
    app, client, approval_id = _create_approved(tmp_path)
    response = client.post(
        f"/approvals/{approval_id}/continue", json={field: value}
    )
    assert response.status_code == 422


def test_empty_continuation_bodies_are_accepted(tmp_path):
    app, client, approval_id = _create_approved(tmp_path)
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 200
    retry = client.post(f"/approvals/{approval_id}/continue", json={})
    assert retry.status_code == 200


@pytest.mark.parametrize(
    "field,value",
    [
        ("continuation_payment_id", "forged"),
        ("approval_id", "forged"),
        ("authorization_id", "forged"),
        ("intent_id", "forged"),
        ("cart_id", "forged"),
        ("intent_hash", "forged"),
        ("cart_hash", "forged"),
        ("system_signature", "00" * 64),
        ("merchant", "Forged Merchant"),
    ],
)
def test_tampered_existing_payment_mandate_cannot_be_returned(
    tmp_path, field, value
):
    app, client, approval_id = _create_approved(tmp_path)
    first = client.post(f"/approvals/{approval_id}/continue")
    assert first.status_code == 200

    db = app.state.session_factory()
    try:
        approval = db.query(DBApprovalRequest).one()
        payment = db.query(DBPaymentMandate).one()
        if field == "continuation_payment_id":
            approval.continuation_payment_id = value
        else:
            setattr(payment, field, value)
        db.commit()
    finally:
        db.close()

    response = client.post(f"/approvals/{approval_id}/continue")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "continuation_corrupt"


def test_existing_unrelated_payment_mandate_cannot_be_substituted(tmp_path):
    app, client, approval_a_id = _create_approved(tmp_path)
    first_a = client.post(f"/approvals/{approval_a_id}/continue")
    assert first_a.status_code == 200
    payment_a_id = first_a.json()["payment_mandate"]["payment_id"]

    second_authorization = client.post(
        "/authorize?execute=false", json=_payload(amount=480000)
    )
    assert second_authorization.status_code == 200
    approval_b_id = second_authorization.json()["approval"]["approval_id"]
    _approve(client, approval_b_id)
    first_b = client.post(f"/approvals/{approval_b_id}/continue")
    assert first_b.status_code == 200
    payment_b = first_b.json()["payment_mandate"]
    payment_b_id = payment_b["payment_id"]
    assert payment_b_id != payment_a_id

    db = app.state.session_factory()
    try:
        approval_a = db.query(DBApprovalRequest).filter_by(
            approval_id=approval_a_id
        ).one()
        stored_b = db.query(DBPaymentMandate).filter_by(
            payment_id=payment_b_id
        ).one()
        payment_b_snapshot = {
            "approval_id": stored_b.approval_id,
            "authorization_id": stored_b.authorization_id,
            "intent_id": stored_b.intent_id,
            "cart_id": stored_b.cart_id,
            "intent_hash": stored_b.intent_hash,
            "cart_hash": stored_b.cart_hash,
            "amount_minor": stored_b.amount_minor,
            "currency": stored_b.currency,
            "merchant": stored_b.merchant,
            "system_signature": stored_b.system_signature,
        }
        original_a_link = approval_a.continuation_payment_id
        approval_b = db.query(DBApprovalRequest).filter_by(
            approval_id=approval_b_id
        ).one()
        approval_b.continuation_payment_id = None
        approval_a.continuation_payment_id = payment_b_id
        db.commit()
    finally:
        db.close()

    response = client.post(f"/approvals/{approval_a_id}/continue")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "continuation_corrupt"
    assert payment_b_id not in response.text

    db = app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 2
        approval_a = db.query(DBApprovalRequest).filter_by(
            approval_id=approval_a_id
        ).one()
        stored_b = db.query(DBPaymentMandate).filter_by(
            payment_id=payment_b_id
        ).one()
        assert original_a_link == payment_a_id
        assert approval_a.continuation_payment_id == payment_b_id
        assert {
            "approval_id": stored_b.approval_id,
            "authorization_id": stored_b.authorization_id,
            "intent_id": stored_b.intent_id,
            "cart_id": stored_b.cart_id,
            "intent_hash": stored_b.intent_hash,
            "cart_hash": stored_b.cart_hash,
            "amount_minor": stored_b.amount_minor,
            "currency": stored_b.currency,
            "merchant": stored_b.merchant,
            "system_signature": stored_b.system_signature,
        } == payment_b_snapshot
    finally:
        db.close()


def test_pending_and_rejected_approvals_cannot_continue(tmp_path):
    app = create_app(database_url=_db_url(tmp_path), policy=_policy())
    client = TestClient(app)
    body = client.post("/authorize?execute=false", json=_payload()).json()
    approval_id = body["approval"]["approval_id"]
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 409

    _approve(client, approval_id)
    db = app.state.session_factory()
    try:
        record = db.query(DBApprovalRequest).one()
        record.status = "REJECTED"
        db.commit()
    finally:
        db.close()
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 409


def test_tampered_approval_signature_fails_closed(tmp_path):
    app, client, approval_id = _create_approved(tmp_path)
    db = app.state.session_factory()
    try:
        record = db.query(DBApprovalRequest).one()
        record.decision_signature = "00" * 64
        db.commit()
    finally:
        db.close()

    response = client.post(f"/approvals/{approval_id}/continue")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "invalid_approval_signature"


def test_tampered_context_and_original_signature_fail_closed(tmp_path):
    app, client, approval_id = _create_approved(tmp_path)
    db = app.state.session_factory()
    try:
        decision = db.query(DBAuthorizationDecision).one()
        decision.intent_hash = "tampered"
        db.commit()
    finally:
        db.close()
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 409

    second_path = tmp_path / "second"
    second_path.mkdir()
    app, client, approval_id = _create_approved(second_path)
    db = app.state.session_factory()
    try:
        decision = db.query(DBAuthorizationDecision).one()
        decision.intent_signature = "00" * 64
        db.commit()
    finally:
        db.close()
    assert client.post(f"/approvals/{approval_id}/continue").status_code == 409


def test_hard_block_cannot_become_payable_after_approval(tmp_path):
    app, client, approval_id = _create_approved(tmp_path)
    db = app.state.session_factory()
    try:
        decision = db.query(DBAuthorizationDecision).one()
        decision.status = "BLOCK"
        db.commit()
    finally:
        db.close()

    response = client.post(f"/approvals/{approval_id}/continue")
    assert response.status_code == 409
    db = app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 0
    finally:
        db.close()
