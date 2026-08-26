from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

import agenttrust.payments.razorpay_adapter as adapter_module
from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def _db_url(tmp_path, name: str = "agenttrust_m2_razorpay_retry.db") -> str:
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


class _FakeClient:
    """
    Fake razorpay.Client replacement that fails on first call and succeeds on second.
    The real razorpay.Client has an 'order' attribute with a 'create' method, so
    this fake exposes the same shape via self.order.
    """

    def __init__(self, auth=None):
        # shared state across instances
        if not hasattr(_FakeClient, "calls"):
            _FakeClient.calls = 0
        # mimic the nested client.order.create API
        self.order = self

    def create(self, data=None):
        # emulate order.create
        _FakeClient.calls += 1
        if _FakeClient.calls == 1:
            raise Exception("simulated Razorpay transient error")
        return {"id": f"order_test_{_FakeClient.calls}"}


def test_razorpay_failure_then_retry(tmp_path, monkeypatch) -> None:
    # Force adapter to use razorpay.Client (not mocked) by setting env vars
    monkeypatch.setenv("RAZORPAY_KEY_ID", "dummy")
    monkeypatch.setenv("RAZORPAY_KEY_SECRET", "dummy")

    # Monkeypatch the razorpay.Client used inside adapter module to our fake
    monkeypatch.setattr(adapter_module.razorpay, "Client", lambda auth=None: _FakeClient(auth))

    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    r = client.post("/authorize", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ALLOW"

    payment_id = body["payment_mandate"]["payment_id"]

    # First execution: attempt once
    r1 = client.post(f"/payments/{payment_id}/execute")
    assert r1.status_code == 200
    body1 = r1.json()

    # Second execution: attempt again
    r2 = client.post(f"/payments/{payment_id}/execute")
    assert r2.status_code == 200
    body2 = r2.json()

    # At least one attempt should have succeeded
    assert (body1["result"]["success"] is True) or (body2["result"]["success"] is True)

    # Verify only one razorpay_order_id persisted across both responses (non-null)
    order_ids = set()
    if body1.get("razorpay_order_id"):
        order_ids.add(body1["razorpay_order_id"])
    if body2.get("razorpay_order_id"):
        order_ids.add(body2["razorpay_order_id"])
    non_nulls = [oid for oid in order_ids if oid]
    assert len(non_nulls) <= 1

    # Ensure the final persisted state (response from second call) has a razorpay_order_id when success
    if body2["result"]["success"]:
        assert body2["razorpay_order_id"] is not None
    else:
        # If second did not succeed, the first must have
        assert body1["razorpay_order_id"] is not None
