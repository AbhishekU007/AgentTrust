from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def _db_url(tmp_path, name: str = "agenttrust_m2_concurrent.db") -> str:
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


def test_concurrent_payment_execution_creates_single_order(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())
    client = TestClient(app)

    payload, _ = _build_signed_payload()
    r = client.post("/authorize", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ALLOW"

    payment_id = body["payment_mandate"]["payment_id"]

    def exec_request():
        # Use a fresh TestClient per thread to simulate separate callers
        c = TestClient(app)
        resp = c.post(f"/payments/{payment_id}/execute")
        return resp.json()

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(exec_request) for _ in range(2)]
        results = [f.result() for f in futures]

    order_ids = set(r["razorpay_order_id"] for r in results)
    assert len(order_ids) == 1
    assert list(order_ids)[0] is not None
