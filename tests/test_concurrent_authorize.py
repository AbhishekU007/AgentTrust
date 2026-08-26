from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def _db_url(tmp_path, name: str = "agenttrust_m2_concurrent_authorize.db") -> str:
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


def _build_signed_payload(*, amount_minor: int = 479900, expires_in_seconds: int = 3600) -> dict:
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
    return payload


def test_concurrent_authorize_creates_single_payment_mandate(tmp_path) -> None:
    app = create_app(database_url=_db_url(tmp_path), policy=_policy_allowing_5000())

    payload = _build_signed_payload()

    def auth_request():
        c = TestClient(app)
        resp = c.post("/authorize", json=payload)
        return resp.json()

    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = [ex.submit(auth_request) for _ in range(2)]
        results = [f.result() for f in futures]

    payment_ids = [r.get("payment_mandate", {}).get("payment_id") for r in results if r.get("payment_mandate")]
    # At most one non-null payment mandate should be created
    non_null = [p for p in payment_ids if p]
    assert len(set(non_null)) <= 1
    # At least one request should be ALLOW
    statuses = [r.get("status") for r in results]
    assert "ALLOW" in statuses
