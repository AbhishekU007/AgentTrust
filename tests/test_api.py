from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.models import CartItem, CartMandate, IntentMandate


def _intent_payload(intent: IntentMandate) -> dict:
    return intent.model_dump(mode="json")


def _cart_payload(cart: CartMandate) -> dict:
    return cart.model_dump(mode="json")


def _build_signed_request(*, amount_minor: int = 479900) -> tuple[dict, IntentMandate, CartMandate]:
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
        items=[CartItem(name="Nike Air Zoom Pegasus", price_minor=amount_minor, quantity=1)],
        total_amount_minor=amount_minor,
    )
    sig = sign_mandate(intent.canonical_bytes(), private_key)

    payload = {
        "intent": _intent_payload(intent),
        "intent_signature": sig.hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": _cart_payload(cart),
    }
    return payload, intent, cart


def test_health_endpoint_returns_ok() -> None:
    client = TestClient(create_app())
    response = client.get("/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "agenttrust"


def test_authorize_valid_signed_payload_allows_and_creates_payment_mandate() -> None:
    client = TestClient(create_app())
    payload, _, _ = _build_signed_request()

    response = client.post("/authorize", json=payload)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "REQUIRE_APPROVAL" or body["status"] == "ALLOW"


def test_authorize_invalid_signature_is_blocked() -> None:
    client = TestClient(create_app())
    payload, _, _ = _build_signed_request()

    payload["intent_signature"] = "00" * 64
    response = client.post("/authorize", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "BLOCK"
    assert "signature" in body["reason"].lower()


def test_signature_substitution_is_blocked() -> None:
    client = TestClient(create_app())
    payload_a, _, _ = _build_signed_request()
    payload_b, intent_b, cart_b = _build_signed_request()

    substituted = {
        "intent": intent_b.model_dump(mode="json"),
        "intent_signature": payload_a["intent_signature"],
        "user_public_key": payload_a["user_public_key"],
        "cart": cart_b.model_dump(mode="json"),
    }
    response = client.post("/authorize", json=substituted)
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "BLOCK"
    assert "signature" in body["reason"].lower()


def test_authorize_rejects_malformed_crypto_material() -> None:
    client = TestClient(create_app())
    payload, _, _ = _build_signed_request()

    payload["intent_signature"] = "not-a-real-signature"
    response = client.post("/authorize", json=payload)

    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["code"] == "invalid_crypto_material"
