from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from agenttrust.crypto import generate_keypair, sign_mandate, serialize_public_key
from agenttrust.ai_buyer import AIRequester, Recommendation
from agenttrust.models import IntentMandate, CartMandate, CartItem


def build_mandates_from_recommendation(
    natural_language_request: str, rec: Recommendation, expires_seconds: int = 3600
) -> Tuple[IntentMandate, CartMandate]:
    """
    Convert an AI Recommendation into an IntentMandate and CartMandate.

    - Picks merchant and category from the first recommended product
    - Builds cart items from recommendation details
    - Sets intent.max_amount_minor = recommendation.total_price_minor
    """

    first = rec.details[0]
    merchant = first.get("merchant")
    category = first.get("category") or first.get("category", "")

    # Build intent
    now = datetime.now(timezone.utc)
    intent = IntentMandate(
        description=natural_language_request,
        max_amount_minor=rec.total_price_minor,
        currency="INR",
        allowed_merchants=[merchant],
        allowed_categories=[category],
        created_at=now,
        expires_at=now + timedelta(seconds=expires_seconds),
    )

    # Build cart items
    items = [
        CartItem(name=d.get("name", "item"), price_minor=d.get("price_minor"), quantity=1)
        for d in rec.details
    ]

    cart = CartMandate(
        intent_id=intent.intent_id,
        merchant=merchant,
        category=category,
        items=items,
        total_amount_minor=rec.total_price_minor,
        currency="INR",
    )

    return intent, cart


def demo_user_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    return generate_keypair()


def sign_intent_hex(intent: IntentMandate, private_key: Ed25519PrivateKey) -> str:
    sig = sign_mandate(intent.canonical_bytes(), private_key)
    return sig.hex()


def user_public_key_pem(public_key: Ed25519PublicKey) -> str:
    return serialize_public_key(public_key).decode("utf-8")


def propose_and_build(natural_language_request: str) -> Recommendation:
    requester = AIRequester()
    return requester.propose(natural_language_request)


# Small typed helper to call the API using fastapi TestClient from tests
# Tests will use TestClient directly; this helper is provided for convenience.
def call_authorize(client, intent: IntentMandate, intent_signature_hex: str, user_public_key_pem: str, cart: CartMandate, execute: bool = False):
    payload = {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": intent_signature_hex,
        "user_public_key": user_public_key_pem,
        "cart": cart.model_dump(mode="json"),
    }
    url = "/authorize?execute=false" if not execute else "/authorize"
    return client.post(url, json=payload)
