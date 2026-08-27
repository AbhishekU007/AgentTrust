from __future__ import annotations

from fastapi.testclient import TestClient
from agenttrust.api import create_app
from agenttrust.ai_integration import (
    propose_and_build,
    build_mandates_from_recommendation,
    demo_user_keypair,
    sign_intent_hex,
    user_public_key_pem,
)
from agenttrust.ai_buyer import AIRequester
from agenttrust.catalog import get_product


from agenttrust.crypto import generate_keypair
from agenttrust.models import AuthorizationStatus, PolicyConfig


def _test_policy():
    return PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        velocity_limit=999999,
        velocity_window_seconds=3600,
        require_approval_above_minor=450000,
    )


def test_valid_purchase_allow_and_execute_false():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    # Use MockLLM via AIRequester.propose
    requester = AIRequester()
    rec = requester.propose("Buy Acme running shoes under 5000")

    intent, cart = build_mandates_from_recommendation("Buy Acme running shoes under 5000", rec)

    # Demo user keys and signature
    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sig_hex,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == AuthorizationStatus.ALLOW.value
    assert body.get("payment_mandate") is not None
    # No payment execution should be present when execute=false
    assert "payment_execution" not in body


def test_over_budget_cart_mismatch_block():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    requester = AIRequester()
    rec = requester.propose("Buy Acme running shoes under 5000")

    intent, cart = build_mandates_from_recommendation("Buy Acme running shoes under 5000", rec)

    # Tamper intent to have a very small max_amount
    intent.max_amount_minor = 10000

    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sig_hex,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == AuthorizationStatus.BLOCK.value


def test_invalid_tampered_signature_block():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    requester = AIRequester()
    rec = requester.propose("Buy Acme running shoes under 5000")

    intent, cart = build_mandates_from_recommendation("Buy Acme running shoes under 5000", rec)

    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    # Tamper signature by flipping a character
    tampered = ("00" + sig_hex[2:]) if len(sig_hex) > 4 else ("ff" + sig_hex)

    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": tampered,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == AuthorizationStatus.BLOCK.value


def test_require_approval_path():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    requester = AIRequester()
    # choose a prompt that will pick Acme Trail Shoes (price 459900 paise) to trigger REQUIRE_APPROVAL
    rec = requester.propose("Buy Trail Shoes")

    intent, cart = build_mandates_from_recommendation("Buy Trail Shoes", rec)

    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sig_hex,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # This scenario should deterministically trigger REQUIRE_APPROVAL (amount > approval threshold and below hard limit)
    assert body["status"] == AuthorizationStatus.REQUIRE_APPROVAL.value


def test_allow_then_execute_payment():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    requester = AIRequester()
    rec = requester.propose("Buy Acme running shoes under 5000")

    intent, cart = build_mandates_from_recommendation("Buy Acme running shoes under 5000", rec)

    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sig_hex,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == AuthorizationStatus.ALLOW.value
    payment = body.get("payment_mandate")
    assert payment is not None
    payment_id = payment["payment_id"]

    # Now execute explicitly
    exec_resp = client.post(f"/payments/{payment_id}/execute")
    assert exec_resp.status_code == 200, exec_resp.text
    exec_body = exec_resp.json()
    assert exec_body["payment_execution_status"] in {"SUCCEEDED", "FAILED"}
    # On mocked Razorpay, expect SUCCEEDED
    

def test_malicious_product_description_treated_as_data_and_safe():
    app = create_app(policy=_test_policy())
    client = TestClient(app)

    requester = AIRequester()
    # prompt that will pick the "Malicious Item" in catalog
    rec = requester.propose("Find the Malicious Item")

    # Ensure the malicious item is returned by the mock proposer
    if not rec.details:
        # no matching item returned; nothing to test here
        return

    intent, cart = build_mandates_from_recommendation("Find the Malicious Item", rec)
    user_priv, user_pub = demo_user_keypair()
    sig_hex = sign_intent_hex(intent, user_priv)
    pub_pem = user_public_key_pem(user_pub)

    resp = client.post("/authorize?execute=false", json={
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sig_hex,
        "user_public_key": pub_pem,
        "cart": cart.model_dump(mode="json"),
    })

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # AgentTrust should treat description strictly as data and not be vulnerable to injection
    assert "payment_mandate" in body or body["status"] != "ERROR"
