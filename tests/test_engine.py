"""End-to-end tests for the AgentTrust authorization engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from agenttrust.engine import AuthorizationEngine
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.models import (
    AuthorizationStatus,
    CartItem,
    CartMandate,
    IntentMandate,
    PolicyConfig,
)


def _make_policy(**overrides) -> PolicyConfig:
    defaults = dict(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        velocity_limit=10,
        velocity_window_seconds=3600,
    )
    defaults.update(overrides)
    return PolicyConfig(**defaults)


def _make_intent(**overrides) -> IntentMandate:
    defaults = dict(
        description="Buy running shoes from Amazon for under ₹5,000",
        max_amount_minor=500000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    defaults.update(overrides)
    return IntentMandate(**defaults)


def _make_cart(intent: IntentMandate, **overrides) -> CartMandate:
    defaults = dict(
        intent_id=intent.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Nike Air Zoom Pegasus", price_minor=479900, quantity=1)],
        total_amount_minor=479900,
    )
    defaults.update(overrides)
    return CartMandate(**defaults)


@pytest.fixture
def engine() -> AuthorizationEngine:
    return AuthorizationEngine(policy=_make_policy())


@pytest.fixture
def user_keys():
    return generate_keypair()


class TestValidPurchase:
    def test_valid_purchase_is_allowed(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent)
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.ALLOW
        assert result.payment_mandate is not None
        assert result.payment_mandate.amount_minor == 479900
        assert result.payment_mandate.merchant == "Amazon"
        assert result.payment_mandate.intent_id == intent.intent_id
        assert result.payment_mandate.cart_id == cart.cart_id
        
        # PaymentMandate binding checks
        assert result.payment_mandate.intent_hash == intent.compute_hash()
        assert result.payment_mandate.cart_hash == cart.compute_hash()
        assert result.payment_mandate.system_signature is not None
        
        # System signature verifies PaymentMandate content
        system_sig_bytes = bytes.fromhex(result.payment_mandate.system_signature)
        assert verify_signature(result.payment_mandate.canonical_bytes(), system_sig_bytes, engine.system_public_key)

    def test_allow_result_has_structured_checks(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)
        cart = _make_cart(intent)
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.ALLOW
        assert len(result.checks) > 0
        for check in result.checks:
            assert check.passed is True


class TestAmountViolation:
    def test_cart_exceeding_policy_limit_is_blocked(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(max_amount_minor=1500000)
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(
            intent,
            items=[CartItem(name="Expensive shoes", price_minor=1299900, quantity=1)],
            total_amount_minor=1299900,
        )
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK
        assert result.payment_mandate is None


class TestMerchantViolation:
    def test_unauthorized_merchant_blocked_by_policy(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(allowed_merchants=["Amazon", "ShadyShop"])
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent, merchant="ShadyShop")
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK
        assert result.payment_mandate is None

    def test_merchant_spoofing_blocked_by_intent(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(allowed_merchants=["Flipkart"])
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent, merchant="Amazon")
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK


class TestCategoryViolation:
    def test_blocked_category_is_rejected(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(allowed_categories=["Weapons"], description="Buy weapons")
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent, category="Weapons")
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK


class TestIntentCartMismatch:
    def test_amount_exceeds_intent_max(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(max_amount_minor=300000)
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent)  # 479900
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK


class TestTamperedMandate:
    def test_modified_intent_after_signing_is_blocked(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)

        # Attacker modifies intent
        intent.max_amount_minor = 99999999

        cart = _make_cart(intent)
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK
        sig_check = next(c for c in result.checks if c.check_name == "signature")
        assert sig_check.passed is False

    def test_signature_substitution(self, engine: AuthorizationEngine, user_keys):
        """Valid signature from Intent A fails when attached to Intent B."""
        priv, pub = user_keys
        intentA = _make_intent(description="Intent A")
        sigA = sign_mandate(intentA.canonical_bytes(), priv)

        intentB = _make_intent(description="Intent B")
        # Attacker submits Intent B but provides Signature from A
        cartB = _make_cart(intentB)
        result = engine.authorize(intentB, sigA, pub, cartB)
        
        assert result.status == AuthorizationStatus.BLOCK
        sig_check = next(c for c in result.checks if c.check_name == "signature")
        assert sig_check.passed is False


class TestExpiredMandate:
    def test_expired_intent_is_blocked(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent)
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.BLOCK
        assert "expired" in result.reason.lower()


class TestReplayProtection:
    def test_consumed_intent_cannot_authorize_second_cart(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart1 = _make_cart(intent)
        result1 = engine.authorize(intent, sig, pub, cart1)
        assert result1.status == AuthorizationStatus.ALLOW

        # Second cart referencing same intent
        cart2 = _make_cart(intent)
        result2 = engine.authorize(intent, sig, pub, cart2)
        assert result2.status == AuthorizationStatus.BLOCK

    def test_intent_nonce_cannot_be_reused_concurrently(self, engine: AuthorizationEngine, user_keys):
        """Simulate sending the exact same payload twice before intent consumption triggers."""
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart1 = _make_cart(intent)
        result1 = engine.authorize(intent, sig, pub, cart1)
        assert result1.status == AuthorizationStatus.ALLOW

        # Submit exact same payload again with a new cart, but intent nonce is the same
        cart2 = _make_cart(intent)
        result2 = engine.authorize(intent, sig, pub, cart2)
        assert result2.status == AuthorizationStatus.BLOCK
        assert "already consumed" in result2.reason.lower()

    def test_cart_replay_is_blocked(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        intent = _make_intent()
        sig = sign_mandate(intent.canonical_bytes(), priv)

        cart = _make_cart(intent)
        result1 = engine.authorize(intent, sig, pub, cart)
        assert result1.status == AuthorizationStatus.ALLOW

        # But wait, intent is consumed after first ALLOW. Let's try cart replay against a NEW intent?
        # Actually, the cart_id and nonce are tied. If we just replay the cart.
        intent2 = _make_intent()
        sig2 = sign_mandate(intent2.canonical_bytes(), priv)
        
        # Modify the cart to point to intent2, but keep cart nonce same
        cart.intent_id = intent2.intent_id
        
        result2 = engine.authorize(intent2, sig2, pub, cart)
        assert result2.status == AuthorizationStatus.BLOCK
        assert "Cart replay" in result2.reason


class TestAuditChainVerification:
    def test_audit_chain_valid_after_mixed_operations(self, engine: AuthorizationEngine, user_keys):
        priv, pub = user_keys
        
        intent1 = _make_intent()
        sig1 = sign_mandate(intent1.canonical_bytes(), priv)
        cart1 = _make_cart(intent1)
        engine.authorize(intent1, sig1, pub, cart1)

        intent2 = _make_intent(max_amount_minor=1500000)
        sig2 = sign_mandate(intent2.canonical_bytes(), priv)
        cart2 = _make_cart(intent2, items=[CartItem(name="Expensive", price_minor=1299900, quantity=1)], total_amount_minor=1299900)
        engine.authorize(intent2, sig2, pub, cart2)

        valid, message = engine.audit.verify_chain()
        assert valid is True


class TestRequireApproval:
    def test_amount_above_approval_threshold(self, user_keys):
        priv, pub = user_keys
        engine = AuthorizationEngine(
            policy=_make_policy(
                max_transaction_amount_minor=1000000,
                require_approval_above_minor=300000,
            )
        )

        intent = _make_intent(max_amount_minor=500000)
        sig = sign_mandate(intent.canonical_bytes(), priv)
        cart = _make_cart(intent)  # 479900
        result = engine.authorize(intent, sig, pub, cart)

        assert result.status == AuthorizationStatus.REQUIRE_APPROVAL
        assert result.payment_mandate is None


class TestPolicyChange:
    def test_block_then_policy_change_then_allow(self, user_keys):
        priv, pub = user_keys
        engine = AuthorizationEngine(
            policy=_make_policy(max_transaction_amount_minor=500000)
        )

        intent1 = _make_intent(max_amount_minor=1000000)
        sig1 = sign_mandate(intent1.canonical_bytes(), priv)
        cart1 = _make_cart(intent1, items=[CartItem(name="Nike", price_minor=750000, quantity=1)], total_amount_minor=750000)
        
        result1 = engine.authorize(intent1, sig1, pub, cart1)
        assert result1.status == AuthorizationStatus.BLOCK

        # Update policy
        engine.update_policy(_make_policy(max_transaction_amount_minor=1000000))

        # Retry - needs new intent and cart because of nonce consumption
        intent2 = _make_intent(max_amount_minor=1000000)
        sig2 = sign_mandate(intent2.canonical_bytes(), priv)
        cart2 = _make_cart(intent2, items=[CartItem(name="Nike", price_minor=750000, quantity=1)], total_amount_minor=750000)
        
        result2 = engine.authorize(intent2, sig2, pub, cart2)
        assert result2.status == AuthorizationStatus.ALLOW
        assert result2.payment_mandate.amount_minor == 750000
