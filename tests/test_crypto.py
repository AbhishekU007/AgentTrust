"""Tests for Ed25519 crypto operations and deterministic canonicalization."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.models import CartItem, CartMandate, IntentMandate


class TestKeyGeneration:
    def test_generates_valid_keypair(self):
        private, public = generate_keypair()
        assert private is not None
        assert public is not None

    def test_keypairs_are_unique(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert pub1.public_bytes_raw() != pub2.public_bytes_raw()


class TestSignAndVerify:
    def test_sign_verify_roundtrip(self):
        private, public = generate_keypair()
        data = b'{"description":"Buy shoes","max_amount_minor":500000}'
        signature = sign_mandate(data, private)
        assert len(signature) == 64
        assert verify_signature(data, signature, public) is True

    def test_tampered_data_fails_verification(self):
        private, public = generate_keypair()
        data = b'{"description":"Buy shoes","max_amount_minor":500000}'
        signature = sign_mandate(data, private)
        tampered = b'{"description":"Buy shoes","max_amount_minor":5000000}'
        assert verify_signature(tampered, signature, public) is False

    def test_wrong_key_fails_verification(self):
        private1, _ = generate_keypair()
        _, public2 = generate_keypair()
        data = b'{"description":"Buy shoes","max_amount_minor":500000}'
        signature = sign_mandate(data, private1)
        assert verify_signature(data, signature, public2) is False

    def test_corrupted_signature_fails(self):
        private, public = generate_keypair()
        data = b"test data"
        signature = sign_mandate(data, private)
        corrupted = bytearray(signature)
        corrupted[0] ^= 0xFF
        assert verify_signature(data, bytes(corrupted), public) is False


class TestCanonicalSerialization:
    """Verify strict JSON canonicalization."""

    def _sign_intent(self, intent: IntentMandate):
        private, public = generate_keypair()
        sig = sign_mandate(intent.canonical_bytes(), private)
        return sig, public

    def _make_intent(self, **overrides) -> IntentMandate:
        defaults = dict(
            intent_id="test-intent-001",
            description="Buy running shoes",
            max_amount_minor=500000,
            currency="INR",
            allowed_merchants=["Amazon"],
            allowed_categories=["Footwear"],
            nonce="test-nonce-001",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2026, 1, 2, tzinfo=timezone.utc),
        )
        defaults.update(overrides)
        return IntentMandate(**defaults)

    def test_identical_mandates_produce_same_canonical_bytes(self):
        a = self._make_intent()
        b = self._make_intent()
        assert a.canonical_bytes() == b.canonical_bytes()

    def test_changing_description_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(description="Buy expensive watches")
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_changing_max_amount_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(max_amount_minor=99999999)
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_changing_currency_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(currency="USD")
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_changing_merchants_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(allowed_merchants=["ShadyShop"])
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_changing_nonce_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(nonce="different-nonce")
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_changing_expires_at_invalidates_signature(self):
        original = self._make_intent()
        sig, pub = self._sign_intent(original)
        modified = self._make_intent(
            expires_at=datetime(2099, 12, 31, tzinfo=timezone.utc)
        )
        assert verify_signature(modified.canonical_bytes(), sig, pub) is False

    def test_no_spaces_in_canonical_bytes(self):
        a = self._make_intent(description="Buy_shoes")
        cb = a.canonical_bytes()
        # Verify strict JSON without spaces in separators
        assert b" " not in cb

    def test_datetime_format_is_strict(self):
        a = self._make_intent()
        cb = a.canonical_bytes()
        # Look for the exact strictly formatted datetime string
        # datetime(2026, 1, 1, tzinfo=timezone.utc) -> 2026-01-01T00:00:00.000000Z
        assert b"2026-01-01T00:00:00.000000Z" in cb
