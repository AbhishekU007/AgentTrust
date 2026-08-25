"""AuthorizationEngine — the central deterministic orchestrator.

Refactored Trust Model:
- USER possesses the private key and signs the Intent externally.
- AGENTTRUST (this engine) is a stateless verifier of user intents.
- AGENTTRUST has its own SYSTEM KEY to cryptographically sign the resulting PaymentMandate.
"""

from __future__ import annotations

import binascii
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agenttrust.audit import AuditLog
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.models import (
    AuthorizationResult,
    AuthorizationStatus,
    CartMandate,
    CheckDetail,
    IntentMandate,
    PaymentMandate,
    PolicyConfig,
)
from agenttrust.interfaces import IAuditLog, IReplayRegistry, ITransactionRepository
from agenttrust.audit import AuditLog
from agenttrust.policy import evaluate_policy
from agenttrust.verification import verify_intent_cart_consistency

class InMemoryReplayRegistry(IReplayRegistry):
    """Fallback in-memory replay protection."""
    def __init__(self) -> None:
        self._consumed: set[tuple[str, str]] = set()

    def check_and_consume(self, mandate_type: str, nonce: str) -> bool:
        key = (mandate_type, nonce)
        if key in self._consumed:
            return False
        self._consumed.add(key)
        return True


class InMemoryTransactionRepository(ITransactionRepository):
    """Fallback in-memory transaction history."""
    def __init__(self) -> None:
        self._consumed_intents: set[str] = set()
        self._transaction_timestamps: list[datetime] = []

    def count_recent_transactions(self, window_seconds: int) -> int:
        if not self._transaction_timestamps:
            return 0
        now = datetime.now(timezone.utc)
        cutoff = now.timestamp() - window_seconds
        return sum(1 for ts in self._transaction_timestamps if ts.timestamp() >= cutoff)
    
    def is_intent_consumed(self, intent_id: str) -> bool:
        return intent_id in self._consumed_intents
    
    def mark_intent_consumed(self, intent_id: str) -> None:
        self._consumed_intents.add(intent_id)
        self._transaction_timestamps.append(datetime.now(timezone.utc))


class AuthorizationEngine:
    """
    Deterministic authorization gateway.
    """

    def __init__(
        self, 
        policy: PolicyConfig,
        audit_log: IAuditLog | None = None,
        replay_registry: IReplayRegistry | None = None,
        transaction_repo: ITransactionRepository | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit_log if audit_log is not None else AuditLog()
        self._replay_registry = replay_registry if replay_registry is not None else InMemoryReplayRegistry()
        self._transaction_repo = transaction_repo if transaction_repo is not None else InMemoryTransactionRepository()

        # AgentTrust System Key (Used to sign PaymentMandates to prove authorization)
        self._system_private_key, self._system_public_key = generate_keypair()

    @property
    def system_public_key(self) -> Ed25519PublicKey:
        return self._system_public_key

    def authorize(
        self,
        intent: IntentMandate,
        intent_signature: bytes,
        user_public_key: Ed25519PublicKey,
        cart: CartMandate,
    ) -> AuthorizationResult:
        """
        Authorize a cart against an intent. Receives all data ephemerally.
        """
        all_checks: list[CheckDetail] = []
        now = datetime.now(timezone.utc)

        # -- 1. Cart Replay Check (uses explicit nonce) --
        if not self._replay_registry.check_and_consume("cart", cart.nonce):
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason=f"Cart replay detected: nonce '{cart.nonce}' already consumed",
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=[
                    CheckDetail(
                        check_name="cart_replay",
                        passed=False,
                        reason="Cart nonce already consumed",
                    )
                ],
            )
            self._record_decision(result, actor="system")
            return result

        # -- 2. Intent Replay/Consumption Check --
        if self._transaction_repo.is_intent_consumed(intent.intent_id):
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason=f"Intent '{intent.intent_id}' already consumed",
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=[
                    CheckDetail(
                        check_name="intent_consumed",
                        passed=False,
                        reason="This intent was already used for a successful authorization",
                    )
                ],
            )
            self._record_decision(result, actor="system")
            return result
        
        # Also check the intent nonce directly against replay registry
        if not self._replay_registry.check_and_consume("intent", intent.nonce):
            # This handles if they submit multiple times before consumption, or concurrently
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason=f"Intent replay detected: nonce '{intent.nonce}' already consumed",
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=[
                    CheckDetail(
                        check_name="intent_replay",
                        passed=False,
                        reason="Intent nonce already consumed",
                    )
                ],
            )
            self._record_decision(result, actor="system")
            return result

        # -- 3. Expiration check (BEFORE authorization) --
        if now > intent.expires_at:
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason=f"Intent expired at {intent.expires_at.isoformat()}",
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=[
                    CheckDetail(
                        check_name="expiration",
                        passed=False,
                        reason=f"Intent expired at {intent.expires_at.isoformat()}",
                    )
                ],
            )
            self._record_decision(result, actor="system")
            return result

        all_checks.append(CheckDetail(check_name="expiration", passed=True, reason="Intent valid"))

        # -- 4. Signature verification (Untrusted Input) --
        sig_valid = verify_signature(intent.canonical_bytes(), intent_signature, user_public_key)
        all_checks.append(
            CheckDetail(
                check_name="signature",
                passed=sig_valid,
                reason="Signature verified" if sig_valid else "Signature verification failed",
            )
        )
        if not sig_valid:
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason="Intent mandate signature verification failed",
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=all_checks,
            )
            self._record_decision(result, actor="system")
            return result

        # -- 5. Intent ↔ Cart consistency --
        consistency_passed, consistency_checks = verify_intent_cart_consistency(intent, cart)
        all_checks.extend(consistency_checks)

        if not consistency_passed:
            failed = [c for c in consistency_checks if not c.passed]
            result = AuthorizationResult(
                status=AuthorizationStatus.BLOCK,
                reason="; ".join(c.reason for c in failed),
                intent_id=intent.intent_id,
                cart_id=cart.cart_id,
                checks=all_checks,
            )
            self._record_decision(result, actor="agent")
            return result

        # -- 6. Policy evaluation --
        recent_count = self._transaction_repo.count_recent_transactions(self.policy.velocity_window_seconds)
        policy_result = evaluate_policy(intent, cart, self.policy, recent_count)
        all_checks.extend(policy_result.checks)

        # -- 7. Build final result --
        result = AuthorizationResult(
            status=policy_result.status,
            reason=policy_result.reason,
            intent_id=intent.intent_id,
            cart_id=cart.cart_id,
            checks=all_checks,
        )

        # -- 8. Create & Sign PaymentMandate (ONLY IF ALLOW) --
        if result.status == AuthorizationStatus.ALLOW:
            payment = PaymentMandate(
                intent_id=intent.intent_id,
                intent_hash=intent.compute_hash(),
                cart_id=cart.cart_id,
                cart_hash=cart.compute_hash(),
                amount_minor=cart.total_amount_minor,
                currency=cart.currency,
                merchant=cart.merchant,
            )
            # Sign it with AgentTrust System Key
            system_sig = sign_mandate(payment.canonical_bytes(), self._system_private_key)
            payment.system_signature = binascii.hexlify(system_sig).decode('utf-8')
            
            result.payment_mandate = payment
            
            self._transaction_repo.mark_intent_consumed(intent.intent_id)

        # -- 9. Audit --
        self._record_decision(result, actor="agent")
        return result

    def _record_decision(self, result: AuthorizationResult, actor: str) -> None:
        event_type = {
            AuthorizationStatus.ALLOW: "AUTHORIZATION_ALLOW",
            AuthorizationStatus.BLOCK: "AUTHORIZATION_BLOCK",
            AuthorizationStatus.REQUIRE_APPROVAL: "AUTHORIZATION_REQUIRE_APPROVAL",
        }[result.status]

        self.audit.record(
            event_type=event_type,
            actor=actor,
            intent_id=result.intent_id,
            cart_id=result.cart_id,
            decision=result.status,
            reason=result.reason,
        )

    def update_policy(self, new_policy: PolicyConfig) -> None:
        self.audit.record(
            event_type="POLICY_UPDATED",
            actor="admin",
            reason=f"Policy updated: max={new_policy.max_transaction_amount_minor}",
        )
        self.policy = new_policy
