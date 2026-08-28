"""Secure continuation of an approved authorization into a payment mandate."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy.orm import Session

from agenttrust.crypto import sign_mandate, verify_signature
from agenttrust.db.schema import (
    DBApprovalRequest,
    DBAuthorizationDecision,
    DBCartMandate,
    DBIntentMandate,
    DBPaymentMandate,
)
from agenttrust.models import (
    ApprovalDecision,
    ApprovalStatus,
    CartItem,
    CartMandate,
    IntentMandate,
    PaymentMandate,
    PolicyConfig,
)
from agenttrust.policy import evaluate_policy
from agenttrust.repositories.approval_repo import SQLiteApprovalRepository
from agenttrust.repositories.transaction_repo import SQLiteTransactionRepository
from agenttrust.verification import verify_intent_cart_consistency


class ApprovalContinuationError(ValueError):
    """A fail-closed continuation rejection with an API-safe error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _decode_signature(value: str) -> bytes:
    try:
        decoded = bytes.fromhex(value.strip())
        if len(decoded) == 64:
            return decoded
    except ValueError:
        pass
    try:
        decoded = base64.b64decode(value.strip(), validate=True)
        if len(decoded) == 64:
            return decoded
    except (binascii.Error, ValueError):
        pass
    raise ApprovalContinuationError("invalid_approval_signature", "Unsupported signature format")


def _decode_public_key(value: str) -> Ed25519PublicKey:
    trimmed = value.strip()
    try:
        if "BEGIN PUBLIC KEY" in trimmed:
            key = load_pem_public_key(trimmed.encode("utf-8"))
            if isinstance(key, Ed25519PublicKey):
                return key
        raw = bytes.fromhex(trimmed)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError):
        pass
    try:
        raw = base64.b64decode(trimmed, validate=True)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError, TypeError):
        pass
    raise ApprovalContinuationError(
        "invalid_approval_signature", "Unsupported approver public key format"
    )


def _load_intent(record: DBIntentMandate) -> IntentMandate:
    return IntentMandate(
        intent_id=record.intent_id,
        description=record.description,
        max_amount_minor=record.max_amount_minor,
        currency=record.currency,
        allowed_merchants=record.allowed_merchants,
        allowed_categories=record.allowed_categories,
        nonce=record.nonce,
        created_at=record.created_at,
        expires_at=record.expires_at,
    )


def _load_cart(record: DBCartMandate) -> CartMandate:
    return CartMandate(
        cart_id=record.cart_id,
        intent_id=record.intent_id,
        merchant=record.merchant,
        category=record.category,
        items=[CartItem(**item) for item in record.items],
        total_amount_minor=record.total_amount_minor,
        currency=record.currency,
        nonce=record.nonce,
        created_at=record.created_at,
    )


def _reject(code: str, message: str) -> None:
    raise ApprovalContinuationError(code, message)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class ApprovalContinuationService:
    """Revalidates an approval and atomically creates its payment mandate."""

    def __init__(
        self,
        db: Session,
        policy: PolicyConfig,
        system_private_key: Ed25519PrivateKey,
        system_public_key: Ed25519PublicKey,
    ) -> None:
        self.db = db
        self.policy = policy
        self.system_private_key = system_private_key
        self.system_public_key = system_public_key

    def continue_approval(self, approval_id: str) -> tuple[PaymentMandate, bool, str]:
        approval_record = self.db.get(DBApprovalRequest, approval_id)
        if approval_record is None:
            _reject("approval_not_found", "Approval request not found")

        try:
            approval = SQLiteApprovalRepository._to_domain(approval_record)
        except ValueError as exc:
            _reject("approval_corrupt", "Stored approval data is invalid")
        now = datetime.now(timezone.utc)
        if approval.status is not ApprovalStatus.APPROVED:
            _reject("approval_not_approved", "Approval is not approved")
        if now >= approval.expires_at:
            _reject("approval_expired", "Approval has expired")
        if not approval.decision_signature or not approval.approver_public_key:
            _reject("invalid_approval_signature", "Approval signature evidence is missing")

        decision = self.db.query(DBAuthorizationDecision).filter(
            DBAuthorizationDecision.decision_id == approval.authorization_id
        ).one_or_none()
        if decision is None:
            _reject("authorization_not_found", "Linked authorization decision not found")
        if decision.decision_id != approval.authorization_id:
            _reject("authorization_mismatch", "Authorization identity does not match approval")
        if decision.status != "REQUIRE_APPROVAL":
            _reject("authorization_not_eligible", "Authorization is not approval-gated")
        if decision.intent_id != approval.intent_id or decision.cart_id != approval.cart_id:
            _reject("authorization_mismatch", "Authorization context does not match approval")

        try:
            decision_payload = ApprovalDecision(
                approval_id=approval.approval_id,
                authorization_id=approval.authorization_id,
                intent_id=approval.intent_id,
                cart_id=approval.cart_id,
                decision=ApprovalStatus.APPROVED,
                decided_at=approval.decided_at,
                approver_id=approval.decided_by,
                approver_public_key=approval.approver_public_key,
            )
        except ValueError as exc:
            _reject("approval_corrupt", "Stored approval decision data is invalid")
        if not verify_signature(
            decision_payload.canonical_bytes(),
            _decode_signature(approval.decision_signature),
            _decode_public_key(approval.approver_public_key),
        ):
            _reject("invalid_approval_signature", "Approval signature verification failed")

        intent_record = self.db.get(DBIntentMandate, approval.intent_id)
        cart_record = self.db.get(DBCartMandate, approval.cart_id)
        if intent_record is None or cart_record is None:
            _reject("authorization_context_missing", "Stored intent or cart is missing")
        try:
            intent = _load_intent(intent_record)
            cart = _load_cart(cart_record)
        except ValueError as exc:
            _reject("authorization_context_invalid", "Stored intent or cart is invalid")
        if intent.compute_hash() != decision.intent_hash:
            _reject("intent_tampered", "Stored intent hash does not match authorization evidence")
        if cart.compute_hash() != decision.cart_hash:
            _reject("cart_tampered", "Stored cart hash does not match authorization evidence")
        if intent.intent_id != approval.intent_id or cart.cart_id != approval.cart_id:
            _reject("authorization_mismatch", "Intent or cart identity does not match approval")
        if datetime.now(timezone.utc) >= _utc(intent.expires_at):
            _reject("intent_expired", "Intent has expired")
        if not decision.intent_signature or not decision.user_public_key:
            _reject("authorization_evidence_missing", "Original authorization evidence is missing")
        if not verify_signature(
            intent.canonical_bytes(),
            _decode_signature(decision.intent_signature),
            _decode_public_key(decision.user_public_key),
        ):
            _reject("invalid_user_signature", "Original user signature verification failed")

        consistent, _ = verify_intent_cart_consistency(intent, cart)
        if not consistent:
            _reject("authorization_context_invalid", "Intent and cart consistency check failed")
        policy_result = evaluate_policy(
            intent,
            cart,
            self.policy,
            SQLiteTransactionRepository(self.db).count_recent_transactions(
                self.policy.velocity_window_seconds
            ),
        )
        if policy_result.status.value != "REQUIRE_APPROVAL":
            _reject(
                "authorization_blocked",
                "Current policy does not permit approval continuation",
            )

        if approval_record.continuation_payment_id is not None:
            payment_record = self.db.get(
                DBPaymentMandate, approval_record.continuation_payment_id
            )
            if payment_record is None:
                _reject("continuation_corrupt", "Continuation payment record is missing")
            self._validate_existing_payment(
                payment_record, approval, decision, intent, cart
            )
            return (
                self._payment_from_db(payment_record),
                True,
                approval.authorization_id,
            )

        payment = PaymentMandate(
            intent_id=intent.intent_id,
            intent_hash=intent.compute_hash(),
            cart_id=cart.cart_id,
            cart_hash=cart.compute_hash(),
            amount_minor=cart.total_amount_minor,
            currency=cart.currency,
            merchant=cart.merchant,
        )
        payment.system_signature = sign_mandate(
            payment.canonical_bytes(), self.system_private_key
        ).hex()
        reserved = SQLiteApprovalRepository(self.db).reserve_continuation(
            approval_id, payment.payment_id, now
        )
        if not reserved:
            existing = self.db.get(DBApprovalRequest, approval_id)
            if existing and existing.continuation_payment_id:
                payment_record = self.db.get(
                    DBPaymentMandate, existing.continuation_payment_id
                )
                if payment_record is not None:
                    self._validate_existing_payment(
                        payment_record, approval, decision, intent, cart
                    )
                    return self._payment_from_db(payment_record), True, approval.authorization_id
            _reject("continuation_race", "Approval continuation was claimed concurrently")

        self.db.add(
            DBPaymentMandate(
                payment_id=payment.payment_id,
                intent_id=payment.intent_id,
                intent_hash=payment.intent_hash,
                cart_id=payment.cart_id,
                cart_hash=payment.cart_hash,
                amount_minor=payment.amount_minor,
                currency=payment.currency,
                merchant=payment.merchant,
                status=payment.status.value,
                created_at=payment.created_at,
                system_signature=payment.system_signature,
                payment_execution_status="NOT_EXECUTED",
                approval_id=approval_id,
                authorization_id=approval.authorization_id,
            )
        )
        self.db.commit()
        return payment, False, approval.authorization_id

    @staticmethod
    def _payment_from_db(record: DBPaymentMandate) -> PaymentMandate:
        return PaymentMandate(
            payment_id=record.payment_id,
            intent_id=record.intent_id,
            intent_hash=record.intent_hash,
            cart_id=record.cart_id,
            cart_hash=record.cart_hash,
            amount_minor=record.amount_minor,
            currency=record.currency,
            merchant=record.merchant,
            status=record.status,
            created_at=_utc(record.created_at),
            system_signature=record.system_signature,
        )

    def _validate_existing_payment(
        self,
        record: DBPaymentMandate,
        approval,
        decision: DBAuthorizationDecision,
        intent: IntentMandate,
        cart: CartMandate,
    ) -> None:
        if record.approval_id != approval.approval_id:
            _reject("continuation_corrupt", "Payment mandate approval linkage is invalid")
        if record.authorization_id != decision.decision_id:
            _reject("continuation_corrupt", "Payment mandate authorization linkage is invalid")
        if record.intent_id != intent.intent_id or record.cart_id != cart.cart_id:
            _reject("continuation_corrupt", "Payment mandate context is invalid")
        if record.intent_hash != decision.intent_hash or record.cart_hash != decision.cart_hash:
            _reject("continuation_corrupt", "Payment mandate hashes are invalid")
        if (
            record.amount_minor != cart.total_amount_minor
            or record.currency != cart.currency
            or record.merchant != cart.merchant
            or record.status != "ALLOW"
        ):
            _reject("continuation_corrupt", "Payment mandate authorization data is invalid")
        try:
            payment = self._payment_from_db(record)
            signature = _decode_signature(record.system_signature)
        except (ApprovalContinuationError, ValueError, TypeError):
            _reject("continuation_corrupt", "Payment mandate signature evidence is invalid")
        if not verify_signature(
            payment.canonical_bytes(), signature, self.system_public_key
        ):
            _reject("continuation_corrupt", "Payment mandate signature verification failed")
