"""FastAPI entrypoint for AgentTrust Milestone 2.

This module wraps the deterministic core engine with API, persistence, and
payment execution adapters while preserving fail-closed semantics.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import os
import uuid
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import Body, Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agenttrust.crypto import generate_keypair, verify_signature
from agenttrust.db.database import build_session_factory, init_db
from agenttrust.db.schema import (
    DBAuthorizationDecision,
    DBApprovalRequest,
    DBCartMandate,
    DBIntentMandate,
    DBPaymentMandate,
    DBSystemKey,
)
from agenttrust.db.unit_of_work import DatabaseUnitOfWork
from agenttrust.engine import AuthorizationEngine
from agenttrust.models import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalTransitionError,
    AuthorizationResult,
    AuthorizationStatus,
    CartMandate,
    IntentMandate,
    PaymentMandate,
    PolicyConfig,
)
from agenttrust.payments.razorpay_adapter import PaymentExecutionResult, RazorpayAdapter
from agenttrust.repositories.audit_repo import SQLiteAuditLog
from agenttrust.repositories.approval_repo import SQLiteApprovalRepository
from agenttrust.repositories.replay_repo import SQLiteReplayRegistry
from agenttrust.repositories.transaction_repo import SQLiteTransactionRepository
from agenttrust.services.approval_continuation import (
    ApprovalContinuationError,
    ApprovalContinuationService,
)
from agenttrust.services.auth import Principal, authenticate, configured_principals
from agenttrust.services.system_identity import SystemIdentity, load_system_identity


def _legacy_test_principal(principal: Principal | None) -> bool:
    return False


class AuthorizeRequest(BaseModel):
    intent: IntentMandate
    intent_signature: str = Field(
        ..., description="Ed25519 signature in hex or base64"
    )
    user_public_key: str = Field(
        ..., description="User Ed25519 public key in PEM, hex, or base64 raw bytes"
    )
    cart: CartMandate


class ErrorResponse(BaseModel):
    code: str
    message: str


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decided_by: str = Field(..., min_length=1)
    decided_at: datetime
    approver_public_key: str = Field(..., min_length=1)
    signature: str = Field(..., min_length=1)


class EmptyContinuationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExecutePaymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass
class ParsedCryptoMaterial:
    signature: bytes
    public_key: Ed25519PublicKey


class PaymentExecutionResponse(BaseModel):
    success: bool
    order_id: str | None
    error_code: str | None = None
    message: str = ""
    is_mocked: bool = False


class ExecutePaymentResponse(BaseModel):
    payment_id: str
    payment_execution_status: str
    razorpay_order_id: str | None
    result: PaymentExecutionResponse


_PROCESS_SYSTEM_PRIVATE_KEY = None
_PROCESS_SYSTEM_PUBLIC_KEY = None
_PROCESS_SYSTEM_KEY_MATERIAL = None


def _system_keypair():
    global _PROCESS_SYSTEM_PRIVATE_KEY, _PROCESS_SYSTEM_PUBLIC_KEY
    global _PROCESS_SYSTEM_KEY_MATERIAL
    configured = os.getenv("AGENTTRUST_SYSTEM_PRIVATE_KEY")
    if configured:
        if _PROCESS_SYSTEM_KEY_MATERIAL != configured:
            try:
                raw = bytes.fromhex(configured)
                if len(raw) != 32:
                    raise ValueError("system key must contain 32 bytes")
                _PROCESS_SYSTEM_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(raw)
                _PROCESS_SYSTEM_PUBLIC_KEY = _PROCESS_SYSTEM_PRIVATE_KEY.public_key()
            except (ValueError, TypeError) as exc:
                raise RuntimeError("AGENTTRUST_SYSTEM_PRIVATE_KEY is invalid") from exc
            _PROCESS_SYSTEM_KEY_MATERIAL = configured
    elif _PROCESS_SYSTEM_PRIVATE_KEY is None or _PROCESS_SYSTEM_PUBLIC_KEY is None:
        _PROCESS_SYSTEM_PRIVATE_KEY, _PROCESS_SYSTEM_PUBLIC_KEY = generate_keypair()
        _PROCESS_SYSTEM_KEY_MATERIAL = None
    return _PROCESS_SYSTEM_PRIVATE_KEY, _PROCESS_SYSTEM_PUBLIC_KEY


def _load_user_public_key(value: str) -> Ed25519PublicKey:
    trimmed = value.strip()
    if "BEGIN PUBLIC KEY" in trimmed:
        loaded = load_pem_public_key(trimmed.encode("utf-8"))
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("Only Ed25519 public keys are supported")
        return loaded

    # Raw Ed25519 public key bytes are 32 bytes.
    try:
        raw = bytes.fromhex(trimmed)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError:
        pass

    try:
        raw = base64.b64decode(trimmed, validate=True)
        if len(raw) == 32:
            return Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError):
        pass

    raise ValueError("Unsupported public key format")


def _load_signature(value: str) -> bytes:
    trimmed = value.strip()
    try:
        sig = bytes.fromhex(trimmed)
        if len(sig) == 64:
            return sig
    except ValueError:
        pass

    try:
        sig = base64.b64decode(trimmed, validate=True)
        if len(sig) == 64:
            return sig
    except (binascii.Error, ValueError):
        pass

    raise ValueError("Unsupported signature format")


def _parse_crypto_material(payload: AuthorizeRequest) -> ParsedCryptoMaterial:
    try:
        signature = _load_signature(payload.intent_signature)
        user_public_key = _load_user_public_key(payload.user_public_key)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ErrorResponse(
                code="invalid_crypto_material",
                message=str(exc),
            ).model_dump(),
        ) from exc

    return ParsedCryptoMaterial(signature=signature, public_key=user_public_key)


def _default_policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        velocity_limit=10,
        velocity_window_seconds=3600,
        require_approval_above_minor=450000,
    )


def _persist_intent(db: Session, intent: IntentMandate) -> None:
    existing = db.get(DBIntentMandate, intent.intent_id)
    if existing is not None:
        return

    try:
        with db.begin_nested():
            db.add(
                DBIntentMandate(
                    intent_id=intent.intent_id,
                    description=intent.description,
                    max_amount_minor=intent.max_amount_minor,
                    currency=intent.currency,
                    allowed_merchants=intent.allowed_merchants,
                    allowed_categories=intent.allowed_categories,
                    nonce=intent.nonce,
                    created_at=intent.created_at,
                    expires_at=intent.expires_at,
                    canonical_bytes_hex=intent.canonical_bytes().hex(),
                )
            )
            db.flush()
    except IntegrityError:
        db.rollback()
        if db.get(DBIntentMandate, intent.intent_id) is None:
            raise


def _persist_cart(db: Session, cart: CartMandate) -> None:
    existing = db.get(DBCartMandate, cart.cart_id)
    if existing is not None:
        return

    try:
        with db.begin_nested():
            db.add(
                DBCartMandate(
                    cart_id=cart.cart_id,
                    intent_id=cart.intent_id,
                    merchant=cart.merchant,
                    category=cart.category,
                    items=[item.model_dump(mode="json") for item in cart.items],
                    total_amount_minor=cart.total_amount_minor,
                    currency=cart.currency,
                    nonce=cart.nonce,
                    created_at=cart.created_at,
                )
            )
            db.flush()
    except IntegrityError:
        db.rollback()
        if db.get(DBCartMandate, cart.cart_id) is None:
            raise


def _persist_payment_mandate(
    db: Session,
    payment: PaymentMandate,
    *,
    principal: Principal | None = None,
    system_key_id: str | None = None,
) -> DBPaymentMandate:
    existing = db.get(DBPaymentMandate, payment.payment_id)
    if existing is not None:
        return existing

    record = DBPaymentMandate(
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
        system_signature=payment.system_signature or "",
        payment_execution_status="NOT_EXECUTED",
        system_key_id=system_key_id,
        principal_id=principal.principal_id if principal else None,
        account_id=principal.account_id if principal else None,
    )
    db.add(record)
    db.flush()
    return record


def _persist_decision(
    db: Session,
    result: AuthorizationResult,
    payment_id: str | None,
    *,
    intent_signature: str | None = None,
    user_public_key: str | None = None,
    intent_hash: str | None = None,
    cart_hash: str | None = None,
    decision_id: str | None = None,
    principal: Principal | None = None,
) -> str:
    resolved_decision_id = decision_id or uuid.uuid4().hex
    db.add(
        DBAuthorizationDecision(
            decision_id=resolved_decision_id,
            intent_id=result.intent_id,
            cart_id=result.cart_id,
            status=result.status.value,
            reason=result.reason,
            checks=[check.model_dump(mode="json") for check in result.checks],
            payment_id=payment_id,
            intent_signature=intent_signature,
            user_public_key=user_public_key,
            intent_hash=intent_hash,
            cart_hash=cart_hash,
            principal_id=principal.principal_id if principal else None,
            account_id=principal.account_id if principal else None,
        )
    )
    return resolved_decision_id


def _approval_for_authorization(
    db: Session,
    *,
    authorization_id: str,
    result: AuthorizationResult,
    expires_at: datetime,
    principal: Principal | None = None,
) -> ApprovalRequest:
    existing = SQLiteApprovalRepository(db).get_by_authorization_id(authorization_id)
    if existing is not None:
        return existing

    requested_at = datetime.now(timezone.utc)
    approval = ApprovalRequest(
        approval_id=uuid.uuid4().hex,
        authorization_id=authorization_id,
        intent_id=result.intent_id,
        cart_id=result.cart_id or "",
        reason=result.reason,
        requested_at=requested_at,
        expires_at=expires_at,
    )
    SQLiteApprovalRepository(db).create(approval)
    if principal:
        db.flush()
        record = db.get(DBApprovalRequest, approval.approval_id)
        record.principal_id = principal.principal_id
        record.account_id = principal.account_id
    return approval


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
        status=AuthorizationStatus(record.status),
        created_at=record.created_at,
        system_signature=record.system_signature,
    )


def _record_payment_execution(
    db_payment: DBPaymentMandate,
    execution: PaymentExecutionResult,
) -> None:
    if execution.success:
        db_payment.razorpay_order_id = execution.order_id
        db_payment.payment_execution_status = "SUCCEEDED"
        db_payment.payment_execution_error = None
        db_payment.payment_execution_error_code = None
        db_payment.payment_executed_at = datetime.now(timezone.utc)
    else:
        db_payment.payment_execution_status = "FAILED"
        db_payment.payment_execution_error = execution.message
        db_payment.payment_execution_error_code = execution.error_code


def _execute_payment_with_adapter(
    db: Session,
    payment_mandate: PaymentMandate,
    db_payment: DBPaymentMandate,
) -> PaymentExecutionResult:
    adapter = RazorpayAdapter(db)
    execution = adapter.execute_payment(payment_mandate)
    _record_payment_execution(db_payment, execution)
    return execution


def _claim_payment_execution(db: Session, db_payment: DBPaymentMandate) -> tuple[str | None, bool]:
    """Claim a mandate once, returning an existing order without provider access."""
    if db_payment.payment_execution_status == "SUCCEEDED":
        return db_payment.razorpay_order_id, False
    if db_payment.payment_execution_status == "EXECUTING":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_execution_in_progress",
                message="Payment mandate execution is already in progress",
            ).model_dump(),
        )

    execution_id = uuid.uuid4().hex
    statement = (
        update(DBPaymentMandate)
        .where(
            DBPaymentMandate.payment_id == db_payment.payment_id,
            DBPaymentMandate.payment_execution_status.in_(
                ("NOT_EXECUTED", "READY", "FAILED")
            ),
        )
        .values(
            payment_execution_status="EXECUTING",
            payment_execution_id=execution_id,
            payment_execution_started_at=datetime.now(timezone.utc),
            payment_execution_error=None,
            payment_execution_error_code=None,
        )
    )
    result = db.execute(statement)
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_execution_in_progress",
                message="Payment mandate execution was claimed concurrently",
            ).model_dump(),
        )
    db.commit()
    db.refresh(db_payment)
    return execution_id, True


def _validate_payment_for_execution(
    db: Session,
    record: DBPaymentMandate,
    policy: PolicyConfig,
    system_public_key,
    verification_keys: dict[str, Any] | None = None,
) -> PaymentMandate:
    """Reconstruct and validate all persisted payment security context."""
    if record.status != AuthorizationStatus.ALLOW.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_mandate_not_executable",
                message="Only an authorized payment mandate can execute",
            ).model_dump(),
        )
    decision_query = db.query(DBAuthorizationDecision)
    if record.authorization_id:
        decision = decision_query.filter(
            DBAuthorizationDecision.decision_id == record.authorization_id
        ).one_or_none()
    else:
        decision = decision_query.filter(
            DBAuthorizationDecision.payment_id == record.payment_id
        ).one_or_none()
    if decision is None or (
        record.approval_id is None
        and decision.payment_id not in {None, record.payment_id}
    ) or (
        record.approval_id is None
        and decision.status != AuthorizationStatus.ALLOW.value
    ) or (
        record.approval_id is not None
        and decision.status != AuthorizationStatus.REQUIRE_APPROVAL.value
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_mandate_invalid",
                message="Payment mandate authorization linkage is invalid",
            ).model_dump(),
        )
    intent_record = db.get(DBIntentMandate, record.intent_id)
    cart_record = db.get(DBCartMandate, record.cart_id)
    if intent_record is None or cart_record is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_mandate_invalid",
                message="Payment mandate context is missing",
            ).model_dump(),
        )
    intent = IntentMandate(
        intent_id=intent_record.intent_id,
        description=intent_record.description,
        max_amount_minor=intent_record.max_amount_minor,
        currency=intent_record.currency,
        allowed_merchants=intent_record.allowed_merchants,
        allowed_categories=intent_record.allowed_categories,
        nonce=intent_record.nonce,
        created_at=intent_record.created_at,
        expires_at=intent_record.expires_at,
    )
    cart = CartMandate(
        cart_id=cart_record.cart_id,
        intent_id=cart_record.intent_id,
        merchant=cart_record.merchant,
        category=cart_record.category,
        items=cart_record.items,
        total_amount_minor=cart_record.total_amount_minor,
        currency=cart_record.currency,
        nonce=cart_record.nonce,
        created_at=cart_record.created_at,
    )
    if (
        intent.compute_hash() != record.intent_hash
        or cart.compute_hash() != record.cart_hash
        or decision.intent_hash != record.intent_hash
        or decision.cart_hash != record.cart_hash
        or intent.intent_id != record.intent_id
        or cart.cart_id != record.cart_id
        or record.amount_minor != cart.total_amount_minor
        or record.currency != cart.currency
        or record.merchant != cart.merchant
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_mandate_invalid",
                message="Payment mandate context or hashes are invalid",
            ).model_dump(),
        )
    payment = _payment_from_db(record)
    verification_key = system_public_key
    if record.system_key_id:
        verification_key = (verification_keys or {}).get(record.system_key_id)
        if verification_key is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse(
                    code="payment_mandate_invalid",
                    message="Payment mandate signing key is unavailable",
                ).model_dump(),
            )
    try:
        valid_signature = verify_signature(
            payment.canonical_bytes(),
            bytes.fromhex(record.system_signature),
            verification_key,
        )
    except (ValueError, TypeError):
        valid_signature = False
    if not valid_signature:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_mandate_invalid",
                message="Payment mandate system signature is invalid",
            ).model_dump(),
        )
    from agenttrust.policy import evaluate_policy
    evaluated = evaluate_policy(
        intent,
        cart,
        policy,
        SQLiteTransactionRepository(db).count_recent_transactions(
            policy.velocity_window_seconds
        ),
    )
    if evaluated.status is AuthorizationStatus.BLOCK:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ErrorResponse(
                code="payment_execution_rejected",
                message="Current policy does not permit payment execution",
            ).model_dump(),
        )
    if record.approval_id is not None:
        approval = db.get(DBApprovalRequest, record.approval_id)
        if (
            approval is None
            or approval.status != ApprovalStatus.APPROVED.value
            or approval.authorization_id != record.authorization_id
            or approval.intent_id != record.intent_id
            or approval.cart_id != record.cart_id
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse(
                    code="payment_execution_rejected",
                    message="Approved payment mandate linkage is invalid",
                ).model_dump(),
            )
        if approval.expires_at <= datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse(
                    code="payment_execution_rejected",
                    message="Approval has expired",
                ).model_dump(),
            )
        try:
            approval_payload = ApprovalDecision(
                approval_id=approval.approval_id,
                authorization_id=approval.authorization_id,
                intent_id=approval.intent_id,
                cart_id=approval.cart_id,
                decision=ApprovalStatus.APPROVED,
                decided_at=approval.decided_at,
                approver_id=approval.decided_by,
                approver_public_key=approval.approver_public_key,
            )
            approval_valid = verify_signature(
                approval_payload.canonical_bytes(),
                _load_signature(approval.decision_signature or ""),
                _load_user_public_key(approval.approver_public_key or ""),
            )
        except (ValueError, TypeError, HTTPException):
            approval_valid = False
        if not approval_valid:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=ErrorResponse(
                    code="payment_execution_rejected",
                    message="Approval signature is invalid",
                ).model_dump(),
            )
    return payment


def create_app(database_url: str | None = None, policy: PolicyConfig | None = None) -> FastAPI:
    app = FastAPI(title="AgentTrust API", version="0.2.0")
    resolved_policy = policy or _default_policy()
    session_factory, local_engine = build_session_factory(database_url)
    identity: SystemIdentity = load_system_identity()
    system_private_key = identity.private_key
    system_public_key = identity.public_key

    app.state.policy = resolved_policy
    app.state.session_factory = session_factory
    app.state.db_engine = local_engine
    app.state.system_private_key = system_private_key
    app.state.system_public_key = system_public_key
    app.state.system_key_id = identity.key_id
    app.state.system_verification_keys = identity.verification_keys
    app.state.principals = configured_principals()

    init_db(local_engine)
    with local_engine.begin() as connection:
        connection.execute(
            text(
                "INSERT OR IGNORE INTO system_keys "
                "(key_id, public_key, state, created_at) VALUES "
                "(:key_id, :public_key, 'ACTIVE', :created_at)"
            ),
            {
                "key_id": identity.key_id,
                "public_key": identity.public_key.public_bytes_raw().hex(),
                "created_at": datetime.now(timezone.utc),
            },
        )
        connection.execute(
            text(
                "UPDATE system_keys SET public_key=:public_key, state='ACTIVE' "
                "WHERE key_id=:key_id"
            ),
            {
                "key_id": identity.key_id,
                "public_key": identity.public_key.public_bytes_raw().hex(),
            },
        )
        for key_id, public_key in identity.verification_keys.items():
            connection.execute(
                text(
                    "INSERT OR IGNORE INTO system_keys "
                    "(key_id, public_key, state, created_at) VALUES "
                    "(:key_id, :public_key, 'RETIRED', :created_at)"
                ),
                {
                    "key_id": key_id,
                    "public_key": public_key.public_bytes_raw().hex(),
                    "created_at": datetime.now(timezone.utc),
                },
            )

    def _build_engine(db: Session) -> AuthorizationEngine:
        return AuthorizationEngine(
            policy=app.state.policy,
            audit_log=SQLiteAuditLog(db),
            replay_registry=SQLiteReplayRegistry(db),
            transaction_repo=SQLiteTransactionRepository(db),
            system_private_key=app.state.system_private_key,
            system_public_key=app.state.system_public_key,
        )

    def _open_db() -> Session:
        return app.state.session_factory()

    def _principal(
        authorization: str | None = Header(default=None),
    ) -> Principal | None:
        return authenticate(app.state.principals, authorization)

    def _audit_context(principal: Principal | None) -> dict[str, str]:
        return (
            {
                "principal_id": principal.principal_id,
                "account_id": principal.account_id,
            }
            if principal
            else {}
        )

    def _audit_actor(principal: Principal | None) -> str:
        return principal.principal_id if principal else "system"

    @app.get("/health")
    def health() -> dict[str, Any]:
        db = _open_db()
        try:
            db.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=ErrorResponse(
                    code="database_unavailable",
                    message="Database connectivity check failed",
                ).model_dump(),
            ) from exc
        finally:
            db.close()

        return {
            "status": "ok",
            "service": "agenttrust",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def _load_approval(
        db: Session, approval_id: str, principal: Principal | None = None
    ) -> ApprovalRequest:
        record = db.get(DBApprovalRequest, approval_id)
        if record is not None and principal and not _legacy_test_principal(principal) and (
            record.principal_id != principal.principal_id
            or record.account_id != principal.account_id
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse(
                    code="approval_not_found", message="Approval request not found"
                ).model_dump(),
            )
        approval = SQLiteApprovalRepository(db).get(approval_id)
        if approval is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=ErrorResponse(
                    code="approval_not_found",
                    message="Approval request not found",
                ).model_dump(),
            )
        return approval

    def _decide_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        decision: ApprovalStatus,
        principal: Principal | None = None,
    ) -> ApprovalRequest:
        db = _open_db()
        try:
            approval = _load_approval(db, approval_id, principal)
            if (
                principal
                and not _legacy_test_principal(principal)
                and payload.decided_by != principal.principal_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=ErrorResponse(
                        code="approver_identity_mismatch",
                        message="decided_by must match the authenticated principal",
                    ).model_dump(),
                )
            now = payload.decided_at
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            else:
                now = now.astimezone(timezone.utc)
            expected_decision = (
                ApprovalStatus.APPROVED
                if decision is ApprovalStatus.APPROVED
                else ApprovalStatus.REJECTED
            )
            decision_payload = ApprovalDecision(
                approval_id=approval.approval_id,
                authorization_id=approval.authorization_id,
                intent_id=approval.intent_id,
                cart_id=approval.cart_id,
                decision=expected_decision,
                decided_at=now,
                approver_id=payload.decided_by,
                approver_public_key=payload.approver_public_key,
            )
            try:
                signature = _load_signature(payload.signature)
                public_key = _load_user_public_key(payload.approver_public_key)
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorResponse(
                        code="invalid_approval_signature",
                        message=str(exc),
                    ).model_dump(),
                ) from exc
            if not verify_signature(decision_payload.canonical_bytes(), signature, public_key):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ErrorResponse(
                        code="invalid_approval_signature",
                        message="Approval signature verification failed",
                    ).model_dump(),
                )
            try:
                if decision is ApprovalStatus.APPROVED:
                    approval.approve(now, payload.decided_by)
                    event_type = "APPROVAL_APPROVED"
                else:
                    approval.reject(now, payload.decided_by)
                    event_type = "APPROVAL_REJECTED"
            except ApprovalTransitionError as exc:
                if approval.status is ApprovalStatus.EXPIRED and approval.decided_by == "system":
                    try:
                        SQLiteApprovalRepository(db).save_transition(
                            approval, ApprovalStatus.PENDING
                        )
                    except ApprovalTransitionError:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=ErrorResponse(
                                code="approval_transition_not_allowed",
                                message="Approval was already decided by another request",
                            ).model_dump(),
                        ) from exc
                    SQLiteAuditLog(db).record(
                        event_type="APPROVAL_EXPIRED",
                        actor=_audit_actor(principal),
                        intent_id=approval.intent_id,
                        cart_id=approval.cart_id,
                        reason="Approval expired before a decision was made",
                        data={
                            "approval_id": approval.approval_id,
                            **_audit_context(principal),
                        },
                    )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=ErrorResponse(
                        code="approval_transition_not_allowed",
                        message=str(exc),
                    ).model_dump(),
                ) from exc
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=ErrorResponse(
                        code="invalid_approval_decision",
                        message=str(exc),
                    ).model_dump(),
                ) from exc

            try:
                approval.approver_public_key = payload.approver_public_key
                approval.decision_signature = payload.signature
                SQLiteApprovalRepository(db).save_transition(
                    approval, ApprovalStatus.PENDING
                )
            except ApprovalTransitionError as exc:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=ErrorResponse(
                        code="approval_transition_not_allowed",
                        message=str(exc),
                    ).model_dump(),
                ) from exc
            SQLiteAuditLog(db).record(
                event_type=event_type,
                actor=payload.decided_by,
                intent_id=approval.intent_id,
                cart_id=approval.cart_id,
                reason=approval.reason,
                data={
                    "approval_id": approval.approval_id,
                    "approver_id": approval.decided_by,
                    "approver_public_key": approval.approver_public_key,
                    "decision_signature": approval.decision_signature,
                    **_audit_context(principal),
                },
            )
            return approval
        finally:
            db.close()

    @app.get("/approvals/{approval_id}", response_model=ApprovalRequest)
    def get_approval(
        approval_id: str, principal: Principal | None = Depends(_principal)
    ) -> ApprovalRequest:
        db = _open_db()
        try:
            return _load_approval(db, approval_id, principal)
        finally:
            db.close()

    @app.post("/approvals/{approval_id}/approve", response_model=ApprovalRequest)
    def approve_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        principal: Principal | None = Depends(_principal),
    ) -> ApprovalRequest:
        return _decide_approval(approval_id, payload, ApprovalStatus.APPROVED, principal)

    @app.post("/approvals/{approval_id}/reject", response_model=ApprovalRequest)
    def reject_approval(
        approval_id: str,
        payload: ApprovalDecisionRequest,
        principal: Principal | None = Depends(_principal),
    ) -> ApprovalRequest:
        return _decide_approval(approval_id, payload, ApprovalStatus.REJECTED, principal)

    @app.post("/approvals/{approval_id}/continue")
    def continue_approval(
        approval_id: str,
        payload: EmptyContinuationRequest | None = Body(default=None),
        principal: Principal | None = Depends(_principal),
    ) -> dict[str, Any]:
        if not approval_id.strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=ErrorResponse(
                    code="invalid_approval_id",
                    message="Approval ID must not be blank",
                ).model_dump(),
            )
        db = _open_db()
        try:
            _load_approval(db, approval_id, principal)
            service = ApprovalContinuationService(
                db=db,
                policy=app.state.policy,
                system_private_key=app.state.system_private_key,
                system_public_key=app.state.system_public_key,
                system_key_id=app.state.system_key_id,
                principal=principal,
                verification_keys=app.state.system_verification_keys,
            )
            try:
                payment, already_completed, authorization_id = (
                    service.continue_approval(approval_id)
                )
            except ApprovalContinuationError as exc:
                event_type = (
                    "APPROVAL_CONTINUATION_ALREADY_COMPLETED"
                    if exc.code == "continuation_already_completed"
                    else "APPROVAL_CONTINUATION_REJECTED"
                )
                SQLiteAuditLog(db).record(
                    event_type=event_type,
                    actor=_audit_actor(principal),
                    reason=str(exc),
                    data={
                        "approval_id": approval_id,
                        "error_code": exc.code,
                        **_audit_context(principal),
                    },
                )
                raise HTTPException(
                    status_code=(
                        status.HTTP_404_NOT_FOUND
                        if exc.code == "approval_not_found"
                        else status.HTTP_409_CONFLICT
                    ),
                    detail=ErrorResponse(
                        code=exc.code,
                        message=str(exc),
                    ).model_dump(),
                ) from exc

            audit = SQLiteAuditLog(db)
            if already_completed:
                audit.record(
                    event_type="APPROVAL_CONTINUATION_ALREADY_COMPLETED",
                    actor=_audit_actor(principal),
                    intent_id=payment.intent_id,
                    cart_id=payment.cart_id,
                    reason="Returning the existing continuation payment mandate",
                    data={
                        "approval_id": approval_id,
                        "authorization_id": authorization_id,
                        "payment_id": payment.payment_id,
                        **_audit_context(principal),
                    },
                )
            return {
                "approval_id": approval_id,
                "authorization_id": authorization_id,
                "payment_mandate": payment.model_dump(mode="json"),
                "already_completed": already_completed,
            }
        finally:
            db.close()

    @app.post("/authorize")
    def authorize(
        payload: AuthorizeRequest,
        execute: bool = True,
        principal: Principal | None = Depends(_principal),
    ) -> dict[str, Any]:
        """
        Authorization endpoint.

        Query parameter `execute` controls whether an ALLOW result will immediately
        execute the PaymentMandate via the Razorpay adapter. Default: True (legacy behavior).
        When execute=False, the PaymentMandate is persisted but not executed; callers may
        later call POST /payments/{payment_id}/execute to perform the external payment.
        """
        parsed = _parse_crypto_material(payload)
        db = _open_db()
        try:
            db.info["coordinated_transaction"] = True
            _persist_intent(db, payload.intent)
            _persist_cart(db, payload.cart)

            engine = _build_engine(db)
            result = engine.authorize(
                intent=payload.intent,
                intent_signature=parsed.signature,
                user_public_key=parsed.public_key,
                cart=payload.cart,
            )

            payment_execution: PaymentExecutionResult | None = None
            db_payment: DBPaymentMandate | None = None
            decision_id: str | None = None

            # If the engine returned a PaymentMandate (ALLOW), always persist it.
            if result.payment_mandate is not None:
                db_payment = _persist_payment_mandate(
                    db,
                    result.payment_mandate,
                    principal=principal,
                    system_key_id=app.state.system_key_id,
                )

                # Only execute the external payment if caller requested execution.
                if execute:
                    payment_execution = _execute_payment_with_adapter(
                        db,
                        result.payment_mandate,
                        db_payment,
                    )

                    event_type = "PAYMENT_EXECUTION_SUCCESS" if payment_execution.success else "PAYMENT_EXECUTION_FAILED"
                    engine.audit.record(
                        event_type=event_type,
                        actor=_audit_actor(principal),
                        intent_id=result.intent_id,
                        cart_id=result.cart_id,
                        decision=result.status,
                        reason=payment_execution.message,
                        data={
                            "payment_id": result.payment_mandate.payment_id,
                            "order_id": payment_execution.order_id,
                            "is_mocked": payment_execution.is_mocked,
                            "error_code": payment_execution.error_code,
                            **_audit_context(principal),
                        },
                    )

            decision_id = _persist_decision(
                db,
                result,
                payment_id=result.payment_mandate.payment_id if result.payment_mandate else None,
                intent_signature=payload.intent_signature,
                user_public_key=payload.user_public_key,
                intent_hash=payload.intent.compute_hash(),
                cart_hash=payload.cart.compute_hash(),
                principal=principal,
            )
            engine.audit.record(
                event_type="AUTHORIZATION_PERSISTED",
                actor=_audit_actor(principal),
                intent_id=result.intent_id,
                cart_id=result.cart_id,
                decision=result.status,
                reason=result.reason,
                data={
                    "authorization_id": decision_id,
                    "payment_id": (
                        result.payment_mandate.payment_id
                        if result.payment_mandate
                        else None
                    ),
                    "system_key_id": (
                        app.state.system_key_id
                        if result.payment_mandate is not None
                        else None
                    ),
                    **_audit_context(principal),
                },
            )
            if db_payment is not None:
                db_payment.authorization_id = decision_id
            response = result.model_dump(mode="json")
            if result.status is AuthorizationStatus.REQUIRE_APPROVAL:
                approval = _approval_for_authorization(
                    db,
                    authorization_id=decision_id,
                    result=result,
                    expires_at=payload.intent.expires_at,
                    principal=principal,
                )
                engine.audit.record(
                    event_type="APPROVAL_REQUESTED",
                    actor="system",
                    intent_id=approval.intent_id,
                    cart_id=approval.cart_id,
                    decision=AuthorizationStatus.REQUIRE_APPROVAL,
                    reason=approval.reason,
                    data={
                        "approval_id": approval.approval_id,
                        "authorization_id": approval.authorization_id,
                        **_audit_context(principal),
                    },
                )
                response["approval"] = approval.model_dump(mode="json")
            if payment_execution is not None:
                response["payment_execution"] = PaymentExecutionResponse(
                    success=payment_execution.success,
                    order_id=payment_execution.order_id,
                    error_code=payment_execution.error_code,
                    message=payment_execution.message,
                    is_mocked=payment_execution.is_mocked,
                ).model_dump()
            with DatabaseUnitOfWork(db):
                pass
            return response
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _execute_payment_request(
        payment_id: str, principal: Principal | None = None
    ) -> ExecutePaymentResponse:
        db = _open_db()
        try:
            db_payment = db.get(DBPaymentMandate, payment_id)
            if db_payment is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=ErrorResponse(
                        code="payment_not_found",
                        message="Payment mandate not found",
                    ).model_dump(),
                )
            if principal and not _legacy_test_principal(principal):
                has_owner_data = (
                    db_payment.principal_id is not None or db_payment.account_id is not None
                )
                if has_owner_data and (
                    db_payment.principal_id != principal.principal_id
                    or db_payment.account_id != principal.account_id
                ):
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=ErrorResponse(
                            code="payment_not_found",
                            message="Payment mandate not found",
                        ).model_dump(),
                    )

            payment_mandate = _validate_payment_for_execution(
                db,
                db_payment,
                app.state.policy,
                app.state.system_public_key,
                app.state.system_verification_keys,
            )
            existing_order_id, claimed = _claim_payment_execution(db, db_payment)
            if not claimed:
                execution = PaymentExecutionResult(
                    success=True,
                    order_id=existing_order_id,
                    message="Payment execution already completed",
                    is_mocked=False,
                )
                SQLiteAuditLog(db).record(
                    event_type="PAYMENT_EXECUTION_ALREADY_COMPLETED",
                    actor=_audit_actor(principal),
                    intent_id=db_payment.intent_id,
                    cart_id=db_payment.cart_id,
                    decision=AuthorizationStatus.ALLOW,
                    reason=execution.message,
                    data={
                        "payment_id": payment_id,
                        "order_id": existing_order_id,
                        **_audit_context(principal),
                    },
                )
            else:
                audit = SQLiteAuditLog(db)
                audit.record(
                    event_type="PAYMENT_EXECUTION_STARTED",
                    actor=_audit_actor(principal),
                    intent_id=db_payment.intent_id,
                    cart_id=db_payment.cart_id,
                    decision=AuthorizationStatus.ALLOW,
                    reason="Explicit payment execution claimed",
                    data={
                        "payment_id": payment_id,
                        "execution_id": db_payment.payment_execution_id,
                        **_audit_context(principal),
                    },
                )
                try:
                    execution = _execute_payment_with_adapter(
                        db, payment_mandate, db_payment
                    )
                except Exception as exc:
                    db.rollback()
                    db_payment = db.get(DBPaymentMandate, payment_id)
                    if db_payment is None:
                        raise
                    execution = PaymentExecutionResult(
                        success=False,
                        order_id=None,
                        error_code="provider_execution_error",
                        message="Payment provider execution failed",
                        is_mocked=False,
                    )
                    _record_payment_execution(db_payment, execution)
                SQLiteAuditLog(db).record(
                    event_type=(
                        "PAYMENT_EXECUTION_SUCCEEDED"
                        if execution.success
                        else "PAYMENT_EXECUTION_FAILED"
                    ),
                    actor=_audit_actor(principal),
                    intent_id=db_payment.intent_id,
                    cart_id=db_payment.cart_id,
                    decision=AuthorizationStatus.ALLOW,
                    reason=execution.message,
                    data={
                        "payment_id": payment_id,
                        "order_id": execution.order_id,
                        "is_mocked": execution.is_mocked,
                        "error_code": execution.error_code,
                        **_audit_context(principal),
                    },
                )
                db.commit()

            return ExecutePaymentResponse(
                payment_id=payment_id,
                payment_execution_status=db_payment.payment_execution_status,
                razorpay_order_id=db_payment.razorpay_order_id,
                result=PaymentExecutionResponse(
                    success=execution.success,
                    order_id=execution.order_id,
                    error_code=execution.error_code,
                    message=execution.message,
                    is_mocked=execution.is_mocked,
                ),
            )
        finally:
            db.close()

    @app.post(
        "/payment-mandates/{payment_id}/execute",
        response_model=ExecutePaymentResponse,
    )
    def execute_payment_mandate(
        payment_id: str,
        payload: ExecutePaymentRequest | None = Body(default=None),
        principal: Principal | None = Depends(_principal),
    ) -> ExecutePaymentResponse:
        return _execute_payment_request(payment_id, principal)

    @app.post("/payments/{payment_id}/execute", response_model=ExecutePaymentResponse)
    def execute_payment(
        payment_id: str, principal: Principal | None = Depends(_principal)
    ) -> ExecutePaymentResponse:
        return _execute_payment_request(payment_id, principal)

    @app.get("/audit")
    def audit(principal: Principal | None = Depends(_principal)) -> dict[str, Any]:
        db = _open_db()
        try:
            audit_log = SQLiteAuditLog(db)
            valid, message = audit_log.verify_chain()
            visible_events = [
                event
                for event in audit_log.events
                if principal is None
                or (
                    isinstance(event.data, dict)
                    and event.data.get("principal_id") == principal.principal_id
                    and event.data.get("account_id") == principal.account_id
                )
            ]
            return {
                "valid": valid,
                "message": message,
                "count": len(visible_events),
                "events": [event.model_dump(mode="json") for event in visible_events],
            }
        finally:
            db.close()

    return app


app = create_app()
