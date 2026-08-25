"""Pydantic v2 models for the AgentTrust mandate and authorization system.

Monetary amounts are strictly integers representing minor units (e.g., paise)
to eliminate floating-point ambiguity.

Canonicalization:
All signed mandates provide a `canonical_bytes()` method that implements
a strict, deterministic JSON serialization to ensure cross-language compatibility.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import hashlib
import uuid

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AuthorizationStatus(str, Enum):
    """Outcome of the authorization pipeline."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


# ---------------------------------------------------------------------------
# Canonicalization Helper
# ---------------------------------------------------------------------------

def _strict_json_serializer(obj: Any) -> Any:
    """
    Strict serializer for datetime and other types to ensure deterministic
    canonical JSON representation.
    """
    if isinstance(obj, datetime):
        # Force UTC, microseconds precision, trailing 'Z'
        if obj.tzinfo is None:
            obj = obj.replace(tzinfo=timezone.utc)
        else:
            obj = obj.astimezone(timezone.utc)
        return obj.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raise TypeError(f"Type {type(obj)} not serializable")


def compute_canonical_bytes(payload: dict[str, Any]) -> bytes:
    """
    Produce a strict canonical UTF-8 byte representation of a dictionary.
    Keys are sorted, spaces removed, nulls excluded, and datetimes
    strictly formatted.
    """
    # Remove None values recursively
    def _clean(d):
        if isinstance(d, dict):
            return {k: _clean(v) for k, v in d.items() if v is not None}
        elif isinstance(d, list):
            return [_clean(v) for v in d]
        return d

    cleaned = _clean(payload)
    return json.dumps(
        cleaned,
        sort_keys=True,
        separators=(",", ":"),
        default=_strict_json_serializer,
    ).encode("utf-8")


def compute_hash(payload: bytes) -> str:
    """Compute SHA-256 hash of canonical bytes."""
    return hashlib.sha256(payload).hexdigest()

# ---------------------------------------------------------------------------
# Mandates
# ---------------------------------------------------------------------------


class IntentMandate(BaseModel):
    """
    The user's purchase intent — the root of trust.
    Signed by the user's private key externally.
    """
    intent_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    description: str = Field(..., description="What the user wants to buy")
    max_amount_minor: int = Field(..., gt=0, description="Max spend in minor units (e.g. paise)")
    currency: str = Field(default="INR")
    allowed_merchants: list[str] = Field(..., min_length=1)
    allowed_categories: list[str] = Field(..., min_length=1)
    nonce: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique nonce for replay protection",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(..., description="Mandate expiration (UTC)")

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation for Ed25519 signing."""
        return compute_canonical_bytes(self.model_dump())
    
    def compute_hash(self) -> str:
        return compute_hash(self.canonical_bytes())


class CartItem(BaseModel):
    """A single item in the agent's proposed cart."""
    name: str
    price_minor: int = Field(..., gt=0)
    quantity: int = Field(default=1, ge=1)


class CartMandate(BaseModel):
    """
    The AI agent's proposed cart.
    """
    cart_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    intent_id: str = Field(..., description="References the parent IntentMandate")
    merchant: str
    category: str
    items: list[CartItem] = Field(..., min_length=1)
    total_amount_minor: int = Field(..., gt=0)
    currency: str = Field(default="INR")
    nonce: str = Field(
        default_factory=lambda: uuid.uuid4().hex,
        description="Unique nonce for cart replay protection",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation."""
        return compute_canonical_bytes(self.model_dump())

    def compute_hash(self) -> str:
        return compute_hash(self.canonical_bytes())


class PaymentMandate(BaseModel):
    """
    An authorized payment instruction — created ONLY after ALLOW.
    Signed by the AgentTrust SYSTEM key to prove authorization.
    """
    payment_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    intent_id: str
    intent_hash: str = Field(..., description="SHA-256 hash of the canonical intent")
    cart_id: str
    cart_hash: str = Field(..., description="SHA-256 hash of the canonical cart")
    amount_minor: int = Field(..., gt=0)
    currency: str = Field(default="INR")
    merchant: str
    status: AuthorizationStatus = Field(default=AuthorizationStatus.ALLOW)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    system_signature: Optional[str] = Field(default=None, description="Hex encoded Ed25519 signature by AgentTrust system key")

    def canonical_bytes(self) -> bytes:
        """Deterministic byte representation excluding the signature itself."""
        return compute_canonical_bytes(self.model_dump(exclude={"system_signature"}))


# ---------------------------------------------------------------------------
# Policy Configuration
# ---------------------------------------------------------------------------


class PolicyConfig(BaseModel):
    """
    Deterministic policy rules (System/Account-level).
    Monetary limits are in minor units (e.g. paise).
    """
    max_transaction_amount_minor: Optional[int] = Field(default=None)
    merchant_allowlist: Optional[list[str]] = Field(default=None)
    blocked_categories: Optional[list[str]] = Field(default=None)
    velocity_limit: Optional[int] = Field(default=None)
    velocity_window_seconds: int = Field(default=3600)
    require_approval_above_minor: Optional[int] = Field(default=None)


# ---------------------------------------------------------------------------
# Authorization Result
# ---------------------------------------------------------------------------


class CheckDetail(BaseModel):
    check_name: str
    passed: bool
    reason: str
    actual_value: Any = None
    allowed_value: Any = None


class AuthorizationResult(BaseModel):
    status: AuthorizationStatus
    reason: str
    intent_id: str
    cart_id: Optional[str] = None
    checks: list[CheckDetail] = Field(default_factory=list)
    payment_mandate: Optional[PaymentMandate] = None


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """A single entry in the tamper-evident audit log."""
    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str
    actor: str = Field(default="system")
    intent_id: Optional[str] = None
    cart_id: Optional[str] = None
    decision: Optional[AuthorizationStatus] = None
    reason: str = ""
    data: Optional[dict[str, Any]] = None
    previous_hash: str = ""
    event_hash: str = ""

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes for hashing (excludes event_hash)."""
        return compute_canonical_bytes(self.model_dump(exclude={"event_hash"}))

