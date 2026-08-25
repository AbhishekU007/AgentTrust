"""SQLAlchemy schema models for AgentTrust."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, Boolean, JSON
from sqlalchemy.sql import func
from agenttrust.db.database import Base


class DBIntentMandate(Base):
    __tablename__ = "intent_mandates"

    intent_id = Column(String, primary_key=True, index=True)
    description = Column(String, nullable=False)
    max_amount_minor = Column(Integer, nullable=False)
    currency = Column(String, nullable=False, default="INR")
    allowed_merchants = Column(JSON, nullable=False)
    allowed_categories = Column(JSON, nullable=False)
    nonce = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    
    # Store the actual signed bytes for audit/verification if needed
    canonical_bytes_hex = Column(String, nullable=False)


class DBCartMandate(Base):
    __tablename__ = "cart_mandates"

    cart_id = Column(String, primary_key=True, index=True)
    intent_id = Column(String, nullable=False, index=True)
    merchant = Column(String, nullable=False)
    category = Column(String, nullable=False)
    items = Column(JSON, nullable=False)
    total_amount_minor = Column(Integer, nullable=False)
    currency = Column(String, nullable=False, default="INR")
    nonce = Column(String, nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False)


class DBPaymentMandate(Base):
    __tablename__ = "payment_mandates"

    payment_id = Column(String, primary_key=True, index=True)
    intent_id = Column(String, nullable=False, index=True)
    intent_hash = Column(String, nullable=False)
    cart_id = Column(String, nullable=False, index=True)
    cart_hash = Column(String, nullable=False)
    amount_minor = Column(Integer, nullable=False)
    currency = Column(String, nullable=False, default="INR")
    merchant = Column(String, nullable=False)
    status = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False)
    system_signature = Column(String, nullable=False)
    
    # Razorpay integration
    razorpay_order_id = Column(String, nullable=True, unique=True, index=True)


class DBAuditEvent(Base):
    __tablename__ = "audit_events"

    # We use integer primary key to strictly preserve order, but also keep event_id
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, nullable=False, unique=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    event_type = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    intent_id = Column(String, nullable=True)
    cart_id = Column(String, nullable=True)
    decision = Column(String, nullable=True)
    reason = Column(String, nullable=False, default="")
    data = Column(JSON, nullable=True)
    previous_hash = Column(String, nullable=False)
    event_hash = Column(String, nullable=False, unique=True)


class DBConsumedNonce(Base):
    """
    Durable replay protection.
    A composite unique constraint on (mandate_type, nonce) physically
    prevents concurrent double spends at the DB layer.
    """
    __tablename__ = "consumed_nonces"

    id = Column(Integer, primary_key=True, autoincrement=True)
    mandate_type = Column(String, nullable=False)  # e.g., 'intent', 'cart'
    nonce = Column(String, nullable=False)
    consumed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    # Composite unique constraint
    __table_args__ = (
        {"sqlite_autoincrement": True},  # Not strictly necessary but safe
    )


# Manually create unique index to bypass SQLAlchemy declarative limitations in some SQLite versions
from sqlalchemy import Index
Index('idx_type_nonce_unique', DBConsumedNonce.mandate_type, DBConsumedNonce.nonce, unique=True)
