"""Razorpay Test Mode Integration."""

from __future__ import annotations

import os
import razorpay
import uuid
import logging
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import select
from agenttrust.models import PaymentMandate
from agenttrust.db.schema import DBPaymentMandate


logger = logging.getLogger(__name__)


@dataclass
class PaymentExecutionResult:
    success: bool
    order_id: str | None
    error_code: str | None = None
    message: str = ""
    is_mocked: bool = False


class RazorpayAdapter:
    def __init__(self, db: Session) -> None:
        self.db = db
        key_id = os.getenv("RAZORPAY_KEY_ID")
        key_secret = os.getenv("RAZORPAY_KEY_SECRET")
        
        self.is_mocked = not (key_id and key_secret)
        if not self.is_mocked:
            self.client = razorpay.Client(auth=(key_id, key_secret))
        else:
            logger.warning("RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET not set. Using MOCKED mode.")
            self.client = None

    def create_order(self, mandate: PaymentMandate) -> str | None:
        result = self.execute_payment(mandate)
        return result.order_id if result.success else None

    def execute_payment(self, mandate: PaymentMandate) -> PaymentExecutionResult:
        """
        Creates a Razorpay order idempotently based on PaymentMandate ID.
        Returns a structured execution result.
        """
        # 1. Idempotency Check: Do we already have an order for this payment?
        stmt = select(DBPaymentMandate).where(DBPaymentMandate.payment_id == mandate.payment_id)
        db_mandate = self.db.execute(stmt).scalar()
        
        if db_mandate and db_mandate.razorpay_order_id:
            logger.info(f"Idempotent hit: Order {db_mandate.razorpay_order_id} already exists for Payment {mandate.payment_id}")
            return PaymentExecutionResult(
                success=True,
                order_id=db_mandate.razorpay_order_id,
                message="Existing Razorpay order reused",
                is_mocked=self.is_mocked,
            )

        # 2. Create the order
        if self.is_mocked:
            # Mock behavior
            order_id = f"order_mock_{uuid.uuid4().hex[:8]}"
        else:
            # Real Razorpay Test API call
            # receipt is unique identifier for this transaction in our system
            data = {
                "amount": mandate.amount_minor,
                "currency": mandate.currency,
                "receipt": mandate.payment_id,
                "notes": {
                    "intent_id": mandate.intent_id,
                    "cart_id": mandate.cart_id,
                    "merchant": mandate.merchant
                }
            }
            try:
                razorpay_order = self.client.order.create(data=data)
                order_id = razorpay_order.get("id")
                if not order_id:
                    return PaymentExecutionResult(
                        success=False,
                        order_id=None,
                        error_code="razorpay_no_order_id",
                        message="Razorpay response did not include order id",
                        is_mocked=False,
                    )
            except Exception as e:
                logger.error(f"Razorpay API error: {e}")
                return PaymentExecutionResult(
                    success=False,
                    order_id=None,
                    error_code="razorpay_api_error",
                    message=str(e),
                    is_mocked=False,
                )

        # 3. Persist the order_id back to DB
        if db_mandate:
            db_mandate.razorpay_order_id = order_id
            self.db.commit()
        else:
            # If the DBPaymentMandate was somehow not persisted yet, we could persist it now,
            # but standard flow dictates engine persists it. We will log a warning.
            logger.warning("DBPaymentMandate not found to attach razorpay_order_id. This shouldn't happen if engine is called first.")
        
        return PaymentExecutionResult(
            success=True,
            order_id=order_id,
            message="Razorpay order created",
            is_mocked=self.is_mocked,
        )
