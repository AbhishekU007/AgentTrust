"""SQLite-backed Transaction Repository."""

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, func
from agenttrust.interfaces import ITransactionRepository
from agenttrust.db.schema import DBIntentMandate, DBAuditEvent, DBPaymentMandate


class SQLiteTransactionRepository(ITransactionRepository):
    def __init__(self, db: Session) -> None:
        self.db = db

    def count_recent_transactions(self, window_seconds: int) -> int:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_seconds)
        
        # Count ALLOWed payments in the time window
        stmt = select(func.count(DBPaymentMandate.payment_id)).where(
            and_(
                DBPaymentMandate.status == "ALLOW",
                DBPaymentMandate.created_at >= cutoff
            )
        )
        return self.db.execute(stmt).scalar() or 0
    
    def is_intent_consumed(self, intent_id: str) -> bool:
        # Check if a PaymentMandate already exists for this intent_id
        stmt = select(DBPaymentMandate.payment_id).where(DBPaymentMandate.intent_id == intent_id)
        result = self.db.execute(stmt).first()
        return result is not None
    
    def mark_intent_consumed(self, intent_id: str) -> None:
        # We don't need to do anything here because the engine will immediately
        # create a PaymentMandate and persist it. 
        # is_intent_consumed relies on checking the PaymentMandate table.
        pass
