"""SQLite-backed Transaction Repository."""

from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, func
from sqlalchemy.exc import IntegrityError
from agenttrust.interfaces import ITransactionRepository
from agenttrust.db.schema import DBConsumedIntent, DBPaymentMandate


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
        stmt = select(DBConsumedIntent.intent_id).where(DBConsumedIntent.intent_id == intent_id)
        result = self.db.execute(stmt).first()
        return result is not None
    
    def mark_intent_consumed(self, intent_id: str) -> None:
        try:
            self.db.add(DBConsumedIntent(intent_id=intent_id))
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
