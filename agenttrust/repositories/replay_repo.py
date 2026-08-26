"""SQLite-backed Replay Repository."""

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from agenttrust.interfaces import IReplayRegistry
from agenttrust.db.schema import DBConsumedNonce


class SQLiteReplayRegistry(IReplayRegistry):
    def __init__(self, db: Session) -> None:
        self.db = db

    def check_and_consume(self, mandate_type: str, nonce: str) -> bool:
        """
        Uses DB unique constraints to definitively prevent replay.
        """
        try:
            record = DBConsumedNonce(mandate_type=mandate_type, nonce=nonce)
            self.db.add(record)
            self.db.commit()
            return True
        except IntegrityError:
            self.db.rollback()
            return False
