"""SQLite-backed Audit Repository."""

from typing import Any, List, Tuple
from sqlalchemy.orm import Session
from agenttrust.interfaces import IAuditLog
from agenttrust.models import AuditEvent, AuthorizationStatus
from agenttrust.db.schema import DBAuditEvent
from agenttrust.audit import AuditLog as CoreAuditLog


class SQLiteAuditLog(IAuditLog):
    def __init__(self, db: Session) -> None:
        self.db = db
        # We wrap the core in-memory engine to handle the hashing logic
        self._core_log = CoreAuditLog()
        self._load_from_db()

    def _load_from_db(self):
        """Load the full historical chain from the DB into the core log."""
        db_events = self.db.query(DBAuditEvent).order_by(DBAuditEvent.id).all()
        for dbe in db_events:
            ev = AuditEvent(
                event_id=dbe.event_id,
                timestamp=dbe.timestamp,
                event_type=dbe.event_type,
                actor=dbe.actor,
                intent_id=dbe.intent_id,
                cart_id=dbe.cart_id,
                decision=dbe.decision,
                reason=dbe.reason,
                data=dbe.data,
                previous_hash=dbe.previous_hash,
            )
            ev.event_hash = dbe.event_hash
            self._core_log._events.append(ev)

    def record(
        self,
        event_type: str,
        actor: str = "system",
        intent_id: str | None = None,
        cart_id: str | None = None,
        decision: AuthorizationStatus | None = None,
        reason: str = "",
        data: dict[str, Any] | None = None,
        *,
        commit: bool = True,
    ) -> AuditEvent:
        
        # 1. Let the core log create the event and compute hashes correctly
        ev = self._core_log.record(
            event_type=event_type,
            actor=actor,
            intent_id=intent_id,
            cart_id=cart_id,
            decision=decision,
            reason=reason,
            data=data,
        )

        # 2. Persist to DB
        db_ev = DBAuditEvent(
            event_id=ev.event_id,
            timestamp=ev.timestamp,
            event_type=ev.event_type,
            actor=ev.actor,
            intent_id=ev.intent_id,
            cart_id=ev.cart_id,
            decision=ev.decision,
            reason=ev.reason,
            data=ev.data,
            previous_hash=ev.previous_hash,
            event_hash=ev.event_hash,
        )
        self.db.add(db_ev)
        if commit and not self.db.info.get("coordinated_transaction"):
            self.db.commit()

        return ev

    def verify_chain(self) -> Tuple[bool, str]:
        # Because we re-loaded the exact objects from the DB into core log, 
        # we can just delegate to the core log's verify_chain.
        return self._core_log.verify_chain()

    @property
    def events(self) -> List[AuditEvent]:
        return self._core_log.events
