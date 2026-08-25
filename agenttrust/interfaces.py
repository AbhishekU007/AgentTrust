"""Interfaces (Protocols) for Dependency Injection to keep the Engine decoupled."""

from typing import Protocol, Any, List, Tuple
from datetime import datetime
from agenttrust.models import AuditEvent, AuthorizationStatus


class IReplayRegistry(Protocol):
    def check_and_consume(self, mandate_type: str, nonce: str) -> bool:
        """
        Atomically check if a nonce was consumed for a mandate type, and consume it.
        Returns True if successful, False if already consumed (replay detected).
        """
        ...


class IAuditLog(Protocol):
    def record(
        self,
        event_type: str,
        actor: str = "system",
        intent_id: str | None = None,
        cart_id: str | None = None,
        decision: AuthorizationStatus | None = None,
        reason: str = "",
        data: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Append a new event to the audit log."""
        ...

    def verify_chain(self) -> Tuple[bool, str]:
        """Verify the integrity of the audit hash chain."""
        ...

    @property
    def events(self) -> List[AuditEvent]:
        """Return the list of events."""
        ...


class ITransactionRepository(Protocol):
    """
    Repository to query historical transaction data for policy evaluation (e.g., velocity limits).
    """
    def count_recent_transactions(self, window_seconds: int) -> int:
        """Return the number of ALLOWed transactions in the last N seconds."""
        ...
    
    def is_intent_consumed(self, intent_id: str) -> bool:
        """Check if an intent has already been used to successfully authorize a cart."""
        ...
    
    def mark_intent_consumed(self, intent_id: str) -> None:
        """Mark an intent as successfully consumed."""
        ...
