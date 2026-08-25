"""Hash-chained, tamper-evident audit log.

Uses strict canonical JSON serialization for events to ensure deterministic
hashes across platforms.
"""

from __future__ import annotations

import hashlib
from typing import Any

from agenttrust.models import AuditEvent, AuthorizationStatus


GENESIS_HASH = "0" * 64


class AuditLog:
    """In-memory hash-chained audit log."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def _compute_hash(self, event: AuditEvent) -> str:
        """
        Compute SHA-256 hash using strict canonical bytes.
        """
        payload = event.canonical_bytes()
        return hashlib.sha256(payload).hexdigest()

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
        """Append a new event to the hash chain and return it."""
        previous_hash = (
            self._events[-1].event_hash if self._events else GENESIS_HASH
        )

        event = AuditEvent(
            event_type=event_type,
            actor=actor,
            intent_id=intent_id,
            cart_id=cart_id,
            decision=decision,
            reason=reason,
            data=data,
            previous_hash=previous_hash,
        )
        event.event_hash = self._compute_hash(event)
        self._events.append(event)
        return event

    def verify_chain(self) -> tuple[bool, str]:
        """
        Walk the full chain and verify integrity.
        """
        if not self._events:
            return True, "Audit log is empty"

        if self._events[0].previous_hash != GENESIS_HASH:
            return False, "First event does not link to genesis hash"

        for i, event in enumerate(self._events):
            expected = self._compute_hash(event)
            if event.event_hash != expected:
                return False, (
                    f"Event {i} ({event.event_id}): hash mismatch — "
                    f"content was modified after recording"
                )

            if i > 0:
                prev = self._events[i - 1]
                if event.previous_hash != prev.event_hash:
                    return False, (
                        f"Event {i} ({event.event_id}): chain break — "
                        f"previous_hash does not match event {i - 1}"
                    )

        return True, f"Audit chain verified: {len(self._events)} events intact"

    def __len__(self) -> int:
        return len(self._events)
