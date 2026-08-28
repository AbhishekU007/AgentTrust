"""Persistence repository for human approval requests."""

from datetime import datetime, timezone

from datetime import datetime

from sqlalchemy import update
from sqlalchemy.orm import Session

from agenttrust.db.schema import DBApprovalRequest
from agenttrust.models import ApprovalRequest, ApprovalStatus, ApprovalTransitionError


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class SQLiteApprovalRepository:
    """Converts approval domain objects to and from SQLAlchemy records."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def create(self, approval: ApprovalRequest, *, commit: bool = True) -> ApprovalRequest:
        self.db.add(
            DBApprovalRequest(
                approval_id=approval.approval_id,
                authorization_id=approval.authorization_id,
                intent_id=approval.intent_id,
                cart_id=approval.cart_id,
                status=approval.status.value,
                reason=approval.reason,
                requested_at=approval.requested_at,
                expires_at=approval.expires_at,
                decided_at=approval.decided_at,
                decided_by=approval.decided_by,
                approver_public_key=approval.approver_public_key,
                decision_signature=approval.decision_signature,
            )
        )
        if commit and not self.db.info.get("coordinated_transaction"):
            self.db.commit()
        return approval

    def get(self, approval_id: str) -> ApprovalRequest | None:
        record = self.db.get(DBApprovalRequest, approval_id)
        if record is None:
            return None
        return self._to_domain(record)

    def get_by_authorization_id(self, authorization_id: str) -> ApprovalRequest | None:
        record = (
            self.db.query(DBApprovalRequest)
            .filter(DBApprovalRequest.authorization_id == authorization_id)
            .one_or_none()
        )
        if record is None:
            return None
        return self._to_domain(record)

    def save_transition(
        self,
        approval: ApprovalRequest,
        expected_status: ApprovalStatus,
    ) -> ApprovalRequest:
        """Persist a domain transition using an atomic compare-and-set."""
        statement = (
            update(DBApprovalRequest)
            .where(
                DBApprovalRequest.approval_id == approval.approval_id,
                DBApprovalRequest.status == expected_status.value,
            )
            .values(
                status=approval.status.value,
                decided_at=approval.decided_at,
                decided_by=approval.decided_by,
                approver_public_key=approval.approver_public_key,
                decision_signature=approval.decision_signature,
            )
        )
        result = self.db.execute(statement)
        if result.rowcount != 1:
            self.db.rollback()
            raise ApprovalTransitionError(
                "Approval was already decided by another request"
            )
        self.db.commit()
        return approval

    def reserve_continuation(
        self,
        approval_id: str,
        payment_id: str,
        completed_at: datetime,
        *,
        commit: bool = True,
    ) -> bool:
        """Atomically claim an approved request for one payment mandate."""
        statement = (
            update(DBApprovalRequest)
            .where(
                DBApprovalRequest.approval_id == approval_id,
                DBApprovalRequest.status == ApprovalStatus.APPROVED.value,
                DBApprovalRequest.continuation_payment_id.is_(None),
            )
            .values(
                continuation_payment_id=payment_id,
                continuation_completed_at=completed_at,
            )
        )
        result = self.db.execute(statement)
        if result.rowcount == 1:
            if commit and not self.db.info.get("coordinated_transaction"):
                self.db.commit()
            return True
        # Refresh the session after a failed compare-and-set so callers do not
        # observe a stale approval object during an idempotent retry.
        self.db.rollback()
        return False

    @staticmethod
    def _to_domain(record: DBApprovalRequest) -> ApprovalRequest:
        return ApprovalRequest(
            approval_id=record.approval_id,
            authorization_id=record.authorization_id,
            intent_id=record.intent_id,
            cart_id=record.cart_id,
            status=ApprovalStatus(record.status),
            reason=record.reason,
            requested_at=_utc(record.requested_at),
            expires_at=_utc(record.expires_at),
            decided_at=_utc(record.decided_at) if record.decided_at else None,
            decided_by=record.decided_by,
            approver_public_key=record.approver_public_key,
            decision_signature=record.decision_signature,
        )
