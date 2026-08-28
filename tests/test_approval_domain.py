from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agenttrust.models import ApprovalRequest, ApprovalStatus, ApprovalTransitionError


REQUESTED = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
EXPIRES = REQUESTED + timedelta(minutes=10)


def make_approval(**overrides) -> ApprovalRequest:
    values = {
        "approval_id": "approval-1",
        "authorization_id": "decision-1",
        "intent_id": "intent-1",
        "cart_id": "cart-1",
        "reason": "Amount exceeds approval threshold",
        "requested_at": REQUESTED,
        "expires_at": EXPIRES,
    }
    values.update(overrides)
    return ApprovalRequest(**values)


def test_valid_pending_approval_can_be_created():
    approval = make_approval()
    assert approval.status is ApprovalStatus.PENDING
    assert approval.decided_at is None
    assert approval.decided_by is None


@pytest.mark.parametrize("field", ["approval_id", "authorization_id", "intent_id", "cart_id"])
def test_required_binding_identifiers_cannot_be_missing(field):
    values = {field: None}
    with pytest.raises(ValidationError):
        make_approval(**values)


def test_invalid_expiration_is_rejected():
    with pytest.raises(ValidationError):
        make_approval(expires_at=REQUESTED)
    with pytest.raises(ValidationError):
        make_approval(expires_at=REQUESTED - timedelta(seconds=1))


def test_valid_expiration_is_accepted():
    assert make_approval().expires_at == EXPIRES


@pytest.mark.parametrize(
    ("method", "expected"),
    [("approve", ApprovalStatus.APPROVED), ("reject", ApprovalStatus.REJECTED)],
)
def test_pending_decision_transitions(method, expected):
    approval = make_approval()
    result = getattr(approval, method)(REQUESTED + timedelta(minutes=1), "human-1")
    assert result.status is expected
    assert result.decided_at == REQUESTED + timedelta(minutes=1)
    assert result.decided_by == "human-1"


def test_pending_can_expire_at_exact_deadline():
    approval = make_approval()
    approval.expire(EXPIRES)
    assert approval.status is ApprovalStatus.EXPIRED
    assert approval.decided_at == EXPIRES
    assert approval.decided_by == "system"


def test_pending_can_expire_after_deadline():
    approval = make_approval()
    now = EXPIRES + timedelta(seconds=1)
    approval.expire(now)
    assert approval.status is ApprovalStatus.EXPIRED
    assert approval.decided_at == now


def test_pending_before_expiry_remains_pending():
    approval = make_approval()
    with pytest.raises(ApprovalTransitionError):
        approval.expire(EXPIRES - timedelta(seconds=1))
    assert approval.status is ApprovalStatus.PENDING


def test_decision_at_or_after_expiry_expires_and_rejects_decision():
    for method in ("approve", "reject"):
        approval = make_approval()
        with pytest.raises(ApprovalTransitionError):
            getattr(approval, method)(EXPIRES, "human-1")
        assert approval.status is ApprovalStatus.EXPIRED


@pytest.mark.parametrize(
    "initial",
    [ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.EXPIRED],
)
@pytest.mark.parametrize("method", ["approve", "reject", "expire"])
def test_terminal_states_reject_all_transitions(initial, method):
    approval = make_approval(
        status=initial,
        decided_at=REQUESTED + timedelta(minutes=1),
        decided_by="human-1" if initial != ApprovalStatus.EXPIRED else "system",
    )
    with pytest.raises(ApprovalTransitionError):
        if method == "expire":
            approval.expire(EXPIRES)
        else:
            getattr(approval, method)(REQUESTED + timedelta(minutes=2), "human-2")


def test_same_injected_timestamps_produce_same_result():
    first = make_approval()
    second = make_approval(approval_id="approval-2")
    now = EXPIRES
    first.expire(now)
    second.expire(now)
    assert first.status == second.status == ApprovalStatus.EXPIRED
    assert first.decided_at == second.decided_at == now
    assert first.decided_by == second.decided_by == "system"


@pytest.mark.parametrize("field", ["approval_id", "authorization_id", "intent_id", "cart_id"])
def test_bound_identity_cannot_change_after_creation(field):
    approval = make_approval()
    with pytest.raises(ValueError):
        setattr(approval, field, "different")


def test_pending_cannot_have_decision_metadata():
    with pytest.raises(ValidationError):
        make_approval(decided_at=REQUESTED, decided_by="human-1")


def test_terminal_state_requires_decision_metadata():
    with pytest.raises(ValidationError):
        make_approval(status=ApprovalStatus.APPROVED)
