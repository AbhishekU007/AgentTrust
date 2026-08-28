from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.models import ApprovalDecision, ApprovalRequest, ApprovalStatus
from agenttrust.repositories.approval_repo import SQLiteApprovalRepository


def _db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'approval-signatures.db').as_posix()}"


def _approval(approval_id: str = "approval-1") -> ApprovalRequest:
    requested_at = datetime(2026, 8, 28, 10, 0, tzinfo=timezone.utc)
    return ApprovalRequest(
        approval_id=approval_id,
        authorization_id="decision-1",
        intent_id="intent-1",
        cart_id="cart-1",
        reason="Manual review required",
        requested_at=requested_at,
        expires_at=requested_at + timedelta(hours=1),
    )


def _seed(app, approval: ApprovalRequest) -> None:
    db = app.state.session_factory()
    try:
        SQLiteApprovalRepository(db).create(approval)
    finally:
        db.close()


def _signed_request(
    approval: ApprovalRequest,
    decision: ApprovalStatus,
    *,
    decided_at: datetime | None = None,
    approver_id: str = "human-1",
    private_key=None,
    public_key=None,
) -> tuple[dict, object, object]:
    if private_key is None or public_key is None:
        private_key, public_key = generate_keypair()
    timestamp = decided_at or approval.requested_at + timedelta(minutes=1)
    public_key_hex = public_key.public_bytes_raw().hex()
    payload = ApprovalDecision(
        approval_id=approval.approval_id,
        authorization_id=approval.authorization_id,
        intent_id=approval.intent_id,
        cart_id=approval.cart_id,
        decision=decision,
        decided_at=timestamp,
        approver_id=approver_id,
        approver_public_key=public_key_hex,
    )
    return (
        {
            "decided_by": approver_id,
            "decided_at": timestamp.isoformat(),
            "approver_public_key": public_key_hex,
            "signature": sign_mandate(payload.canonical_bytes(), private_key).hex(),
        },
        private_key,
        public_key,
    )


def test_valid_approved_signature_succeeds_and_is_persisted(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    request, _, _ = _signed_request(approval, ApprovalStatus.APPROVED)

    response = TestClient(app).post("/approvals/approval-1/approve", json=request)

    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"
    assert response.json()["decision_signature"] == request["signature"]
    assert response.json()["approver_public_key"] == request["approver_public_key"]


def test_valid_rejected_signature_succeeds(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    request, _, _ = _signed_request(approval, ApprovalStatus.REJECTED)

    response = TestClient(app).post("/approvals/approval-1/reject", json=request)

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"


@pytest.mark.parametrize("mutation", ["decided_at", "decided_by"])
def test_signed_decision_metadata_mutations_fail_verification(mutation, tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    request, _, _ = _signed_request(approval, ApprovalStatus.APPROVED)
    altered = dict(request)
    altered[mutation] = (
        "different"
        if mutation != "decided_at"
        else (approval.requested_at + timedelta(minutes=2)).isoformat()
    )

    response = TestClient(app).post("/approvals/approval-1/approve", json=altered)

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_approval_signature"


@pytest.mark.parametrize("field", ["approval_id", "authorization_id", "intent_id", "cart_id"])
def test_client_cannot_submit_stored_context_fields(field, tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    request, _, _ = _signed_request(approval, ApprovalStatus.APPROVED)
    request[field] = "different"

    response = TestClient(app).post("/approvals/approval-1/approve", json=request)

    assert response.status_code == 422


def test_modified_signature_wrong_key_and_malformed_material_fail(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    request, _, _ = _signed_request(approval, ApprovalStatus.APPROVED)
    _, other_public_key = generate_keypair()
    client = TestClient(app)

    modified = dict(request)
    modified["signature"] = "00" * 64
    assert client.post("/approvals/approval-1/approve", json=modified).status_code == 400

    wrong_key = dict(request)
    wrong_key["approver_public_key"] = other_public_key.public_bytes_raw().hex()
    assert client.post("/approvals/approval-1/approve", json=wrong_key).status_code == 400

    malformed = dict(request)
    malformed["approver_public_key"] = "not-a-key"
    assert client.post("/approvals/approval-1/approve", json=malformed).status_code == 400


def test_signature_cannot_be_replayed_for_another_approval_or_decision(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    first = _approval()
    second = _approval("approval-2")
    _seed(app, first)
    _seed(app, second)
    request, _, _ = _signed_request(first, ApprovalStatus.APPROVED)
    client = TestClient(app)

    assert client.post("/approvals/approval-2/approve", json=request).status_code == 400
    assert client.post("/approvals/approval-1/reject", json=request).status_code == 400


@pytest.mark.parametrize(
    "field",
    ["approval_id", "authorization_id", "intent_id", "cart_id", "decision", "decided_at", "approver_id"],
)
def test_mutating_any_signed_payload_field_invalidates_signature(field):
    approval = _approval()
    private_key, public_key = generate_keypair()
    public_key_hex = public_key.public_bytes_raw().hex()
    payload = ApprovalDecision(
        approval_id=approval.approval_id,
        authorization_id=approval.authorization_id,
        intent_id=approval.intent_id,
        cart_id=approval.cart_id,
        decision=ApprovalStatus.APPROVED,
        decided_at=approval.requested_at + timedelta(minutes=1),
        approver_id="human-1",
        approver_public_key=public_key_hex,
    )
    signature = sign_mandate(payload.canonical_bytes(), private_key)
    values = payload.model_dump()
    values[field] = (
        ApprovalStatus.REJECTED
        if field == "decision"
        else "different"
        if field not in {"decided_at"}
        else approval.requested_at + timedelta(minutes=2)
    )
    altered = ApprovalDecision(**values)

    assert verify_signature(altered.canonical_bytes(), signature, public_key) is False


def test_approval_signature_remains_verifiable_after_reload(tmp_path):
    db_url = _db_url(tmp_path)
    app = create_app(database_url=db_url)
    approval = _approval()
    _seed(app, approval)
    request, _, public_key = _signed_request(approval, ApprovalStatus.APPROVED)
    assert TestClient(app).post("/approvals/approval-1/approve", json=request).status_code == 200

    reloaded_app = create_app(database_url=db_url)
    db = reloaded_app.state.session_factory()
    try:
        stored = SQLiteApprovalRepository(db).get("approval-1")
    finally:
        db.close()

    assert stored is not None
    payload = ApprovalDecision(
        approval_id=stored.approval_id,
        authorization_id=stored.authorization_id,
        intent_id=stored.intent_id,
        cart_id=stored.cart_id,
        decision=stored.status,
        decided_at=stored.decided_at,
        approver_id=stored.decided_by,
        approver_public_key=stored.approver_public_key,
    )
    assert verify_signature(
        payload.canonical_bytes(),
        bytes.fromhex(stored.decision_signature),
        public_key,
    )


def test_second_signed_decision_cannot_overwrite_terminal_state(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    first, private_key, public_key = _signed_request(approval, ApprovalStatus.APPROVED)
    client = TestClient(app)
    assert client.post("/approvals/approval-1/approve", json=first).status_code == 200
    second, _, _ = _signed_request(
        approval,
        ApprovalStatus.REJECTED,
        private_key=private_key,
        public_key=public_key,
        approver_id="human-2",
    )
    assert client.post("/approvals/approval-1/reject", json=second).status_code == 409


def test_valid_signature_cannot_approve_expired_approval(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    approval.expires_at = approval.requested_at + timedelta(minutes=1)
    _seed(app, approval)
    request, _, _ = _signed_request(
        approval,
        ApprovalStatus.APPROVED,
        decided_at=approval.expires_at,
    )

    response = TestClient(app).post("/approvals/approval-1/approve", json=request)

    assert response.status_code == 409
    assert TestClient(app).get("/approvals/approval-1").json()["status"] == "EXPIRED"


def test_two_valid_signed_decisions_have_one_winner(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)
    first, _, _ = _signed_request(approval, ApprovalStatus.APPROVED, approver_id="human-a")
    second, _, _ = _signed_request(approval, ApprovalStatus.APPROVED, approver_id="human-b")

    def submit(request: dict) -> int:
        return TestClient(app).post("/approvals/approval-1/approve", json=request).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(submit, (first, second)))

    assert sorted(statuses) == [200, 409]
    assert TestClient(app).get("/approvals/approval-1").json()["status"] == "APPROVED"
