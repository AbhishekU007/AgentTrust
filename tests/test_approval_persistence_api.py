from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.models import ApprovalDecision, ApprovalRequest, ApprovalStatus
from agenttrust.repositories.approval_repo import SQLiteApprovalRepository


def _db_url(tmp_path) -> str:
    return f"sqlite:///{(tmp_path / 'approvals.db').as_posix()}"


def _approval(*, approval_id: str = "approval-1", expires_at=None) -> ApprovalRequest:
    requested_at = datetime.now(timezone.utc)
    return ApprovalRequest(
        approval_id=approval_id,
        authorization_id="decision-1",
        intent_id="intent-1",
        cart_id="cart-1",
        reason="Manual review required",
        requested_at=requested_at,
        expires_at=expires_at or requested_at + timedelta(minutes=10),
    )


def _seed(app, approval: ApprovalRequest) -> None:
    db = app.state.session_factory()
    try:
        SQLiteApprovalRepository(db).create(approval)
    finally:
        db.close()


def _decision(client: TestClient, operation: str, actor: str) -> dict:
    stored = client.get("/approvals/approval-1").json()
    private_key, public_key = generate_keypair()
    decided_at = datetime.fromisoformat(stored["requested_at"]) + timedelta(minutes=1)
    public_key_hex = public_key.public_bytes_raw().hex()
    payload = ApprovalDecision(
        approval_id=stored["approval_id"],
        authorization_id=stored["authorization_id"],
        intent_id=stored["intent_id"],
        cart_id=stored["cart_id"],
        decision=ApprovalStatus.APPROVED if operation == "approve" else ApprovalStatus.REJECTED,
        decided_at=decided_at,
        approver_id=actor,
        approver_public_key=public_key_hex,
    )
    return {
        "decided_by": actor,
        "decided_at": decided_at.isoformat(),
        "approver_public_key": public_key_hex,
        "signature": sign_mandate(payload.canonical_bytes(), private_key).hex(),
    }


def test_approval_can_be_created_and_retrieved_from_sqlite(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    approval = _approval()
    _seed(app, approval)

    db = app.state.session_factory()
    try:
        loaded = SQLiteApprovalRepository(db).get(approval.approval_id)
    finally:
        db.close()

    assert loaded is not None
    assert loaded.model_dump() == approval.model_dump()


def test_get_existing_approval(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    response = TestClient(app).get("/approvals/approval-1")

    assert response.status_code == 200
    assert response.json()["status"] == "PENDING"
    assert response.json()["intent_id"] == "intent-1"


def test_get_missing_approval_returns_404(tmp_path):
    response = TestClient(create_app(database_url=_db_url(tmp_path))).get(
        "/approvals/missing"
    )

    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "approval_not_found"


def test_approve_pending_approval_persists_terminal_state(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    client = TestClient(app)
    response = client.post("/approvals/approval-1/approve", json=_decision(client, "approve", "human-a"))

    assert response.status_code == 200
    assert response.json()["status"] == "APPROVED"
    assert response.json()["decided_by"] == "human-a"
    assert client.get("/approvals/approval-1").json()["status"] == "APPROVED"


def test_reject_pending_approval_persists_terminal_state(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    client = TestClient(app)
    response = client.post("/approvals/approval-1/reject", json=_decision(client, "reject", "human-r"))

    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"


def test_terminal_approval_transitions_return_409(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())
    client = TestClient(app)
    assert client.post(
        "/approvals/approval-1/approve", json=_decision(client, "approve", "human-a")
    ).status_code == 200

    for operation in ("approve", "reject"):
        response = client.post(
            f"/approvals/approval-1/{operation}", json=_decision(client, operation, "human-b")
        )
        assert response.status_code == 409
        assert response.json()["detail"]["code"] == "approval_transition_not_allowed"


def test_rejected_approval_cannot_be_approved_or_rejected_again(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())
    client = TestClient(app)
    assert client.post(
        "/approvals/approval-1/reject", json=_decision(client, "reject", "human-r")
    ).status_code == 200

    for operation in ("approve", "reject"):
        assert client.post(
            f"/approvals/approval-1/{operation}", json=_decision(client, operation, "human-x")
        ).status_code == 409


def test_expired_approval_is_persisted_as_terminal_and_cannot_be_decided(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    requested_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    _seed(
        app,
        ApprovalRequest(
            approval_id="approval-1",
            authorization_id="decision-1",
            intent_id="intent-1",
            cart_id="cart-1",
            reason="Manual review required",
            requested_at=requested_at,
            expires_at=requested_at + timedelta(seconds=1),
        ),
    )

    client = TestClient(app)
    response = client.post(
        "/approvals/approval-1/approve",
        json=_decision(client, "approve", "human-a"),
    )

    assert response.status_code == 409
    current = client.get("/approvals/approval-1").json()
    assert current["status"] == "EXPIRED"
    assert current["decided_by"] == "system"
    assert client.post(
        "/approvals/approval-1/reject", json=_decision(client, "reject", "human-r")
    ).status_code == 409


def test_decision_request_cannot_modify_bound_fields(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    client = TestClient(app)
    invalid = _decision(client, "approve", "human-a")
    invalid["intent_id"] = "different"
    response = client.post("/approvals/approval-1/approve", json=invalid)

    assert response.status_code == 422
    assert TestClient(app).get("/approvals/approval-1").json()["intent_id"] == "intent-1"


def test_malformed_decision_payload_returns_422(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    for payload in ({}, {"decided_by": ""}, {"decided_by": "   "}):
        client = TestClient(app)
        response = client.post("/approvals/approval-1/approve", json=payload)
        assert response.status_code == 422


def test_concurrent_approve_requests_have_one_winner(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    def approve(actor: str) -> int:
        client = TestClient(app)
        return client.post(
            "/approvals/approval-1/approve", json=_decision(client, "approve", actor)
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(approve, ("human-a", "human-b")))

    assert sorted(statuses) == [200, 409]
    final = TestClient(app).get("/approvals/approval-1").json()
    assert final["status"] == "APPROVED"


def test_concurrent_approve_and_reject_have_one_valid_terminal_winner(tmp_path):
    app = create_app(database_url=_db_url(tmp_path))
    _seed(app, _approval())

    def decide(operation: str) -> int:
        client = TestClient(app)
        return client.post(
            f"/approvals/approval-1/{operation}",
            json=_decision(client, operation, operation),
        ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(decide, ("approve", "reject")))

    assert sorted(statuses) == [200, 409]
    final = TestClient(app).get("/approvals/approval-1").json()
    assert final["status"] in {"APPROVED", "REJECTED"}
