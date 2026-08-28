from concurrent.futures import ThreadPoolExecutor

from fastapi.testclient import TestClient

from tests.test_approval_continuation import _create_approved, _db_url, _payload, _policy
from agenttrust.api import create_app
from agenttrust.db.schema import DBPaymentMandate


def test_two_continuations_create_one_payment_mandate(tmp_path):
    app, _, approval_id = _create_approved(tmp_path)

    def continue_request() -> tuple[int, str]:
        response = TestClient(app).post(f"/approvals/{approval_id}/continue")
        return response.status_code, response.json()["payment_mandate"]["payment_id"]

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: continue_request(), range(2)))

    assert results[0][0] == 200
    assert results[1][0] == 200
    assert results[0][1] == results[1][1]
    db = app.state.session_factory()
    try:
        assert db.query(DBPaymentMandate).count() == 1
    finally:
        db.close()


def test_missing_approval_and_client_fields_are_rejected(tmp_path):
    app = create_app(database_url=_db_url(tmp_path), policy=_policy())
    client = TestClient(app)
    assert client.post("/approvals/missing/continue").status_code == 404

    body = client.post(
        "/approvals/not-real/continue",
        json={"authorization_id": "forged", "amount_minor": 1},
    )
    assert body.status_code == 422
