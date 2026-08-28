from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
import threading

from fastapi.testclient import TestClient

from agenttrust.api import create_app
from agenttrust.crypto import generate_keypair, sign_mandate
from agenttrust.db.schema import DBPaymentMandate
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig
from agenttrust.payments.razorpay_adapter import RazorpayAdapter
import agenttrust.api as api_module


def _policy() -> PolicyConfig:
    return PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon"],
        blocked_categories=["Weapons"],
        velocity_limit=50,
        velocity_window_seconds=3600,
        require_approval_above_minor=900000,
    )


def _payload() -> dict:
    private_key, public_key = generate_keypair()
    intent = IntentMandate(
        description="Buy shoes",
        max_amount_minor=500000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    cart = CartMandate(
        intent_id=intent.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Shoes", price_minor=100000)],
        total_amount_minor=100000,
    )
    return {
        "intent": intent.model_dump(mode="json"),
        "intent_signature": sign_mandate(intent.canonical_bytes(), private_key).hex(),
        "user_public_key": public_key.public_bytes_raw().hex(),
        "cart": cart.model_dump(mode="json"),
    }


def test_explicit_execution_succeeds_and_is_idempotent(tmp_path, monkeypatch) -> None:
    calls = 0
    original = RazorpayAdapter.execute_payment

    def counted(self, mandate):
        nonlocal calls
        calls += 1
        return original(self, mandate)

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", counted)
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38.db').as_posix()}",
        policy=_policy(),
    )
    client = TestClient(app)
    authorized = client.post("/authorize?execute=false", json=_payload())
    payment_id = authorized.json()["payment_mandate"]["payment_id"]

    first = client.post(f"/payment-mandates/{payment_id}/execute")
    second = client.post(f"/payment-mandates/{payment_id}/execute")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["payment_execution_status"] == "SUCCEEDED"
    assert second.json()["payment_execution_status"] == "SUCCEEDED"
    assert second.json()["razorpay_order_id"] == first.json()["razorpay_order_id"]
    assert calls == 1


def test_concurrent_explicit_execution_calls_provider_once(tmp_path, monkeypatch) -> None:
    calls = 0
    original = RazorpayAdapter.execute_payment
    provider_started = threading.Event()
    release_provider = threading.Event()

    def counted(self, mandate):
        nonlocal calls
        calls += 1
        provider_started.set()
        release_provider.wait(timeout=5)
        return original(self, mandate)

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", counted)
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_concurrent.db').as_posix()}",
        policy=_policy(),
    )
    payment_id = TestClient(app).post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]

    def request():
        return TestClient(app).post(
            f"/payment-mandates/{payment_id}/execute"
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(request), executor.submit(request)]
        assert provider_started.wait(timeout=5)
        release_provider.set()
        responses = [future.result() for future in futures]

    assert sum(response.status_code == 200 for response in responses) == 1
    assert sum(response.status_code == 409 for response in responses) == 1
    assert calls == 1


def test_execution_endpoint_rejects_forged_context(tmp_path) -> None:
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_forged.db').as_posix()}",
        policy=_policy(),
    )
    response = TestClient(app).post(
        "/payment-mandates/does-not-matter/execute",
        json={"amount": 1},
    )
    assert response.status_code == 422


def test_execution_state_survives_recreated_app(tmp_path) -> None:
    db_url = f"sqlite:///{(tmp_path / 'm38_restart.db').as_posix()}"
    app1 = create_app(database_url=db_url, policy=_policy())
    client1 = TestClient(app1)
    authorized = client1.post("/authorize?execute=false", json=_payload())
    payment_id = authorized.json()["payment_mandate"]["payment_id"]
    first = client1.post(f"/payment-mandates/{payment_id}/execute")
    assert first.status_code == 200

    app2 = create_app(database_url=db_url, policy=_policy())
    retry = TestClient(app2).post(f"/payment-mandates/{payment_id}/execute")
    assert retry.status_code == 200
    assert retry.json()["razorpay_order_id"] == first.json()["razorpay_order_id"]

    db = app2.state.session_factory()
    try:
        row = db.get(DBPaymentMandate, payment_id)
        assert row is not None
        assert row.payment_execution_status == "SUCCEEDED"
    finally:
        db.close()


def test_execution_survives_true_process_restart(tmp_path, monkeypatch) -> None:
    private_key, _ = generate_keypair()
    raw = private_key.private_bytes_raw().hex()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", raw)
    db_url = f"sqlite:///{(tmp_path / 'm38_process.db').as_posix()}"
    app = create_app(database_url=db_url, policy=_policy())
    authorized = TestClient(app).post("/authorize?execute=false", json=_payload())
    payment_id = authorized.json()["payment_mandate"]["payment_id"]

    script = (
        "import json, sys\n"
        "from fastapi.testclient import TestClient\n"
        "from agenttrust.api import create_app\n"
        "from agenttrust.models import PolicyConfig\n"
        "p=PolicyConfig(max_transaction_amount_minor=500000, "
        "merchant_allowlist=['Amazon'], blocked_categories=['Weapons'], "
        "velocity_limit=50, velocity_window_seconds=3600, "
        "require_approval_above_minor=900000)\n"
        "r=TestClient(create_app(database_url=sys.argv[1], policy=p)).post("
        "f'/payment-mandates/{sys.argv[2]}/execute')\n"
        "print(json.dumps({'status': r.status_code, 'body': r.json()}))\n"
    )
    child_env = os.environ.copy()
    child_env["AGENTTRUST_SYSTEM_PRIVATE_KEY"] = raw
    completed = subprocess.run(
        [sys.executable, "-c", script, db_url, payment_id],
        check=True,
        capture_output=True,
        text=True,
        env=child_env,
    )
    result = json.loads(completed.stdout.strip().splitlines()[-1])
    assert result["status"] == 200
    assert result["body"]["payment_execution_status"] == "SUCCEEDED"


def test_incorrect_system_key_fails_closed(tmp_path, monkeypatch) -> None:
    first_key, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", first_key.private_bytes_raw().hex())
    db_url = f"sqlite:///{(tmp_path / 'm38_wrong_key.db').as_posix()}"
    app = create_app(database_url=db_url, policy=_policy())
    authorized = TestClient(app).post("/authorize?execute=false", json=_payload())
    payment_id = authorized.json()["payment_mandate"]["payment_id"]

    second_key, _ = generate_keypair()
    monkeypatch.setenv("AGENTTRUST_SYSTEM_PRIVATE_KEY", second_key.private_bytes_raw().hex())
    wrong_app = create_app(database_url=db_url, policy=_policy())
    response = TestClient(wrong_app).post(
        f"/payment-mandates/{payment_id}/execute"
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "payment_mandate_invalid"


def test_claim_failure_never_calls_provider(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_claim.db').as_posix()}",
        policy=_policy(),
    )
    client = TestClient(app)
    payment_id = client.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]
    calls = 0

    def fail_claim(db, record):
        raise api_module.HTTPException(status_code=409, detail={"code": "claim_failed"})

    def provider(self, mandate):
        nonlocal calls
        calls += 1
        raise AssertionError("provider must not be called")

    monkeypatch.setattr(api_module, "_claim_payment_execution", fail_claim)
    monkeypatch.setattr(RazorpayAdapter, "execute_payment", provider)
    response = TestClient(app, raise_server_exceptions=False).post(
        f"/payment-mandates/{payment_id}/execute"
    )
    assert response.status_code == 409
    assert calls == 0


def test_provider_failure_is_persisted_without_false_success(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_failure.db').as_posix()}",
        policy=_policy(),
    )
    client = TestClient(app)
    payment_id = client.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]

    def fail_provider(self, mandate):
        return type(
            "Result",
            (),
            {
                "success": False,
                "order_id": None,
                "error_code": "definitive_failure",
                "message": "provider rejected",
                "is_mocked": True,
            },
        )()

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", fail_provider)
    response = TestClient(app, raise_server_exceptions=False).post(
        f"/payment-mandates/{payment_id}/execute"
    )
    assert response.status_code == 200
    assert response.json()["payment_execution_status"] == "FAILED"
    assert response.json()["result"]["success"] is False


def test_continuation_does_not_call_provider(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_boundary.db').as_posix()}",
        policy=_policy(),
    )
    calls = 0

    def provider(self, mandate):
        nonlocal calls
        calls += 1
        raise AssertionError("continuation must not invoke provider")

    monkeypatch.setattr(RazorpayAdapter, "execute_payment", provider)
    response = TestClient(app).post("/authorize?execute=false", json=_payload())
    assert response.status_code == 200
    assert response.json()["payment_mandate"] is not None
    assert calls == 0


def test_audit_failure_leaves_claimed_execution_fail_closed(tmp_path, monkeypatch) -> None:
    app = create_app(
        database_url=f"sqlite:///{(tmp_path / 'm38_audit.db').as_posix()}",
        policy=_policy(),
    )
    client = TestClient(app)
    payment_id = client.post("/authorize?execute=false", json=_payload()).json()[
        "payment_mandate"
    ]["payment_id"]

    def fail_audit(self, *args, **kwargs):
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr(api_module.SQLiteAuditLog, "record", fail_audit)
    response = TestClient(app, raise_server_exceptions=False).post(
        f"/payment-mandates/{payment_id}/execute"
    )
    assert response.status_code == 500

    db = app.state.session_factory()
    try:
        row = db.get(DBPaymentMandate, payment_id)
        assert row is not None
        assert row.payment_execution_status == "EXECUTING"
        assert db.query(DBPaymentMandate).count() == 1
    finally:
        db.close()
