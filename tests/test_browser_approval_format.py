"""
Test that the browser approval payload format matches the backend's expectations.
This ensures the JavaScript signing produces the same canonical bytes as the backend.
"""
from datetime import datetime, timezone

from agenttrust.models import ApprovalDecision
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature


def test_approval_timestamp_format_matches_backend():
    """
    Verify that a timestamp in the format the browser generates
    (ISO string with 6 decimal places and Z suffix) produces the same
    canonical bytes as the backend's _strict_json_serializer.
    """
    # Simulate what the browser generates: ISO string with 6 decimals and Z
    timestamp_iso = "2025-08-29T17:00:42.036000Z"
    
    # Backend parses this into a datetime
    parsed_datetime = datetime.fromisoformat(timestamp_iso.replace('Z', '+00:00'))
    
    # Backend constructs ApprovalDecision with this datetime
    approval_decision = ApprovalDecision(
        version="1",
        domain="agenttrust.approval-decision",
        approval_id="test-approval",
        authorization_id="test-auth",
        intent_id="test-intent",
        cart_id="test-cart",
        decision="APPROVED",
        decided_at=parsed_datetime,
        approver_id="demo-user",
        approver_public_key="0123456789abcdef0123456789abcdef",
    )
    
    # Get the canonical bytes
    canonical_bytes = approval_decision.canonical_bytes()
    
    # Verify the canonical representation contains the timestamp with correct format
    canonical_str = canonical_bytes.decode('utf-8')
    assert '"decided_at":"2025-08-29T17:00:42.036000Z"' in canonical_str, \
        f"Expected timestamp format in canonical bytes, got: {canonical_str}"


def test_browser_approval_signature_verification():
    """
    Verify that a signature computed on a browser-generated approval payload
    can be verified by the backend.
    """
    private_key, public_key = generate_keypair()
    
    # Browser constructs this exact payload (with timestamp in the correct format)
    timestamp_iso = "2025-08-29T17:00:42.036000Z"
    parsed_datetime = datetime.fromisoformat(timestamp_iso.replace('Z', '+00:00'))
    
    approval_decision = ApprovalDecision(
        version="1",
        domain="agenttrust.approval-decision",
        approval_id="browser-test",
        authorization_id="auth-123",
        intent_id="intent-123",
        cart_id="cart-123",
        decision="APPROVED",
        decided_at=parsed_datetime,
        approver_id="demo-user",
        approver_public_key=public_key.public_bytes_raw().hex(),
    )
    
    # Browser signs the canonical bytes
    canonical_bytes = approval_decision.canonical_bytes()
    signature = sign_mandate(canonical_bytes, private_key)
    
    # Backend verifies the signature
    is_valid = verify_signature(
        canonical_bytes,
        signature,
        public_key
    )
    assert is_valid, "Signature verification failed"


def test_approval_decision_field_order():
    """
    Verify that ApprovalDecision fields are ordered correctly for canonical serialization.
    This matters because the browser must construct the same field order as the backend.
    """
    timestamp = datetime(2025, 8, 29, 17, 0, 42, 36000, tzinfo=timezone.utc)
    
    approval = ApprovalDecision(
        version="1",
        domain="agenttrust.approval-decision",
        approval_id="test",
        authorization_id="auth",
        intent_id="intent",
        cart_id="cart",
        decision="APPROVED",
        decided_at=timestamp,
        approver_id="user",
        approver_public_key="abc123",
    )
    
    # Verify canonical representation has sorted keys
    canonical = approval.canonical_bytes().decode('utf-8')
    
    # Keys should appear in sorted order
    approval_idx = canonical.find('"approval_id"')
    auth_idx = canonical.find('"authorization_id"')
    cart_idx = canonical.find('"cart_id"')
    decided_idx = canonical.find('"decided_at"')
    decision_idx = canonical.find('"decision"')
    domain_idx = canonical.find('"domain"')
    intent_idx = canonical.find('"intent_id"')
    
    indices = [
        ('approval_id', approval_idx),
        ('authorization_id', auth_idx),
        ('cart_id', cart_idx),
        ('decided_at', decided_idx),
        ('decision', decision_idx),
        ('domain', domain_idx),
        ('intent_id', intent_idx),
    ]
    
    # Verify all keys are present
    for name, idx in indices:
        assert idx >= 0, f"Key {name} not found in canonical representation"
    
    # Verify they appear in sorted order
    sorted_indices = sorted([idx for _, idx in indices])
    actual_indices = [idx for _, idx in indices]
    assert actual_indices == sorted_indices, \
        f"Keys not in sorted order: {[name for name, _ in indices]}"
