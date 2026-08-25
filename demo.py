"""AgentTrust Milestone 1 Demo Script.

Demonstrates the core authorization flow with the stateless verifier architecture:
1. Valid transaction -> ALLOW
2. Transaction exceeding policy -> BLOCK
3. Policy update
4. Same transaction retried -> ALLOW
"""

import binascii
from datetime import datetime, timedelta, timezone

from agenttrust.engine import AuthorizationEngine
from agenttrust.crypto import generate_keypair, sign_mandate, verify_signature
from agenttrust.models import CartItem, CartMandate, IntentMandate, PolicyConfig


def print_result(step: str, result):
    print(f"\n--- {step} ---")
    print(f"Status: {result.status.value}")
    if result.status.value != "ALLOW":
        print(f"Reason: {result.reason}")
    if result.payment_mandate:
        print(f"Payment Mandate Created: {result.payment_mandate.payment_id}")
        print(f"Amount: {result.payment_mandate.amount_minor / 100} INR")
        print(f"System Signature: {result.payment_mandate.system_signature[:16]}...")
    print("-" * 40)


def main():
    print("Initializing AgentTrust Authorization Engine...")
    
    # Start with a strict policy: Max 5,000 INR
    initial_policy = PolicyConfig(
        max_transaction_amount_minor=500000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
        require_approval_above_minor=460000
    )
    engine = AuthorizationEngine(policy=initial_policy)
    print(f"Active Policy: Max {initial_policy.max_transaction_amount_minor / 100} INR")

    # Generate User Keys (External to Engine)
    user_private_key, user_public_key = generate_keypair()
    print("User Keypair generated.")

    # ---------------------------------------------------------
    # Step 1: Valid transaction -> ALLOW
    # ---------------------------------------------------------
    print("\n[Step 1] Attempting a valid 4,500 INR purchase...")
    
    # User creates intent locally
    intent1 = IntentMandate(
        description="Buy running shoes",
        max_amount_minor=1000000,  # User authorizes up to 10k
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    # User signs it locally
    sig1 = sign_mandate(intent1.canonical_bytes(), user_private_key)

    # Agent creates cart
    cart1 = CartMandate(
        intent_id=intent1.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Nike Shoes", price_minor=450000, quantity=1)],
        total_amount_minor=450000
    )
    
    # Agent submits to Engine
    result1 = engine.authorize(intent1, sig1, user_public_key, cart1)
    print_result("Step 1 Result", result1)

    # ---------------------------------------------------------
    # Step 2: Transaction exceeding policy -> BLOCK
    # ---------------------------------------------------------
    print("\n[Step 2] Attempting a 7,500 INR purchase (exceeds policy limit of 5,000)...")
    
    intent2 = IntentMandate(
        description="Buy premium shoes",
        max_amount_minor=1000000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    sig2 = sign_mandate(intent2.canonical_bytes(), user_private_key)

    cart2 = CartMandate(
        intent_id=intent2.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Premium Nike Shoes", price_minor=750000, quantity=1)],
        total_amount_minor=750000
    )
    
    result2 = engine.authorize(intent2, sig2, user_public_key, cart2)
    print_result("Step 2 Result", result2)

    # ---------------------------------------------------------
    # Step 3: Policy change
    # ---------------------------------------------------------
    print("\n[Step 3] Administrator updates policy to allow up to 10,000 INR...")
    updated_policy = PolicyConfig(
        max_transaction_amount_minor=1000000,
        merchant_allowlist=["Amazon", "Flipkart"],
        blocked_categories=["Weapons", "Gambling"],
    )
    engine.update_policy(updated_policy)
    print(f"New Policy: Max {updated_policy.max_transaction_amount_minor / 100} INR")

    # ---------------------------------------------------------
    # Step 4: Transaction retried -> ALLOW
    # ---------------------------------------------------------
    print("\n[Step 4] Retrying the 7,500 INR purchase with the new policy...")
    
    intent3 = IntentMandate(
        description="Buy premium shoes (Retry)",
        max_amount_minor=1000000,
        allowed_merchants=["Amazon"],
        allowed_categories=["Footwear"],
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
    )
    sig3 = sign_mandate(intent3.canonical_bytes(), user_private_key)

    cart3 = CartMandate(
        intent_id=intent3.intent_id,
        merchant="Amazon",
        category="Footwear",
        items=[CartItem(name="Premium Nike Shoes", price_minor=750000, quantity=1)],
        total_amount_minor=750000
    )
    
    result3 = engine.authorize(intent3, sig3, user_public_key, cart3)
    print_result("Step 4 Result", result3)

    print("\nDemo complete. All logic was executed deterministically via AgentTrust.")

if __name__ == "__main__":
    main()
