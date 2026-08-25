"""Intent ↔ Cart consistency verification.

Checks whether the cart matches what the USER authorized in their intent.
"""

from __future__ import annotations

from agenttrust.models import CartMandate, CheckDetail, IntentMandate


def verify_intent_cart_consistency(
    intent: IntentMandate, cart: CartMandate
) -> tuple[bool, list[CheckDetail]]:
    """
    Verify cart is consistent with parent intent.
    """
    checks: list[CheckDetail] = []

    # 1. Intent ID linkage
    id_match = cart.intent_id == intent.intent_id
    checks.append(
        CheckDetail(
            check_name="intent_linkage",
            passed=id_match,
            reason=(
                "Cart correctly references parent intent"
                if id_match
                else f"Cart references intent '{cart.intent_id}' but expected '{intent.intent_id}'"
            ),
            actual_value=cart.intent_id,
            allowed_value=intent.intent_id,
        )
    )

    # 2. Amount: cart total <= intent max
    amount_ok = cart.total_amount_minor <= intent.max_amount_minor
    checks.append(
        CheckDetail(
            check_name="intent_amount",
            passed=amount_ok,
            reason=(
                f"Cart total {cart.total_amount_minor} within authorized max {intent.max_amount_minor}"
                if amount_ok
                else f"Cart total {cart.total_amount_minor} exceeds authorized max {intent.max_amount_minor}"
            ),
            actual_value=cart.total_amount_minor,
            allowed_value=intent.max_amount_minor,
        )
    )

    # 3. Merchant
    allowed_merchants_lower = [m.lower() for m in intent.allowed_merchants]
    merchant_ok = cart.merchant.lower() in allowed_merchants_lower
    checks.append(
        CheckDetail(
            check_name="intent_merchant",
            passed=merchant_ok,
            reason=(
                f"Merchant '{cart.merchant}' is authorized"
                if merchant_ok
                else f"Merchant '{cart.merchant}' not in authorized list: {intent.allowed_merchants}"
            ),
            actual_value=cart.merchant,
            allowed_value=intent.allowed_merchants,
        )
    )

    # 4. Category
    allowed_cats_lower = [c.lower() for c in intent.allowed_categories]
    category_ok = cart.category.lower() in allowed_cats_lower
    checks.append(
        CheckDetail(
            check_name="intent_category",
            passed=category_ok,
            reason=(
                f"Category '{cart.category}' is authorized"
                if category_ok
                else f"Category '{cart.category}' not in authorized list: {intent.allowed_categories}"
            ),
            actual_value=cart.category,
            allowed_value=intent.allowed_categories,
        )
    )

    # 5. Currency match
    currency_ok = cart.currency == intent.currency
    checks.append(
        CheckDetail(
            check_name="intent_currency",
            passed=currency_ok,
            reason=(
                f"Currency matches: {cart.currency}"
                if currency_ok
                else f"Currency mismatch: cart={cart.currency}, intent={intent.currency}"
            ),
            actual_value=cart.currency,
            allowed_value=intent.currency,
        )
    )

    # 6. Item total consistency
    computed_total = sum(item.price_minor * item.quantity for item in cart.items)
    total_consistent = computed_total == cart.total_amount_minor
    checks.append(
        CheckDetail(
            check_name="cart_total_consistency",
            passed=total_consistent,
            reason=(
                f"Cart items total {computed_total} matches declared total {cart.total_amount_minor}"
                if total_consistent
                else f"Cart items total {computed_total} != declared total {cart.total_amount_minor}"
            ),
            actual_value=computed_total,
            allowed_value=cart.total_amount_minor,
        )
    )

    all_passed = all(c.passed for c in checks)
    return all_passed, checks
