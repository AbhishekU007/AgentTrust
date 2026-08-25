"""Deterministic policy engine — global/account-level authorization rules."""

from __future__ import annotations

from agenttrust.models import (
    AuthorizationResult,
    AuthorizationStatus,
    CartMandate,
    CheckDetail,
    IntentMandate,
    PolicyConfig,
)


def evaluate_policy(
    intent: IntentMandate,
    cart: CartMandate,
    policy: PolicyConfig,
    recent_transaction_count: int = 0,
) -> AuthorizationResult:
    checks: list[CheckDetail] = []
    has_block = False
    has_require_approval = False

    # -- 1. Transaction amount hard limit (BLOCK) --
    if policy.max_transaction_amount_minor is not None:
        ok = cart.total_amount_minor <= policy.max_transaction_amount_minor
        checks.append(
            CheckDetail(
                check_name="transaction_limit",
                passed=ok,
                reason=(
                    f"Amount {cart.total_amount_minor} within limit {policy.max_transaction_amount_minor}"
                    if ok
                    else f"Amount {cart.total_amount_minor} exceeds hard limit {policy.max_transaction_amount_minor}"
                ),
                actual_value=cart.total_amount_minor,
                allowed_value=policy.max_transaction_amount_minor,
            )
        )
        if not ok:
            has_block = True

    # -- 2. Merchant allowlist (BLOCK) --
    if policy.merchant_allowlist is not None:
        allowlist_lower = [m.lower() for m in policy.merchant_allowlist]
        ok = cart.merchant.lower() in allowlist_lower
        checks.append(
            CheckDetail(
                check_name="merchant_allowlist",
                passed=ok,
                reason=(
                    f"Merchant '{cart.merchant}' is in allowlist"
                    if ok
                    else f"Merchant '{cart.merchant}' not in allowlist: {policy.merchant_allowlist}"
                ),
                actual_value=cart.merchant,
                allowed_value=policy.merchant_allowlist,
            )
        )
        if not ok:
            has_block = True

    # -- 3. Category restrictions (BLOCK) --
    if policy.blocked_categories is not None:
        blocked_lower = [c.lower() for c in policy.blocked_categories]
        is_blocked = cart.category.lower() in blocked_lower
        checks.append(
            CheckDetail(
                check_name="category_restriction",
                passed=not is_blocked,
                reason=(
                    f"Category '{cart.category}' is permitted"
                    if not is_blocked
                    else f"Category '{cart.category}' is blocked"
                ),
                actual_value=cart.category,
                allowed_value=policy.blocked_categories,
            )
        )
        if is_blocked:
            has_block = True

    # -- 4. Velocity limit (BLOCK) --
    if policy.velocity_limit is not None:
        ok = recent_transaction_count < policy.velocity_limit
        checks.append(
            CheckDetail(
                check_name="velocity_limit",
                passed=ok,
                reason=(
                    f"{recent_transaction_count} transactions in window (limit: {policy.velocity_limit})"
                    if ok
                    else f"Velocity exceeded: {recent_transaction_count} transactions in window (limit: {policy.velocity_limit})"
                ),
                actual_value=recent_transaction_count,
                allowed_value=policy.velocity_limit,
            )
        )
        if not ok:
            has_block = True

    # -- 5. Approval threshold (REQUIRE_APPROVAL) --
    if policy.require_approval_above_minor is not None and not has_block:
        needs_approval = cart.total_amount_minor > policy.require_approval_above_minor
        checks.append(
            CheckDetail(
                check_name="approval_threshold",
                passed=not needs_approval,
                reason=(
                    f"Amount {cart.total_amount_minor} below approval threshold {policy.require_approval_above_minor}"
                    if not needs_approval
                    else f"Amount {cart.total_amount_minor} exceeds approval threshold {policy.require_approval_above_minor} — manual approval required"
                ),
                actual_value=cart.total_amount_minor,
                allowed_value=policy.require_approval_above_minor,
            )
        )
        if needs_approval:
            has_require_approval = True

    if has_block:
        failed = [c for c in checks if not c.passed]
        return AuthorizationResult(
            status=AuthorizationStatus.BLOCK,
            reason="; ".join(c.reason for c in failed),
            intent_id=intent.intent_id,
            cart_id=cart.cart_id,
            checks=checks,
        )

    if has_require_approval:
        approval_checks = [c for c in checks if c.check_name == "approval_threshold" and not c.passed]
        return AuthorizationResult(
            status=AuthorizationStatus.REQUIRE_APPROVAL,
            reason="; ".join(c.reason for c in approval_checks),
            intent_id=intent.intent_id,
            cart_id=cart.cart_id,
            checks=checks,
        )

    return AuthorizationResult(
        status=AuthorizationStatus.ALLOW,
        reason="All policy checks passed",
        intent_id=intent.intent_id,
        cart_id=cart.cart_id,
        checks=checks,
    )
