# AgentTrust Architecture

This document explains the important architectural decisions for the AgentTrust deterministic authorization core (Milestone 1).

## 1. Why Ed25519 for Digital Signatures?
Ed25519 is chosen over RSA or ECDSA because it produces deterministic signatures (the same input always produces the exact same signature without relying on random number generators) and is fast. The keys are small (32 bytes) and signatures are compact (64 bytes). It is widely audited and safe from many common cryptographic pitfalls.

## 2. Why Canonical Serialization?
We do not sign mutable Pydantic objects directly because their representation in memory or string format can vary based on field ordering, null values, etc. We use a canonical JSON serialization (sorting keys, excluding the signature itself) to ensure a deterministic UTF-8 byte stream. This means any mutation to any signed field produces a completely different byte representation, which immediately invalidates the Ed25519 signature.

## 3. Why Deterministic Policy Instead of an LLM?
Financial authorization must be reliable and fail-closed. LLMs are probabilistic, prone to hallucinations, and vulnerable to prompt injection attacks. AgentTrust explicitly isolates the LLM (the AI Buyer Agent) from the authorization decision. The AuthorizationEngine is entirely deterministic: it evaluates hard rules, intent constraints, and limits to yield a definitive `ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`.

## 4. Why Intent/Cart Consistency is Separate from Policy?
Separation of concerns:
*   **Intent ↔ Cart Consistency Engine:** Evaluates whether the cart the agent wants to execute matches what the *user explicitly authorized* (e.g., amount is under the authorized limit, merchant is allowed, currency matches).
*   **Policy Engine:** Enforces broader *system or account-level rules* across all transactions (e.g., daily spending limits, velocity limits, global merchant allowlists, approval thresholds).

This makes responsibilities clear and avoids duplicating logic.

## 5. How Replay Protection Works
Replay tracking is scoped specifically by mandate type. For example, a consumed intent is tracked as `("intent", nonce)`. This prevents cross-type collisions (e.g., an intent and a cart using the same nonce). A previously consumed mandate cannot be executed again because the engine verifies freshness against the `ReplayRegistry` before proceeding.

## 6. How the Audit Hash Chain Works
AgentTrust maintains a tamper-evident audit log. 
Each event's payload includes the `previous_hash`. The hash of the current event is computed as:
`hash_n = SHA256(event_n_payload)` (where `event_n_payload` contains `hash_{n-1}`).
This creates a linked chain where every hash transitively depends on all preceding events. The `verify_chain()` function can reliably detect if any event was modified, deleted, or if the order was swapped.

## 7. Why the System Fails Closed
If a critical verification or security condition cannot be established (e.g., invalid signature, expired mandate, malformed data), the system defaults to `BLOCK`. It never approves a transaction just because an error occurred. This ensures that unauthorized payments cannot slip through due to unexpected states or missing data.

## 8. PaymentMandate Semantics
A `PaymentMandate` represents an *authorized* payment instruction. It is only created at the very end of the authorization flow, strictly after all security, verification, and policy checks pass and yield an `ALLOW` decision.
