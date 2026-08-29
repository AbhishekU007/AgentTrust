AgentTrust — Milestone 2

Purpose
-------
AgentTrust is a prototype authorization gateway that verifies user-signed IntentMandates, enforces deterministic policy, produces cryptographically-signed PaymentMandates when authorized, and optionally executes payments in Razorpay Test Mode.

Quick start
-----------
1. Copy the example env file:
   cp .env.example .env
2. (Optional) Fill in RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to enable real Razorpay Test Mode. If left empty, the adapter runs in MOCKED mode.
3. Start the API locally:
   uvicorn agenttrust.api:app --reload
4. Open the product demo in a browser:
   http://localhost:8000/
5. Run the test suite:
   python -m pytest

Demo workflow
-------------
The browser UI at `/` is the simplest end-to-end workflow for AgentTrust:
- configure a bearer token from `AGENTTRUST_API_TOKENS` if auth is enabled
- submit an intent and cart with a user public key and intent signature
- inspect the authorization decision (`ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`)
- if approval is required, submit a signed approval decision to `/approvals/{approval_id}/approve`
- continue the approved flow via `/approvals/{approval_id}/continue` to create the PaymentMandate
- call `/payments/{payment_id}/execute` only when the user explicitly approves the payment
- review `/audit` for the complete signed event trail

Environment variables (.env.example)
-----------------------------------
- AGENTTRUST_DB_URL: optional database URL. Defaults to sqlite:///./agenttrust.db
- RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET: Razorpay Test Mode credentials. When both are set, the application uses the real Razorpay Test API. Leave blank for local/mock mode.
- LOG_LEVEL: logging verbosity (DEBUG, INFO, WARNING, ERROR)
- AGENTTRUST_API_TOKENS: optional JSON map of bearer tokens to principal IDs.
- AGENTTRUST_SYSTEM_PRIVATE_KEY: externally provisioned raw Ed25519 private key hex.
- AGENTTRUST_SYSTEM_KEY_ID: non-secret active signing-key identifier.
- AGENTTRUST_SYSTEM_PUBLIC_KEYS: JSON map of historical key IDs to public-key hex.

Authentication
--------------
When `AGENTTRUST_API_TOKENS` is configured, authorization, approval, continuation,
execution, and audit routes require `Authorization: Bearer <token>`. The server
derives the principal from the configured token; request body actor/account fields
are not trusted. `/health` is intentionally public and only checks database
connectivity. With no token configuration, the pre-M3.9 local demo mode remains
available for backwards-compatible development tests.

System key identity and rotation
--------------------------------
Payment mandates persist only the non-secret `system_key_id`. The active private
key is supplied externally through configuration. Retired public keys may be
listed in `AGENTTRUST_SYSTEM_PUBLIC_KEYS` so old mandates remain verifiable after
rotation. Unknown or unavailable key IDs fail closed. Private keys and bearer
tokens are never persisted, audited, logged, or returned by the API.

Razorpay adapter: mock vs real
-----------------------------
- Mocked mode (default when RAZORPAY_KEY_ID or RAZORPAY_KEY_SECRET are empty):
  - The adapter returns deterministic fake order IDs (order_mock_<hex>). Use this for local development and tests.
- Real Razorpay Test Mode: set both RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to your Razorpay test credentials. The adapter will call the Razorpay Orders API and persist the returned order ID.

Reservation semantics and idempotency
------------------------------------
To prevent duplicate external orders (double-spend), AgentTrust uses a small DB-backed reservation step before creating a Razorpay order:

1. Adapter attempts to insert a consumed nonce record: (mandate_type="payment_execution", nonce=payment_id). This is an atomic DB insert guarded by a unique constraint.
2. If the insert succeeds, the process "owns" the right to create the external order and proceeds to call Razorpay.
3. If the insert fails due to uniqueness (IntegrityError), it means another worker/process already reserved or created the order. The adapter returns an error code `concurrent_execution_in_progress`; client should retry with backoff, or call the /payments/{payment_id}/execute endpoint again later to reuse the persisted order.
4. On Razorpay API failure, the reservation is released (deleted) so subsequent retries can attempt creation again.

Client retry guidance
---------------------
- If a client receives `concurrent_execution_in_progress`, it should back off (exponential backoff) and retry.
- Do NOT retry aggressively — prefer progressive backoff to reduce the thundering herd.
- The payment_id (PaymentMandate ID) is the idempotency identity for payment creation. Clients may store it and retry the same idempotency identity safely.

Audit & transactional notes
---------------------------
- Audit events are persistent and tamper-evident via a SHA-256 hash chain. The audit chain survives reload and detects tampering.
- Currently, audit event persistence is committed separately from some decision/payment writes (single-commit-per-repo). This simplifies early development but can lead to temporary out-of-sync states if a subsequent commit fails. Recommended future improvement: group decision + audit + payment metadata writes into a single DB transaction for atomicity.

Concurrency and durability
-------------------------
- Durable replay protection for intents/carts uses DB uniqueness constraints and repository-level atomic insert+commit semantics. This prevents replays being consumed twice.
- The payment reservation ensures a single creator for Razorpay orders across concurrent requests. A parallel test suite exercises these behaviors.

Testing
-------
- Run the full test suite with: python -m pytest
- The project includes concurrency tests that validate: concurrent authorize requests, concurrent payment execution, and Razorpay failure→retry behavior.

Security notes
--------------
- The user's private key must never be stored on AgentTrust; the system only receives the user's public key and signature and verifies them on every request.
- AgentTrust signs PaymentMandates with its system key generated at startup (for demo). In a production design, the system key must be managed securely and rotated per policy.

Contact / Next steps
--------------------
- To harden the system further, consider:
  - Grouping audit + decision + payment persistence into a single DB transaction
  - Leaving a failure-marker with TTL on reservations to avoid repeated retries when Razorpay is degraded
  - Adding operational observability for reservation failures and API latency
