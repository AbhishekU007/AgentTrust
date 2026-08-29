# AgentTrust

### Authorization Infrastructure for Autonomous Payments

> An authorization boundary between autonomous intent and financial execution.

![AgentTrust Dashboard](assets\header.png)

AgentTrust is a security-focused authorization gateway for autonomous payment workflows.

It sits between an AI agent or application and a payment provider, verifying cryptographically signed user intent, enforcing deterministic authorization policy, requiring explicit approval for higher-risk transactions, and keeping payment execution separate from authorization.

> **Core principle:** An agent can request a payment. AgentTrust decides whether that request is authorized, and payment execution remains an explicit action.

---

## Architecture
![AgentTrust Architecture](assets\architecture.png)

---

## Core Workflow

```text
IntentMandate
     │
     ▼
Signature Verification
     │
     ▼
Deterministic Policy Evaluation
     │
     ├──────────────┐
     ▼              ▼
   BLOCK          ALLOW
                      │
                      ▼
               PaymentMandate
                      │
                      ▼
             Explicit Execution
                      │
                      ▼
                 Razorpay / Mock
```

For transactions above the configured approval threshold:

```text
Intent
  │
  ▼
Authorization
  │
  ▼
REQUIRE_APPROVAL
  │
  ▼
Signed Approval
  │
  ▼
Approved Continuation
  │
  ▼
PaymentMandate
  │
  ▼
Explicit Payment Execution
  │
  ▼
Razorpay / Mock
```

Authorization, approval, and execution are deliberately separate stages.

---

## What AgentTrust Provides

### Cryptographically Signed Intent

Clients submit an `IntentMandate` and `CartMandate` together with:

- Ed25519 public key
- Ed25519 signature
- Intent identifier
- Expiration
- Nonce
- Maximum authorized amount
- Currency
- Allowed merchants
- Allowed categories

AgentTrust verifies the signature before evaluating the request.

**User private keys are never stored by AgentTrust.**

### Deterministic Policy Enforcement

Authorization is evaluated through deterministic policy checks including:

- Expiration
- Signature validity
- Intent/cart linkage
- Authorized amount
- Merchant allowlists
- Category restrictions
- Currency
- Cart total consistency
- Transaction limits
- Velocity limits
- Approval thresholds

The authorization result is one of:

```text
ALLOW
BLOCK
REQUIRE_APPROVAL
```

### Approval Gating

Transactions requiring additional authorization create a persistent approval request.

Approval decisions are themselves cryptographically signed using Ed25519.

AgentTrust verifies:

- Approval state
- Approval expiration
- Authenticated principal
- Decision maker identity
- Approval signature
- Signed decision contents

An approval must be explicitly continued before a `PaymentMandate` is created.

### Explicit Payment Execution

Authorization does **not** automatically execute a payment.

After an approved flow produces a `PaymentMandate`, payment execution requires an explicit request:

```http
POST /payments/{payment_id}/execute
```

Before execution, AgentTrust validates the payment mandate, authorization state, approval state, expiration, and system signature.

---

## Authentication & Identity

Optional bearer authentication is provided through:

```text
AGENTTRUST_API_TOKENS
```

Example:

```json
{
  "demo-token": "demo-user",
  "ops-token": "operator"
}
```

Protected routes receive:

```http
Authorization: Bearer <token>
```

The authenticated principal is derived from the configured token.

Client-supplied actor/account fields are **not trusted** for identity-sensitive authorization decisions.

`/health` remains publicly accessible.

For local development, leaving `AGENTTRUST_API_TOKENS` empty preserves the legacy local development mode.

---

## Cryptography

AgentTrust uses **Ed25519** for signing and verification.

The system supports signed:

- `IntentMandate`
- `ApprovalDecision`
- `PaymentMandate`

Signed payloads use deterministic canonical JSON serialization so that both sides operate on the same signing bytes.

### Canonicalization

Canonicalization:

- Sorts JSON keys
- Uses compact separators
- Removes `None` values
- Normalizes timestamps to UTC
- Produces deterministic serialized bytes

The system signing key is externally provisioned.

`PaymentMandate`s persist the non-secret `system_key_id`, while private keys are never persisted.

Historical public keys can be configured to support system-key rotation.

Unknown or unavailable system key IDs fail closed.

---

## Audit Trail

AgentTrust persists authorization, approval, payment, and related security events.

Audit events form a SHA-256 hash chain:

```text
Event N-1
    │
    ▼
Event N
    │
    ▼
Event N+1
```

Each event references the previous event's hash.

The chain can be verified through:

```http
GET /audit
```

Tampering with the event sequence or event contents causes verification to fail.

---

## Payment Integration

AgentTrust includes a **Razorpay payment adapter**.

### Mock Mode

When Razorpay credentials are not configured, the adapter operates in mocked mode.

Example result:

```json
{
  "success": true,
  "order_id": "order_mock_dff4b599",
  "message": "Razorpay order created",
  "is_mocked": true
}
```

Mock mode is intended for local development and testing.

### Razorpay Test Mode

Configure:

```text
RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET
```

When both are present, AgentTrust uses the Razorpay Orders API in Test Mode and persists the resulting order ID.

---

## Replay, Idempotency & Concurrency

AgentTrust uses persistent database constraints and reservation semantics to protect payment workflows.

### Replay Protection

Intent and cart replay protection uses database uniqueness constraints and repository-level atomic insertion.

### Payment Execution Reservation

Before creating an external payment order, the payment execution identity is atomically reserved.

This prevents concurrent requests from independently creating duplicate external orders.

If another worker already owns the reservation, the API can return:

```text
concurrent_execution_in_progress
```

Clients should retry with progressive backoff.

The `payment_id` acts as the idempotency identity for payment creation.

---

## Browser Demo

AgentTrust includes an interactive browser demonstration at:

```text
/
```

The demo provides a complete workflow for:

- Bearer-token authentication
- Intent and cart configuration
- Browser-side Ed25519 signing
- Authorization
- Approval
- Signed approval decisions
- Approval continuation
- Explicit payment execution
- Audit verification
- API response inspection

The browser demo uses the same signing formats validated by the backend.

---

## API

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service/database health check |
| `GET` | `/` | Interactive browser demo |
| `POST` | `/authorize` | Verify intent and evaluate policy |
| `GET` | `/approvals/{approval_id}` | Retrieve an approval |
| `POST` | `/approvals/{approval_id}/approve` | Approve a request with a signed decision |
| `POST` | `/approvals/{approval_id}/reject` | Reject an approval |
| `POST` | `/approvals/{approval_id}/continue` | Continue an approved authorization |
| `POST` | `/payment-mandates/{payment_id}/execute` | Execute a payment mandate |
| `POST` | `/payments/{payment_id}/execute` | Explicitly execute a payment |
| `GET` | `/audit` | Verify and retrieve the audit trail |

Interactive API documentation is available at:

```text
/docs
```

---

## Quick Start

### 1. Configure the environment

Copy the example environment file:

```bash
cp .env.example .env
```

### 2. Start the API

```bash
uvicorn agenttrust.api:app --reload
```

### 3. Open the browser demo

```text
http://localhost:8000/
```

### 4. Open the API documentation

```text
http://localhost:8000/docs
```

### 5. Run the tests

```bash
python -m pytest
```

---

## Environment Variables

The application supports:

```text
AGENTTRUST_DB_URL
AGENTTRUST_API_TOKENS

AGENTTRUST_SYSTEM_PRIVATE_KEY
AGENTTRUST_SYSTEM_KEY_ID
AGENTTRUST_SYSTEM_PUBLIC_KEYS

RAZORPAY_KEY_ID
RAZORPAY_KEY_SECRET

LOG_LEVEL
```

> **Security:** Never commit real credentials, bearer tokens, private keys, or local databases.

---

## Testing

The test suite covers:

- Cryptographic signing and verification
- Deterministic authorization policy
- API integration
- Approval persistence
- Approval signatures
- Approval continuation
- Authenticated identity enforcement
- Explicit payment execution
- Concurrent authorization
- Concurrent payment execution
- Replay protection
- Razorpay failure and retry behavior
- Transactional durability
- Browser approval-signature compatibility
- AI/buyer integration

### Verified Release State

**241 tests passing.**

---

## Project Structure

```text
AgentTrust/
├── agenttrust/
│   ├── api.py
│   ├── models.py
│   ├── crypto.py
│   ├── engine.py
│   ├── policy.py
│   ├── verification.py
│   ├── audit.py
│   ├── catalog.py
│   ├── ai_buyer.py
│   ├── ai_integration.py
│   ├── llm_models.py
│   ├── llm_provider.py
│   ├── db/
│   ├── repositories/
│   ├── services/
│   └── payments/
├── tests/
├── demo.py
├── .env.example
├── README.md
└── requirements.txt
```

---

## Current Limitations

AgentTrust is a **prototype authorization gateway** and is not presented as a production-certified payment network.

Known areas for future hardening include:

- Grouping audit, decision, and payment persistence into a single atomic database transaction
- Stronger operational observability
- Improved handling of long-lived payment reservation failures
- Production-grade secret and key management
- Deployment and infrastructure hardening

These limitations are separate from the authorization, approval, signature-verification, and explicit-execution controls currently implemented.

---

## Design Principle

AgentTrust is built around a simple separation of responsibilities:

```text
Intent
  ≠
Authorization
  ≠
Approval
  ≠
Execution
```

An agent can express an intent.

AgentTrust verifies that intent and evaluates it against deterministic policy.

Higher-risk transactions can require a cryptographically signed approval.

Only an explicit execution action can initiate payment.

> **AgentTrust provides the authorization boundary between autonomous intent and financial execution.**

---

## Security Philosophy

AgentTrust is designed around **least trust and explicit authorization**:

1. **Intent is signed** — requests originate from verifiable cryptographic intent.
2. **Policy is deterministic** — authorization decisions are governed by explicit rules.
3. **Approval is separate** — higher-risk actions require an additional signed decision.
4. **Execution is explicit** — authorization never silently triggers payment execution.
5. **Identity is authenticated** — sensitive authorization decisions use the authenticated principal rather than untrusted client fields.
6. **Auditability is preserved** — security-relevant events are persisted in a tamper-evident hash chain.
7. **Secrets stay external** — private keys and credentials are not persisted by the authorization layer.

---

## Status

**Prototype / Verified Release**

- Authorization gateway: Implemented
- Ed25519 signing: Implemented
- Deterministic policy enforcement: Implemented
- Approval workflow: Implemented
- Explicit payment execution: Implemented
- Razorpay integration: Implemented
- Mock payment mode: Implemented
- Replay protection: Implemented
- Concurrent execution protection: Implemented
- Hash-chained audit trail: Implemented
- Browser demo: Implemented
- Test suite: **241 tests passing**
