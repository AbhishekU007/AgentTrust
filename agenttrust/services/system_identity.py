"""Externally provisioned system signing identity and public-key registry."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class SystemIdentity:
    key_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey
    verification_keys: dict[str, Ed25519PublicKey]


_EPHEMERAL_PRIVATE_KEY: Ed25519PrivateKey | None = None


def load_system_identity() -> SystemIdentity:
    global _EPHEMERAL_PRIVATE_KEY
    configured = os.getenv("AGENTTRUST_SYSTEM_PRIVATE_KEY")
    if configured:
        try:
            raw = bytes.fromhex(configured)
            if len(raw) != 32:
                raise ValueError
            private_key = Ed25519PrivateKey.from_private_bytes(raw)
        except (ValueError, TypeError) as exc:
            raise RuntimeError("AGENTTRUST_SYSTEM_PRIVATE_KEY is invalid") from exc
    else:
        if _EPHEMERAL_PRIVATE_KEY is None:
            _EPHEMERAL_PRIVATE_KEY = Ed25519PrivateKey.generate()
        private_key = _EPHEMERAL_PRIVATE_KEY
    key_id = os.getenv("AGENTTRUST_SYSTEM_KEY_ID", "system-default")
    if not key_id.strip():
        raise RuntimeError("AGENTTRUST_SYSTEM_KEY_ID is invalid")
    public_key = private_key.public_key()
    keys: dict[str, Ed25519PublicKey] = {key_id: public_key}
    raw_historical = os.getenv("AGENTTRUST_SYSTEM_PUBLIC_KEYS", "")
    if raw_historical:
        try:
            historical = json.loads(raw_historical)
            if not isinstance(historical, dict):
                raise ValueError
            for historical_id, encoded in historical.items():
                if historical_id == key_id:
                    continue
                keys[str(historical_id)] = Ed25519PublicKey.from_public_bytes(
                    bytes.fromhex(str(encoded))
                )
        except (ValueError, TypeError, KeyError) as exc:
            raise RuntimeError("AGENTTRUST_SYSTEM_PUBLIC_KEYS is invalid") from exc
    return SystemIdentity(key_id, private_key, public_key, keys)
