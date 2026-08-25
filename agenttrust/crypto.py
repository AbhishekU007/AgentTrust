"""Ed25519 digital signature operations for mandate signing and verification.

Why Ed25519:
- Deterministic signatures (same input → same signature, no randomness needed)
- Fast: ~60k signatures/sec, ~20k verifications/sec
- Small keys (32 bytes) and signatures (64 bytes)
- No configuration parameters to get wrong (unlike RSA/ECDSA)
- Widely audited, included in the `cryptography` library

The signing flow:
    mandate data → canonical JSON → UTF-8 bytes → Ed25519 sign → 64-byte signature

Verification reproduces the exact same canonical bytes and checks the signature.
Any mutation of the signed fields produces different bytes → verification fails.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_mandate(data: bytes, private_key: Ed25519PrivateKey) -> bytes:
    """
    Sign canonical mandate bytes with Ed25519.

    Args:
        data: Canonical byte representation of a mandate (from canonical_bytes()).
        private_key: The signer's Ed25519 private key.

    Returns:
        64-byte Ed25519 signature.
    """
    return private_key.sign(data)


def verify_signature(
    data: bytes, signature: bytes, public_key: Ed25519PublicKey
) -> bool:
    """
    Verify an Ed25519 signature against the provided canonical data.

    Fail-closed: any error during verification returns False.
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:
        # InvalidSignature, malformed data, or any other error → reject
        return False


def serialize_private_key(private_key: Ed25519PrivateKey) -> bytes:
    """Serialize private key to PEM bytes (for storage)."""
    return private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )


def serialize_public_key(public_key: Ed25519PublicKey) -> bytes:
    """Serialize public key to PEM bytes (for distribution)."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
