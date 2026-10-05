"""Canonical JSON and Ed25519 verification for watchpost commands.

The signature covers the canonical JSON of the command object: keys sorted, no spaces,
UTF-8 with non-ASCII characters kept as is. The signature travels beside the command as
standard base64 of the 64 raw bytes. The `cryptography` package is the optional `control`
extra and is imported only when a signature is checked.
"""

from __future__ import annotations

import base64
import binascii
import json


class SigningUnavailable(Exception):
    """The cryptography package is not installed, so nothing can be verified."""


def canonical_json(command: object) -> bytes:
    return json.dumps(command, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def verify_signature(command: object, signature_b64: object, public_key: bytes) -> bool:
    """True only for a valid signature. Any malformed input is simply False."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise SigningUnavailable("install the control extra: pip install 'hostwatch[control]'") from exc
    if not isinstance(signature_b64, str):
        return False
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        message = canonical_json(command)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (binascii.Error, ValueError, TypeError, InvalidSignature):
        return False
    return True
