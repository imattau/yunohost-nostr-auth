"""NIP-01 event structure and secp256k1/Schnorr signature verification.

Verifies that a signed Nostr event actually attests to a given challenge:
correct event id (hash of the serialized event), valid Schnorr signature
over that id, and that the event content matches the expected
action/domain/nonce (PLAN.md Phase 3).

Never accepts or stores a private key - only public keys and signed events.
"""

from __future__ import annotations


def verify_event_signature(event: dict) -> bool:
    """Verify `event["sig"]` is a valid Schnorr signature by `event["pubkey"]`
    over `event["id"]`, and that `event["id"]` matches the NIP-01 serialization
    of the event's other fields.

    TODO: implement using coincurve (see pyproject.toml).
    """
    raise NotImplementedError
