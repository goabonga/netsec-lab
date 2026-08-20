# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Covert-channel simulator: encode data in a header field, destroy it by normalizing.

Two bytes of a hidden message ride in each IP Identification field; a receiver
that knows the scheme reassembles them. Content inspection sees nothing. A header
normalizer that rewrites the ID field destroys the channel. Pure logic.
"""

from __future__ import annotations

from netlab_core import verdict


def encode(message: bytes) -> list[int]:
    """Encode a message into a list of 16-bit IP ID values (2 bytes each)."""
    padded = message + (b"\x00" if len(message) % 2 else b"")
    return [int.from_bytes(padded[i : i + 2], "big") for i in range(0, len(padded), 2)]


def decode(ids: list[int]) -> bytes:
    """Recover the message from the IP ID values."""
    return b"".join(i.to_bytes(2, "big") for i in ids).rstrip(b"\x00")


def normalize(ids: list[int]) -> list[int]:
    """Rewrite the ID field (as a normalizer would), destroying the channel."""
    return [0 for _ in ids]


def demo() -> None:
    """Reference scenario: exfiltrate a secret, then normalize the channel away."""
    secret = b"TOKEN=42"
    ids = encode(secret)
    verdict("ALERT", f"exfiltrated {secret!r} in {len(ids)} IP ID fields -> {decode(ids)!r}")
    print("\n--- header normalizer rewrites the ID field ---")
    recovered = decode(normalize(ids))
    verdict("FORWARD" if recovered != secret else "DROP", f"after normalization: {recovered!r}")
