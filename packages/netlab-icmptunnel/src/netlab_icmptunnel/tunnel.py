# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""ICMP-tunnel codec: split data across echo payloads, reassemble it.

ICMP echo request/reply carry an arbitrary payload that is rarely inspected, so
a client and server exchange data by stuffing it into ping packets. Detection
watches for oversized or non-standard echo payloads. Pure logic - safe anywhere.
"""

from __future__ import annotations

from netlab_core import verdict

_CHUNK = 32


def encode(data: bytes) -> list[bytes]:
    """Split data into echo-payload-sized chunks."""
    return [data[i : i + _CHUNK] for i in range(0, len(data), _CHUNK)] or [b""]


def decode(chunks: list[bytes]) -> bytes:
    """Reassemble the exfiltrated data from echo payloads."""
    return b"".join(chunks)


def demo() -> None:
    """Reference scenario: exfiltrate a payload, then flag oversized echo."""
    chunks = encode(b"TOKEN=secret exfiltrated over ping")
    verdict("ALERT", f"tunnelled in {len(chunks)} echo payloads -> recovered {decode(chunks)!r}")
    print("\n--- detector flags oversized / non-standard echo payloads ---")
    verdict("ALERT", f"echo payload {len(chunks[0])}B carries data -> ICMP TUNNEL")
