# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""TTL insertion/evasion simulator (Ptacek-Newsham): the flow-normalization core.

A segment reaches a node only while its TTL outlasts the hop distance. If the IDS
is closer than the host, the attacker can send a segment with a TTL that reaches
the IDS but expires before the host: the IDS *inserts* bytes into its stream that
the host never sees. A normalizer that enforces a minimum TTL (>= the host's
distance) makes the IDS see exactly what the host sees. Pure logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass(frozen=True)
class Segment:
    ttl: int
    data: bytes


def reconstruct(segments: list[Segment], observer_hop: int) -> bytes:
    """Reconstruct the byte stream a node at ``observer_hop`` actually receives."""
    return b"".join(s.data for s in segments if s.ttl > observer_hop)


def demo() -> None:
    """Reference scenario: an inserted low-TTL segment the host never sees."""
    ids_hop, host_hop = 1, 5
    segments = [Segment(64, b"GET /"), Segment(3, b"BENIGN"), Segment(64, b"evil")]
    ids_view = reconstruct(segments, ids_hop)
    host_view = reconstruct(segments, host_hop)
    print(f"IDS  sees: {ids_view!r}")
    print(f"host sees: {host_view!r}")
    if ids_view != host_view:
        verdict("ALERT", "IDS and host disagree (TTL insertion) -> EVASION")
    print("\n--- normalizer enforces a minimum TTL (>= host distance) ---")
    normalized = [s for s in segments if s.ttl > host_hop]
    if reconstruct(normalized, ids_hop) == host_view:
        verdict("FORWARD", "normalized: IDS now sees exactly what the host sees")
