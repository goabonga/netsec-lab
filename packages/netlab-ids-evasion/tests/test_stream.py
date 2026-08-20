# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the TTL insertion/evasion simulator."""

from __future__ import annotations

from netlab_ids_evasion.stream import Segment, reconstruct

SEGS = [Segment(64, b"GET /"), Segment(3, b"BENIGN"), Segment(64, b"evil")]


def test_ids_and_host_diverge() -> None:
    assert reconstruct(SEGS, observer_hop=1) == b"GET /BENIGNevil"  # IDS sees the insertion
    assert reconstruct(SEGS, observer_hop=5) == b"GET /evil"  # host does not


def test_normalization_matches_host() -> None:
    normalized = [s for s in SEGS if s.ttl > 5]
    assert reconstruct(normalized, observer_hop=1) == reconstruct(SEGS, observer_hop=5)
