# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""QUIC header classifier: what a middlebox can and cannot see.

QUIC runs over UDP. Its first byte's high bit marks a long-header packet
(Initial/Handshake), where the version and a partly-visible ClientHello (SNI) can
be fingerprinted; short-header packets are fully encrypted and opaque. Inspection
therefore relies on the Initial, not the stream. Pure logic - safe anywhere.
"""

from __future__ import annotations

from netlab_core import verdict


def is_long_header(first_byte: int) -> bool:
    """Return True for a QUIC long-header (Initial/Handshake) packet."""
    return bool(first_byte & 0x80)


def classify(first_byte: int) -> str:
    """Describe what is inspectable in a QUIC packet from its first byte."""
    if is_long_header(first_byte):
        return "long header (Initial/Handshake): version + SNI fingerprintable"
    return "short header: fully encrypted, opaque to inspection"


def demo() -> None:
    """Reference scenario: a QUIC Initial vs an established short-header packet."""
    verdict("ALERT", f"0xC0 -> {classify(0xC0)}")
    verdict("FORWARD", f"0x40 -> {classify(0x40)}")
