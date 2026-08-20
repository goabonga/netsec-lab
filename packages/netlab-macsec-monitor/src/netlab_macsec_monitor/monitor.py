# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""MACsec link monitor: flag ports that lost protection or use a weak cipher.

Watches per-port MACsec state and alerts when a protected link falls back to
cleartext (SecTAG absent) or negotiates a cipher outside the approved set - the
downgrade an attacker forces before tapping the link. Pure logic - safe anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict

STRONG_CIPHERS = {"GCM-AES-256", "GCM-AES-128", "GCM-AES-XPN-256", "GCM-AES-XPN-128"}


@dataclass
class PortState:
    port: str
    macsec_active: bool
    cipher: str = "GCM-AES-256"


def check(state: PortState) -> str:
    """Return 'protected', 'cleartext' or 'weak' for a port."""
    if not state.macsec_active:
        return "cleartext"
    if state.cipher not in STRONG_CIPHERS:
        return "weak"
    return "protected"


def demo() -> None:
    """Reference scenario: one protected port, one downgraded to cleartext."""
    for state in (
        PortState("Gi0/1", macsec_active=True, cipher="GCM-AES-256"),
        PortState("Gi0/2", macsec_active=False),
        PortState("Gi0/3", macsec_active=True, cipher="NULL"),
    ):
        status = check(state)
        if status == "protected":
            verdict("FORWARD", f"{state.port}: MACsec {state.cipher}")
        else:
            verdict("ALERT", f"{state.port}: {status} -> link no longer trustworthy")
