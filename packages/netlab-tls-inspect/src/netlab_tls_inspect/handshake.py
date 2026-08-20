# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Passive TLS metadata inspection: SNI-based egress policy.

Reads the Server Name Indication from a TLS ClientHello (visible in cleartext,
no interception) and applies an allowlist egress policy. Passive metadata only -
no MITM, no decryption. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class ClientHello:
    sni: str
    version: str = "TLS 1.3"


@dataclass
class SniPolicy:
    allowlist: set[str]

    def decision(self, hello: ClientHello) -> str:
        """Return 'allow' if the SNI is on the allowlist, else 'block'."""
        return "allow" if hello.sni in self.allowlist else "block"


def demo() -> None:
    """Reference scenario: allow corporate domains, block exfiltration host."""
    policy = SniPolicy(allowlist={"updates.example.com", "docs.example.com"})
    handshakes = [
        ClientHello("docs.example.com"),
        ClientHello("evil-exfil.example.net"),
    ]
    for hello in handshakes:
        decision = policy.decision(hello)
        icon = "FORWARD" if decision == "allow" else "DROP"
        verdict(icon, f"SNI {hello.sni} ({hello.version}) = {decision}")
