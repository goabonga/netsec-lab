# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""SNMP community-string simulator: why v1/v2c falls to a wordlist.

SNMP v1/v2c authenticate only with a plaintext community string, so a short
wordlist recovers it and walks the MIB. SNMPv3 adds real user authentication and
privacy, and management ACLs restrict who may ask. Pure logic - safe anywhere.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class Agent:
    community: str = "public"
    v3: bool = False

    def check(self, community: str) -> bool:
        """Return True if the community grants access (never for a v3 agent)."""
        return not self.v3 and community == self.community


def brute(agent: Agent, wordlist: Iterable[str]) -> str | None:
    """Return the community that authenticates, or None."""
    for candidate in wordlist:
        if agent.check(candidate):
            return candidate
    return None


def demo() -> None:
    """Reference scenario: brute a v2c agent, then fail against v3."""
    wordlist = ["public", "private", "cisco", "admin"]
    print("--- 1) SNMP v2c agent with a guessable community ---")
    found = brute(Agent(community="private"), wordlist)
    verdict("ALERT", f"community recovered: {found!r}")
    print("\n--- 2) SNMPv3 agent (community brute fails) ---")
    result = brute(Agent(v3=True), wordlist)
    verdict("FORWARD" if result is None else "DROP", f"brute result: {result!r}")
