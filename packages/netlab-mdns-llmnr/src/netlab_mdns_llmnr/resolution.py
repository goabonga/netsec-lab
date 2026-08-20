# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""LAN name-resolution poisoning simulator: the host-side defence.

When DNS has no answer, Windows/macOS fall back to LLMNR / mDNS / NBT-NS, asking
the whole segment 'who is NAME?'. Any host may answer, so an attacker replies
first and the victim connects to it. Disabling LLMNR/NBT-NS removes the fallback.
Network dimension only. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class NameResolution:
    llmnr_enabled: bool = True

    def resolve(self, name: str, dns_answer: str | None) -> str:
        """Return who answers: 'dns', 'attacker' (poisoned) or 'none'."""
        if dns_answer:
            verdict("FORWARD", f"{name} resolved by DNS -> {dns_answer}")
            return "dns"
        if self.llmnr_enabled:
            verdict("ALERT", f"{name} fell back to LLMNR -> attacker answers first (POISONED)")
            return "attacker"
        verdict("DROP", f"{name} unresolved (LLMNR/NBT-NS disabled) -> fails safely")
        return "none"


def demo() -> None:
    """Reference scenario: a typo host name, with and without LLMNR."""
    print("--- 1) DNS has no record, LLMNR enabled -> poisoned ---")
    NameResolution(llmnr_enabled=True).resolve("fileservr", dns_answer=None)
    print("\n--- 2) LLMNR/NBT-NS disabled -> resolution fails safely ---")
    NameResolution(llmnr_enabled=False).resolve("fileservr", dns_answer=None)
