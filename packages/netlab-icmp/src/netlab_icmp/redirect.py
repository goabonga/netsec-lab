# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""ICMP redirect policy simulator: the host-side defence.

An ICMP Redirect (type 5) tells a host to use a different next-hop for a
destination; a forged one reroutes the victim through the attacker. A host that
ignores redirects (``net.ipv4.conf.all.accept_redirects=0``) is immune. Pure
logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class RedirectPolicy:
    accept_redirects: bool = True
    routes: dict[str, str] = field(default_factory=dict)  # dest -> next-hop

    def on_redirect(self, dest: str, new_gw: str) -> bool:
        """Return True if the redirect was applied (route changed), False if ignored."""
        if not self.accept_redirects:
            verdict("FORWARD", f"redirect for {dest} ignored (accept_redirects=0)")
            return False
        self.routes[dest] = new_gw
        verdict("ALERT", f"route to {dest} redirected via {new_gw} -> MITM")
        return True


def demo() -> None:
    """Reference scenario: a forged redirect against an accepting vs a hardened host."""
    print("--- 1) host accepts ICMP redirects ---")
    RedirectPolicy(accept_redirects=True).on_redirect("93.184.216.34", "192.168.1.66")
    print("\n--- 2) hardened host ignores ICMP redirects ---")
    RedirectPolicy(accept_redirects=False).on_redirect("93.184.216.34", "192.168.1.66")
