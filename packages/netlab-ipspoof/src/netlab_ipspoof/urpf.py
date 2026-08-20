# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""BCP38 / uRPF ingress-filter simulator: the edge-router defence.

An interface only legitimately receives packets whose source address belongs to
the prefix reachable through it. Unicast Reverse Path Forwarding drops packets
whose source could not have arrived on that interface - which is how spoofing is
contained at the network edge. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class IngressFilter:
    iface_prefix: str  # legitimate source prefix, e.g. "192.168.1.0/24"

    def check(self, src_ip: str) -> bool:
        """Return True if the source is plausible, False if it is spoofed."""
        net = ipaddress.ip_network(self.iface_prefix)
        if ipaddress.ip_address(src_ip) in net:
            verdict("FORWARD", f"src {src_ip} in {self.iface_prefix}")
            return True
        verdict("DROP", f"src {src_ip} outside {self.iface_prefix} -> SPOOFED (uRPF)")
        return False


def demo() -> None:
    """Reference scenario: a legitimate source vs a spoofed one."""
    f = IngressFilter(iface_prefix="192.168.1.0/24")
    print("--- 1) legitimate source on the LAN ---")
    f.check("192.168.1.10")
    print("\n--- 2) spoofed source (uRPF strict drops it) ---")
    f.check("8.8.8.8")
