# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Port-security simulator: the switch-side defence, dependency-free.

A switch port with a per-port MAC limit. Learning more source MACs than the
limit is a CAM-flooding attempt; the port raises a violation and shuts down
instead of failing open into a hub. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class SecurePort:
    port: str
    max_mac: int = 3
    _macs: set[str] = field(default_factory=set)
    shutdown: bool = False

    def learn(self, mac: str) -> bool:
        """Return True if the frame is accepted, False if the port blocks it."""
        if self.shutdown:
            verdict("DROP", "port err-disabled", context=self.port)
            return False
        if mac in self._macs:
            return True
        if len(self._macs) >= self.max_mac:
            verdict(
                "DROP",
                f"MAC limit {self.max_mac} exceeded -> VIOLATION (shutdown)",
                context=self.port,
            )
            self.shutdown = True
            return False
        self._macs.add(mac)
        verdict("LEARN", f"{mac} ({len(self._macs)}/{self.max_mac})", context=self.port)
        return True


def demo() -> SecurePort:
    """Reference scenario: a CAM flood on a port limited to 3 MACs."""
    port = SecurePort(port="Gi0/3", max_mac=3)
    print("--- flooding random source MACs on Gi0/3 (port-security max 3) ---")
    for i in range(6):
        port.learn(f"12:34:56:00:00:{i:02x}")
    return port
