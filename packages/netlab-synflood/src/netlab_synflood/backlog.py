# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""SYN-flood / SYN-cookies simulator: the listener-side defence.

TCP allocates state on a SYN and waits for the final ACK (a half-open
connection). Flooding SYNs fills the backlog so real handshakes are refused. SYN
cookies encode the connection state in the SYN/ACK sequence number and allocate
nothing until the ACK returns. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class TcpListener:
    backlog: int = 128
    use_syn_cookies: bool = False
    half_open: int = 0

    def on_syn(self) -> bool:
        """Return True if the SYN is accepted, False if the backlog refuses it."""
        if self.use_syn_cookies:
            verdict("FORWARD", "SYN cookie issued (no state allocated)")
            return True
        if self.half_open >= self.backlog:
            verdict("DROP", f"backlog full ({self.backlog}) -> SYN FLOOD DoS")
            return False
        self.half_open += 1
        verdict("LEARN", f"half-open {self.half_open}/{self.backlog}")
        return True


def demo() -> None:
    """Reference scenario: a SYN flood against a small backlog, with/without cookies."""
    print("--- 1) no SYN cookies (backlog 3) ---")
    weak = TcpListener(backlog=3)
    for _ in range(5):
        weak.on_syn()
    print("\n--- 2) SYN cookies enabled ---")
    strong = TcpListener(backlog=3, use_syn_cookies=True)
    for _ in range(5):
        strong.on_syn()
