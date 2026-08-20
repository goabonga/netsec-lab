# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""TCP sequence-window simulator: why ISN randomization matters.

A TCP endpoint only accepts a segment whose sequence number falls in its receive
window. To inject data or a RST an attacker must land a sequence number in that
window; a randomized ISN over the 2^32 space makes a blind guess vanishingly
unlikely. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class TcpSession:
    rcv_next: int
    window: int = 65535

    def accept(self, seq: int) -> bool:
        """Return True if a segment with this sequence would be accepted."""
        if self.rcv_next <= seq < self.rcv_next + self.window:
            verdict("FORWARD", f"seq {seq} in window")
            return True
        verdict(
            "DROP",
            f"seq {seq} out of window -> injection rejected (needs a valid ISN)",
        )
        return False


def demo() -> None:
    """Reference scenario: an in-window segment vs a blind attacker's guess."""
    session = TcpSession(rcv_next=1_000_000, window=65535)
    print("--- 1) legitimate in-window segment ---")
    session.accept(1_030_000)
    print("\n--- 2) blind attacker guessing the sequence (randomized ISN) ---")
    session.accept(42)
