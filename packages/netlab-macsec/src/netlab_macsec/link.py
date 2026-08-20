# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""MACsec (802.1AE) link simulator: the positive control - the "TLS of layer 2".

A MACsec-protected link encrypts and integrity-protects every frame, so an
injected or replayed frame fails the integrity/replay check and is dropped. A
cleartext link accepts anything on the wire. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass
class MacsecLink:
    protected: bool = True
    _last_pn: int = 0  # highest accepted packet number (replay window)

    def receive(self, authentic: bool, packet_number: int = 0) -> bool:
        """Return True if the frame is accepted, False if MACsec drops it."""
        if not self.protected:
            verdict("FORWARD", "cleartext link accepts frame (no protection)")
            return True
        if not authentic:
            verdict("DROP", "integrity check failed -> injected frame")
            return False
        if packet_number <= self._last_pn:
            verdict("DROP", f"replay (pn {packet_number} <= {self._last_pn})")
            return False
        self._last_pn = packet_number
        verdict("FORWARD", f"authentic frame pn {packet_number}")
        return True


def demo() -> None:
    """Reference scenario: injection and replay on a MACsec link vs a cleartext link."""
    print("--- 1) MACsec link: injected and replayed frames are dropped ---")
    link = MacsecLink(protected=True)
    link.receive(authentic=True, packet_number=1)
    link.receive(authentic=False, packet_number=2)  # injected
    link.receive(authentic=True, packet_number=1)  # replay
    print("\n--- 2) cleartext link: anything on the wire is accepted ---")
    MacsecLink(protected=False).receive(authentic=False, packet_number=99)
