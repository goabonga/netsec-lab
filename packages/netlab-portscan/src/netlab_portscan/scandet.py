# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Scan-detection simulator: the sensor-side defence.

A host probing many distinct ports in a short window is scanning. A detector
that counts distinct destination ports per source flags it and can rate-limit or
drop the source. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class ScanDetector:
    threshold: int = 20
    _ports: dict[str, set[int]] = field(default_factory=dict)
    _flagged: set[str] = field(default_factory=set)

    def observe(self, src: str, port: int) -> bool:
        """Return True when the source is flagged as scanning."""
        ports = self._ports.setdefault(src, set())
        ports.add(port)
        if len(ports) > self.threshold and src not in self._flagged:
            self._flagged.add(src)
            verdict("ALERT", f"{src} probed {len(ports)} ports -> PORT SCAN")
            return True
        return False


def demo() -> None:
    """Reference scenario: one source sweeping many ports past the threshold."""
    det = ScanDetector(threshold=20)
    print("--- one host probing 25 ports (threshold 20) ---")
    for port in range(1, 26):
        det.observe("192.168.1.66", port)
