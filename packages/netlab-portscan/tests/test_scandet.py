# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the scan-detection simulator."""

from __future__ import annotations

from netlab_portscan.scandet import ScanDetector


def test_sweep_is_flagged() -> None:
    det = ScanDetector(threshold=5)
    flags = [det.observe("1.2.3.4", p) for p in range(10)]
    assert any(flags)


def test_few_ports_not_flagged() -> None:
    det = ScanDetector(threshold=20)
    assert not any(det.observe("1.2.3.4", p) for p in range(5))
