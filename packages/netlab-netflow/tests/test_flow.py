# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the NetFlow fan-out simulator."""

from __future__ import annotations

from netlab_netflow.flow import FlowTable


def test_fanout_counts_distinct_destinations() -> None:
    t = FlowTable()
    for i in range(5):
        t.add("tcp", "src", f"10.0.0.{i}", 445, 60)
    assert t.fanout("src") == 5


def test_scanner_flagged_over_threshold() -> None:
    t = FlowTable()
    for i in range(12):
        t.add("tcp", "scanner", f"10.0.0.{i}", 445, 60)
    assert t.scanners(threshold=10) == ["scanner"]
