# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""NetFlow-style flow aggregation and fan-out anomaly detection.

Aggregates packets into 5-tuple flows and flags hosts talking to an unusually
large number of distinct destinations (horizontal scan / worm fan-out). Pure
logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass(frozen=True)
class FlowKey:
    proto: str
    src: str
    dst: str
    dport: int


@dataclass
class Flow:
    key: FlowKey
    packets: int = 0
    bytes: int = 0


@dataclass
class FlowTable:
    flows: dict[FlowKey, Flow] = field(default_factory=dict)

    def add(self, proto: str, src: str, dst: str, dport: int, size: int) -> None:
        key = FlowKey(proto, src, dst, dport)
        flow = self.flows.setdefault(key, Flow(key))
        flow.packets += 1
        flow.bytes += size

    def fanout(self, src: str) -> int:
        return len({k.dst for k in self.flows if k.src == src})

    def scanners(self, threshold: int) -> list[str]:
        srcs = {k.src for k in self.flows}
        return sorted(s for s in srcs if self.fanout(s) >= threshold)


def demo() -> None:
    """Reference scenario: one host fans out to many destinations."""
    table = FlowTable()
    for i in range(20):
        table.add("tcp", "10.0.0.66", f"10.0.0.{i}", 445, 60)  # scanner
    table.add("tcp", "10.0.0.5", "93.184.216.34", 443, 1500)  # normal
    for scanner in table.scanners(threshold=10):
        verdict("ALERT", f"{scanner} reached {table.fanout(scanner)} distinct hosts -> scan")
    verdict("FORWARD", "10.0.0.5 fan-out within normal range")
