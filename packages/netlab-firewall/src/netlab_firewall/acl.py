# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Stateful firewall / ACL simulator: first-match rules with default deny.

Models an ordered access list evaluated top-down (first match wins) over a
default-deny policy, plus stateful inspection: return traffic of an established
connection is allowed without an explicit rule. Pure logic - safe anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netlab_core import verdict


@dataclass
class Packet:
    proto: str
    src: str
    dst: str
    dport: int
    established: bool = False


@dataclass
class Rule:
    action: str  # "allow" or "deny"
    proto: str = "any"
    src: str = "any"
    dst: str = "any"
    dport: int | None = None

    def matches(self, pkt: Packet) -> bool:
        return (
            (self.proto in ("any", pkt.proto))
            and (self.src in ("any", pkt.src))
            and (self.dst in ("any", pkt.dst))
            and (self.dport is None or self.dport == pkt.dport)
        )


@dataclass
class Firewall:
    rules: list[Rule] = field(default_factory=list)
    default: str = "deny"
    stateful: bool = True

    def evaluate(self, pkt: Packet) -> str:
        """Return 'allow' or 'deny' for a packet."""
        if self.stateful and pkt.established:
            return "allow"
        for rule in self.rules:
            if rule.matches(pkt):
                return rule.action
        return self.default


def demo() -> None:
    """Reference scenario: allow established + outbound web, deny the rest."""
    fw = Firewall(
        rules=[Rule("allow", proto="tcp", dport=443), Rule("allow", proto="tcp", dport=80)],
        default="deny",
        stateful=True,
    )
    packets = [
        Packet("tcp", "10.0.0.5", "93.184.216.34", 443),
        Packet("tcp", "203.0.113.9", "10.0.0.5", 22),
        Packet("tcp", "93.184.216.34", "10.0.0.5", 51000, established=True),
    ]
    for pkt in packets:
        decision = fw.evaluate(pkt)
        icon = "FORWARD" if decision == "allow" else "DROP"
        verdict(icon, f"{pkt.proto} {pkt.src} -> {pkt.dst}:{pkt.dport} = {decision}")
