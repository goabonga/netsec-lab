# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Generic MAC/IP/VLAN/port binding table - reused by DHCP snooping, DAI
and IP Source Guard.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field


@dataclass
class Binding:
    mac: str
    ip: str
    vlan: int
    port: str
    lease: int = 0


@dataclass
class BindingTable:
    """Learned mapping built from legitimate exchanges."""

    _by_mac: dict[str, Binding] = field(default_factory=dict)

    def learn(self, binding: Binding) -> None:
        self._by_mac[binding.mac] = binding

    def get(self, mac: str) -> Binding | None:
        return self._by_mac.get(mac)

    def is_valid(self, mac: str, ip: str) -> bool:
        """Core of IP Source Guard: has this (mac, ip) pair been learned?"""
        b = self._by_mac.get(mac)
        return b is not None and b.ip == ip

    def __iter__(self) -> Iterator[Binding]:
        return iter(self._by_mac.values())

    def __len__(self) -> int:
        return len(self._by_mac)
