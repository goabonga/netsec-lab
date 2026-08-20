# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the Dynamic ARP Inspection simulator."""

from __future__ import annotations

from netlab_arp.dai import ArpInspector, ArpOp, ArpPacket
from netlab_core import Binding, BindingTable


def _inspector() -> ArpInspector:
    b = BindingTable()
    b.learn(Binding(mac="aa:bb", ip="10.0.0.5", vlan=10, port="Gi0/2"))
    return ArpInspector(bindings=b, trusted_ports={"Gi0/1"})


def test_legit_arp_forwarded() -> None:
    dai = _inspector()
    assert dai.handle(ArpPacket(ArpOp.REPLY, "aa:bb", "10.0.0.5", "Gi0/2")) is True


def test_spoofed_arp_dropped() -> None:
    dai = _inspector()
    assert dai.handle(ArpPacket(ArpOp.REPLY, "66:66", "10.0.0.1", "Gi0/3")) is False


def test_trusted_port_bypasses_check() -> None:
    dai = _inspector()
    assert dai.handle(ArpPacket(ArpOp.REPLY, "99:99", "10.0.0.9", "Gi0/1")) is True
