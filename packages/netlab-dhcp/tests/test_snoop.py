# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the DHCP snooping simulator."""

from __future__ import annotations

from netlab_dhcp.snoop import DhcpPacket, DhcpType, SnoopingSwitch


def test_rogue_offer_dropped_on_untrusted_port() -> None:
    sw = SnoopingSwitch(trusted_ports={"Gi0/1"})
    dropped = sw.handle(DhcpPacket(DhcpType.OFFER, "66:66", "Gi0/3", your_ip="1.2.3.4"))
    assert dropped is False


def test_legit_ack_learns_client_binding() -> None:
    sw = SnoopingSwitch(trusted_ports={"Gi0/1"})
    sw.handle(DhcpPacket(DhcpType.ACK, "de:ad", "Gi0/1", your_ip="10.0.0.5", client_mac="aa:bb"))
    assert sw.bindings.is_valid("aa:bb", "10.0.0.5")


def test_starvation_rate_limited() -> None:
    sw = SnoopingSwitch(trusted_ports={"Gi0/1"}, max_discover_per_port=2)
    results = [sw.handle(DhcpPacket(DhcpType.DISCOVER, f"m{i}", "Gi0/3")) for i in range(4)]
    assert results == [True, True, False, False]
