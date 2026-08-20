# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the CDP/LLDP policy simulator."""

from __future__ import annotations

from netlab_discovery.policy import DiscoveryPolicy, Neighbour


def test_discovery_on_infra_port_ok() -> None:
    p = DiscoveryPolicy(infra_ports={"Gi0/1"})
    assert p.observe(Neighbour("lldp", "core", "Gi0/1")) is True


def test_discovery_on_access_port_violation() -> None:
    p = DiscoveryPolicy(infra_ports={"Gi0/1"})
    assert p.observe(Neighbour("lldp", "rogue", "Gi0/3")) is False
