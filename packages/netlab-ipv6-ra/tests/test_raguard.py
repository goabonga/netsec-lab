# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the RA Guard simulator."""

from __future__ import annotations

from netlab_ipv6_ra.raguard import RaGuard, RouterAdvert


def test_ra_on_trusted_port_accepted() -> None:
    g = RaGuard(trusted_ports={"Gi0/1"})
    assert g.handle(RouterAdvert("de:ad", "2001:db8::/64", "Gi0/1")) is True


def test_rogue_ra_on_access_port_dropped() -> None:
    g = RaGuard(trusted_ports={"Gi0/1"})
    assert g.handle(RouterAdvert("66:66", "2001:db8:66::/64", "Gi0/3")) is False
