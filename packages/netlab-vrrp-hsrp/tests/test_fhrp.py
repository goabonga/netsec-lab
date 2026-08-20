# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the FHRP (VRRP/HSRP) election simulator."""

from __future__ import annotations

from netlab_vrrp_hsrp.fhrp import VirtualRouter


def test_higher_priority_takes_master() -> None:
    v = VirtualRouter(master_priority=100)
    assert v.advertise(255) is True
    assert v.master_priority == 255


def test_authentication_rejects_forged_advert() -> None:
    v = VirtualRouter(master_priority=100, require_auth=True)
    assert v.advertise(255, authenticated=False) is False
    assert v.master_priority == 100


def test_lower_priority_ignored() -> None:
    assert VirtualRouter(master_priority=200).advertise(50) is False
