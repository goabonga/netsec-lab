# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the IGMP snooping / join-control simulator."""

from __future__ import annotations

from netlab_igmp.snoop import SnoopController


def test_forged_join_eavesdrops_unrestricted_group() -> None:
    c = SnoopController()
    assert c.join("239.1.1.1", "Gi0/3") is True
    assert "Gi0/3" in c.members["239.1.1.1"]


def test_restricted_group_denies_unauthorized_join() -> None:
    c = SnoopController(restricted={"239.1.1.1": {"Gi0/2"}})
    assert c.join("239.1.1.1", "Gi0/3") is False
