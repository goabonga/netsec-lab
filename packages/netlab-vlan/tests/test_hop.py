# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the VLAN double-tagging simulator."""

from __future__ import annotations

from netlab_vlan.hop import Frame, VlanSwitch


def test_double_tag_hops_when_native_matches() -> None:
    sw = VlanSwitch(native_vlan=1, access_vlan=1)
    assert sw.forward(Frame(tags=(1, 20), ingress_port="Gi0/3")) == 20


def test_dedicated_native_vlan_blocks_hop() -> None:
    sw = VlanSwitch(native_vlan=999, access_vlan=1)
    # outer tag 1 != native 999 -> not stripped, frame stays on the access VLAN
    assert sw.forward(Frame(tags=(1, 20), ingress_port="Gi0/3")) == 1


def test_drop_tagged_on_access() -> None:
    sw = VlanSwitch(native_vlan=999, drop_tagged_on_access=True)
    assert sw.forward(Frame(tags=(1, 20), ingress_port="Gi0/3")) is None


def test_untagged_frame_uses_access_vlan() -> None:
    assert VlanSwitch(access_vlan=10).forward(Frame(tags=(), ingress_port="Gi0/2")) == 10
