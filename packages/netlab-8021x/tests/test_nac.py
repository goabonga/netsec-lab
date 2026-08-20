# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the 802.1X / MAB NAC simulator."""

from __future__ import annotations

from netlab_8021x.nac import NacPort


def test_mab_admits_known_mac() -> None:
    assert NacPort(mab_allow={"aa:bb": "printer"}).admit("aa:bb", profile="printer") is True


def test_cloned_mac_rejected_with_profiling() -> None:
    p = NacPort(mab_allow={"aa:bb": "printer"}, require_profile=True)
    assert p.admit("aa:bb", profile="workstation") is False


def test_unknown_mac_rejected() -> None:
    assert NacPort(mab_allow={"aa:bb": "printer"}).admit("66:66") is False
