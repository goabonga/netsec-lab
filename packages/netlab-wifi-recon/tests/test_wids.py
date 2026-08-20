# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the WIDS airspace simulator."""

from __future__ import annotations

from netlab_wifi_recon.wids import Airspace


def test_known_ap_ok() -> None:
    assert Airspace(known_bssids={"aa:bb"}).observe("corp", "aa:bb") is True


def test_rogue_ap_flagged() -> None:
    assert Airspace(known_bssids={"aa:bb"}).observe("corp", "66:66") is False
