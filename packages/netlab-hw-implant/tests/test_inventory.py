# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the asset-inventory / NAC simulator."""

from __future__ import annotations

from netlab_hw_implant.inventory import AssetInventory


def test_known_device_authorized() -> None:
    assert AssetInventory(known={"aa:bb"}).observe("aa:bb") is True


def test_rogue_device_blocked() -> None:
    assert AssetInventory(known={"aa:bb"}).observe("66:66") is False
