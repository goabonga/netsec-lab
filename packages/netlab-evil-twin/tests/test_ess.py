# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the ESS twin-detection simulator."""

from __future__ import annotations

from netlab_evil_twin.ess import EssMonitor


def test_sanctioned_bssid_ok() -> None:
    assert EssMonitor(legit={"corp": {"aa:bb"}}).observe("corp", "aa:bb") is True


def test_twin_bssid_flagged() -> None:
    assert EssMonitor(legit={"corp": {"aa:bb"}}).observe("corp", "66:66") is False
