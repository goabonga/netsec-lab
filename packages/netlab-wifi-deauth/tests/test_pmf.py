# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the 802.11w PMF simulator."""

from __future__ import annotations

from netlab_wifi_deauth.pmf import Association


def test_forged_deauth_disconnects_without_pmf() -> None:
    assert Association(pmf=False).on_deauth(authentic=False) is True


def test_pmf_ignores_forged_deauth() -> None:
    assert Association(pmf=True).on_deauth(authentic=False) is False
