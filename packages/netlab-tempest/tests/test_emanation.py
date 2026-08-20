# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the TEMPEST emanation link-budget simulator."""

from __future__ import annotations

from netlab_tempest.emanation import reconstructable


def test_unshielded_close_is_reconstructable() -> None:
    assert reconstructable(emission_dbm=20.0, distance_m=1.0, shielding_db=0.0) is True


def test_shielding_defeats_reconstruction() -> None:
    assert reconstructable(emission_dbm=20.0, distance_m=10.0, shielding_db=80.0) is False
