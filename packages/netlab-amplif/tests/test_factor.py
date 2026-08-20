# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the amplification-factor simulator."""

from __future__ import annotations

from netlab_amplif.factor import Reflector, measure


def test_factor() -> None:
    assert Reflector("x", 10, 500).factor == 50.0


def test_anti_spoofing_blocks() -> None:
    assert measure(Reflector("x", 10, 500), anti_spoofing=True) == 0.0


def test_without_anti_spoofing_amplifies() -> None:
    assert measure(Reflector("x", 10, 500), anti_spoofing=False) == 50.0
