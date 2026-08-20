# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the tap-exposure simulator."""

from __future__ import annotations

from netlab_tap.exposure import TappedLink


def test_cleartext_link_exposed() -> None:
    assert TappedLink(encrypted=False).capture() is True


def test_encrypted_link_safe() -> None:
    assert TappedLink(encrypted=True).capture() is False
