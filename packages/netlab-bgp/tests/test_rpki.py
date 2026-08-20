# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the BGP RPKI origin-validation simulator."""

from __future__ import annotations

from netlab_bgp.rpki import Announcement, Bgp


def _bgp() -> Bgp:
    return Bgp(roas={"192.0.2.0/24": 64500})


def test_valid_origin() -> None:
    assert _bgp().validate(Announcement("192.0.2.0/24", 64500)) == "valid"


def test_hijack_is_invalid() -> None:
    assert _bgp().validate(Announcement("192.0.2.0/24", 64666)) == "invalid"


def test_rpki_drops_hijack() -> None:
    assert _bgp().accept(Announcement("192.0.2.0/24", 64666), rpki=True) is False


def test_without_rpki_hijack_accepted() -> None:
    assert _bgp().accept(Announcement("192.0.2.0/24", 64666), rpki=False) is True


def test_unknown_prefix() -> None:
    assert _bgp().validate(Announcement("203.0.113.0/24", 64500)) == "unknown"
