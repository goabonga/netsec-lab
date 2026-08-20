# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the IGP route-injection simulator."""

from __future__ import annotations

from netlab_routing.igp import Router


def test_unauthenticated_route_rejected_with_auth() -> None:
    assert Router(require_auth=True).inject("10.0.0.0/8", "1.2.3.4") is False


def test_route_installed_without_auth() -> None:
    r = Router(require_auth=False)
    assert r.inject("10.0.0.0/8", "1.2.3.4") is True
    assert r.table["10.0.0.0/8"] == "1.2.3.4"
