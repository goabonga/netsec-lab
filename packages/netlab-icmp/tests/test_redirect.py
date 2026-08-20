# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the ICMP redirect policy simulator."""

from __future__ import annotations

from netlab_icmp.redirect import RedirectPolicy


def test_accepting_host_is_redirected() -> None:
    p = RedirectPolicy(accept_redirects=True)
    assert p.on_redirect("1.2.3.4", "10.0.0.66") is True
    assert p.routes["1.2.3.4"] == "10.0.0.66"


def test_hardened_host_ignores_redirect() -> None:
    p = RedirectPolicy(accept_redirects=False)
    assert p.on_redirect("1.2.3.4", "10.0.0.66") is False
    assert "1.2.3.4" not in p.routes
