# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the SNI egress-policy simulator."""

from __future__ import annotations

from netlab_tls_inspect.handshake import ClientHello, SniPolicy


def test_allowlisted_sni_allowed() -> None:
    p = SniPolicy(allowlist={"good.example.com"})
    assert p.decision(ClientHello("good.example.com")) == "allow"


def test_unknown_sni_blocked() -> None:
    p = SniPolicy(allowlist={"good.example.com"})
    assert p.decision(ClientHello("evil.example.net")) == "block"
