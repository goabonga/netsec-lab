# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the BCP38 / uRPF simulator."""

from __future__ import annotations

from netlab_ipspoof.urpf import IngressFilter


def test_legit_source_passes() -> None:
    assert IngressFilter("192.168.1.0/24").check("192.168.1.10") is True


def test_spoofed_source_dropped() -> None:
    assert IngressFilter("192.168.1.0/24").check("8.8.8.8") is False
