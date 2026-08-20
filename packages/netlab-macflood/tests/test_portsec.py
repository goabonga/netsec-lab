# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the port-security simulator."""

from __future__ import annotations

from netlab_macflood.portsec import SecurePort


def test_learns_up_to_limit() -> None:
    p = SecurePort(port="Gi0/3", max_mac=3)
    assert [p.learn(f"m{i}") for i in range(3)] == [True, True, True]
    assert not p.shutdown


def test_violation_shuts_port_down() -> None:
    p = SecurePort(port="Gi0/3", max_mac=2)
    results = [p.learn(f"m{i}") for i in range(4)]
    assert results == [True, True, False, False]
    assert p.shutdown


def test_known_mac_is_free() -> None:
    p = SecurePort(port="Gi0/3", max_mac=1)
    assert p.learn("aa") is True
    assert p.learn("aa") is True  # already known, no new slot
