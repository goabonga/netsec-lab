# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the SNMP community-string simulator."""

from __future__ import annotations

from netlab_snmp.agent import Agent, brute


def test_brute_recovers_community() -> None:
    assert brute(Agent(community="private"), ["public", "private", "x"]) == "private"


def test_v3_agent_resists_brute() -> None:
    assert brute(Agent(v3=True), ["public", "private"]) is None
