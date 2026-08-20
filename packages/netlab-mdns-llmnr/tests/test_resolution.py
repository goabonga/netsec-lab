# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the LAN name-resolution poisoning simulator."""

from __future__ import annotations

from netlab_mdns_llmnr.resolution import NameResolution


def test_dns_answer_wins() -> None:
    assert NameResolution().resolve("host", dns_answer="10.0.0.5") == "dns"


def test_llmnr_fallback_poisoned() -> None:
    assert NameResolution(llmnr_enabled=True).resolve("typo", dns_answer=None) == "attacker"


def test_disabled_llmnr_fails_safely() -> None:
    assert NameResolution(llmnr_enabled=False).resolve("typo", dns_answer=None) == "none"
