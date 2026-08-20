# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the WPA2 PMKID crack (real crypto)."""

from __future__ import annotations

from netlab_wpa_crack.crack import crack_pmkid, pmk, pmkid

SSID, AP, STA = "corp-wifi", "aa:bb:cc:00:00:01", "11:22:33:44:55:66"


def test_pmk_is_32_bytes() -> None:
    assert len(pmk("password1", SSID)) == 32


def test_crack_recovers_weak_passphrase() -> None:
    target = pmkid(pmk("letmein", SSID), AP, STA)
    assert crack_pmkid(target, SSID, AP, STA, ["admin", "letmein", "x"]) == "letmein"


def test_crack_fails_when_absent() -> None:
    target = pmkid(pmk("Str0ng!Passphrase", SSID), AP, STA)
    assert crack_pmkid(target, SSID, AP, STA, ["admin", "letmein"]) is None
