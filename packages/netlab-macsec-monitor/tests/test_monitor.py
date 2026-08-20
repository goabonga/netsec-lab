# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the MACsec link monitor."""

from __future__ import annotations

from netlab_macsec_monitor.monitor import PortState, check


def test_protected_link() -> None:
    assert check(PortState("Gi0/1", macsec_active=True, cipher="GCM-AES-256")) == "protected"


def test_cleartext_flagged() -> None:
    assert check(PortState("Gi0/2", macsec_active=False)) == "cleartext"


def test_weak_cipher_flagged() -> None:
    assert check(PortState("Gi0/3", macsec_active=True, cipher="NULL")) == "weak"
