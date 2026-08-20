# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the Kerberos enctype simulator."""

from __future__ import annotations

from netlab_kerberos_net.enctype import is_crackable


def test_legacy_enctype_crackable() -> None:
    assert is_crackable("rc4-hmac") is True


def test_aes_not_crackable() -> None:
    assert is_crackable("aes256-cts-hmac-sha1-96") is False
