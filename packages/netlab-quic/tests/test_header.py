# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the QUIC header classifier and the emitter's forged packets."""

from __future__ import annotations

from netlab_quic.attack import _quic_initial, _quic_short
from netlab_quic.header import classify, is_long_header


def test_long_header_detected() -> None:
    assert is_long_header(0xC0) is True
    assert "Initial" in classify(0xC0)


def test_short_header_opaque() -> None:
    assert is_long_header(0x40) is False
    assert "opaque" in classify(0x40)


def test_emitted_initial_is_long_header_with_sni() -> None:
    pkt = _quic_initial("example.com")
    assert is_long_header(pkt[0]) is True
    assert b"sni=example.com" in pkt


def test_emitted_short_header_is_opaque() -> None:
    assert is_long_header(_quic_short()[0]) is False
