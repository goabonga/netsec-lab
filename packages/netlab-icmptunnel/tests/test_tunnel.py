# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the ICMP-tunnel codec."""

from __future__ import annotations

from netlab_icmptunnel.tunnel import decode, encode


def test_roundtrip() -> None:
    data = b"A" * 100
    assert decode(encode(data)) == data


def test_chunking() -> None:
    assert len(encode(b"x" * 70)) == 3  # 32-byte chunks
