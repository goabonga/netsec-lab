# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the covert-channel simulator."""

from __future__ import annotations

from netlab_covert.channel import decode, encode, normalize


def test_roundtrip() -> None:
    assert decode(encode(b"HELLO")) == b"HELLO"


def test_normalization_destroys_channel() -> None:
    ids = encode(b"SECRET")
    assert decode(normalize(ids)) != b"SECRET"
