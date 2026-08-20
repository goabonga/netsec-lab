# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the DNS-tunnel codec / detector."""

from __future__ import annotations

from netlab_dnstunnel.tunnel import decode, encode, label_entropy


def test_roundtrip() -> None:
    assert decode(encode(b"exfil me", "d.example.com")) == b"exfil me"


def test_encoded_label_is_high_entropy() -> None:
    label = encode(b"random binary payload", "d.example.com")[0].split(".", 1)[0]
    assert label_entropy(label) > 2.5
