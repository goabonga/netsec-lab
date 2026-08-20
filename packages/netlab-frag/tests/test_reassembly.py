# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the fragment reassembly simulator."""

from __future__ import annotations

from netlab_frag.reassembly import Fragment, reassemble

FRAGS = [Fragment(0, b"AAAAAAAA"), Fragment(4, b"BBBB")]


def test_first_wins_differs_from_last_wins() -> None:
    assert reassemble(FRAGS, prefer="first") == b"AAAAAAAA"
    assert reassemble(FRAGS, prefer="last") == b"AAAABBBB"


def test_normalizer_drops_overlap() -> None:
    assert reassemble(FRAGS, drop_overlap=True) is None


def test_non_overlapping_reassembles() -> None:
    assert reassemble([Fragment(0, b"AB"), Fragment(2, b"CD")]) == b"ABCD"
