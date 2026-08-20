# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the WPS PIN maths."""

from __future__ import annotations

from netlab_wps_brute.pin import brute_attempts, checksum, is_valid


def test_checksum_makes_valid_pin() -> None:
    pin7 = 1234567
    assert is_valid(pin7 * 10 + checksum(pin7))


def test_bad_checksum_invalid() -> None:
    pin7 = 1234567
    wrong = (checksum(pin7) + 1) % 10
    assert not is_valid(pin7 * 10 + wrong)


def test_two_halves_reduces_space() -> None:
    assert brute_attempts(two_halves=True) < brute_attempts(two_halves=False)
