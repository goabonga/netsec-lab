# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the NTP time-shift simulator."""

from __future__ import annotations

from netlab_ntp.clock import NtpClient


def test_plain_client_accepts_shift() -> None:
    assert NtpClient(nts=False).apply(offset_s=-1000.0) is True


def test_nts_rejects_unauthenticated_time() -> None:
    assert NtpClient(nts=True).apply(offset_s=-1000.0, authenticated=False) is False
