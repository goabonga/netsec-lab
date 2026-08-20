# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the TCP sequence-window simulator."""

from __future__ import annotations

from netlab_tcphijack.session import TcpSession


def test_in_window_segment_accepted() -> None:
    assert TcpSession(rcv_next=1000, window=100).accept(1050) is True


def test_out_of_window_segment_rejected() -> None:
    assert TcpSession(rcv_next=1000, window=100).accept(500000) is False


def test_boundary() -> None:
    s = TcpSession(rcv_next=1000, window=100)
    assert s.accept(1000) is True
    assert s.accept(1100) is False
