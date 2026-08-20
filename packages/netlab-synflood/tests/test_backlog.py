# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the SYN-flood / SYN-cookies simulator."""

from __future__ import annotations

from netlab_synflood.backlog import TcpListener


def test_backlog_fills_and_refuses() -> None:
    lis = TcpListener(backlog=3)
    assert [lis.on_syn() for _ in range(5)] == [True, True, True, False, False]


def test_syn_cookies_never_refuse() -> None:
    lis = TcpListener(backlog=3, use_syn_cookies=True)
    assert all(lis.on_syn() for _ in range(10))
