# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the MACsec link simulator."""

from __future__ import annotations

from netlab_macsec.link import MacsecLink


def test_authentic_frame_accepted() -> None:
    assert MacsecLink(protected=True).receive(authentic=True, packet_number=1) is True


def test_injected_frame_dropped() -> None:
    assert MacsecLink(protected=True).receive(authentic=False, packet_number=1) is False


def test_replay_dropped() -> None:
    link = MacsecLink(protected=True)
    link.receive(authentic=True, packet_number=5)
    assert link.receive(authentic=True, packet_number=5) is False


def test_cleartext_link_accepts_anything() -> None:
    assert MacsecLink(protected=False).receive(authentic=False, packet_number=0) is True
