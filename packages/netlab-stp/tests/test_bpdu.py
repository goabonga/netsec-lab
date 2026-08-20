# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the STP election / BPDU Guard simulator."""

from __future__ import annotations

from netlab_stp.bpdu import Bridge


def test_superior_bpdu_takes_root() -> None:
    b = Bridge(priority=32768)
    assert b.receive_bpdu(sender_root_priority=0, ingress_port="Gi0/1") is True
    assert b.root_priority == 0


def test_inferior_bpdu_ignored() -> None:
    b = Bridge(priority=100)
    assert b.receive_bpdu(sender_root_priority=4096, ingress_port="Gi0/1") is True
    assert b.root_priority == 100


def test_bpdu_guard_blocks_edge_port() -> None:
    b = Bridge(priority=32768, edge_ports={"Gi0/2"})
    assert b.receive_bpdu(sender_root_priority=0, ingress_port="Gi0/2") is False
    assert b.root_priority == 32768  # unchanged, BPDU was dropped
