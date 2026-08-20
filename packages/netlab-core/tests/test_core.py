# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Smoke tests for the foundation: everything imports without scapy or root."""

from __future__ import annotations

import argparse

import pytest
from netlab_core import Binding, BindingTable, ConsentError, Lesson, require_consent


def test_binding_source_guard() -> None:
    t = BindingTable()
    t.learn(Binding(mac="aa:bb", ip="10.0.0.5", vlan=10, port="Gi0/2"))
    assert t.is_valid("aa:bb", "10.0.0.5")
    assert not t.is_valid("aa:bb", "10.0.0.6")
    assert len(t) == 1


def test_consent_blocks_without_flag() -> None:
    with pytest.raises(ConsentError):
        require_consent(argparse.Namespace(i_own_this_network=False))


def test_consent_passes_with_flag() -> None:
    require_consent(argparse.Namespace(i_own_this_network=True))


def test_lesson_render() -> None:
    out = Lesson(
        slug="demo",
        layer="L2",
        title="Demo",
        summary="s",
        attack=["a"],
        defense=["d"],
    ).render()
    assert "# Demo" in out and "## Attack" in out and "## Defense" in out
