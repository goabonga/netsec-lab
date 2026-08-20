# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the stateful firewall simulator."""

from __future__ import annotations

from netlab_firewall.acl import Firewall, Packet, Rule


def test_first_match_allow() -> None:
    fw = Firewall([Rule("allow", proto="tcp", dport=443)])
    assert fw.evaluate(Packet("tcp", "a", "b", 443)) == "allow"


def test_default_deny() -> None:
    fw = Firewall([Rule("allow", proto="tcp", dport=443)])
    assert fw.evaluate(Packet("tcp", "a", "b", 22)) == "deny"


def test_stateful_allows_return_traffic() -> None:
    fw = Firewall([], default="deny", stateful=True)
    assert fw.evaluate(Packet("tcp", "b", "a", 51000, established=True)) == "allow"
