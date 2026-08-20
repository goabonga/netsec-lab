# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Unit tests for the DNS cache-poisoning simulator."""

from __future__ import annotations

from netlab_dns.resolver import Query, Resolver

Q = Query(port=53210, txid=0x1234)


def test_wrong_txid_rejected() -> None:
    assert Resolver().accept_reply(Q, 53210, 0x9999) is False


def test_matching_reply_accepted() -> None:
    assert Resolver().accept_reply(Q, 53210, 0x1234) is True


def test_dnssec_rejects_unsigned() -> None:
    assert Resolver(dnssec=True).accept_reply(Q, 53210, 0x1234, signed=False) is False
