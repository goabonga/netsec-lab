# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""DNS cache-poisoning simulator: the resolver-side defence.

A resolver only accepts a reply whose source port and 16-bit transaction ID
match its outstanding query. Source-port randomization multiplies the entropy an
off-path attacker must guess; DNSSEC signs records so a forged answer fails
validation regardless. Pure logic - safe to run anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from netlab_core import verdict


@dataclass(frozen=True)
class Query:
    port: int
    txid: int


@dataclass
class Resolver:
    dnssec: bool = False

    def accept_reply(
        self, query: Query, reply_port: int, reply_txid: int, signed: bool = True
    ) -> bool:
        """Return True if the reply is accepted (cached), False if rejected."""
        if self.dnssec and not signed:
            verdict("DROP", "unsigned answer fails DNSSEC validation")
            return False
        if reply_port != query.port or reply_txid != query.txid:
            verdict("DROP", "port/txid mismatch -> forged reply dropped")
            return False
        verdict("ALERT", f"reply accepted for txid {reply_txid:#06x} (cache updated)")
        return True


def demo() -> None:
    """Reference scenario: a forged reply, a lucky guess, then DNSSEC."""
    query = Query(port=53210, txid=0x1234)
    print("--- 1) forged reply, wrong txid ---")
    Resolver().accept_reply(query, reply_port=53210, reply_txid=0x9999)
    print("\n--- 2) forged reply, guessed txid (no DNSSEC) -> POISONED ---")
    Resolver().accept_reply(query, reply_port=53210, reply_txid=0x1234)
    print("\n--- 3) same forgery under DNSSEC ---")
    Resolver(dnssec=True).accept_reply(query, reply_port=53210, reply_txid=0x1234, signed=False)
