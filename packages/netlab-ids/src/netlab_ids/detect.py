# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-ids: run the content rules over live traffic."""

from __future__ import annotations

import argparse
from typing import Any

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_ids.rules import RuleSet, content_ruleset


class Sensor:
    def __init__(self, ruleset: RuleSet) -> None:
        self._scapy = load_scapy()
        self.ruleset = ruleset

    def _handle(self, pkt: Any) -> None:
        s = self._scapy
        if pkt.haslayer(s.Raw):
            for rule in self.ruleset.alerts(bytes(pkt[s.Raw].load)):
                verdict("ALERT", f"sid {rule.sid}: {rule.msg}")

    def run(self, iface: str) -> None:
        print(
            f"[*] IDS sensor on {iface} ({len(self.ruleset.rules)} content rules). Ctrl-C to stop."
        )
        self._scapy.sniff(iface=iface, prn=self._handle, store=0)


def run(args: argparse.Namespace) -> int:
    Sensor(content_ruleset()).run(args.iface)
    return 0
