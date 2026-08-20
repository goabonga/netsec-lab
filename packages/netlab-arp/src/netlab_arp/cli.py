# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-arp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_arp import attack, defend, detect
from netlab_arp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-arp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("brief", help="print the teaching brief")

    a = sub.add_parser("attack", help="poison ARP caches for a MITM (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--victim", default="192.168.99.10", help="victim IP")
    a.add_argument("--gateway", default="192.168.99.1", help="gateway IP to impersonate")
    a.add_argument("--interval", type=float, default=2.0, help="re-poison interval (s)")

    d = sub.add_parser("detect", help="watch for ARP cache poisoning")
    d.add_argument("--iface", default="veth-host")

    sub.add_parser("defend", help="demonstrate Dynamic ARP Inspection (simulator)")

    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "attack":
        require_consent(args)
        return attack.run(args)
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
