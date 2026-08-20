# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-icmp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_icmp import attack, defend, detect
from netlab_icmp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-icmp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="forge an ICMP redirect (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--victim", default="192.168.99.10")
    a.add_argument("--gateway", default="192.168.99.1", help="real gateway to impersonate")
    a.add_argument("--attacker", default="192.168.99.66", help="new next-hop (attacker)")
    a.add_argument("--dest", default="93.184.216.34", help="destination to hijack")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="flag ICMP redirects")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate ignoring redirects (simulator)")
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
