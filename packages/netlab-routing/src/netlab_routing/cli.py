# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-routing: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_routing import attack, defend, detect
from netlab_routing.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-routing", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="inject a RIP route (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--prefix", default="10.0.0.0")
    a.add_argument("--mask", default="255.0.0.0")
    a.add_argument("--next-hop", default="192.168.99.66")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="flag RIP updates from unexpected sources")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--allow", nargs="*", default=[], help="legitimate router IP(s)")
    sub.add_parser("defend", help="demonstrate neighbour authentication (simulator)")
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
