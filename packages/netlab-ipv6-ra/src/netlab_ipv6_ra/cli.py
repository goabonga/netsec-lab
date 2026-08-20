# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-ipv6-ra: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_ipv6_ra import attack, defend, detect
from netlab_ipv6_ra.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-ipv6-ra", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="flood rogue RAs (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--prefix", default="2001:db8:66::", help="advertised prefix")
    a.add_argument("--dns", default="2001:db8:66::1", help="advertised RDNSS (attacker)")
    a.add_argument("--lifetime", type=int, default=1800)
    a.add_argument("--count", type=int, default=10)
    a.add_argument("--interval", type=float, default=1.0)
    d = sub.add_parser("detect", help="watch for rogue RAs")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--allow", nargs="*", default=[], help="legit router link-local address(es)")
    sub.add_parser("defend", help="demonstrate RA Guard (simulator)")
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
