# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-igmp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_igmp import attack, defend, detect
from netlab_igmp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-igmp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="forge an IGMP join (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--group", default="239.1.1.1", help="multicast group to join")
    a.add_argument("--count", type=int, default=3)
    d = sub.add_parser("detect", help="flag joins to sensitive groups")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--sensitive", nargs="*", default=["239.1.1.1"], help="sensitive group(s)")
    sub.add_parser("defend", help="demonstrate join restriction (simulator)")
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
