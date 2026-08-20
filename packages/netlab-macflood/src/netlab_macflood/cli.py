# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-macflood: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_macflood import attack, defend, detect
from netlab_macflood.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-macflood", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("brief", help="print the teaching brief")

    a = sub.add_parser("attack", help="flood the CAM table (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--count", type=int, default=5000, help="number of bogus frames")

    d = sub.add_parser("detect", help="watch for CAM flooding")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--threshold", type=int, default=100, help="distinct-MAC alert threshold")

    sub.add_parser("defend", help="demonstrate port-security (simulator)")

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
