# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-stp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_stp import attack, defend, detect
from netlab_stp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-stp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("brief", help="print the teaching brief")

    a = sub.add_parser("attack", help="claim the STP root bridge (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--priority", type=int, default=0, help="advertised root priority (lower wins)")
    a.add_argument("--interval", type=float, default=2.0, help="BPDU interval (s)")

    d = sub.add_parser("detect", help="watch for an STP root takeover")
    d.add_argument("--iface", default="veth-host")

    sub.add_parser("defend", help="demonstrate BPDU Guard (simulator)")

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
