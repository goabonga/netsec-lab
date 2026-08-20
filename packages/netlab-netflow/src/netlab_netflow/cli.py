# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-netflow: brief / detect / defend (defensive module, no attack)."""

from __future__ import annotations

import argparse

from netlab_netflow import defend, detect
from netlab_netflow.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-netflow", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    d = sub.add_parser("detect", help="build flows from live traffic and flag fan-out")
    d.add_argument("--iface", default="veth-host", help="lab interface")
    d.add_argument(
        "--threshold", type=int, default=10, help="distinct-destination fan-out threshold"
    )
    sub.add_parser("defend", help="export flows and flag anomalies on a synthetic trace")
    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
