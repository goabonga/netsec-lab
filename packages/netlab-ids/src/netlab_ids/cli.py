# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-ids: brief / detect / defend (defensive module, no attack)."""

from __future__ import annotations

import argparse

from netlab_ids import defend, detect
from netlab_ids.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-ids", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    d = sub.add_parser("detect", help="run the content rules over live traffic")
    d.add_argument("--iface", default="veth-host", help="lab interface")
    sub.add_parser("defend", help="score the rule catalogue against labelled traffic")
    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
