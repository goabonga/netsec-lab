# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-firewall: brief / detect / defend (defensive module, no attack)."""

from __future__ import annotations

import argparse

from netlab_firewall import defend, detect
from netlab_firewall.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-firewall", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    d = sub.add_parser("detect", help="evaluate live traffic against the ACL")
    d.add_argument("--iface", default="veth-host", help="lab interface")
    sub.add_parser("defend", help="demonstrate the default-deny stateful policy")
    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
