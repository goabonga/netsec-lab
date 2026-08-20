# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-ipspoof: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_ipspoof import attack, defend, detect
from netlab_ipspoof.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-ipspoof", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="send a source-spoofed packet (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--spoof-src", default="8.8.8.8", help="forged source IP")
    a.add_argument("--dst", default="192.168.99.1")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="flag off-prefix source addresses")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--prefix", default="192.168.99.0/24", help="legitimate local prefix")
    sub.add_parser("defend", help="demonstrate BCP38 / uRPF (simulator)")
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
