# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-snmp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_snmp import attack, defend, detect
from netlab_snmp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-snmp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="brute-force the SNMP community (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--target", default="192.168.99.1")
    a.add_argument("--community", nargs="*", default=[], help="community wordlist")
    a.add_argument("--timeout", type=float, default=1.0)
    d = sub.add_parser("detect", help="flag SNMP community brute-forcing")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--threshold", type=int, default=5)
    sub.add_parser("defend", help="demonstrate SNMPv3 vs community brute (simulator)")
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
