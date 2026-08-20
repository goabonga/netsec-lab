# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-amplif: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_amplif import attack, defend, detect
from netlab_amplif.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-amplif", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="spoofed reflection off a reflector you own (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--reflector", default="192.168.99.53", help="reflector you own")
    a.add_argument("--victim", default="192.168.99.10", help="spoofed source (measurement target)")
    a.add_argument("--qname", default="example.com")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="flag reflected replies to a victim")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--victim", default="192.168.99.10")
    d.add_argument("--min-size", type=int, default=512)
    sub.add_parser("defend", help="show amplification factors and BCP38 (simulator)")
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
