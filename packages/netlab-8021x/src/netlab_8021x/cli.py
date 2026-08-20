# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-8021x: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_8021x import attack, defend, detect
from netlab_8021x.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-8021x", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="MAB spoofing - clone a trusted MAC (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--spoof-mac", default="00:11:22:33:44:55", help="trusted MAC to clone")
    a.add_argument("--dst", default="192.168.99.1")
    a.add_argument("--count", type=int, default=5)
    a.add_argument("--interval", type=float, default=0.5)
    d = sub.add_parser("detect", help="watch for cloned protected MACs")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--protected", nargs="*", default=[], help="MAC(s) that should not appear here")
    sub.add_parser("defend", help="demonstrate MAB + device profiling (simulator)")
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
