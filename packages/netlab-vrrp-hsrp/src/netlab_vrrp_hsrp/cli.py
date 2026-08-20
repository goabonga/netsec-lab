# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-vrrp-hsrp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_vrrp_hsrp import attack, defend, detect
from netlab_vrrp_hsrp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-vrrp-hsrp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="preempt the VRRP master (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--vrid", type=int, default=1)
    a.add_argument("--priority", type=int, default=255)
    a.add_argument("--vip", default="192.168.99.1", help="virtual gateway IP")
    a.add_argument("--count", type=int, default=10)
    a.add_argument("--interval", type=float, default=1.0)
    d = sub.add_parser("detect", help="flag a VRRP master takeover")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate FHRP authentication (simulator)")
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
