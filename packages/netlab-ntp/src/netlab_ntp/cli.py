# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-ntp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_ntp import attack, defend, detect
from netlab_ntp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-ntp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="forge an NTP reply to shift the clock (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--victim", default="192.168.99.10")
    a.add_argument("--server", default="192.168.99.1", help="NTP server to impersonate")
    a.add_argument("--offset", type=int, default=0, help="forged NTP timestamp")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="flag NTP from unexpected servers")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--allow", nargs="*", default=[], help="legitimate NTP server(s)")
    sub.add_parser("defend", help="demonstrate NTS authenticated time (simulator)")
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
