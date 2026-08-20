# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-dhcp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_dhcp import attack, defend, detect
from netlab_dhcp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-dhcp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("brief", help="print the teaching brief")

    a = sub.add_parser("attack", help="run the rogue DHCP server (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--pool-base", default="192.168.99.")
    a.add_argument("--gateway", default="192.168.99.1", help="attacker IP (becomes router + DNS)")
    a.add_argument("--dns", default=None, help="defaults to gateway")
    a.add_argument("--netmask", default="255.255.255.0")
    a.add_argument("--lease", type=int, default=600)

    d = sub.add_parser("detect", help="detect a rogue DHCP server")
    d.add_argument("--iface", default="veth-host")
    d.add_argument(
        "--allow", nargs="*", default=[], help="legitimate server_id(s), e.g. 192.168.1.1"
    )

    sub.add_parser("defend", help="demonstrate DHCP snooping (simulator)")

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
