# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-vlan: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_vlan import attack, defend, detect
from netlab_vlan.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-vlan", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="double-tagging VLAN hop (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--native", type=int, default=1, help="native VLAN (outer tag)")
    a.add_argument("--target", type=int, default=20, help="target VLAN (inner tag)")
    a.add_argument("--dst", default="192.168.20.1")
    a.add_argument("--count", type=int, default=5)
    d = sub.add_parser("detect", help="watch for double-tagged frames")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate native-VLAN hardening (simulator)")
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
