# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-wps-brute: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_wps_brute import attack, defend, detect
from netlab_wps_brute.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-wps-brute", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="enumerate the reduced WPS PIN space (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="wlan0mon")
    a.add_argument("--sample", type=int, default=100000, help="PIN range to checksum-filter")
    d = sub.add_parser("detect", help="flag WPS registrar brute-force")
    d.add_argument("--iface", default="wlan0mon")
    sub.add_parser("defend", help="demonstrate the PIN search-space maths (simulator)")
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
