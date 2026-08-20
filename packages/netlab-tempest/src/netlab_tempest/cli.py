# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-tempest: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_tempest import attack, defend, detect
from netlab_tempest.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-tempest", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="model an emanation-eavesdropping attempt")
    add_consent_arg(a)
    a.add_argument("--emission", type=float, default=20.0, help="emission level (dBm)")
    a.add_argument("--distance", type=float, default=10.0, help="attacker distance (m)")
    a.add_argument("--shielding", type=float, default=0.0, help="shielding (dB)")
    d = sub.add_parser("detect", help="note on emanation (un)detectability")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate shielding (link-budget simulator)")
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
