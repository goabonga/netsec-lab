# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-bgp: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_bgp import attack, defend, detect
from netlab_bgp.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-bgp", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="simulate a prefix hijack (lab AS mesh)")
    add_consent_arg(a)
    a.add_argument("--prefix", default="192.0.2.0/24", help="victim prefix")
    a.add_argument("--owner-as", type=int, default=64500, help="legitimate origin AS")
    a.add_argument("--hijack-as", type=int, default=64666, help="hijacking AS")
    a.add_argument("--rpki", action="store_true", help="enable RPKI origin validation")
    d = sub.add_parser("detect", help="RPKI-validate an announcement")
    d.add_argument("--prefix", default="192.0.2.0/24")
    d.add_argument("--owner-as", type=int, default=64500)
    d.add_argument("--origin-as", type=int, default=64666, help="observed origin AS")
    sub.add_parser("defend", help="demonstrate RPKI/ROA (simulator)")
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
