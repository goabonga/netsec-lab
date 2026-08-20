# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-quic: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_quic import attack, defend, detect
from netlab_quic.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-quic", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="emit QUIC traffic for the classifier (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--target", default="192.0.2.1", help="destination IP (cosmetic in the lab)")
    a.add_argument("--sni", default="example.com", help="SNI to embed in the Initial")
    a.add_argument("--count", type=int, default=3, help="number of Initial packets to emit")
    d = sub.add_parser("detect", help="classify QUIC packets")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate Initial-vs-short-header visibility (simulator)")
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
