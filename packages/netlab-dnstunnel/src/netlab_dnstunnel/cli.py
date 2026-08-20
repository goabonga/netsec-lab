# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-dnstunnel: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_dnstunnel import attack, defend, detect
from netlab_dnstunnel.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-dnstunnel", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="exfiltrate data over DNS (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--resolver", default="192.168.99.53")
    a.add_argument("--domain", default="exfil.example.com")
    a.add_argument("--message", default="TOKEN=secret")
    d = sub.add_parser("detect", help="flag DNS tunnelling")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--entropy", type=float, default=2.5, help="label entropy threshold (bits/char)")
    sub.add_parser("defend", help="demonstrate entropy-based detection (simulator)")
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
