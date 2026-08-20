# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-dns: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_dns import attack, defend, detect
from netlab_dns.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-dns", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="race a resolver to poison its cache (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--resolver", default="192.168.99.53")
    a.add_argument("--server", default="8.8.8.8", help="spoofed authoritative server")
    a.add_argument("--qname", default="example.com")
    a.add_argument("--answer", default="192.168.99.66", help="poisoned A record")
    a.add_argument("--dport", type=int, default=53210, help="resolver source port")
    a.add_argument("--txid-start", type=int, default=0)
    a.add_argument("--count", type=int, default=1000)
    d = sub.add_parser("detect", help="flag DNS answer races")
    d.add_argument("--iface", default="veth-host")
    sub.add_parser("defend", help="demonstrate txid/port matching and DNSSEC (simulator)")
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
