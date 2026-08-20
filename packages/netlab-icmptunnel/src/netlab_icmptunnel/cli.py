# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-icmptunnel: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_icmptunnel import attack, defend, detect
from netlab_icmptunnel.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-icmptunnel", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="exfiltrate data over ICMP echo (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    a.add_argument("--dst", default="192.168.99.1")
    a.add_argument("--message", default="TOKEN=secret")
    d = sub.add_parser("detect", help="flag oversized echo payloads")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--max-payload", type=int, default=56, help="normal ping payload size")
    sub.add_parser("defend", help="demonstrate echo-payload inspection (simulator)")
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
