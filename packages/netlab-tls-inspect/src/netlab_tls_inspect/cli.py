# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-tls-inspect: brief / detect / defend (defensive module, no attack)."""

from __future__ import annotations

import argparse

from netlab_tls_inspect import defend, detect
from netlab_tls_inspect.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-tls-inspect", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    d = sub.add_parser("detect", help="extract SNI from live ClientHello and apply the allowlist")
    d.add_argument("--iface", default="veth-host", help="lab interface")
    d.add_argument(
        "--allow",
        nargs="*",
        default=["updates.example.com", "docs.example.com"],
        help="SNI allowlist",
    )
    sub.add_parser("defend", help="enforce an SNI allowlist over sample handshakes")
    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
