# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-tls: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_tls import attack, defend, detect
from netlab_tls.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-tls", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="simulate an SSL-strip downgrade (lab only)")
    add_consent_arg(a)
    a.add_argument("--hsts", action="store_true", help="model a victim with HSTS enabled")
    d = sub.add_parser("detect", help="flag plaintext HTTP to HTTPS-only hosts")
    d.add_argument("--iface", default="veth-host")
    d.add_argument("--https-hosts", nargs="*", default=[], help="IP(s) that must use HTTPS")
    sub.add_parser("defend", help="demonstrate HSTS against SSL stripping (simulator)")
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
