# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-kerberos-net: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_kerberos_net import attack, defend, detect
from netlab_kerberos_net.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-kerberos-net", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="capture Kerberos exchanges on the wire (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="veth-host")
    d = sub.add_parser("detect", help="flag legacy Kerberos enctypes")
    d.add_argument("--enctypes", nargs="*", default=["rc4-hmac", "aes256-cts-hmac-sha1-96"])
    sub.add_parser("defend", help="demonstrate enctype strength (simulator)")
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
