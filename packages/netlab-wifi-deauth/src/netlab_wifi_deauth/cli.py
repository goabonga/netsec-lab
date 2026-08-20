# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-wifi-deauth: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_wifi_deauth import attack, defend, detect
from netlab_wifi_deauth.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-wifi-deauth", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="deauth flood (monitor mode, lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="wlan0mon")
    a.add_argument("--bssid", default="aa:bb:cc:00:00:01", help="AP BSSID")
    a.add_argument("--client", default="ff:ff:ff:ff:ff:ff", help="client MAC (broadcast = all)")
    a.add_argument("--count", type=int, default=50)
    a.add_argument("--interval", type=float, default=0.1)
    d = sub.add_parser("detect", help="flag a deauth flood")
    d.add_argument("--iface", default="wlan0mon")
    d.add_argument("--threshold", type=int, default=20)
    sub.add_parser("defend", help="demonstrate 802.11w PMF (simulator)")
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
