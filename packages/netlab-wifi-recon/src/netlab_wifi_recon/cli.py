# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-wifi-recon: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_wifi_recon import attack, defend, detect
from netlab_wifi_recon.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-wifi-recon", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="passive airspace harvest (monitor mode, lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="wlan0mon", help="monitor-mode interface")
    d = sub.add_parser("detect", help="WIDS rogue-AP detection")
    d.add_argument("--iface", default="wlan0mon")
    d.add_argument("--known", nargs="*", default=[], help="sanctioned BSSID(s)")
    sub.add_parser("defend", help="demonstrate WIDS rogue-AP detection (simulator)")
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
