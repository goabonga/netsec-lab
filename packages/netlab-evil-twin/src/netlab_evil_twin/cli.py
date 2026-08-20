# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-evil-twin: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_evil_twin import attack, defend, detect
from netlab_evil_twin.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-evil-twin", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="beacon a cloned SSID (monitor mode, lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="wlan0mon")
    a.add_argument("--ssid", default="corp-wifi", help="SSID to clone")
    a.add_argument("--bssid", default="66:66:66:66:66:66", help="attacker BSSID")
    a.add_argument("--count", type=int, default=100)
    a.add_argument("--interval", type=float, default=0.1)
    d = sub.add_parser("detect", help="flag SSID twins")
    d.add_argument("--iface", default="wlan0mon")
    d.add_argument("--ssid", default="corp-wifi")
    d.add_argument("--legit", nargs="*", default=[], help="sanctioned BSSID(s) for the SSID")
    sub.add_parser("defend", help="demonstrate ESS twin detection (simulator)")
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
