# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-wpa-crack: brief / attack / detect / defend."""

from __future__ import annotations

import argparse

from netlab_core import add_consent_arg, require_consent

from netlab_wpa_crack import attack, defend, detect
from netlab_wpa_crack.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-wpa-crack", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    a = sub.add_parser("attack", help="crack a captured PMKID, or capture one (lab only)")
    add_consent_arg(a)
    a.add_argument("--iface", default="wlan0mon")
    a.add_argument("--pmkid", help="captured PMKID (hex) -> offline crack (no radio)")
    a.add_argument("--ssid", default="corp-wifi")
    a.add_argument("--ap-mac", default="aa:bb:cc:00:00:01")
    a.add_argument("--sta-mac", default="11:22:33:44:55:66")
    a.add_argument("--wordlist", help="wordlist file")
    d = sub.add_parser("detect", help="flag handshake-capture attempts")
    d.add_argument("--iface", default="wlan0mon")
    sub.add_parser("defend", help="demonstrate weak vs strong passphrase (crypto)")
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
