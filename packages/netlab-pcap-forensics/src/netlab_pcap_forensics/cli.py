# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""CLI for netlab-pcap-forensics: brief / detect / defend (defensive module, no attack)."""

from __future__ import annotations

import argparse

from netlab_pcap_forensics import defend, detect
from netlab_pcap_forensics.lesson import LESSON


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netlab-pcap-forensics", description=LESSON.title)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("brief", help="print the teaching brief")
    d = sub.add_parser("detect", help="triage a pcap file offline")
    d.add_argument("--pcap", required=True, help="path to the capture to analyse")
    sub.add_parser("defend", help="triage a synthetic capture")
    args = parser.parse_args(argv)
    if args.cmd == "brief":
        print(LESSON.render())
        return 0
    if args.cmd == "detect":
        return detect.run(args)
    return defend.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
