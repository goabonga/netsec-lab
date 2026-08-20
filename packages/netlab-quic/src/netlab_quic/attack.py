# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Attack side of netlab-quic: emit QUIC traffic for the classifier. LAB ONLY.

QUIC fingerprinting is passive - the observer lives in detect.py. To exercise it
in the isolated lab you need QUIC on the wire, so this side emits what a real
client would send: a long-header Initial (version + a stand-in ClientHello
carrying the SNI, which a middlebox can fingerprint) and an opaque short-header
packet. Point detect.py at the same segment to classify them.
"""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy


def _quic_initial(sni: str) -> bytes:
    """A teaching stand-in for a QUIC v1 Initial (long header, first byte 0xC0)."""
    version = b"\x00\x00\x00\x01"  # QUIC v1
    dcid = b"\xde\xad\xbe\xef\xde\xad\xbe\xef"
    scid = b"\xca\xfe\xba\xbe"
    header = bytes([0xC0]) + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    # Stand-in CRYPTO frame: not real TLS, but carries the SNI to show it is exposed.
    crypto = b"\x00CRYPTO/ClientHello sni=" + sni.encode()
    return header + crypto


def _quic_short() -> bytes:
    """A short-header packet (first byte 0x40): fully encrypted, opaque."""
    return bytes([0x40]) + b"\x00" * 16


def run(args: argparse.Namespace) -> int:
    s = load_scapy()
    base = s.Ether() / s.IP(dst=args.target) / s.UDP(sport=54321, dport=443)
    initial = base / s.Raw(load=_quic_initial(args.sni))
    short = base / s.Raw(load=_quic_short())
    s.sendp([initial] * args.count, iface=args.iface, verbose=0)
    s.sendp(short, iface=args.iface, verbose=0)
    verdict(
        "ALERT",
        f"emitted {args.count} QUIC Initial(s) (SNI={args.sni}) + 1 short-header "
        f"packet on {args.iface} -> {args.target}:443",
    )
    return 0
