# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Chris <goabonga@pm.me>

"""Detect side of netlab-pcap-forensics: triage a pcap file offline."""

from __future__ import annotations

import argparse

from netlab_core import verdict
from netlab_core.sniffing import load_scapy

from netlab_pcap_forensics.analysis import Record, cleartext_creds, summarize


def run(args: argparse.Namespace) -> int:
    scapy = load_scapy()
    packets = scapy.rdpcap(args.pcap)
    records = []
    for pkt in packets:
        if not pkt.haslayer(scapy.IP):
            continue
        payload = bytes(pkt[scapy.Raw].load) if pkt.haslayer(scapy.Raw) else b""
        dport = int(pkt[scapy.TCP].dport) if pkt.haslayer(scapy.TCP) else 0
        records.append(Record("ip", pkt[scapy.IP].src, pkt[scapy.IP].dst, dport, payload))
    for leak in cleartext_creds(records):
        verdict("ALERT", f"cleartext credential {leak.src} -> {leak.dst}:{leak.dport}")
    summary = summarize(records)
    verdict(
        "INFO",
        f"packets={summary['packets']} talkers={summary['talkers']} "
        f"leaks={summary['cleartext_creds']}",
    )
    return 0
